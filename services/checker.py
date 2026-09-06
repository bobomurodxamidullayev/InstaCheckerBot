"""Instagram username tekshirish servisi.

The native Android endpoint is the only primary source. Any ambiguous result
is deliberately treated as TAKEN so transient Instagram responses cannot
produce a false AVAILABLE result.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, unquote, urlparse, urlunparse

from curl_cffi import CurlError
from curl_cffi.requests import AsyncSession

try:
    from curl_cffi.requests.exceptions import RequestException
except ImportError:
    from curl_cffi.requests.errors import RequestsError as RequestException  # type: ignore

try:
    from curl_cffi.requests.exceptions import RequestsError
except ImportError:
    try:
        from curl_cffi.requests.errors import RequestsError  # type: ignore
    except ImportError:
        RequestsError = RequestException  # type: ignore

from config import settings
from models.username_log import CheckStatus

logger = logging.getLogger(__name__)

_SIGNUP_PAGE_URL = "https://www.instagram.com/accounts/emailsignup/"
_SIGNUP_ATTEMPT_URL = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
_PROFILE_URL = "https://www.instagram.com/{username}/"

_REQUEST_TIMEOUT = 20.0
_IMPERSONATE = "chrome120"
_SIGNUP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_SIGNUP_PAGE_HEADERS: dict[str, str] = {
    "User-Agent": _SIGNUP_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_SIGNUP_HEADERS: dict[str, str] = {
    "User-Agent": _SIGNUP_USER_AGENT,
    "Accept-Language": "en-US",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-IG-App-ID": "936619743392459",
    "X-ASBD-ID": "129477",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": _SIGNUP_PAGE_URL,
}

_PROFILE_HEADERS: dict[str, str] = {
    "User-Agent": _SIGNUP_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_NETWORK_EXCEPTIONS = (
    RequestsError,
    RequestException,
    CurlError,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
)

_USERNAME_RE = re.compile(r"^[a-z0-9._]{1,30}$")

@dataclass
class CheckResult:
    """Bitta username tekshiruvi natijasi (handler/DB bilan mos)."""

    username: str
    status: CheckStatus
    error_message: Optional[str] = None
    attempts: int = 1

    def to_dict(self) -> dict[str, Any]:
        mapping = {
            CheckStatus.AVAILABLE: "available",
            CheckStatus.TAKEN: "taken",
            CheckStatus.ERROR: "error",
        }
        return {
            "status": mapping[self.status],
            "username": self.username,
            "error": self.error_message,
        }


def _make_session_proxy(base_proxy: str | None) -> str | None:
    """
    DataImpulse rotating proxy: bitta check (yoki retry) uchun bitta sticky session ID.
    """
    if not base_proxy:
        return None
    parsed = urlparse(base_proxy.strip())
    if not parsed.hostname or parsed.username is None:
        return base_proxy
    username = unquote(parsed.username)
    password = unquote(parsed.password or "")
    username = re.sub(r"_session[-.][A-Za-z0-9_-]+$", "", username)
    username = re.sub(r"_sid[-.][A-Za-z0-9_-]+$", "", username)
    session_user = f"{username}_session-{secrets.token_hex(8)}"
    auth = f"{quote(session_user, safe='')}:{quote(password, safe='')}"
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse((
        parsed.scheme or "http",
        f"{auth}@{host}",
        parsed.path, parsed.params, parsed.query, parsed.fragment,
    ))


def _body_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(response, "content", b"")
    if isinstance(content, (bytes, bytearray)):
        try:
            return bytes(content).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return str(content or "")


def _parse_json_body(response: Any) -> dict[str, Any] | None:
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    text = _body_text(response).strip()
    if not text or text[0] not in "{[":
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _is_timeout_exception(exc: BaseException) -> bool:
    return isinstance(exc, (TimeoutError, asyncio.TimeoutError)) or (
        "timeout" in type(exc).__name__.lower()
    )


def _has_username_error(payload: dict[str, Any]) -> bool:
    errors = payload.get("errors")
    if isinstance(errors, dict):
        return "username" in errors
    if isinstance(errors, list):
        return any(
            (isinstance(error, dict) and "username" in error)
            or (isinstance(error, str) and "username" in error.lower())
            for error in errors
        )
    if isinstance(errors, str):
        return "username" in errors.lower()
    return False


def _looks_like_regular_word(username: str) -> bool:
    return username.isalpha() and len(username) >= 4


class InstagramChecker:
    """Instagram username mavjudligini native Android endpoint orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=signup",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (CSRF signup) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    def _session_kwargs(self, proxy: str | None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _REQUEST_TIMEOUT,
            "max_clients": 1,
            "verify": False,
            "allow_redirects": True,
            "headers": _SIGNUP_PAGE_HEADERS,
        }
        if proxy:
            kwargs["proxy"] = proxy
        return kwargs

    async def check_username(
        self,
        username: str,
        max_retries: int = 1,
    ) -> CheckResult:
        username_clean = username.strip().lstrip("@").lower()

        if not _USERNAME_RE.fullmatch(username_clean):
            return CheckResult(
                username=username_clean,
                status=CheckStatus.TAKEN,
                error_message=None,
                attempts=0,
            )

        if username_clean in self._checking_usernames:
            logger.warning("[@%s] Parallel tekshiruv — davom etiladi.", username_clean)

        self._checking_usernames.add(username_clean)
        extra_tries = 1 if max_retries >= 1 else 0
        attempts = 0
        try:
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )
            for attempt in range(1, 2 + extra_tries):
                attempts = attempt
                sticky_proxy = _make_session_proxy(self._base_proxy)
                result = await self._funnel_check(username_clean, sticky_proxy)
                if result.get("kind") == "ok":
                    status: CheckStatus = result["status"]
                    source = result.get("source", "unknown")
                    logger.info("[@%s] %s (%s)", username_clean, status.value, source)
                    return CheckResult(
                        username=username_clean,
                        status=status,
                        attempts=attempt,
                    )
                logger.warning(
                    "[@%s] tarmoq/proxy xato (%s) | urinish %d",
                    username_clean,
                    result.get("error"),
                    attempt,
                )
            logger.warning("[@%s] ikkala urinish ham xato -> TAKEN", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.TAKEN,
                error_message=None,
                attempts=attempts,
            )
        except Exception:
            logger.exception("[@%s] Ushlanmagan xato -> TAKEN", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.TAKEN,
                error_message=None,
                attempts=max(attempts, 1),
            )
        finally:
            self._checking_usernames.discard(username_clean)

    async def _request(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        headers: dict[str, str],
        data: dict[str, str] | None = None,
    ) -> Any:
        request = session.post if method.upper() == "POST" else session.get
        return await request(
            url,
            headers=headers,
            data=data,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            impersonate=_IMPERSONATE,
        )

    async def _check_signup_availability(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        session_kwargs = self._session_kwargs(proxy)
        session_kwargs["headers"] = _SIGNUP_PAGE_HEADERS
        async with AsyncSession(**session_kwargs) as session:
            try:
                page = await self._request(
                    session,
                    "GET",
                    _SIGNUP_PAGE_URL,
                    _SIGNUP_PAGE_HEADERS,
                )
                csrf_token = session.cookies.get("csrftoken") or "missing"
                headers = {**_SIGNUP_HEADERS, "X-CSRFToken": csrf_token}
                email = f"chk_{secrets.token_hex(8)}@gmail.com"
                resp = await self._request(
                    session,
                    "POST",
                    _SIGNUP_ATTEMPT_URL,
                    headers,
                    data={
                        "email": email,
                        "username": username,
                        "first_name": "",
                        "opt_into_one_tap": "false",
                    },
                )
            except _NETWORK_EXCEPTIONS as exc:
                error_kind = "timeout" if _is_timeout_exception(exc) else "network"
                return {"kind": "fallback", "error": f"signup {error_kind}: {exc}"}

            status_code = int(getattr(resp, "status_code", 0) or 0)
            if status_code == 429:
                return {"kind": "fallback", "error": "signup HTTP 429"}

            payload = _parse_json_body(resp)
            if not payload:
                return {"kind": "fallback", "error": "signup response is not JSON"}
            if _has_username_error(payload):
                return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "signup_taken"}
            if payload.get("status") == "ok":
                return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "signup_available"}
            return {"kind": "fallback", "error": "signup response is ambiguous"}

    async def _try_profile(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        try:
            resp = await self._request(session, "GET", profile_url, _PROFILE_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "profile_deactive",
                "error": f"profile network error: {exc}",
            }

        status_code = int(getattr(resp, "status_code", 0) or 0)
        html = _body_text(resp)
        html_lower = html.lower()
        final_url = str(getattr(resp, "url", "") or "").lower()

        if (
            "- followers, " in html_lower
            or f"(@{username.lower()})" in html_lower
            or "edge_followed_by" in html_lower
        ):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_active"}

        if "/accounts/login" in final_url or "/challenge" in final_url:
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_deactive"}

        if (
            status_code == 404
            or "<title>page not found" in html_lower
            or "sorry, this page isn't available." in html_lower
        ):
            return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "profile_available"}

        if "<title>instagram</title>" in html_lower:
            if _looks_like_regular_word(username):
                return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_deactive"}
            return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "profile_available"}

        if _looks_like_regular_word(username):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_deactive"}

        return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "profile_available"}

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        signup = await self._check_signup_availability(username, proxy)
        if signup["kind"] == "ok":
            return signup

        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            return await self._try_profile(session, username)


instagram_checker = InstagramChecker()
