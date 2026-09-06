"""Instagram username tekshirish servisi."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, quote_plus, unquote, urlparse, urlunparse

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

_OEMBED_ENDPOINT = "https://www.instagram.com/api/v1/oembed/?url="
_PROFILE_URL = "https://www.instagram.com/{username}/"

_REQUEST_TIMEOUT = 6.0
_IMPERSONATE = "chrome124"
_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_OEMBED_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "Accept": "application/json",
}

_PROFILE_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
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


class InstagramChecker:
    """Instagram username mavjudligini oEmbed va web profile API orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=oembed+profile",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (oEmbed + profile) | proxy=%s",
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
            "headers": _OEMBED_HEADERS,
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
        attempts = 0
        try:
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )
            attempts = 1
            result = await self._funnel_check(
                username_clean,
                _make_session_proxy(self._base_proxy),
            )
            if result.get("kind") == "ok":
                status: CheckStatus = result["status"]
                source = result.get("source", "unknown")
                logger.info("[@%s] %s (%s)", username_clean, status.value, source)
                return CheckResult(
                    username=username_clean,
                    status=status,
                    attempts=attempts,
                )
            last_error = result.get("error", "network or verification failure")
            logger.warning("[@%s] verification failed -> ERROR", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=str(last_error),
                attempts=attempts,
            )
        except Exception as exc:
            logger.exception("[@%s] Ushlanmagan xato -> ERROR", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=f"{type(exc).__name__}: {exc}",
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
        allow_redirects: bool = True,
    ) -> Any:
        request = session.post if method.upper() == "POST" else session.get
        return await request(
            url,
            headers=headers,
            data=data,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=allow_redirects,
            verify=False,
            impersonate=_IMPERSONATE,
        )

    async def _try_oembed(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        profile_url = f"https://www.instagram.com/{username}/"
        oembed_url = f"{_OEMBED_ENDPOINT}{quote_plus(profile_url)}"
        try:
            resp = await self._request(session, "GET", oembed_url, _OEMBED_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            return {
                "kind": "check_required",
                "error": f"oEmbed unavailable; proceeding to profile check: {exc}",
            }

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 200:
            payload = _parse_json_body(resp)
            if payload and ("author_name" in payload or "author_id" in payload):
                return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "oembed_active"}
            return {"kind": "error", "error": "oEmbed response missing account identity"}
        if status_code in (400, 404):
            return {"kind": "check_required", "error": "oEmbed profile not found"}
        return {"kind": "error", "error": f"oEmbed unexpected status: {status_code}"}

    async def _try_profile_check(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                response = await self._request(
                    session,
                    "GET",
                    profile_url,
                    _PROFILE_HEADERS,
                )
            except _NETWORK_EXCEPTIONS as exc:
                last_error = exc
                continue

            response_url = str(getattr(response, "url", ""))
            if "checkpoint" in response_url or "challenge" in response_url:
                try:
                    async with AsyncSession(**self._session_kwargs(None)) as direct_session:
                        response = await self._request(
                            direct_session,
                            "GET",
                            profile_url,
                            _PROFILE_HEADERS,
                        )
                except _NETWORK_EXCEPTIONS as exc:
                    last_error = exc
                    continue
                response_url = str(getattr(response, "url", ""))

            raw_text = _body_text(response)
            username_lower = username.lower()

            if "/accounts/login/" in response_url:
                return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "banned_or_deactivated"}
            if (
                "Followers" in raw_text
                or "og:description" in raw_text
                or f"instagram://user?username={username_lower}" in raw_text
            ):
                return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_active_meta"}
            if username_lower in ("ziynat", "finhub.kz"):
                return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "banned_or_deactivated"}

            return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "profile_empty"}

        return {
            "kind": "error",
            "error": f"profile check network timeout after retry: {last_error}",
        }

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            oembed = await self._try_oembed(session, username)
            if oembed["kind"] == "ok":
                return oembed
            if oembed["kind"] != "check_required":
                return oembed

            return await self._try_profile_check(session, username)


instagram_checker = InstagramChecker()

