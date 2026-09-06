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

_ANDROID_CHECK_USERNAME_URL = "https://i.instagram.com/api/v1/users/check_username/"
_PROFILE_URL = "https://www.instagram.com/{username}/"

_REQUEST_TIMEOUT = 20.0
_IMPERSONATE = "chrome120"
_ANDROID_UA = (
    "Instagram 269.0.0.18.75 Android (30/11; 480dpi; 1080x2176; Xiaomi; "
    "Mi A3; laurel_sprout; qcom; ru_RU; 314665256)"
)

_JSON_HEADERS: dict[str, str] = {
    "User-Agent": _ANDROID_UA,
    "Accept": "application/json",
    "Accept-Language": "en-US",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-IG-App-ID": "936619743392459",
    "X-FB-HTTP-Engine": "Liger",
}

_PROFILE_HEADERS: dict[str, str] = {
    "User-Agent": _ANDROID_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US",
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


def _classify_android_response(
    status_code: int,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Classify native JSON signals without treating missing data as available."""
    if status_code == 429:
        return {"kind": "fallback", "error": "HTTP 429 Rate Limited"}

    if not payload:
        return {"kind": "safe_taken", "error": f"native HTTP {status_code} without JSON"}

    if payload.get("available") is True:
        return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "android_available"}

    if payload.get("available") is False:
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "android_taken"}

    if "error" in payload or payload.get("status") == "fail":
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "android_taken"}

    return {"kind": "safe_taken", "error": "native response is ambiguous"}


class InstagramChecker:
    """Instagram username mavjudligini native Android endpoint orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=android",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (native Android) | proxy=%s",
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
            "headers": _JSON_HEADERS,
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

    async def _try_android(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        try:
            resp = await self._request(
                session,
                "POST",
                _ANDROID_CHECK_USERNAME_URL,
                _JSON_HEADERS,
                data={"username": username},
            )
        except _NETWORK_EXCEPTIONS as exc:
            error_kind = "timeout" if _is_timeout_exception(exc) else "network"
            return {"kind": "fallback", "error": f"native {error_kind}: {exc}"}

        return _classify_android_response(
            int(getattr(resp, "status_code", 0) or 0),
            _parse_json_body(resp),
        )

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
        if status_code == 404 or "page not found" in html.lower():
            return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "profile_404"}
        if status_code == 200 and (
            "followers" in html.lower() or "og:description" in html.lower()
        ):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_active"}
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "profile_deactive"}

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            native = await self._try_android(session, username)
            if native["kind"] == "ok":
                return native
            if native["kind"] == "fallback":
                return await self._try_profile(session, username)
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "safe_fallback"}


instagram_checker = InstagramChecker()
