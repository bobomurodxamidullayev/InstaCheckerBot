"""Instagram username tekshirish servisi — Yakuniy API va Strict HTML pipeline."""
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OEMBED_ENDPOINT = "https://www.instagram.com/api/v1/oembed/?url="
_PROFILE_URL = "https://www.instagram.com/{username}/"
_CHECK_USERNAME_API_URL = "https://www.instagram.com/api/v1/web/accounts/check_username/"

_REQUEST_TIMEOUT = 6.0
_PROFILE_TIMEOUT = 9.0
_DIRECT_PROFILE_TIMEOUT = 7.0
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

# ---------------------------------------------------------------------------
# Tier-1 pre-validation constants
# ---------------------------------------------------------------------------

_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")

_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
    "meta", "privacy", "terms", "settings", "profile"
})

# ---------------------------------------------------------------------------
# HTML signal constants
# ---------------------------------------------------------------------------

_TAKEN_URL_MARKERS: tuple[str, ...] = (
    "/accounts/login",
    "/challenge",
    "checkpoint",
    "/accounts/suspended",
)

_TAKEN_BODY_MARKERS: tuple[str, ...] = (
    "instapp:owner_user_id",
    "profile_pic_url",
    "biography",
    "Followers",
    "og:description",
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session_proxy(base_proxy: str | None) -> str | None:
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


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=signup_api_enabled",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (API validator + strict fallback) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    def _session_kwargs(
        self,
        proxy: str | None,
        timeout: float = _REQUEST_TIMEOUT,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": timeout,
            "max_clients": 1,
            "verify": False,
            "allow_redirects": True,
            "headers": _OEMBED_HEADERS,
        }
        if proxy:
            kwargs["proxy"] = proxy
        return kwargs

    async def _request(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        headers: dict[str, str],
        data: dict[str, str] | None = None,
        allow_redirects: bool = True,
        timeout: float = _REQUEST_TIMEOUT,
    ) -> Any:
        fn = session.post if method.upper() == "POST" else session.get
        return await fn(
            url,
            headers=headers,
            data=data,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False,
            impersonate=_IMPERSONATE,
        )

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    async def check_username(
        self,
        username: str,
        max_retries: int = 1,
    ) -> CheckResult:
        username_clean = username.strip().lstrip("@").lower()

        # TIER 1
        tier1 = self._tier1_prevalidate(username_clean)
        if tier1 is not None:
            status, reason = tier1
            logger.info("[@%s] TIER-1 rejected → %s (%s)", username_clean, status.value, reason)
            return CheckResult(username=username_clean, status=status, error_message=reason, attempts=0)

        if username_clean in self._checking_usernames:
            logger.warning("[@%s] Parallel tekshiruv — davom etiladi.", username_clean)

        self._checking_usernames.add(username_clean)
        attempts = 0
        try:
            await asyncio.sleep(random.uniform(settings.check_delay_min, settings.check_delay_max))
            attempts = 1
            result = await self._funnel_check(username_clean, _make_session_proxy(self._base_proxy))
            
            if result.get("kind") == "ok":
                status = result["status"]
                source = result.get("source", "unknown")
                reason = result.get("reason")
                logger.info("[@%s] %s (%s) [%s]", username_clean, status.value, reason, source)
                return CheckResult(username=username_clean, status=status, error_message=reason, attempts=attempts)
            
            last_error = result.get("error", "network or verification failure")
            logger.warning("[@%s] verification failed → ERROR: %s", username_clean, last_error)
            return CheckResult(username=username_clean, status=CheckStatus.ERROR, error_message=str(last_error), attempts=attempts)
            
        except Exception as exc:
            logger.exception("[@%s] Ushlanmagan xato → ERROR", username_clean)
            return CheckResult(username=username_clean, status=CheckStatus.ERROR, error_message=f"{type(exc).__name__}: {exc}", attempts=max(attempts, 1))
        finally:
            self._checking_usernames.discard(username_clean)

    # ------------------------------------------------------------------
    # TIER 1 — Pre-validation
    # ------------------------------------------------------------------

    def _tier1_prevalidate(self, username: str) -> tuple[CheckStatus, str] | None:
        if len(username) < 1 or len(username) > 30:
            return CheckStatus.TAKEN, "invalid_length"
        if _INVALID_SYNTAX_RE.search(username):
            return CheckStatus.TAKEN, "invalid_syntax"
        if "." in username and len(username) <= 4:
            return CheckStatus.TAKEN, "invalid_syntax"
        if username in _RESERVED_NAMES:
            return CheckStatus.TAKEN, "reserved"
        return None

    # ------------------------------------------------------------------
    # TIER 2 — oEmbed
    # ------------------------------------------------------------------

    async def _try_oembed(self, session: AsyncSession, username: str) -> dict[str, Any]:
        profile_url = f"https://www.instagram.com/{username}/"
        oembed_url = f"{_OEMBED_ENDPOINT}{quote_plus(profile_url)}"
        try:
            resp = await self._request(session, "GET", oembed_url, _OEMBED_HEADERS)
            status_code = int(getattr(resp, "status_code", 0) or 0)
            if status_code == 200:
                payload = _parse_json_body(resp)
                if payload and ("author_name" in payload or "author_id" in payload):
                    return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "oembed_active", "reason": "oembed_active"}
        except _NETWORK_EXCEPTIONS:
            pass
        return {"kind": "check_required", "error": "oEmbed passed or failed - falling through"}

    # ------------------------------------------------------------------
    # TIER 3 — Instagram API Check (The ultimate registration truth)
    # ------------------------------------------------------------------
    
    async def _try_api_check(self, session: AsyncSession, username: str) -> dict[str, Any]:
        try:
            # 1. Obtain CSRF Token by visiting signup page
            token = session.cookies.get("csrftoken")
            if not token:
                try:
                    resp = await self._request(session, "GET", "https://www.instagram.com/accounts/emailsignup/", _PROFILE_HEADERS)
                    token = session.cookies.get("csrftoken") or getattr(resp, "cookies", {}).get("csrftoken")
                except Exception:
                    pass
            csrftoken = token or secrets.token_hex(16)

            # 2. POST to the registration checker endpoint
            headers = {
                "User-Agent": _CHROME_USER_AGENT,
                "X-CSRFToken": csrftoken,
                "X-Requested-With": "XMLHttpRequest",
                "Referer": "https://www.instagram.com/accounts/emailsignup/",
                "Content-Type": "application/x-www-form-urlencoded",
            }
            payload = {"username": username}
            
            resp = await session.post(
                _CHECK_USERNAME_API_URL, 
                headers=headers, 
                data=payload, 
                timeout=_REQUEST_TIMEOUT,
                verify=False,
                impersonate=_IMPERSONATE
            )

            status_code = int(getattr(resp, "status_code", 0) or 0)
            if status_code == 200:
                data = _parse_json_body(resp)
                if data:
                    # TRULY AVAILABLE (mantafli, dasdas...)
                    if data.get("available") is True or (data.get("status") == "ok" and not data.get("errors")):
                        return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "signup_api", "reason": "truly_available"}
                    
                    # TAKEN / BANNED / RESTRICTED (apex.uz, cristiano)
                    if data.get("available") is False or "errors" in data or "username" in data.get("errors", {}):
                        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "signup_api", "reason": "username_is_taken"}
            
            return {"kind": "check_required", "error": f"API returned {status_code} - falling back"}
        except Exception as exc:
            return {"kind": "check_required", "error": f"API validation error: {exc}"}

    # ------------------------------------------------------------------
    # TIER 4 — Strict HTML Fallback (If API is blocked)
    # ------------------------------------------------------------------

    async def _try_html_fallback(self, session: AsyncSession, username: str, proxy: str | None) -> dict[str, Any]:
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        response = None
        try:
            response = await self._request(session, "GET", profile_url, _PROFILE_HEADERS, timeout=_PROFILE_TIMEOUT)
        except _NETWORK_EXCEPTIONS as exc:
            if proxy:
                try:
                    async with AsyncSession(**self._session_kwargs(None, _DIRECT_PROFILE_TIMEOUT)) as direct_session:
                        response = await self._request(direct_session, "GET", profile_url, _PROFILE_HEADERS, timeout=_DIRECT_PROFILE_TIMEOUT)
                except _NETWORK_EXCEPTIONS:
                    return {"kind": "error", "error": "HTML tier network error"}
            else:
                return {"kind": "error", "error": "HTML tier network error"}

        if not response:
            return {"kind": "error", "error": "No response"}

        response_url = str(getattr(response, "url", ""))
        status_code = int(getattr(response, "status_code", 0) or 0)
        html = _body_text(response)

        return self._classify_html(username, status_code, response_url, html)

    def _classify_html(self, username: str, status_code: int, response_url: str, html: str) -> dict[str, Any]:
        # 1. Redirect / Gate
        if any(marker in response_url for marker in _TAKEN_URL_MARKERS):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "html_strict_fallback", "reason": "login_or_checkpoint_redirect"}

        # 2. Definite Profile Markers
        deep_link_marker = f"instagram://user?username={username.lower()}"
        ownership_markers = (*_TAKEN_BODY_MARKERS, deep_link_marker)
        if any(m in html for m in ownership_markers):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "html_strict_fallback", "reason": "profile_active_private_or_banned"}

        # 3. EXPLICIT Not-Found (The ONLY way a handle is AVAILABLE via HTML)
        if status_code == 404 or "Page Not Found" in html or "Sorry, this page isn't available" in html:
            return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "html_strict_fallback", "reason": "truly_available"}

        # 4. GHOST SHELL 200 (The apex.uz case) -> MUST BE TAKEN! Never guess it's available.
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "html_strict_fallback", "reason": "banned_or_deactivated"}

    # ------------------------------------------------------------------
    # Funnel: Tier 1 → Tier 2 → Tier 3 → Tier 4
    # ------------------------------------------------------------------

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            # 1. oEmbed Check
            oembed = await self._try_oembed(session, username)
            if oembed["kind"] == "ok":
                return oembed
            
            # 2. Ultimate API Check (Reads DB directly)
            api_result = await self._try_api_check(session, username)
            if api_result["kind"] == "ok":
                return api_result

            # 3. Fallback to Strict HTML rules if API is rate-limited
            logger.warning("[@%s] API blocked or rate-limited. Falling back to Strict HTML.", username)
            return await self._try_html_fallback(session, username, proxy)


instagram_checker = InstagramChecker()