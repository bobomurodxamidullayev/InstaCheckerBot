"""Instagram username tekshirish servisi — 3-tier pipeline (web_profile_info API)."""
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
_PROFILE_INFO_URL = (
    "https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
)

# Instagram's official web app ID — required by the profile-info endpoint.
# This is the public app ID embedded in every instagram.com page load.
_IG_APP_ID = "936619743392459"

_REQUEST_TIMEOUT = 6.0
_PROFILE_TIMEOUT = 9.0
_DIRECT_PROFILE_TIMEOUT = 7.0
_PROFILE_INFO_TIMEOUT = 10.0
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

# Structural patterns Instagram always rejects at registration:
#   ^\.    — starts with a dot
#   \.\.   — two consecutive dots
#   \.$    — ends with a dot
#   [^...] — any char that isn't alphanumeric, dot, or underscore
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")

# Names reserved by Instagram's own navigation / system routes
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
})


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


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Instagram username mavjudligini 3-bosqichli pipeline orqali tekshiradi.

    Tier 1  — Pre-validation regex       (so'rovsiz lahzali rad etish)
    Tier 2  — oEmbed GET                 (faol profilni tezkor aniqlash)
    Tier 3  — web_profile_info API GET   (aniq mavjudlik tekshiruvi, 429 yo'q)
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=web_profile_info",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (web_profile_info pipeline) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

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

        # ----------------------------------------------------------------
        # TIER 1 — Pre-validation (instant, no network)
        # ----------------------------------------------------------------
        tier1 = self._tier1_prevalidate(username_clean)
        if tier1 is not None:
            status, reason = tier1
            logger.info(
                "[@%s] TIER-1 rejected → %s (%s)", username_clean, status.value, reason
            )
            return CheckResult(
                username=username_clean,
                status=status,
                error_message=reason,
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
                status = result["status"]
                source = result.get("source", "unknown")
                reason = result.get("reason")
                logger.info("[@%s] %s (%s)", username_clean, status.value, source)
                return CheckResult(
                    username=username_clean,
                    status=status,
                    error_message=reason,
                    attempts=attempts,
                )
            last_error = result.get("error", "network or verification failure")
            logger.warning("[@%s] verification failed → ERROR", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=str(last_error),
                attempts=attempts,
            )
        except Exception as exc:
            logger.exception("[@%s] Ushlanmagan xato → ERROR", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=f"{type(exc).__name__}: {exc}",
                attempts=max(attempts, 1),
            )
        finally:
            self._checking_usernames.discard(username_clean)

    # ------------------------------------------------------------------
    # TIER 1 — Pre-validation (no network)
    # ------------------------------------------------------------------

    def _tier1_prevalidate(
        self, username: str
    ) -> tuple[CheckStatus, str] | None:
        """
        Instant rejection without making any network requests.
        Returns (status, reason) if the username must be rejected,
        or None to proceed to network checks.
        """
        # Instagram requires 1–30 chars
        if len(username) < 1 or len(username) > 30:
            return CheckStatus.TAKEN, "invalid_length"

        # Structural syntax: leading/trailing/consecutive dots, illegal chars
        if _INVALID_SYNTAX_RE.search(username):
            return CheckStatus.TAKEN, "invalid_syntax"

        # Short handles with a dot are always rejected by Instagram
        # (e.g. uz.n, a.bc — len ≤ 4 and contains '.')
        if "." in username and len(username) <= 4:
            return CheckStatus.TAKEN, "invalid_syntax"

        # Reserved system / navigation names
        if username in _RESERVED_NAMES:
            return CheckStatus.TAKEN, "reserved"

        return None

    # ------------------------------------------------------------------
    # TIER 2 — oEmbed (fast active-profile gate)
    # ------------------------------------------------------------------

    async def _try_oembed(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        """
        Returns kind="ok" (TAKEN) when oEmbed confirms an active account.
        Returns kind="check_required" to fall through to web_profile_info.
        """
        profile_url = f"https://www.instagram.com/{username}/"
        oembed_url = f"{_OEMBED_ENDPOINT}{quote_plus(profile_url)}"
        try:
            resp = await self._request(session, "GET", oembed_url, _OEMBED_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            return {
                "kind": "check_required",
                "error": f"oEmbed network error; falling through: {exc}",
            }

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 200:
            payload = _parse_json_body(resp)
            if payload and ("author_name" in payload or "author_id" in payload):
                return {
                    "kind": "ok",
                    "status": CheckStatus.TAKEN,
                    "source": "oembed_active",
                    "reason": "oembed_active",
                }
            return {
                "kind": "check_required",
                "error": "oEmbed 200 but no account identity — falling through",
            }
        return {
            "kind": "check_required",
            "error": f"oEmbed status {status_code}; falling through to profile_info",
        }

    # ------------------------------------------------------------------
    # TIER 3 — web_profile_info API GET (definitive gate)
    # ------------------------------------------------------------------

    async def _try_profile_info(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Queries Instagram's internal web_profile_info endpoint with the official
        app ID header. This GET-only API never triggers 429 and correctly
        identifies banned, deactivated, and 14-day-hold handles.

        HTTP 200 + data.user != null → TAKEN (active account)
        HTTP 404 + user/checkpoint/require_login in body → TAKEN (banned/deactivated)
        HTTP 404 + "Not Found" / status:fail without user → AVAILABLE (truly free)
        Any other / network fail → HTML fallback
        """
        api_url = _PROFILE_INFO_URL.format(username=quote(username, safe="._"))
        api_headers: dict[str, str] = {
            "User-Agent": _CHROME_USER_AGENT,
            "X-IG-App-ID": _IG_APP_ID,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": f"https://www.instagram.com/{username}/",
        }

        response = None
        try:
            response = await self._request(
                session,
                "GET",
                api_url,
                api_headers,
                timeout=_PROFILE_INFO_TIMEOUT,
            )
        except _NETWORK_EXCEPTIONS as proxy_error:
            # Proxy failed — retry once with direct connection
            if proxy:
                try:
                    async with AsyncSession(
                        **self._session_kwargs(None, _PROFILE_INFO_TIMEOUT)
                    ) as direct_session:
                        response = await self._request(
                            direct_session,
                            "GET",
                            api_url,
                            api_headers,
                            timeout=_PROFILE_INFO_TIMEOUT,
                        )
                except _NETWORK_EXCEPTIONS as direct_error:
                    logger.warning(
                        "[@%s] profile_info proxy+direct failed: %s — HTML fallback",
                        username, direct_error,
                    )
                    return await self._html_fallback(session, username, proxy)
            else:
                logger.warning(
                    "[@%s] profile_info network error: %s — HTML fallback",
                    username, proxy_error,
                )
                return await self._html_fallback(session, username, proxy)

        status_code = int(getattr(response, "status_code", 0) or 0)
        body = _body_text(response)
        data = _parse_json_body(response) or {}

        logger.debug(
            "[@%s] profile_info status=%d body_snip=%r",
            username, status_code, body[:160],
        )

        # ------------------------------------------------------------------
        # HTTP 200 — check whether data.user is populated
        # ------------------------------------------------------------------
        if status_code == 200:
            outer = data.get("data", {})
            if isinstance(outer, dict):
                user_obj = outer.get("user")
                if user_obj is not None:
                    # data.user present (even if private) → account exists
                    logger.info("[@%s] profile_info 200 → TAKEN (profile_active)", username)
                    return {
                        "kind": "ok",
                        "status": CheckStatus.TAKEN,
                        "source": "profile_info_200",
                        "reason": "profile_active",
                    }
            # 200 but data.user is null or missing — treat same as 404 logic below
            logger.debug("[@%s] profile_info 200 but data.user null — treating as 404", username)
            status_code = 0  # fall through to 404 branch

        # ------------------------------------------------------------------
        # HTTP 404 — distinguish banned/deactivated from truly unclaimed
        # ------------------------------------------------------------------
        if status_code == 404 or status_code == 0:
            # Signals that the handle exists in Instagram's DB but is hidden
            _exists_signals = ("user", "checkpoint", "require_login")
            if any(sig in body for sig in _exists_signals):
                logger.info(
                    "[@%s] profile_info 404+signals → TAKEN (banned_or_deactivated)", username
                )
                return {
                    "kind": "ok",
                    "status": CheckStatus.TAKEN,
                    "source": "profile_info_404_exists",
                    "reason": "banned_or_deactivated",
                }

            # Clean not-found: "Not Found" text OR status:fail without any user object
            _not_found_signals = ("Not Found", "\"status\": \"fail\"", "\"status\":\"fail\"")
            if any(sig in body for sig in _not_found_signals) or not any(
                sig in body for sig in _exists_signals
            ):
                logger.info(
                    "[@%s] profile_info 404+not-found → AVAILABLE (truly_available)", username
                )
                return {
                    "kind": "ok",
                    "status": CheckStatus.AVAILABLE,
                    "source": "profile_info_404_clean",
                    "reason": "truly_available",
                }

        # ------------------------------------------------------------------
        # Unexpected status (e.g. 302, 429, 500) — fall back to HTML check
        # ------------------------------------------------------------------
        logger.warning(
            "[@%s] profile_info unexpected status=%d — HTML fallback", username, status_code
        )
        return await self._html_fallback(session, username, proxy)

    # ------------------------------------------------------------------
    # HTML fallback (used only when profile_info is indeterminate)
    # ------------------------------------------------------------------

    async def _html_fallback(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Fallback: fetch the public profile HTML page and inspect for signals.

        TAKEN when any of:
          • Redirect to /accounts/login or URL contains checkpoint
          • "instapp:owner_user_id" in HTML
          • "Followers" in HTML

        AVAILABLE when:
          • "Page Not Found" in HTML or HTTP 404

        ERROR when none of the above match.
        """
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        response = None
        try:
            response = await self._request(
                session,
                "GET",
                profile_url,
                _PROFILE_HEADERS,
                timeout=_PROFILE_TIMEOUT,
            )
        except _NETWORK_EXCEPTIONS as exc:
            if proxy:
                try:
                    async with AsyncSession(
                        **self._session_kwargs(None, _DIRECT_PROFILE_TIMEOUT)
                    ) as direct_session:
                        response = await self._request(
                            direct_session,
                            "GET",
                            profile_url,
                            _PROFILE_HEADERS,
                            timeout=_DIRECT_PROFILE_TIMEOUT,
                        )
                except _NETWORK_EXCEPTIONS as direct_error:
                    return {
                        "kind": "error",
                        "error": f"HTML fallback proxy+direct failed: {direct_error}",
                    }
            else:
                return {"kind": "error", "error": f"HTML fallback network error: {exc}"}

        if response is None:
            return {"kind": "error", "error": "HTML fallback: no response"}

        response_url = str(getattr(response, "url", ""))
        sc = int(getattr(response, "status_code", 0) or 0)
        html = _body_text(response)

        # Checkpoint redirect via proxy — retry direct once
        if "checkpoint" in response_url or "challenge" in response_url:
            try:
                async with AsyncSession(
                    **self._session_kwargs(None, _DIRECT_PROFILE_TIMEOUT)
                ) as direct_session:
                    response = await self._request(
                        direct_session,
                        "GET",
                        profile_url,
                        _PROFILE_HEADERS,
                        timeout=_DIRECT_PROFILE_TIMEOUT,
                    )
                response_url = str(getattr(response, "url", ""))
                sc = int(getattr(response, "status_code", 0) or 0)
                html = _body_text(response)
            except _NETWORK_EXCEPTIONS:
                pass  # continue with what we have

        # TAKEN signals
        if (
            "/accounts/login" in response_url
            or "checkpoint" in response_url
            or "instapp:owner_user_id" in html
            or "Followers" in html
        ):
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "html_fallback",
                "reason": "profile_active_or_banned",
            }

        # AVAILABLE signals
        if sc == 404 or "Page Not Found" in html or "Sorry, this page isn't available" in html:
            return {
                "kind": "ok",
                "status": CheckStatus.AVAILABLE,
                "source": "html_fallback",
                "reason": "truly_available",
            }

        # Indeterminate
        return {"kind": "error", "error": f"html_fallback_indeterminate (status={sc})"}

    # ------------------------------------------------------------------
    # Funnel: Tier 1 → Tier 2 → Tier 3
    # ------------------------------------------------------------------

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            # ---- TIER 2: oEmbed (fast active-profile gate) ----
            oembed = await self._try_oembed(session, username)
            if oembed["kind"] == "ok":
                return oembed
            if oembed["kind"] not in ("check_required",):
                return oembed  # propagate unexpected errors

            # ---- TIER 3: web_profile_info API GET (definitive) ----
            return await self._try_profile_info(session, username, proxy)


instagram_checker = InstagramChecker()
