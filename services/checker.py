"""Instagram username tekshirish servisi — 3-tier pipeline."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
import time
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
_SIGNUP_ATTEMPT_URL = (
    "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
)

_REQUEST_TIMEOUT = 6.0
_PROFILE_TIMEOUT = 9.0
_DIRECT_PROFILE_TIMEOUT = 7.0
_SIGNUP_TIMEOUT = 10.0
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

# Structural patterns Instagram will always reject at registration:
#   ^\.    — starts with a dot
#   \.\.   — two consecutive dots
#   \.$    — ends with a dot
#   [^...] — any char that isn't alphanumeric, dot, or underscore
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")

# Names reserved by Instagram's own navigation / system routes
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security",
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

    Tier 1  — Pre-validation regex      (so'rovsiz lahzali rad etish)
    Tier 2  — oEmbed + profile GET      (band usernamelarni aniqlash)
    Tier 3  — Web signup attempt check  (haqiqiy bo'sh usernamelarni tasdiqlash)
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=3-tier",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (3-tier pipeline) | proxy=%s",
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
        request = session.post if method.upper() == "POST" else session.get
        return await request(
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
        or None if it should proceed to network checks.
        """
        # Length check
        if len(username) < 2 or len(username) > 30:
            return CheckStatus.TAKEN, "invalid_length"

        # Structural syntax (leading/trailing/double dots, invalid chars)
        if _INVALID_SYNTAX_RE.search(username):
            return CheckStatus.TAKEN, "invalid_syntax"

        # Reserved system names
        if username in _RESERVED_NAMES:
            return CheckStatus.TAKEN, "reserved"

        return None

    # ------------------------------------------------------------------
    # TIER 2a — oEmbed
    # ------------------------------------------------------------------

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
                return {
                    "kind": "ok",
                    "status": CheckStatus.TAKEN,
                    "source": "oembed_active",
                    "reason": "profile_active",
                }
            return {
                "kind": "check_required",
                "error": "oEmbed response missing account identity",
            }
        return {
            "kind": "check_required",
            "error": f"oEmbed status {status_code}; proceeding to profile check",
        }

    # ------------------------------------------------------------------
    # TIER 2b — Profile GET
    # ------------------------------------------------------------------

    async def _try_profile_check(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Returns:
          kind="ok"             → definite TAKEN (login-redirect, follower meta)
          kind="error"          → network failure
          kind="signup_required"→ empty shell / 404; must proceed to Tier 3
        """
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        try:
            response = await self._request(
                session,
                "GET",
                profile_url,
                _PROFILE_HEADERS,
                timeout=_PROFILE_TIMEOUT,
            )
        except _NETWORK_EXCEPTIONS as proxy_error:
            if not proxy:
                return {
                    "kind": "error",
                    "error": f"profile check network error: {proxy_error}",
                }
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
                    "error": f"profile check proxy and direct requests failed: {direct_error}",
                }

        response_url = str(getattr(response, "url", ""))
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
            except _NETWORK_EXCEPTIONS as direct_error:
                return {
                    "kind": "error",
                    "error": f"profile check proxy and direct requests failed: {direct_error}",
                }
            response_url = str(getattr(response, "url", ""))

        raw_text = _body_text(response)
        username_lower = username.lower()

        # Definite TAKEN: Instagram redirected to login (banned / deactivated / private)
        if "/accounts/login/" in response_url:
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "login_redirect",
                "reason": "profile_active",
            }

        # Definite TAKEN: follower metadata or deep-link present in page
        if (
            "Followers" in raw_text
            or "og:description" in raw_text
            or f"instagram://user?username={username_lower}" in raw_text
        ):
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "profile_active_meta",
                "reason": "profile_active",
            }

        # Profile returned an empty shell / 404 → advance to Tier 3
        # Do NOT return AVAILABLE here — Tier 3 is the definitive check.
        return {"kind": "signup_required"}

    # ------------------------------------------------------------------
    # TIER 3 — Web signup availability check (definitive)
    # ------------------------------------------------------------------

    async def _try_signup_check(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        POST to Instagram's web registration validator.

        Catches (via errors.username in response):
          • 14-day hold accounts
          • Deactivated / banned accounts
          • Reserved / system names
          • Dot-trick variants  (e.g. uz.n)

        Only returns AVAILABLE when Instagram itself confirms the name
        is free for registration.
        """
        # Extract csrftoken from session cookies; fall back to a hex token
        # that IG accepts for unauthenticated signup attempts.
        csrftoken: str = ""
        try:
            cookies = getattr(session, "cookies", None)
            if cookies is not None:
                csrftoken = cookies.get("csrftoken", "") or ""
        except Exception:
            pass
        if not csrftoken:
            csrftoken = secrets.token_hex(16)

        signup_headers: dict[str, str] = {
            "User-Agent": _CHROME_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRFToken": csrftoken,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/accounts/emailsignup/",
            "Origin": "https://www.instagram.com",
        }

        payload: dict[str, str] = {
            "email": f"test_{int(time.time())}@gmail.com",
            "username": username,
            "first_name": "Test User",
            "opt_into_one_tap": "false",
        }

        async def _do_post(sess: AsyncSession) -> Any:
            return await self._request(
                sess,
                "POST",
                _SIGNUP_ATTEMPT_URL,
                signup_headers,
                data=payload,
                allow_redirects=False,
                timeout=_SIGNUP_TIMEOUT,
            )

        # ---- Attempt 1 ----
        resp = None
        try:
            resp = await _do_post(session)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning(
                "[@%s] signup check network error (attempt 1): %s — retrying direct",
                username,
                exc,
            )

        status_code = int(getattr(resp, "status_code", 0) or 0) if resp else 0

        # ---- Fallback: retry once on 429 / timeout / no response ----
        if resp is None or status_code == 429:
            logger.warning(
                "[@%s] signup check got %s — retrying via direct IP",
                username,
                status_code or "no-response",
            )
            try:
                async with AsyncSession(
                    **self._session_kwargs(None, _SIGNUP_TIMEOUT)
                ) as direct_session:
                    resp = await _do_post(direct_session)
                    status_code = int(getattr(resp, "status_code", 0) or 0)
            except _NETWORK_EXCEPTIONS as exc2:
                # Both attempts failed → ERROR, never false AVAILABLE
                logger.error(
                    "[@%s] signup check failed after retry: %s → ERROR",
                    username,
                    exc2,
                )
                return {
                    "kind": "error",
                    "error": f"signup_check_failed_after_retry: {exc2}",
                }

        # Still rate-limited after direct retry → ERROR (safe failure)
        if status_code == 429:
            logger.error(
                "[@%s] signup check still rate-limited after retry → ERROR",
                username,
            )
            return {"kind": "error", "error": "signup_check_rate_limited"}

        # ---- Evaluate JSON response ----
        data = _parse_json_body(resp)
        if data is None:
            # Non-JSON (e.g. HTML challenge page) → ERROR, not AVAILABLE
            logger.warning(
                "[@%s] signup check returned non-JSON (status=%d) → ERROR",
                username,
                status_code,
            )
            return {
                "kind": "error",
                "error": f"signup_check_non_json_response (status={status_code})",
            }

        # Instagram signals username is unavailable via data["errors"]["username"]
        errors: Any = data.get("errors", {})
        if isinstance(errors, dict) and errors.get("username"):
            username_errors = errors["username"]
            first_msg = (
                username_errors[0]
                if isinstance(username_errors, list) and username_errors
                else str(username_errors)
            )
            logger.info(
                "[@%s] signup check → TAKEN (registration_rejected: %s)",
                username,
                first_msg,
            )
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "signup_check",
                "reason": "registration_rejected",
            }

        # No username errors → Instagram would accept this name → truly available
        logger.info("[@%s] signup check → AVAILABLE (truly_available)", username)
        return {
            "kind": "ok",
            "status": CheckStatus.AVAILABLE,
            "source": "signup_check",
            "reason": "truly_available",
        }

    # ------------------------------------------------------------------
    # Funnel: orchestrates Tier 2 → Tier 3
    # ------------------------------------------------------------------

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            # ---- TIER 2a: oEmbed ----
            oembed = await self._try_oembed(session, username)
            if oembed["kind"] == "ok":
                return oembed
            if oembed["kind"] not in ("check_required",):
                return oembed  # propagate unexpected errors

            # ---- TIER 2b: profile GET ----
            profile = await self._try_profile_check(session, username, proxy)
            if profile["kind"] == "ok":
                return profile
            if profile["kind"] == "error":
                return profile

            # kind == "signup_required": profile was an empty shell / 404
            # ---- TIER 3: web signup check (definitive) ----
            return await self._try_signup_check(session, username, proxy)


instagram_checker = InstagramChecker()
