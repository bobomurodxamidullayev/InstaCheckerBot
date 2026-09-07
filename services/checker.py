"""Instagram username tekshirish servisi — 3-tier pipeline."""
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
_RECOVERY_URL = (
    "https://www.instagram.com/api/v1/web/accounts/account_recovery_send_ajax/"
)

_REQUEST_TIMEOUT = 6.0
_PROFILE_TIMEOUT = 9.0
_DIRECT_PROFILE_TIMEOUT = 7.0
_RECOVERY_TIMEOUT = 10.0
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

# Names reserved by Instagram's own navigation / system routes
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
})

# Phrases that appear on Instagram's genuine 404 / not-found shell
_NOT_FOUND_PHRASES: tuple[str, ...] = (
    "Page Not Found",
    "Sorry, this page isn't available",
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


async def _fetch_csrftoken(session: AsyncSession) -> str:
    """
    Extract csrftoken from the session cookie jar.
    If absent, fire a lightweight GET to instagram.com to seed cookies.
    Falls back to a 32-char hex token (accepted by unauthenticated endpoints).
    """
    def _from_cookies(sess: AsyncSession) -> str:
        try:
            cookies = getattr(sess, "cookies", None)
            if cookies is not None:
                return cookies.get("csrftoken", "") or ""
        except Exception:
            pass
        return ""

    token = _from_cookies(session)
    if token:
        return token

    # Seed the cookie jar with a lightweight homepage GET
    try:
        await session.get(
            "https://www.instagram.com/",
            headers=_PROFILE_HEADERS,
            timeout=6.0,
            verify=False,
            impersonate=_IMPERSONATE,
        )
        token = _from_cookies(session)
    except Exception:
        pass

    return token or secrets.token_hex(16)


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Instagram username mavjudligini 3-bosqichli pipeline orqali tekshiradi.

    Tier 1  — Pre-validation regex      (so'rovsiz lahzali rad etish)
    Tier 2  — oEmbed + profile GET      (tezkor faol profil aniqlash)
    Tier 3  — Password-recovery POST    (DB darajasida mavjudlikni tasdiqlash)
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
    # TIER 2a — oEmbed (fast active-profile gate)
    # ------------------------------------------------------------------

    async def _try_oembed(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        """
        Returns kind="ok" (TAKEN) when oEmbed confirms an active account.
        Returns kind="check_required" to fall through to profile GET.
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
            "error": f"oEmbed status {status_code}; falling through to profile check",
        }

    # ------------------------------------------------------------------
    # TIER 2b — Profile HTML GET (active-profile signals only)
    # ------------------------------------------------------------------

    async def _try_profile_check(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Examines the public profile page for definitive TAKEN signals only.

        Returns:
          kind="ok", status=TAKEN        — confirmed active / hidden account
          kind="recovery_required"       — page is empty or 404; proceed to Tier 3
          kind="error"                   — unrecoverable network failure

        NOTE: AVAILABLE is never returned here. Only the Tier-3 recovery POST
        can confirm that a handle does not exist in Instagram's database.
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
            # Retry without proxy on proxy failure
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
                    "error": f"profile check proxy and direct both failed: {direct_error}",
                }

        response_url = str(getattr(response, "url", ""))

        # Checkpoint / challenge redirect on proxy → retry direct
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
                    "error": f"profile check direct retry failed: {direct_error}",
                }
            response_url = str(getattr(response, "url", ""))

        raw_text = _body_text(response)
        status_code = int(getattr(response, "status_code", 0) or 0)

        # ------------------------------------------------------------------
        # DEFINITE TAKEN signals — no need for Tier 3
        # ------------------------------------------------------------------

        # 1. Login or checkpoint redirect → account hidden (banned / deactivated / private)
        if "/accounts/login" in response_url or "checkpoint" in response_url:
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "login_redirect",
                "reason": "login_redirect",
            }

        # 2. Standard profile metadata (public / private active account)
        username_lower = username.lower()
        if (
            "Followers" in raw_text
            or "og:description" in raw_text
            or "instapp:owner_user_id" in raw_text
            or f"instagram://user?username={username_lower}" in raw_text
        ):
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "profile_active_meta",
                "reason": "profile_active_meta",
            }

        # ------------------------------------------------------------------
        # AMBIGUOUS — empty React shell, 404, or unknown status.
        # Forward profile_status_code and profile_raw_text to Tier 3 so they
        # can be used as a safe fallback if the recovery POST fails.
        # ------------------------------------------------------------------
        return {
            "kind": "recovery_required",
            "profile_status_code": status_code,
            "profile_raw_text": raw_text,
        }

    # ------------------------------------------------------------------
    # TIER 3 — Password-recovery POST (definitive DB existence gate)
    # ------------------------------------------------------------------

    async def _try_recovery_check(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
        profile_status_code: int,
        profile_raw_text: str,
    ) -> dict[str, Any]:
        """
        POST to Instagram's account-recovery endpoint.

        Instagram's password-reset flow looks up the username in its master
        database regardless of whether the account is active, banned, deactivated,
        or on a 14-day deletion hold.

        Response evaluation:
          • "email_sent" / "sms_sent" / "user_id" / '"status": "ok"' in body
              → account IS in the DB  → TAKEN, "banned_or_deactivated"
          • "user_not_found" / "No users found" / fail+user combo in body
              → account NOT in DB     → AVAILABLE, "truly_available"
          • 429 / network error       → retry once via direct IP, then fall back
              to Tier-2 profile signal to stay conservative.
        """
        csrftoken = await _fetch_csrftoken(session)

        recovery_headers: dict[str, str] = {
            "User-Agent": _CHROME_USER_AGENT,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-CSRFToken": csrftoken,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/accounts/password/reset/",
            "Origin": "https://www.instagram.com",
        }

        payload: dict[str, str] = {
            "email_or_username": username,
            "recaptcha_challenge_field": "",
        }

        async def _do_post(sess: AsyncSession, csrf: str) -> Any:
            hdrs = dict(recovery_headers)
            hdrs["X-CSRFToken"] = csrf
            return await self._request(
                sess,
                "POST",
                _RECOVERY_URL,
                hdrs,
                data=payload,
                allow_redirects=False,
                timeout=_RECOVERY_TIMEOUT,
            )

        # ---- Attempt 1 (proxy session) ----
        resp = None
        try:
            resp = await _do_post(session, csrftoken)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning(
                "[@%s] recovery POST network error (attempt 1): %s — retrying direct",
                username, exc,
            )

        status_code = int(getattr(resp, "status_code", 0) or 0) if resp else 0

        # ---- Retry once via direct IP on 429 or no-response ----
        if resp is None or status_code == 429:
            logger.warning(
                "[@%s] recovery POST got %s — retrying via direct IP",
                username, status_code or "no-response",
            )
            try:
                async with AsyncSession(
                    **self._session_kwargs(None, _RECOVERY_TIMEOUT)
                ) as direct_sess:
                    direct_csrf = await _fetch_csrftoken(direct_sess)
                    resp = await _do_post(direct_sess, direct_csrf)
                    status_code = int(getattr(resp, "status_code", 0) or 0)
            except _NETWORK_EXCEPTIONS as exc2:
                logger.error(
                    "[@%s] recovery POST failed after retry: %s — using profile fallback",
                    username, exc2,
                )
                return self._recovery_fallback(username, profile_status_code, profile_raw_text)

        # Still rate-limited after direct retry → safe profile fallback
        if status_code == 429:
            logger.error(
                "[@%s] recovery POST still 429 after retry — using profile fallback", username,
            )
            return self._recovery_fallback(username, profile_status_code, profile_raw_text)

        body = _body_text(resp) if resp else ""
        logger.debug(
            "[@%s] recovery POST status=%d body_snip=%r", username, status_code, body[:120]
        )

        # ---- Evaluate response body ----

        # Account EXISTS in Instagram's DB (active, banned, deactivated, or 14-day hold)
        _exists_signals = ("email_sent", "sms_sent", "user_id", '"status": "ok"')
        if status_code == 200 and any(sig in body for sig in _exists_signals):
            logger.info("[@%s] recovery → TAKEN (banned_or_deactivated)", username)
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "recovery_check",
                "reason": "banned_or_deactivated",
            }

        # Account does NOT exist in Instagram's DB — handle is truly free
        _not_found_signals = ("user_not_found", "No users found")
        _fail_combo = "status" in body and "fail" in body and "user" in body
        if any(sig in body for sig in _not_found_signals) or _fail_combo:
            logger.info("[@%s] recovery → AVAILABLE (truly_available)", username)
            return {
                "kind": "ok",
                "status": CheckStatus.AVAILABLE,
                "source": "recovery_check",
                "reason": "truly_available",
            }

        # Ambiguous response → fall back to Tier-2 profile snapshot
        logger.warning(
            "[@%s] recovery POST ambiguous (status=%d) — using profile fallback",
            username, status_code,
        )
        return self._recovery_fallback(username, profile_status_code, profile_raw_text)

    def _recovery_fallback(
        self,
        username: str,
        profile_status_code: int,
        profile_raw_text: str,
    ) -> dict[str, Any]:
        """
        Conservative fallback when the recovery POST cannot produce a definitive answer.
        Uses the Tier-2 profile-page snapshot:
          - Explicit 404 / "Page Not Found" text → AVAILABLE
          - Everything else                       → TAKEN (safe default)
        """
        if profile_status_code == 404 or any(
            p in profile_raw_text for p in _NOT_FOUND_PHRASES
        ):
            logger.info(
                "[@%s] recovery fallback → AVAILABLE (profile 404/not-found)", username
            )
            return {
                "kind": "ok",
                "status": CheckStatus.AVAILABLE,
                "source": "recovery_fallback",
                "reason": "truly_available",
            }
        logger.info(
            "[@%s] recovery fallback → TAKEN (conservative, profile ambiguous)", username
        )
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "recovery_fallback",
            "reason": "banned_or_deactivated",
        }

    # ------------------------------------------------------------------
    # Funnel: Tier 2a → Tier 2b → Tier 3
    # ------------------------------------------------------------------

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            # ---- TIER 2a: oEmbed (fast gate) ----
            oembed = await self._try_oembed(session, username)
            if oembed["kind"] == "ok":
                return oembed
            if oembed["kind"] not in ("check_required",):
                return oembed  # propagate unexpected errors

            # ---- TIER 2b: profile HTML GET ----
            profile = await self._try_profile_check(session, username, proxy)
            if profile["kind"] == "ok":
                return profile
            if profile["kind"] == "error":
                return profile

            # kind == "recovery_required": page was an empty / 404 shell
            # ---- TIER 3: password-recovery POST (definitive DB gate) ----
            return await self._try_recovery_check(
                session,
                username,
                proxy,
                profile_status_code=profile.get("profile_status_code", 0),
                profile_raw_text=profile.get("profile_raw_text", ""),
            )


instagram_checker = InstagramChecker()
