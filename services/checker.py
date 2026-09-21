"""
services/checker.py — Authenticated Instagram username availability checker.

Uses curl_cffi with Chrome 124 browser impersonation, a valid Instagram
session cookie, and the configured DataImpulse residential proxy to query
Instagram's ``web_profile_info`` JSON endpoint.

Strategy:
    Instagram's login wall blocks unauthenticated requests from any IP
    (residential or data-center) with a 302 redirect to /accounts/login/.
    To bypass this, we inject a valid ``sessionid`` cookie and route every
    request through the DataImpulse rotating residential proxy defined in
    ``settings.proxy_url``.  The ``web_profile_info`` endpoint returns a
    clean JSON payload with the user object or ``null`` — no HTML parsing
    required.

    curl_cffi's ``impersonate="chrome124"`` matches a real Chrome 124 TLS
    fingerprint, so Instagram sees the request as originating from a
    legitimate browser on a residential IP.

Integration:
    - CheckResult dataclass and CheckStatus enum are the public interface.
    - Module-level singleton ``instagram_checker`` is used by queue_manager.py
      and handlers.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

from curl_cffi.requests import AsyncSession

from config import settings
from models.username_log import CheckStatus

logger = logging.getLogger(__name__)


# ─── Instagram session credentials ─────────────────────────────────────────────
# Replace these with valid values from a logged-in browser session.
# How to obtain:
#   1. Log in to instagram.com in Chrome (use a burner account).
#   2. Open DevTools → Application → Cookies → instagram.com.
#   3. Copy the values for 'sessionid' and 'csrftoken'.
# These rotate periodically — refresh them if you start seeing 401 errors.
INSTA_SESSION_ID = "40137255195%3AdYjlsW9FTWJ9MD%3A19%3A3AAYkrmRfVGsglXHzdexZG6BF4FPHdkYlRnApGfH8Fg"
INSTA_CSRF_TOKEN = "cUHu0IfNR8e9jfzUlfOreEaXcTldRvp8"


# ─── Public data structures ────────────────────────────────────────────────────

@dataclass
class CheckResult:
    """Single username check outcome — consumed by queue_manager and formatters."""

    username: str
    status: CheckStatus
    reason: Optional[str] = None
    error_message: Optional[str] = None
    http_status: Optional[int] = None
    response_time: float = 0.0


# ─── Constants ──────────────────────────────────────────────────────────────────

_PROFILE_URL_TEMPLATE = (
    "https://www.instagram.com/api/v1/users/web_profile_info/?username={}"
)

_RESERVED_USERNAMES: frozenset[str] = frozenset({
    "admin", "administrator", "instagram", "support", "help",
    "contact", "root", "explore", "about", "press", "developer",
    "terms", "privacy", "security", "meta", "facebook",
})

# Instagram username rules:
#   • 1–30 characters
#   • Only letters (a-z), digits (0-9), periods (.) and underscores (_)
#   • Cannot start or end with a period
#   • No consecutive periods
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9._]{1,30}$")


# ─── Core checker ───────────────────────────────────────────────────────────────

class InstagramChecker:
    """
    Deterministic, authenticated Instagram username availability checker.

    Uses curl_cffi AsyncSession with Chrome 124 impersonation, injected
    session cookies, and the DataImpulse residential proxy to query the
    ``web_profile_info`` JSON endpoint.

    * HTTP 200 + user object present   →  **TAKEN**
    * HTTP 404 / user object is None   →  **AVAILABLE**
    * HTTP 401 / 302 to login          →  **ERROR** (session expired)
    * HTTP 429                         →  **ERROR** (rate-limited)
    * Anything else                    →  **ERROR** (retried)
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: float = 8.0,
    ) -> None:
        self._proxy = proxy
        self._timeout = timeout
        self._session: Optional[AsyncSession] = None

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialise the HTTP session with auth cookies and proxy."""
        if self._session is not None:
            return

        # Resolve proxy: explicit constructor arg > settings.proxy_url > None
        proxy = self._proxy or (settings.proxy_url if settings.proxy_enabled else None)

        self._session = AsyncSession(
            impersonate="chrome124",
            proxy=proxy,
            timeout=self._timeout,
        )

        # Inject authenticated session cookies.
        self._session.cookies.set(
            "sessionid", INSTA_SESSION_ID,
            domain=".instagram.com", path="/",
        )
        self._session.cookies.set(
            "csrftoken", INSTA_CSRF_TOKEN,
            domain=".instagram.com", path="/",
        )

        logger.info(
            "InstagramChecker started | proxy=%s | session_id=%s…",
            proxy or "direct",
            INSTA_SESSION_ID[:20] + "…" if len(INSTA_SESSION_ID) > 20 else INSTA_SESSION_ID,
        )

    async def stop(self) -> None:
        """Alias for close — used by bot lifecycle hooks."""
        await self.close()

    async def close(self) -> None:
        """Tear down the HTTP session and release resources."""
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    async def _get_session(self) -> AsyncSession:
        """Lazily initialise and return the active session."""
        if self._session is None:
            await self.start()
        return self._session  # type: ignore[return-value]

    # ── Tier 1: Offline pre-validation ──────────────────────────────────────

    @staticmethod
    def _tier1_prevalidate(username: str) -> Optional[CheckResult]:
        """
        Fast, network-free rejection of syntactically invalid or reserved
        usernames.  Returns a CheckResult(TAKEN) when rejected, or None
        if the name should proceed to the API tier.
        """
        t0 = time.perf_counter()

        # Syntax rules
        if (
            not _USERNAME_RE.match(username)
            or username.startswith(".")
            or username.endswith(".")
            or ".." in username
        ):
            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                reason="invalid_syntax",
                response_time=round(time.perf_counter() - t0, 4),
            )

        # Reserved names
        if username in _RESERVED_USERNAMES:
            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                reason="reserved",
                response_time=round(time.perf_counter() - t0, 4),
            )

        return None  # OK — proceed to API check

    # ── Tier 2: Authenticated web_profile_info check ────────────────────────

    async def _tier2_api_check(self, username: str, start_time: float) -> CheckResult:
        """
        GET Instagram's ``web_profile_info`` endpoint as an authenticated
        session routed through the residential proxy.

        Decision matrix
        ───────────────
        HTTP 200 + user object present   →  TAKEN
        HTTP 200 + user object is None   →  AVAILABLE
        HTTP 404                         →  AVAILABLE
        HTTP 401 / 403                   →  ERROR (session_expired)
        HTTP 302 (redirect to login)     →  ERROR (login_redirect)
        HTTP 429                         →  ERROR (rate_limited)
        Other / network fault            →  ERROR (retriable)
        """
        session = await self._get_session()

        url = _PROFILE_URL_TEMPLATE.format(username)

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "X-CSRFToken": INSTA_CSRF_TOKEN,
            "X-IG-App-ID": "936619743392459",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"https://www.instagram.com/{username}/",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }

        try:
            resp = await session.get(
                url,
                headers=headers,
                timeout=self._timeout,
                allow_redirects=False,
            )
        except Exception as exc:
            logger.warning("Network error checking @%s: %s", username, exc)
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="network_error",
                error_message=f"{type(exc).__name__}: {exc}",
                response_time=round(time.perf_counter() - start_time, 3),
            )

        elapsed = round(time.perf_counter() - start_time, 3)

        # ── HTTP 302/301: redirect (usually to /accounts/login/) ────────
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "")
            logger.warning(
                "Redirect for @%s: HTTP %d → %s", username, resp.status_code, location,
            )
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="login_redirect",
                error_message=(
                    f"HTTP {resp.status_code} redirect to {location} — "
                    "session cookies may be expired or IP is blocked"
                ),
                http_status=resp.status_code,
                response_time=elapsed,
            )

        # ── HTTP 401 / 403: authentication failure ──────────────────────
        if resp.status_code in (401, 403):
            logger.error(
                "Auth failure for @%s: HTTP %d — session cookies likely expired",
                username, resp.status_code,
            )
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="session_expired",
                error_message=(
                    f"HTTP {resp.status_code} — session cookies expired. "
                    "Update INSTA_SESSION_ID and INSTA_CSRF_TOKEN in checker.py"
                ),
                http_status=resp.status_code,
                response_time=elapsed,
            )

        # ── HTTP 404: profile does not exist → AVAILABLE ────────────────
        if resp.status_code == 404:
            return CheckResult(
                username=username,
                status=CheckStatus.AVAILABLE,
                reason="truly_available",
                http_status=404,
                response_time=elapsed,
            )

        # ── HTTP 429: rate-limited → ERROR (retriable) ──────────────────
        if resp.status_code == 429:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="rate_limited",
                error_message="HTTP 429 — rate limited",
                http_status=429,
                response_time=elapsed,
            )

        # ── Other non-200 status codes → ERROR ─────────────────────────
        if resp.status_code != 200:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="http_error",
                error_message=f"HTTP {resp.status_code}",
                http_status=resp.status_code,
                response_time=elapsed,
            )

        # ── HTTP 200: parse JSON and inspect user object ────────────────
        try:
            data: dict[str, Any] = resp.json()
        except Exception:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="invalid_json",
                error_message="Response body is not valid JSON",
                http_status=200,
                response_time=elapsed,
            )

        user_obj = data.get("data", {}).get("user")

        if user_obj is not None:
            # Profile exists — handle is taken.
            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                reason="username_is_taken",
                http_status=200,
                response_time=elapsed,
            )

        # User object is None / missing — handle is available.
        return CheckResult(
            username=username,
            status=CheckStatus.AVAILABLE,
            reason="truly_available",
            http_status=200,
            response_time=elapsed,
        )

    # ── Public interface ────────────────────────────────────────────────────

    async def check_username(
        self,
        username: str,
        max_retries: int = 2,
        **kwargs: Any,
    ) -> CheckResult:
        """
        Check a single Instagram username for availability.

        Pipeline:
            1. Tier 1 — syntax / reserved pre-validation (instant, no network).
            2. Tier 2 — authenticated web_profile_info API via proxy.

        Retries on transient errors (network failures, HTTP 429) up to
        *max_retries* times with incremental back-off.

        Non-retriable errors (401, 403, 302 login redirect) are returned
        immediately — retrying with the same expired cookies is pointless.
        """
        start_time = time.perf_counter()
        clean = username.strip().lower()

        # ── Tier 1: offline pre-validation ──────────────────────────────
        precheck = self._tier1_prevalidate(clean)
        if precheck is not None:
            return precheck

        # ── Tier 2: authenticated API check (with retries) ──────────────
        # Reasons that should NOT be retried (fix credentials, not loop).
        _non_retriable = frozenset({"session_expired", "login_redirect"})

        last_result: Optional[CheckResult] = None

        for attempt in range(max_retries + 1):
            result = await self._tier2_api_check(clean, start_time)

            # Definitive answers — return immediately.
            if result.status in (CheckStatus.AVAILABLE, CheckStatus.TAKEN):
                return result

            # Non-retriable auth errors — return immediately.
            if result.reason in _non_retriable:
                return result

            # Transient error — retry after back-off.
            last_result = result
            if attempt < max_retries:
                backoff = 1.5 * (attempt + 1)
                logger.info(
                    "Retry %d/%d for @%s (reason=%s), sleeping %.1fs",
                    attempt + 1, max_retries, clean, result.reason, backoff,
                )
                # Reset session on rate-limit to cycle connection / proxy IP.
                if result.reason == "rate_limited":
                    await self.close()
                await asyncio.sleep(backoff)

        # All retries exhausted — return last error.
        return last_result or CheckResult(
            username=clean,
            status=CheckStatus.ERROR,
            reason="max_retries_exceeded",
            error_message="All attempts exhausted",
            response_time=round(time.perf_counter() - start_time, 3),
        )

    async def check(self, username: str, **kwargs: Any) -> CheckResult:
        """Convenience alias used by some call sites."""
        return await self.check_username(username, **kwargs)


# ─── Module-level singleton ────────────────────────────────────────────────────
instagram_checker = InstagramChecker()