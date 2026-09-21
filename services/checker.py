"""
services/checker.py — Production-grade Instagram username availability checker.

Uses direct profile page requests to ``https://www.instagram.com/{username}/``
via ``curl_cffi`` with Chrome 124 TLS impersonation and a DataImpulse
residential rotating proxy.  Fully cookie-free — no ``sessionid``,
``csrftoken``, or any authentication tokens are sent.

Strategy:
    1. **Tier 1** — offline syntax, length, and reserved-word pre-validation
       (instant, no network).
    2. **Tier 2** — lightweight GET to the profile URL via the residential
       proxy.  The HTTP status code deterministically resolves availability:

       • HTTP 200 / 301 / 302  →  profile exists → **TAKEN**
       • HTTP 404              →  profile absent  → **AVAILABLE**
       • HTTP 429              →  rate-limited    → internal back-off,
                                   session reset (cycles proxy IP), and
                                   transparent retry — never surfaced to
                                   the caller prematurely.
       • HTTP 407              →  proxy auth fail → **ERROR**
       • Network / timeout     →  transient fault → retry with back-off

    Rate-limit resilience:
       HTTP 429 responses are absorbed *inside* ``_tier2_api_check`` via an
       internal retry loop with exponential back-off (3 s → 6 s → 12 s,
       capped at 30 s).  Each 429 triggers a full session reset that tears
       down and rebuilds the ``AsyncSession``, causing the DataImpulse
       rotating proxy to assign a fresh residential IP.  The outer
       ``check_username`` retry loop handles non-429 transient errors
       (network faults, 5xx, etc.) separately with its own back-off.
       Together the two loops provide up to ~8 total attempts before an
       ``ERROR`` is returned, virtually eliminating 429-induced failures.

Integration:
    - ``CheckResult`` dataclass and ``CheckStatus`` enum are the public
      interface consumed by ``queue_manager.py``, handlers, and formatters.
    - Module-level singleton ``instagram_checker`` is used by ``bot.py``
      lifecycle hooks (``start`` / ``stop``) and all call sites.
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

_PROFILE_URL_TEMPLATE = "https://www.instagram.com/{username}/"

# Browser-realistic headers — no auth cookies, no API-specific markers.
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "max-age=0",
}

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

# ── Internal 429-retry tunables ─────────────────────────────────────────────
_RATE_LIMIT_MAX_INTERNAL_RETRIES = 4   # retries *within* a single _tier2 call
_RATE_LIMIT_BASE_DELAY = 3.0           # seconds — first 429 back-off
_RATE_LIMIT_MAX_DELAY = 30.0           # cap for exponential growth


# ─── Core checker ───────────────────────────────────────────────────────────────

class InstagramChecker:
    """
    Cookie-free Instagram username availability checker.

    Uses ``curl_cffi`` ``AsyncSession`` with Chrome 124 impersonation and the
    DataImpulse residential rotating proxy to GET the public profile page.
    No session cookies, CSRF tokens, or login credentials are sent.

    Decision matrix (Tier 2 — profile page request):
    ─────────────────────────────────────────────────
    HTTP 200 / 301 / 302  (profile exists)        →  **TAKEN**
    HTTP 404              (profile absent)         →  **AVAILABLE**
    HTTP 429              (rate-limited)           →  back-off + session
                                                      reset → retry internally
    HTTP 407              (proxy auth failure)     →  **ERROR**
    HTTP 5xx / network    (transient)              →  **ERROR** (outer retry)
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: float = 10.0,
    ) -> None:
        self._proxy = proxy
        self._timeout = timeout
        self._session: Optional[AsyncSession] = None

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialise the HTTP session with proxy (no cookies)."""
        if self._session is not None:
            return

        proxy = self._proxy or (settings.proxy_url if settings.proxy_enabled else None)

        self._session = AsyncSession(
            impersonate="chrome124",
            proxy=proxy,
            timeout=self._timeout,
        )

        logger.info(
            "InstagramChecker started (profile-check mode) | proxy=%s",
            proxy or "direct",
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

    async def _reset_session(self) -> None:
        """
        Close and re-create the session.

        On a rotating residential proxy (DataImpulse) this forces a fresh
        IP assignment, clearing any per-IP rate-limit state Instagram holds.
        """
        await self.close()
        await self.start()

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

    # ── Tier 2: Profile page check (cookie-free, proxy-backed) ──────────────

    async def _tier2_api_check(self, username: str, start_time: float) -> CheckResult:
        """
        GET ``https://www.instagram.com/{username}/`` via the residential
        proxy and evaluate the HTTP status code.

        HTTP 429 is handled *internally* with an exponential back-off loop
        and session reset (to cycle the proxy IP).  The caller never sees a
        429 unless all internal retries are exhausted.

        Returns
        -------
        CheckResult
            TAKEN, AVAILABLE, or ERROR (for truly unrecoverable faults).
        """
        url = _PROFILE_URL_TEMPLATE.format(username=username)

        # ── Internal 429-absorption loop ────────────────────────────────
        for rate_attempt in range(_RATE_LIMIT_MAX_INTERNAL_RETRIES + 1):
            session = await self._get_session()

            try:
                resp = await session.get(
                    url,
                    headers=_BROWSER_HEADERS,
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

            status = resp.status_code
            elapsed = round(time.perf_counter() - start_time, 3)

            # ── HTTP 404: profile does not exist → AVAILABLE ────────────
            if status == 404:
                return CheckResult(
                    username=username,
                    status=CheckStatus.AVAILABLE,
                    reason="not_found",
                    http_status=404,
                    response_time=elapsed,
                )

            # ── HTTP 200 / 301 / 302: profile exists → TAKEN ───────────
            if status in (200, 301, 302):
                return CheckResult(
                    username=username,
                    status=CheckStatus.TAKEN,
                    reason="profile_exists",
                    http_status=status,
                    response_time=elapsed,
                )

            # ── HTTP 429: rate-limited → back-off + cycle proxy IP ──────
            if status == 429:
                if rate_attempt < _RATE_LIMIT_MAX_INTERNAL_RETRIES:
                    delay = min(
                        _RATE_LIMIT_BASE_DELAY * (2 ** rate_attempt),
                        _RATE_LIMIT_MAX_DELAY,
                    )
                    logger.warning(
                        "HTTP 429 for @%s — internal retry %d/%d, "
                        "resetting session and sleeping %.1fs to cycle proxy IP",
                        username,
                        rate_attempt + 1,
                        _RATE_LIMIT_MAX_INTERNAL_RETRIES,
                        delay,
                    )
                    await self._reset_session()
                    await asyncio.sleep(delay)
                    continue  # retry with fresh session / IP

                # All internal retries exhausted — surface as ERROR.
                logger.error(
                    "HTTP 429 for @%s — all %d internal retries exhausted",
                    username, _RATE_LIMIT_MAX_INTERNAL_RETRIES,
                )
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="rate_limited",
                    error_message=(
                        f"HTTP 429 — rate limited after "
                        f"{_RATE_LIMIT_MAX_INTERNAL_RETRIES} internal retries"
                    ),
                    http_status=429,
                    response_time=elapsed,
                )

            # ── HTTP 407: proxy authentication required ─────────────────
            if status == 407:
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="proxy_auth_failed",
                    error_message=(
                        "HTTP 407 — proxy authentication failed "
                        "(check PROXY_URL credentials)"
                    ),
                    http_status=407,
                    response_time=elapsed,
                )

            # ── HTTP 401 / 403: Instagram blocked the request ───────────
            if status in (401, 403):
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="blocked",
                    error_message=f"HTTP {status} — request blocked by Instagram",
                    http_status=status,
                    response_time=elapsed,
                )

            # ── HTTP 5xx: server error → ERROR (retriable by outer loop) ─
            if status >= 500:
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="server_error",
                    error_message=f"HTTP {status} — Instagram server error",
                    http_status=status,
                    response_time=elapsed,
                )

            # ── Any other unexpected status → ERROR ─────────────────────
            logger.warning(
                "Unexpected HTTP %d for @%s", status, username,
            )
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="http_error",
                error_message=f"HTTP {status} — unexpected status code",
                http_status=status,
                response_time=elapsed,
            )

        # Defensive — should never be reached due to the explicit return
        # inside the 429 exhaustion branch above.
        return CheckResult(
            username=username,
            status=CheckStatus.ERROR,
            reason="rate_limited",
            error_message="HTTP 429 — internal retries exhausted (fallback)",
            http_status=429,
            response_time=round(time.perf_counter() - start_time, 3),
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
            2. Tier 2 — profile page check via residential proxy, with
               internal 429-absorption and outer retry for other transient
               errors.

        The inner ``_tier2_api_check`` absorbs HTTP 429 with up to
        ``_RATE_LIMIT_MAX_INTERNAL_RETRIES`` back-off cycles.  This outer
        loop retries on non-429 transient errors (network faults, HTTP 5xx,
        blocks) up to *max_retries* times with exponential back-off and
        session reset.
        """
        start_time = time.perf_counter()
        clean = username.strip().lower()

        # ── Tier 1: offline pre-validation ──────────────────────────────
        precheck = self._tier1_prevalidate(clean)
        if precheck is not None:
            return precheck

        # ── Tier 2: profile check (with outer retries) ──────────────────
        last_result: Optional[CheckResult] = None

        for attempt in range(max_retries + 1):
            result = await self._tier2_api_check(clean, start_time)

            # Definitive answers — return immediately.
            if result.status in (CheckStatus.AVAILABLE, CheckStatus.TAKEN):
                return result

            # Transient error — retry after exponential back-off.
            last_result = result
            if attempt < max_retries:
                backoff = min(2.0 * (2 ** attempt), 20.0)  # 2s, 4s, 8s … cap 20s
                logger.info(
                    "Outer retry %d/%d for @%s (reason=%s), sleeping %.1fs",
                    attempt + 1, max_retries, clean, result.reason, backoff,
                )
                # Reset session to cycle proxy IP on any transient error.
                await self._reset_session()
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