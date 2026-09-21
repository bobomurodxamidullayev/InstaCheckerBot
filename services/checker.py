"""
services/checker.py — Cookie-free Instagram username availability checker.

Uses curl_cffi with Chrome 124 browser impersonation to request the public
profile page at ``https://www.instagram.com/{username}/``.  Instagram serves
a full 200 response for any existing handle (public or private) and a clean
404 for non-existent profiles — no cookies, CSRF tokens, or login credentials
required.

Strategy:
    The direct profile URL is the most stable unauthenticated surface on
    Instagram.  Unlike internal API routes (web_profile_info, oEmbed,
    check_username) that enforce strict auth/cookie/query-param validation,
    the public profile page is designed for browsers and search-engine
    crawlers.  With curl_cffi browser impersonation the TLS fingerprint
    matches a real Chrome 124 session, avoiding bot-detection triggers.

    Redirects are intercepted (``allow_redirects=False``) to detect
    rate-limiting / challenge redirects that would otherwise silently land
    on a login page and produce a false positive.

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

_PROFILE_URL_TEMPLATE = "https://www.instagram.com/{}/"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
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

# Lightweight patterns to confirm a real profile page was served (not a
# generic error shell or login interstitial).  We only need ONE match.
_PROFILE_SIGNALS = (
    '"@',                       # og:description contains "@username"
    '"profilePage_',            # internal React component identifier
    '"profile_pic_url"',        # JSON-LD / shared-data field
    'property="og:title"',      # Open Graph title tag
    '"UserProfilePage"',        # page type identifier in shared data
)


# ─── Core checker ───────────────────────────────────────────────────────────────

class InstagramChecker:
    """
    Deterministic, cookie-free Instagram username availability checker.

    Uses curl_cffi AsyncSession with Chrome 124 impersonation and the
    direct public profile page — no session cookies or login credentials.

    * HTTP 200 + profile page content   →  **TAKEN**
    * HTTP 404                          →  **AVAILABLE**
    * HTTP 301/302 to login/challenge   →  **ERROR** (blocked / rate-limited)
    * Anything else                     →  **ERROR** (retried)
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
        """Initialise the underlying HTTP session (no cookies needed)."""
        if self._session is not None:
            return
        self._session = AsyncSession(
            impersonate="chrome124",
            proxy=self._proxy,
            timeout=self._timeout,
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

    # ── Tier 2: Public profile page check (cookie-free) ─────────────────────

    async def _tier2_api_check(self, username: str, start_time: float) -> CheckResult:
        """
        GET the public Instagram profile page to deterministically resolve
        whether *username* exists — no cookies or auth required.

        Redirects are intercepted (``allow_redirects=False``) so that
        rate-limit / challenge redirects to ``/accounts/login/`` or
        ``/challenge/`` are caught and surfaced as retriable errors
        instead of producing false positives.

        Decision matrix
        ───────────────
        HTTP 200 + profile content confirmed  →  TAKEN
        HTTP 404                              →  AVAILABLE
        HTTP 301/302 to /accounts/login/      →  ERROR (blocked)
        HTTP 301/302 to /challenge/           →  ERROR (challenge)
        HTTP 429                              →  ERROR (rate_limited)
        Other / network fault                 →  ERROR (retriable)
        """
        session = await self._get_session()
        url = _PROFILE_URL_TEMPLATE.format(username)

        try:
            resp = await session.get(
                url,
                headers=_HEADERS,
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

        # ── HTTP 404: profile does not exist → AVAILABLE ────────────────
        if resp.status_code == 404:
            return CheckResult(
                username=username,
                status=CheckStatus.AVAILABLE,
                reason="truly_available",
                http_status=404,
                response_time=elapsed,
            )

        # ── HTTP 301/302/303/307/308: redirect → inspect Location ───────
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location", "").lower()

            if "/accounts/login" in location or "/accounts/signup" in location:
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="login_redirect",
                    error_message=(
                        f"HTTP {resp.status_code} redirect to login — "
                        "possible rate-limit or IP block"
                    ),
                    http_status=resp.status_code,
                    response_time=elapsed,
                )

            if "/challenge/" in location:
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="challenge_redirect",
                    error_message=(
                        f"HTTP {resp.status_code} redirect to challenge — "
                        "Instagram is requesting verification"
                    ),
                    http_status=resp.status_code,
                    response_time=elapsed,
                )

            # Any other redirect (e.g. trailing-slash normalisation) — follow
            # it manually once and treat the final status as the real answer.
            # This covers the rare ``/Username`` → ``/username/`` redirect.
            try:
                resp = await session.get(
                    location if location.startswith("http") else f"https://www.instagram.com{location}",
                    headers=_HEADERS,
                    timeout=self._timeout,
                    allow_redirects=False,
                )
            except Exception as exc:
                logger.warning("Redirect follow error for @%s: %s", username, exc)
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="network_error",
                    error_message=f"Redirect follow failed: {type(exc).__name__}: {exc}",
                    response_time=round(time.perf_counter() - start_time, 3),
                )
            elapsed = round(time.perf_counter() - start_time, 3)

            # Re-evaluate the followed response (404 / 200 / error).
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

        # ── HTTP 200: verify the body is a real profile page ────────────
        #
        # Instagram always returns a 200 HTML shell — even for error pages
        # served via client-side rendering.  We do a lightweight scan for
        # profile-specific markers to confirm the handle truly exists.
        try:
            body = resp.text
        except Exception:
            body = ""

        # Check for any profile-specific signal in the HTML.
        if any(signal in body for signal in _PROFILE_SIGNALS):
            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                reason="username_is_taken",
                http_status=200,
                response_time=elapsed,
            )

        # If the page contains a clear "not found" indicator served inside
        # a 200 shell (Instagram's SPA sometimes does this), mark available.
        not_found_indicators = (
            '"HttpErrorPage"',
            "Sorry, this page isn",       # "Sorry, this page isn't available."
            '"error_page"',
        )
        if any(indicator in body for indicator in not_found_indicators):
            return CheckResult(
                username=username,
                status=CheckStatus.AVAILABLE,
                reason="truly_available",
                http_status=200,
                response_time=elapsed,
            )

        # 200 but no recognizable markers — could be a JS-only shell or
        # a CAPTCHA interstitial.  Surface as a retriable error rather
        # than guessing wrong.
        body_preview = body[:300].replace("\n", " ").strip() if body else "(empty)"
        logger.warning(
            "Unrecognized 200 body for @%s (len=%d): %s",
            username, len(body), body_preview,
        )
        return CheckResult(
            username=username,
            status=CheckStatus.ERROR,
            reason="unrecognized_response",
            error_message="HTTP 200 but no profile markers found — possible CAPTCHA or JS shell",
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
            2. Tier 2 — public profile page check (cookie-free).

        Retries on transient errors (network failures, HTTP 429, redirects)
        up to *max_retries* times with incremental back-off.
        """
        start_time = time.perf_counter()
        clean = username.strip().lower()

        # ── Tier 1: offline pre-validation ──────────────────────────────
        precheck = self._tier1_prevalidate(clean)
        if precheck is not None:
            return precheck

        # ── Tier 2: profile page check (with retries) ───────────────────
        last_result: Optional[CheckResult] = None

        for attempt in range(max_retries + 1):
            result = await self._tier2_api_check(clean, start_time)

            # Definitive answers — return immediately.
            if result.status in (CheckStatus.AVAILABLE, CheckStatus.TAKEN):
                return result

            # Transient error — retry after back-off.
            last_result = result
            if attempt < max_retries:
                backoff = 1.5 * (attempt + 1)
                logger.info(
                    "Retry %d/%d for @%s (reason=%s), sleeping %.1fs",
                    attempt + 1, max_retries, clean, result.reason, backoff,
                )
                # Reset session on rate-limit or redirect blocks to cycle
                # the TCP connection and clear any server-side affinity.
                if result.reason in ("rate_limited", "login_redirect", "challenge_redirect"):
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