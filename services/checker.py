"""
services/checker.py — Cookie-free Instagram username availability checker.

Uses curl_cffi with Chrome 124 browser impersonation and the configured
DataImpulse residential proxy to query Instagram's public oEmbed endpoint.
No session cookies or login credentials required.

Strategy:
    Instagram's ``/api/v1/oembed/`` endpoint is a stable, public,
    unauthenticated API designed for third-party embed widgets.  It
    returns JSON metadata (``author_name``, ``author_id``, etc.) for
    existing profiles (HTTP 200) and a clean 404 for non-existent ones.

    Routing through a residential proxy (DataImpulse) prevents data-center
    IP blocks, while curl_cffi's browser impersonation matches a real
    Chrome 124 TLS fingerprint — making the request indistinguishable
    from a legitimate browser on a home connection.

    No ``sessionid`` or ``csrftoken`` cookies are injected, so there is
    zero risk of IP-session mismatch revocation (the root cause of
    previous 401 errors).

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

_OEMBED_URL_TEMPLATE = (
    "https://www.instagram.com/api/v1/oembed/"
    "?url=https://www.instagram.com/{username_clean}/"
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Referer": "https://www.instagram.com/",
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


# ─── Core checker ───────────────────────────────────────────────────────────────

class InstagramChecker:
    """
    Deterministic, cookie-free Instagram username availability checker.

    Uses curl_cffi AsyncSession with Chrome 124 impersonation and the
    DataImpulse residential proxy to query Instagram's public oEmbed API.
    No session cookies or login credentials are used.

    * HTTP 200 + author metadata present  →  **TAKEN**
    * HTTP 404                            →  **AVAILABLE**
    * HTTP 429                            →  **ERROR** (rate-limited)
    * HTTP 401/403                        →  **ERROR** (blocked)
    * Anything else                       →  **ERROR** (retried)
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
        """Initialise the HTTP session with proxy (no cookies)."""
        if self._session is not None:
            return

        # Resolve proxy: explicit constructor arg > settings.proxy_url > None
        proxy = self._proxy or (settings.proxy_url if settings.proxy_enabled else None)

        self._session = AsyncSession(
            impersonate="chrome124",
            proxy=proxy,
            timeout=self._timeout,
        )

        logger.info(
            "InstagramChecker started (cookie-free) | proxy=%s",
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

    # ── Tier 2: Public oEmbed check (cookie-free, proxy-backed) ─────────────

    async def _tier2_api_check(self, username: str, start_time: float) -> CheckResult:
        """
        GET Instagram's public ``oEmbed`` endpoint via the residential proxy
        to deterministically resolve whether *username* exists.

        No cookies or authentication tokens are sent — the oEmbed API is
        fully public and designed for unauthenticated embed lookups.

        Decision matrix
        ───────────────
        HTTP 200 + author_name/author_id present  →  TAKEN
        HTTP 404 (profile does not exist)          →  AVAILABLE
        HTTP 400 (malformed — treat as available)  →  AVAILABLE
        HTTP 429                                   →  ERROR (rate_limited)
        HTTP 407                                   →  ERROR (proxy_auth_failed)
        Other / network fault                      →  ERROR (retriable)
        """
        session = await self._get_session()

        url = _OEMBED_URL_TEMPLATE.format(username_clean=username)

        try:
            resp = await session.get(
                url,
                headers=_HEADERS,
                timeout=self._timeout,
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

        # ── HTTP 400: bad request (non-existent profile URL) → AVAILABLE
        # Instagram's oEmbed returns 400 for URLs that don't resolve to a
        # valid profile — functionally identical to 404 for our purposes.
        if resp.status_code == 400:
            return CheckResult(
                username=username,
                status=CheckStatus.AVAILABLE,
                reason="truly_available",
                http_status=400,
                response_time=elapsed,
            )

        # ── HTTP 429: rate-limited → ERROR (retriable) ──────────────────
        if resp.status_code == 429:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="rate_limited",
                error_message="HTTP 429 — rate limited by Instagram",
                http_status=429,
                response_time=elapsed,
            )

        # ── HTTP 407: proxy authentication required ─────────────────────
        if resp.status_code == 407:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="proxy_auth_failed",
                error_message="HTTP 407 — proxy authentication failed (check PROXY_URL credentials)",
                http_status=407,
                response_time=elapsed,
            )

        # ── HTTP 5xx: server error → ERROR (retriable) ─────────────────
        if resp.status_code >= 500:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="server_error",
                error_message=f"HTTP {resp.status_code} — Instagram server error",
                http_status=resp.status_code,
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

        # ── HTTP 200: parse JSON and verify author metadata ─────────────
        try:
            data: dict[str, Any] = resp.json()
        except Exception:
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="invalid_json",
                error_message="HTTP 200 but response body is not valid JSON",
                http_status=200,
                response_time=elapsed,
            )

        # oEmbed returns {"author_name": "...", "author_id": ..., ...}
        # for existing profiles.  Verify at least one identifying field.
        has_author = bool(data.get("author_name") or data.get("author_id"))

        if has_author:
            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                reason="username_is_taken",
                http_status=200,
                response_time=elapsed,
            )

        # 200 but no author metadata — edge case for deactivated / empty
        # profiles that return a stub response.  Treat as available.
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
            2. Tier 2 — public oEmbed API via residential proxy (cookie-free).

        Retries on transient errors (network failures, HTTP 429, 5xx) up to
        *max_retries* times with incremental back-off.
        """
        start_time = time.perf_counter()
        clean = username.strip().lower()

        # ── Tier 1: offline pre-validation ──────────────────────────────
        precheck = self._tier1_prevalidate(clean)
        if precheck is not None:
            return precheck

        # ── Tier 2: oEmbed API check (with retries) ─────────────────────
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
                # Reset session on rate-limit to cycle proxy IP.
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