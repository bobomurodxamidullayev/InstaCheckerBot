"""
services/checker.py — Authenticated Instagram username availability checker.

Uses curl_cffi with Chrome 124 browser impersonation and live session
credentials to query Instagram's web_profile_info endpoint.  A real
profile response means the handle is TAKEN; a 404 / null-user response
means the handle is AVAILABLE.

Integration:
    - CheckResult dataclass and CheckStatus enum are the public interface.
    - Module-level singleton `instagram_checker` is used by queue_manager.py
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

# ─── Authenticated session credentials ─────────────────────────────────────────
INSTA_SESSION_ID = (
    "40137255195%3AdYjlsW9FTWJ9MD%3A19%3A3AAYkrmRfVGsglXHzdexZG6BF4FPHdkYlRnApGfH8Fg"
)
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

    Uses curl_cffi AsyncSession with Chrome 124 impersonation and injected
    session cookies so that every request is treated as a logged-in browser
    interaction.  Queries the ``web_profile_info`` endpoint:

    * HTTP 200 + valid user object  →  **TAKEN**
    * HTTP 404 / user is ``None``   →  **AVAILABLE**
    * Anything else                 →  **ERROR** (retried)
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
        """Initialise the underlying HTTP session with auth cookies."""
        if self._session is not None:
            return
        self._session = AsyncSession(
            impersonate="chrome124",
            proxy=self._proxy,
            timeout=self._timeout,
        )
        # Bind authenticated cookies to the session.
        self._session.cookies.set(
            "sessionid", INSTA_SESSION_ID,
            domain=".instagram.com", path="/",
        )
        self._session.cookies.set(
            "csrftoken", INSTA_CSRF_TOKEN,
            domain=".instagram.com", path="/",
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
        session to deterministically resolve whether *username* exists.

        Decision matrix
        ───────────────
        HTTP 200 + user object present  →  TAKEN
        HTTP 404 / user object is None  →  AVAILABLE
        HTTP 429                        →  ERROR (rate_limited, retriable)
        Other / network fault           →  ERROR (retriable)
        """
        session = await self._get_session()

        url = _PROFILE_URL_TEMPLATE.format(username)

        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "X-IG-App-ID": "936619743392459",
            "X-CSRFToken": INSTA_CSRF_TOKEN,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"https://www.instagram.com/{username}/",
            "Accept": "*/*",
        }

        try:
            resp = await session.get(
                url,
                headers=headers,
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
            2. Tier 2 — authenticated GET to web_profile_info API.

        Retries on transient errors (network failures, HTTP 429) up to
        *max_retries* times with incremental back-off.
        """
        start_time = time.perf_counter()
        clean = username.strip().lower()

        # ── Tier 1: offline pre-validation ──────────────────────────────
        precheck = self._tier1_prevalidate(clean)
        if precheck is not None:
            return precheck

        # ── Tier 2: authenticated API check (with retries) ──────────────
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
                # Reset session on rate-limit to cycle cookies / connection.
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