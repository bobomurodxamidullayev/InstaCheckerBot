"""Instagram username availability checker — Authenticated API pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved-word pre-validation (no network call).
  Tier 2  — Authenticated POST to /api/v1/web/accounts/check_username/ using
             a dedicated Instagram session (sessionid + csrftoken cookies).
             No HTML guessing, no fallback tiers.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from dataclasses import dataclass
from typing import Any, Optional

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
# Credentials — dedicated authorized Instagram session
# ---------------------------------------------------------------------------

INSTA_SESSION_ID = (
    "23761489380%3AKb1sdzj29KjSCF%3A3%3A"
    "AYhau5evQnEkTxUMgaO4OuZnXf6WJVv_dYHYbwCJKw"
)
INSTA_CSRF_TOKEN = "JUL4o1baRX59czy51wZIVO1cTzvFkRSs"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHECK_USERNAME_API_URL = (
    "https://www.instagram.com/api/v1/web/accounts/check_username/"
)
_API_TIMEOUT = 8.0
_IMPERSONATE = "chrome124"
_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_API_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "X-CSRFToken": INSTA_CSRF_TOKEN,
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.instagram.com/accounts/edit/",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://www.instagram.com",
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

# Disallows leading/trailing/consecutive dots and any non [a-zA-Z0-9._] char.
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")

_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
    "meta", "privacy", "terms", "settings", "profile",
})

# ---------------------------------------------------------------------------
# Data models — kept identical for queue_manager.py compatibility
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Result of a single username availability check."""

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
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_json_body(response: Any) -> dict[str, Any] | None:
    """Safely parse a JSON dict from a curl_cffi response."""
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    # Fallback: decode raw bytes manually.
    content = getattr(response, "content", b"")
    if isinstance(content, (bytes, bytearray)):
        text = bytes(content).decode("utf-8", errors="ignore").strip()
    else:
        text = str(getattr(response, "text", "") or "").strip()
    if not text or text[0] != "{":
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Deterministic Instagram username availability checker.

    Two-tier pipeline:
      1. Syntax / reserved-word pre-validation (instant, no I/O).
      2. Authenticated POST to Instagram's check_username API.
         Returns ERROR on any non-200 response — no HTML guessing.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()
        logger.info(
            "InstagramChecker ready | proxy=%s | session_auth=enabled",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle hooks (kept for queue_manager.py compatibility)
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info(
            "InstagramChecker started | proxy=%s | api=check_username",
            bool(self._proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker stopped.")

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    async def check_username(
        self,
        username: str,
        max_retries: int = 1,  # kept for signature compatibility
    ) -> CheckResult:
        """
        Check whether *username* is available on Instagram.

        Returns a :class:`CheckResult` with one of:
          - ``AVAILABLE`` — API confirmed the handle is free.
          - ``TAKEN``     — API confirmed it is taken / has errors.
          - ``ERROR``     — Network failure, timeout, or unexpected HTTP status.
        """
        clean = username.strip().lstrip("@").lower()

        # ── Tier 1: instant pre-validation ──────────────────────────────
        tier1 = self._tier1_prevalidate(clean)
        if tier1 is not None:
            status, reason = tier1
            logger.info(
                "[@%s] TIER-1 rejected → %s (%s)", clean, status.value, reason
            )
            return CheckResult(
                username=clean, status=status, error_message=reason, attempts=0
            )

        if clean in self._in_flight:
            logger.warning("[@%s] Duplicate in-flight check detected.", clean)

        self._in_flight.add(clean)
        try:
            # Polite inter-request delay to avoid hammering the API.
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )
            # ── Tier 2: authenticated API call ──────────────────────────
            return await self._tier2_api_check(clean)
        except Exception as exc:
            logger.exception("[@%s] Unhandled exception in checker.", clean)
            return CheckResult(
                username=clean,
                status=CheckStatus.ERROR,
                error_message=f"{type(exc).__name__}: {exc}",
                attempts=1,
            )
        finally:
            self._in_flight.discard(clean)

    # ------------------------------------------------------------------
    # Tier 1 — Syntax / reserved-word pre-validation
    # ------------------------------------------------------------------

    def _tier1_prevalidate(
        self, username: str
    ) -> tuple[CheckStatus, str] | None:
        """Return ``(status, reason)`` if *username* is invalid, else ``None``."""
        if not 1 <= len(username) <= 30:
            return CheckStatus.TAKEN, "invalid_length"
        if _INVALID_SYNTAX_RE.search(username):
            return CheckStatus.TAKEN, "invalid_syntax"
        if "." in username and len(username) <= 4:
            return CheckStatus.TAKEN, "invalid_syntax"
        if username in _RESERVED_NAMES:
            return CheckStatus.TAKEN, "reserved"
        return None

    # ------------------------------------------------------------------
    # Tier 2 — Authenticated API validator
    # ------------------------------------------------------------------

    async def _tier2_api_check(self, username: str) -> CheckResult:
        """
        POST ``{"username": username}`` to Instagram's check_username endpoint
        using the authorised session credentials.

        Deterministic outcomes:
          ``{"available": true}``            → AVAILABLE, "truly_available"
          ``{"available": false}`` / errors  → TAKEN,     "username_is_taken"
          Non-200 / network failure          → ERROR,     HTTP status or exc

        Key implementation notes:
          - ``verify`` is intentionally omitted (defaults to True) so that
            curl_cffi retains full control of the TLS handshake.  Passing
            ``verify=False`` internally sets curl's ``-k`` flag which breaks
            the JA3/TLS ClientHello that ``impersonate="chrome124"`` builds,
            causing Instagram to send SSLV3_ALERT_HANDSHAKE_FAILURE.
          - ``allow_redirects=True`` (default) is required because Instagram
            redirects unauthenticated/malformed requests via 302 before
            issuing the real response.  Disabling it surfaces a 404 from the
            redirect target, not the actual API result.
          - Cookies are injected both into the jar *and* as an explicit
            ``Cookie:`` header so they are guaranteed to be sent on the very
            first request (jar serialisation can be skipped if the session
            hasn't made a prior request to the same domain).
        """
        # Build cookie string for explicit header injection.
        cookie_header = (
            f"sessionid={INSTA_SESSION_ID}; csrftoken={INSTA_CSRF_TOKEN}"
        )
        headers = {**_API_HEADERS, "Cookie": cookie_header}

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _API_TIMEOUT,
            # NOTE: do NOT pass verify=False here — it breaks chrome TLS impersonation.
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        try:
            async with AsyncSession(**session_kwargs) as session:
                # Also set the cookie jar so any subsequent redirected request
                # within this session carries the credentials automatically.
                session.cookies.set(
                    "sessionid", INSTA_SESSION_ID, domain=".instagram.com"
                )
                session.cookies.set(
                    "csrftoken", INSTA_CSRF_TOKEN, domain=".instagram.com"
                )

                resp = await session.post(
                    _CHECK_USERNAME_API_URL,
                    headers=headers,
                    data={"username": username},
                    timeout=_API_TIMEOUT,
                    # allow_redirects defaults to True — do NOT override to False.
                )

        except _NETWORK_EXCEPTIONS as exc:
            detail = f"{type(exc).__name__}: {exc}"
            logger.warning("[@%s] Network error — %s", username, detail)
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                error_message=detail,
                attempts=1,
            )

        status_code = int(getattr(resp, "status_code", 0) or 0)

        # ── Unexpected / rate-limited response ──────────────────────────
        if status_code != 200:
            detail = f"http_{status_code}"
            logger.warning(
                "[@%s] API returned %d → ERROR (%s)", username, status_code, detail
            )
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                error_message=detail,
                attempts=1,
            )

        # ── Parse the JSON body ─────────────────────────────────────────
        data = _parse_json_body(resp)
        if data is None:
            logger.warning("[@%s] 200 OK but non-JSON body → ERROR", username)
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                error_message="non_json_response",
                attempts=1,
            )

        # ── Deterministic classification ────────────────────────────────
        if data.get("available") is True:
            logger.info(
                "[@%s] AVAILABLE (truly_available) [check_username_api]", username
            )
            return CheckResult(
                username=username,
                status=CheckStatus.AVAILABLE,
                error_message="truly_available",
                attempts=1,
            )

        if data.get("available") is False or "errors" in data:
            logger.info(
                "[@%s] TAKEN (username_is_taken) [check_username_api]", username
            )
            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                error_message="username_is_taken",
                attempts=1,
            )

        # ── Ambiguous payload — treat conservatively as ERROR ───────────
        logger.warning(
            "[@%s] Ambiguous API payload → ERROR | body=%s",
            username,
            str(data)[:200],
        )
        return CheckResult(
            username=username,
            status=CheckStatus.ERROR,
            error_message=f"ambiguous_payload: {str(data)[:120]}",
            attempts=1,
        )


# ---------------------------------------------------------------------------
# Module-level singleton (imported by queue_manager.py)
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()