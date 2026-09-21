"""
services/checker.py — Production-grade Instagram username *registration-eligibility* checker.

Uses Instagram's ``web_create_ajax/attempt/`` registration validation endpoint
to determine whether a handle is truly open for new account creation — not merely
whether a visible profile exists.  This eliminates false positives for
banned, disabled, spam-blocked, or deleted accounts (e.g. ``uz.n``, ``ziynat``)
that return HTTP 404 on profile views but **cannot** actually be registered.

Strategy:
    1. **Tier 1** — offline syntax, length, and reserved-word pre-validation
       (instant, no network).
    2. **Tier 2** — POST to Instagram's registration attempt endpoint via the
       DataImpulse residential proxy with Chrome 124 TLS impersonation.

    The registration endpoint evaluates the username against Instagram's full
    internal ruleset (active accounts, disabled accounts, banned handles,
    reserved words, spam filters, etc.) and returns an explicit JSON payload:

    • ``username_suggestions`` present  →  username is **unavailable** (TAKEN).
    • No username error / suggestions    →  username is **available** for
      registration right now.

    A fresh ``csrftoken`` is obtained from the signup page on every session
    initialisation — no hardcoded ``sessionid`` or ``csrftoken`` values are
    stored, preventing IP-session mismatch or token expiry errors.

Integration:
    - ``CheckResult`` dataclass and ``CheckStatus`` enum are the public interface.
    - Module-level singleton ``instagram_checker`` is used by queue_manager.py,
      handlers, and bot lifecycle hooks.
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

_SIGNUP_PAGE_URL = "https://www.instagram.com/accounts/emailsignup/"
_ATTEMPT_URL = "https://www.instagram.com/accounts/web_create_ajax/attempt/"

_COMMON_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Origin": "https://www.instagram.com",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "X-Requested-With": "XMLHttpRequest",
    "X-Instagram-AJAX": "1",
}

# Dummy but valid-looking registration payload fields.
# Instagram only validates the username field during the ``attempt`` step;
# the rest are required to pass basic payload validation but are never
# submitted to actually create an account.
_DUMMY_EMAIL = "checkbot_placeholder_9182@proton.me"
_DUMMY_FIRST_NAME = "Check"
_DUMMY_PASSWORD = "Xk#9vLm2$qR8pZ!w"

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
    Deterministic Instagram username **registration-eligibility** checker.

    Uses ``curl_cffi`` ``AsyncSession`` with Chrome 124 impersonation and the
    DataImpulse residential proxy to POST to Instagram's registration attempt
    endpoint.  No hardcoded session cookies are used — a fresh ``csrftoken``
    is obtained from the signup page on every session initialisation.

    Decision matrix (Tier 2 — registration attempt endpoint):
    ──────────────────────────────────────────────────────────
    Response contains ``username_suggestions`` or username
    errors in ``errors.username``                       →  **TAKEN**
    Response has ``status: "ok"`` with no username
    errors and no ``username_suggestions``              →  **AVAILABLE**
    HTTP 429                                            →  **ERROR** (rate-limited)
    HTTP 407                                            →  **ERROR** (proxy auth)
    Network / timeout / other                           →  **ERROR** (retried)
    """

    def __init__(
        self,
        proxy: Optional[str] = None,
        timeout: float = 8.0,
    ) -> None:
        self._proxy = proxy
        self._timeout = timeout
        self._session: Optional[AsyncSession] = None
        self._csrftoken: Optional[str] = None

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Initialise the HTTP session with proxy and obtain a fresh CSRF token."""
        if self._session is not None:
            return

        proxy = self._proxy or (settings.proxy_url if settings.proxy_enabled else None)

        self._session = AsyncSession(
            impersonate="chrome124",
            proxy=proxy,
            timeout=self._timeout,
        )

        # Obtain a fresh csrftoken from the signup page.
        await self._refresh_csrf_token()

        logger.info(
            "InstagramChecker started (registration-eligibility mode) | proxy=%s | csrf=%s",
            proxy or "direct",
            "obtained" if self._csrftoken else "MISSING",
        )

    async def _refresh_csrf_token(self) -> None:
        """
        GET the Instagram signup page to extract a fresh ``csrftoken`` cookie.

        The signup page always sets this cookie for unauthenticated visitors.
        We use it in the ``X-CSRFToken`` header of subsequent POST requests.
        """
        if self._session is None:
            return

        try:
            resp = await self._session.get(
                _SIGNUP_PAGE_URL,
                headers={
                    "User-Agent": _COMMON_HEADERS["User-Agent"],
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9",
                },
                timeout=self._timeout,
            )

            # Extract csrftoken from the session cookie jar.
            csrf = None

            # Method 1: dict-style access (most reliable for curl_cffi).
            try:
                csrf = self._session.cookies.get("csrftoken")
            except Exception:
                pass

            # Method 2: iterate cookie jar objects.
            if not csrf:
                try:
                    for cookie in self._session.cookies:
                        if cookie.name == "csrftoken":
                            csrf = cookie.value
                            break
                except Exception:
                    pass

            # Method 3: parse Set-Cookie header manually.
            if not csrf:
                set_cookie_headers = resp.headers.get("set-cookie", "")
                if "csrftoken=" in set_cookie_headers:
                    for part in set_cookie_headers.split("csrftoken="):
                        if part:
                            csrf = part.split(";")[0].strip()
                            break

            # Method 4: look for csrf_token in the HTML/JS response body.
            if not csrf and resp.text:
                body = resp.text
                # Instagram embeds {"config":{"csrf_token":"..."}} in the page.
                marker = '"csrf_token":"'
                idx = body.find(marker)
                if idx != -1:
                    start = idx + len(marker)
                    end = body.find('"', start)
                    if end != -1:
                        csrf = body[start:end]

            self._csrftoken = csrf
            if csrf:
                logger.debug("CSRF token refreshed: %s…", csrf[:12])
            else:
                logger.warning(
                    "Could not extract csrftoken from signup page (HTTP %d).",
                    resp.status_code,
                )

        except Exception as exc:
            logger.warning("Failed to refresh CSRF token: %s", exc)
            self._csrftoken = None

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
            self._csrftoken = None

    async def _reset_session(self) -> None:
        """Close the current session and re-initialise (cycles the proxy IP)."""
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

    # ── Tier 2: Registration attempt endpoint (cookie-free, proxy-backed) ───

    async def _tier2_api_check(self, username: str, start_time: float) -> CheckResult:
        """
        POST to Instagram's ``web_create_ajax/attempt/`` endpoint to
        determine whether *username* is truly available for registration.

        This endpoint is the same one Instagram's web signup form uses to
        validate fields in real-time.  It returns a JSON payload indicating:

        • ``errors.username`` present or ``username_suggestions`` present
          →  The handle is taken, reserved, banned, or otherwise unavailable.
        • No username error and ``status == "ok"``
          →  The handle is genuinely free for new registration.

        No account is created — the ``/attempt/`` step only validates.
        """
        session = await self._get_session()

        # Ensure we have a CSRF token.
        if not self._csrftoken:
            await self._refresh_csrf_token()
            if not self._csrftoken:
                return CheckResult(
                    username=username,
                    status=CheckStatus.ERROR,
                    reason="csrf_unavailable",
                    error_message="Could not obtain CSRF token from Instagram signup page",
                    response_time=round(time.perf_counter() - start_time, 3),
                )

        headers = {
            **_COMMON_HEADERS,
            "X-CSRFToken": self._csrftoken,
            "Content-Type": "application/x-www-form-urlencoded",
        }

        payload = {
            "email": _DUMMY_EMAIL,
            "username": username,
            "first_name": _DUMMY_FIRST_NAME,
            "password": _DUMMY_PASSWORD,
            "opt_into_one_tap": "false",
        }

        try:
            resp = await session.post(
                _ATTEMPT_URL,
                headers=headers,
                data=payload,
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

        # ── HTTP 403 / 401: blocked or CSRF invalid → ERROR (retriable) ─
        if resp.status_code in (401, 403):
            logger.warning(
                "HTTP %d for @%s — CSRF token may be stale, will reset session.",
                resp.status_code, username,
            )
            return CheckResult(
                username=username,
                status=CheckStatus.ERROR,
                reason="auth_blocked",
                error_message=f"HTTP {resp.status_code} — session/CSRF rejected, will retry with fresh token",
                http_status=resp.status_code,
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

        # ── HTTP 200: parse JSON response ───────────────────────────────
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

        # ── Evaluate the registration response payload ──────────────────
        #
        # The ``/attempt/`` endpoint returns JSON like:
        #
        #   Taken / banned / reserved:
        #     {"errors": {"username": [{"message": "...", "code": "..."}]},
        #      "username_suggestions": ["alt1", "alt2", ...],
        #      "status": "ok"}
        #
        #   Available (all fields passed validation):
        #     {"errors": {},  "status": "ok",  "dryrun_passed": true}
        #     or simply no "username" key in "errors" and no "username_suggestions".
        #
        # We check for ANY sign that the username was rejected.

        errors = data.get("errors", {})
        username_errors = errors.get("username") if isinstance(errors, dict) else None
        has_suggestions = bool(data.get("username_suggestions"))

        # TAKEN: username errors present or suggestions offered.
        if username_errors or has_suggestions:
            # Extract the human-readable reason if available.
            reject_reason = "username_is_taken"
            if isinstance(username_errors, list) and username_errors:
                first_error = username_errors[0]
                if isinstance(first_error, dict):
                    reject_reason = first_error.get("code", "username_is_taken")
                elif isinstance(first_error, str):
                    reject_reason = first_error

            return CheckResult(
                username=username,
                status=CheckStatus.TAKEN,
                reason=reject_reason,
                http_status=200,
                response_time=elapsed,
            )

        # AVAILABLE: status is "ok" and no username rejection signals.
        status_field = data.get("status", "")
        if status_field == "ok":
            # Double-check: if "dryrun_passed" is explicitly False, treat
            # as taken (safety net for undocumented edge cases).
            if data.get("dryrun_passed") is False:
                return CheckResult(
                    username=username,
                    status=CheckStatus.TAKEN,
                    reason="dryrun_failed",
                    http_status=200,
                    response_time=elapsed,
                )

            return CheckResult(
                username=username,
                status=CheckStatus.AVAILABLE,
                reason="truly_available",
                http_status=200,
                response_time=elapsed,
            )

        # Edge case: unexpected response shape — treat as ERROR to be safe,
        # rather than producing a false positive.
        logger.warning(
            "Unexpected registration response for @%s: %s",
            username, data,
        )
        return CheckResult(
            username=username,
            status=CheckStatus.ERROR,
            reason="unexpected_response",
            error_message=f"Unexpected JSON payload (status={status_field!r})",
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
        Check a single Instagram username for registration availability.

        Pipeline:
            1. Tier 1 — syntax / reserved pre-validation (instant, no network).
            2. Tier 2 — registration attempt endpoint via residential proxy.

        Retries on transient errors (network failures, HTTP 429, 5xx, 401/403)
        up to *max_retries* times with exponential back-off.  Session is reset
        on rate-limits and auth errors to cycle the proxy IP and refresh the
        CSRF token.
        """
        start_time = time.perf_counter()
        clean = username.strip().lower()

        # ── Tier 1: offline pre-validation ──────────────────────────────
        precheck = self._tier1_prevalidate(clean)
        if precheck is not None:
            return precheck

        # ── Tier 2: registration attempt check (with retries) ───────────
        last_result: Optional[CheckResult] = None

        for attempt in range(max_retries + 1):
            result = await self._tier2_api_check(clean, start_time)

            # Definitive answers — return immediately.
            if result.status in (CheckStatus.AVAILABLE, CheckStatus.TAKEN):
                return result

            # Transient error — retry after exponential back-off.
            last_result = result
            if attempt < max_retries:
                backoff = min(2.0 * (2 ** attempt), 30.0)  # 2s, 4s, 8s … cap 30s
                logger.info(
                    "Retry %d/%d for @%s (reason=%s), sleeping %.1fs",
                    attempt + 1, max_retries, clean, result.reason, backoff,
                )
                # Reset session on rate-limit, auth errors, or CSRF failure
                # to cycle the proxy IP and obtain a fresh CSRF token.
                if result.reason in (
                    "rate_limited",
                    "auth_blocked",
                    "csrf_unavailable",
                    "proxy_auth_failed",
                ):
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