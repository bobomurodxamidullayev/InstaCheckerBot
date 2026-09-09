"""Instagram username availability checker — Web Profile Info API.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Single GET request to Instagram Web Profile Info API:
             GET /api/v1/users/web_profile_info/?username={username}
             via curl_cffi (Chrome TLS fingerprint).

             HTTP 200 + user data   → TAKEN  (profile exists)
             HTTP 404 / user null   → AVAILABLE
             HTTP 400 / user_not_found → AVAILABLE
             HTTP 302 (login redirect) / 429 → ERROR (retry)

ANONIM REJIM: Hech qanday Instagram akkaunt, session cookie yoki
CSRF token talab etilmaydi. Signup sahifalari butunlay ishlatilmaydi.
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
    from curl_cffi.requests.exceptions import RequestException as CurlRequestException
except ImportError:
    try:
        from curl_cffi.requests.errors import RequestsError as CurlRequestException  # type: ignore
    except ImportError:
        CurlRequestException = CurlError  # type: ignore

from config import settings
from models.username_log import CheckStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Web Profile Info endpoint
_PROFILE_INFO_URL = "https://www.instagram.com/api/v1/users/web_profile_info/?username={}"
_API_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"
_PROXY_RETRY_DELAY = 1.0

_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_IG_APP_ID = "936619743392459"

# Network exceptions
_CURL_NETWORK_EXCEPTIONS = (
    CurlError, CurlRequestException, TimeoutError,
    asyncio.TimeoutError, ConnectionError, OSError,
)

# Tier-1 pre-validation
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$ |[^a-zA-Z0-9._]")
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
    "meta", "privacy", "terms", "settings", "profile",
})


# ---------------------------------------------------------------------------
# Data models
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
# Helpers
# ---------------------------------------------------------------------------

def _safe_json_curl(resp: Any) -> dict[str, Any] | None:
    """Safely parse JSON dict from curl_cffi response."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    content = getattr(resp, "content", b"")
    if isinstance(content, (bytes, bytearray)):
        text = bytes(content).decode("utf-8", errors="ignore").strip()
    else:
        text = str(getattr(resp, "text", "") or "").strip()
    if not text or text[0] != "{":
        return None
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _build_headers(username: str) -> dict[str, str]:
    """Build request headers for Web Profile Info API."""
    return {
        "User-Agent": _CHROME_USER_AGENT,
        "X-IG-App-ID": _IG_APP_ID,
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "*/*",
        "Referer": f"https://www.instagram.com/{username}/",
    }


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Anonim Instagram username availability checker — Web Profile Info API.

    Hech qanday Instagram akkaunt, session cookie yoki CSRF token talab etilmaydi.
    Signup sahifalari butunlay ishlatilmaydi.

    curl_cffi (Chrome TLS fingerprint) orqali web_profile_info GET endpointi
    tekshiriladi.

    QOIDALAR:
      AVAILABLE — HTTP 404 yoki user data null/topilmadi.
      TAKEN     — HTTP 200 + user data mavjud.
      ERROR     — Network/proxy/429/redirect infra muammo.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()

        logger.info(
            "InstagramChecker ready (Web Profile Info + curl_cffi) | proxy=%s | mode=anonymous",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info(
            "InstagramChecker started (Web Profile Info, curl_cffi, no session needed)"
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker stopped.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_username(
        self,
        username: str,
        max_retries: int = 2,
    ) -> CheckResult:
        """
        Instagram username mavjudligini tekshirish.

        Returns:
          AVAILABLE — Username Instagramda mavjud emas (404 / user_not_found).
          TAKEN     — Profil mavjud (HTTP 200 + user data).
          ERROR     — Infra muammo (network/proxy/429/redirect).
        """
        clean = username.strip().lstrip("@").lower()

        # Tier 1
        tier1 = self._tier1_prevalidate(clean)
        if tier1 is not None:
            status, reason = tier1
            logger.info("[@%s] TIER-1 -> %s (%s)", clean, status.value, reason)
            return CheckResult(clean, status, reason, 0)

        if clean in self._in_flight:
            logger.warning("[@%s] Duplicate in-flight.", clean)

        self._in_flight.add(clean)
        try:
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )

            last: CheckResult | None = None
            for attempt in range(1, max_retries + 1):
                result = await self._web_profile_info_check(clean)
                result.attempts = attempt

                if result.status != CheckStatus.ERROR:
                    return result

                last = result
                logger.info(
                    "[@%s] Urinish %d/%d -> ERROR (%s)",
                    clean, attempt, max_retries, result.error_message,
                )

                if attempt < max_retries:
                    em = (result.error_message or "").lower()
                    if "429" in em or "rate_limit" in em:
                        await asyncio.sleep(settings.rate_limit_sleep)
                    elif "redirect" in em:
                        await asyncio.sleep(random.uniform(5.0, 10.0))
                    else:
                        await asyncio.sleep(random.uniform(2.0, 4.0))

            return last or CheckResult(
                clean, CheckStatus.ERROR, "max_retries_exhausted", max_retries
            )
        except Exception as exc:
            logger.exception("[@%s] Kutilmagan istisno.", clean)
            return CheckResult(
                clean, CheckStatus.ERROR,
                f"{type(exc).__name__}: {exc}", 1,
            )
        finally:
            self._in_flight.discard(clean)

    # ------------------------------------------------------------------
    # Tier 1 — local validation
    # ------------------------------------------------------------------

    def _tier1_prevalidate(
        self, username: str
    ) -> tuple[CheckStatus, str] | None:
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
    # Web Profile Info GET (curl_cffi, Chrome TLS, NO AUTH)
    # ------------------------------------------------------------------

    async def _web_profile_info_check(
        self, username: str
    ) -> CheckResult:
        """
        GET /api/v1/users/web_profile_info/?username={username}
        via curl_cffi (Chrome TLS fingerprint).

        Klassifikatsiya:
          HTTP 200 + data.user mavjud        → TAKEN
          HTTP 404                            → AVAILABLE
          HTTP 400 / user_not_found in body   → AVAILABLE
          HTTP 302 (login redirect) / 429     → ERROR (qayta urinish)
        """
        url = _PROFILE_INFO_URL.format(username)
        headers = _build_headers(username)

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _API_TIMEOUT,
            "verify": False,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        # SOCKS5 retry: 2 urinish (proxy uzilsa 1s kutib qayta)
        max_proxy_retries = 2
        resp = None

        for proxy_attempt in range(1, max_proxy_retries + 1):
            try:
                async with AsyncSession(**session_kwargs) as session:
                    resp = await session.get(
                        url,
                        headers=headers,
                        allow_redirects=False,  # Redirect'ni qo'lda aniqlash
                    )
                # Muvaffaqiyat — loopdan chiqamiz
                break

            except _CURL_NETWORK_EXCEPTIONS as exc:
                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Proksi/SOCKS5 xato (urinish %d/%d), %gs kutib qayta: %s",
                        username, proxy_attempt, max_proxy_retries,
                        _PROXY_RETRY_DELAY, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                detail = f"network_{type(exc).__name__}"
                logger.warning(
                    "[@%s] Web Profile Info xato (barcha urinishlar): %s",
                    username, exc,
                )
                return CheckResult(username, CheckStatus.ERROR, detail)

            except Exception as exc:
                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Kutilmagan xato (urinish %d/%d), %gs kutib qayta: %s",
                        username, proxy_attempt, max_proxy_retries,
                        _PROXY_RETRY_DELAY, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                detail = f"unexpected_{type(exc).__name__}"
                logger.warning(
                    "[@%s] Web Profile Info kutilmagan (barcha): %s",
                    username, exc,
                )
                return CheckResult(username, CheckStatus.ERROR, detail)

        if resp is None:
            logger.warning(
                "[@%s] Web Profile Info: barcha %d urinish xato",
                username, max_proxy_retries,
            )
            return CheckResult(
                username, CheckStatus.ERROR, "all_retries_failed"
            )

        sc = int(getattr(resp, "status_code", 0) or 0)

        # ── 429 → ERROR (rate limited) ─────────────────────────────
        if sc == 429:
            logger.warning("[@%s] Web Profile Info 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "api_429")

        # ── 302 redirect (login sahifasiga) → ERROR ────────────────
        if sc in (301, 302, 303, 307, 308):
            location = ""
            try:
                location = str(
                    getattr(resp, "headers", {}).get("location", "")
                )
            except Exception:
                pass
            logger.warning(
                "[@%s] Web Profile Info redirect (%d) -> %s",
                username, sc, location[:100],
            )
            return CheckResult(
                username, CheckStatus.ERROR, f"redirect_{sc}"
            )

        # ── 404 → AVAILABLE ────────────────────────────────────────
        if sc == 404:
            logger.info(
                "[@%s] AVAILABLE (HTTP 404 — user not found)", username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "not_found_404"
            )

        # ── Response body tahlil qilish ────────────────────────────
        body_text = ""
        try:
            body_text = str(getattr(resp, "text", "") or "")
        except Exception:
            pass

        # ── 400 yoki user_not_found in body → AVAILABLE ────────────
        if sc == 400 or "user_not_found" in body_text.lower():
            logger.info(
                "[@%s] AVAILABLE (HTTP %d / user_not_found)", username, sc,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, f"not_found_{sc}"
            )

        # ── JSON parse qilish ──────────────────────────────────────
        data = _safe_json_curl(resp)

        if data is None:
            body_preview = body_text[:200] if body_text else "(empty)"
            logger.warning(
                "[@%s] Web Profile Info non-JSON (HTTP %d) | body=%s",
                username, sc, body_preview,
            )
            # Login sahifasi HTML bo'lishi mumkin
            if "login" in body_text.lower() or "/accounts/login/" in body_text.lower():
                return CheckResult(
                    username, CheckStatus.ERROR, "login_page_html"
                )
            return CheckResult(
                username, CheckStatus.ERROR, f"non_json_{sc}"
            )

        logger.debug(
            "[@%s] Web Profile Info response: HTTP %d | %s",
            username, sc, json.dumps(data, ensure_ascii=False)[:300],
        )

        # ── HTTP 200 + user data → TAKEN ───────────────────────────
        if sc == 200:
            user_data = None
            # Standard format: {"data": {"user": {...}}}
            data_block = data.get("data")
            if isinstance(data_block, dict):
                user_data = data_block.get("user")

            # Alternative: {"user": {...}} (to'g'ridan-to'g'ri)
            if user_data is None:
                user_data = data.get("user")

            if user_data and isinstance(user_data, dict):
                ig_username = user_data.get("username", "")
                logger.info(
                    "[@%s] TAKEN (profile_exists, ig_user=%s) [Web Profile Info]",
                    username, ig_username,
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "profile_exists"
                )

            # HTTP 200 lekin user null/None → AVAILABLE
            if user_data is None:
                logger.info(
                    "[@%s] AVAILABLE (HTTP 200 but user is null)", username,
                )
                return CheckResult(
                    username, CheckStatus.AVAILABLE, "user_null_200"
                )

        # ── status check (agar mavjud bo'lsa) ──────────────────────
        status_field = data.get("status", "")
        if status_field == "fail":
            error_type = str(data.get("error_type", ""))
            message = str(data.get("message", ""))

            # Rate limit
            if any(w in message.lower() for w in ("wait", "try again", "rate")):
                logger.warning(
                    "[@%s] Web Profile Info rate limit: %s", username, message[:80],
                )
                return CheckResult(
                    username, CheckStatus.ERROR, "api_rate_limit"
                )

            # IP block / checkpoint
            if error_type in (
                "checkpoint_required", "checkpoint_challenge_required",
                "spam", "rate_limit_error", "sentry_block",
                "generic_request_error", "ip_block",
            ):
                logger.warning(
                    "[@%s] Web Profile Info infra block: %s", username, error_type,
                )
                return CheckResult(
                    username, CheckStatus.ERROR, f"block_{error_type}"
                )

        # ── Noaniq → ERROR ─────────────────────────────────────────
        logger.warning(
            "[@%s] Noaniq Web Profile Info javob -> ERROR | HTTP %d | body=%s",
            username, sc, str(data)[:200],
        )
        return CheckResult(
            username, CheckStatus.ERROR, f"unknown_response_{sc}"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()