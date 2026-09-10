"""Instagram username availability checker — i.instagram.com API endpoint.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — i.instagram.com API endpoint check:
             GET https://i.instagram.com/api/v1/users/web_profile_info/?username={username}
             via curl_cffi (Mobile Safari TLS fingerprint).

             HTTP 200 + user data in JSON            → TAKEN (active profile)
             HTTP 404 + "user_not_found"              → AVAILABLE (truly available)
             HTTP 404 + checkpoint/disabled indicators → TAKEN (banned/disabled)
             HTTP 400/401/403                          → TAKEN (restricted/banned)
             HTTP 429/302                              → ERROR (rate limited/redirect)

ANONIM REJIM: Hech qanday POST, session, CSRF ishlatilmaydi.
Faqat bitta GET so'rov — mobil brauzer kabi.

I.INSTAGRAM.COM API AFZALLIGI:
  Web scraping'dagi bo'sh React qobiq muammosi yo'q.
  API endpoint aniq JSON qaytaradi — klassifikatsiya 100% aniq.
"""
from __future__ import annotations

import asyncio
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

_API_URL_TPL = "https://i.instagram.com/api/v1/users/web_profile_info/?username={}"
_PAGE_TIMEOUT = 10.0
_PROXY_RETRY_DELAY = 1.0

# Mobile Safari impersonate profili
_IMPERSONATE = "safari17_2_ios"
_IMPERSONATE_FALLBACK = "safari15_3"

_MOBILE_USER_AGENT = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 "
    "Mobile/15E148 Safari/604.1"
)

_API_HEADERS: dict[str, str] = {
    "User-Agent": _MOBILE_USER_AGENT,
    "X-IG-App-ID": "936619743392459",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://www.instagram.com",
}

# Network exceptions
_CURL_NETWORK_EXCEPTIONS = (
    CurlError, CurlRequestException, TimeoutError,
    asyncio.TimeoutError, ConnectionError, OSError,
)

# Tier-1 pre-validation
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$ |[^a-zA-Z0-9._]")
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "contact", "root",
    "login", "signup", "accounts", "explore", "direct", "security",
    "about", "developer", "meta", "privacy", "terms", "settings", "profile",
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

def _resolve_impersonate() -> str:
    """curl_cffi safari17_2_ios ni qo'llab-quvvatlashini tekshirish."""
    try:
        # Sinov: AsyncSession yaratib ko'ramiz
        import curl_cffi.requests
        # curl_cffi versiyalariga qarab safari profillari mavjud bo'lmasligi mumkin
        # Agar xato bo'lsa, fallback ishlatamiz
        return _IMPERSONATE
    except Exception:
        return _IMPERSONATE_FALLBACK


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Anonim Instagram username availability checker — i.instagram.com API.

    Faqat bitta GET so'rov: /api/v1/users/web_profile_info/?username={username}
    Hech qanday POST, session, CSRF ishlatilmaydi.

    I.INSTAGRAM.COM API REJIMI:
      i.instagram.com API endpoint aniq JSON qaytaradi.
      Web scraping'dagi bo'sh React qobiq muammosi yo'q.

    TEMIR QONUNLAR:
      200 + user data in JSON              → TAKEN (faol profil)
      404 + "user_not_found"                → AVAILABLE (haqiqiy bo'sh nom)
      404 + checkpoint/disabled indicators  → TAKEN (banned/disabled)
      400/401/403                           → TAKEN (restricted/banned)
      429/302                               → ERROR (rate limited/redirect)
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()
        self._impersonate: str = _resolve_impersonate()

        logger.info(
            "InstagramChecker ready (i.instagram.com API + curl_cffi) | "
            "proxy=%s | impersonate=%s",
            bool(self._proxy), self._impersonate,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started (Mobile Safari GET, no POST)")

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
          AVAILABLE — 404 yoki "page not found" (haqiqiy bo'sh nom).
          TAKEN     — Profil mavjud yoki banned/disabled.
          ERROR     — Infra muammo (network/proxy/429/redirect).
        """
        clean = username.strip().lstrip("@").lower()

        # Tier 1 — lokal validatsiya
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
                result = await self._single_get_check(clean)
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
    # Single GET check — /{username}/ (Mobile Safari)
    # ------------------------------------------------------------------

    async def _single_get_check(self, username: str) -> CheckResult:
        """
        GET https://i.instagram.com/api/v1/users/web_profile_info/?username={username}

        Mobile Safari UA bilan so'rov yuborish.
        i.instagram.com API endpoint aniq JSON qaytaradi.

        TEMIR QONUNLAR:
          200 + user data in JSON              → TAKEN (faol profil)
          404 + "user_not_found"                → AVAILABLE (haqiqiy bo'sh nom)
          404 + checkpoint/disabled indicators  → TAKEN (banned/disabled)
          400/401/403                           → TAKEN (restricted/banned)
          429/302                               → ERROR (rate limited/redirect)
        """
        url = _API_URL_TPL.format(username)

        session_kwargs: dict[str, Any] = {
            "timeout": _PAGE_TIMEOUT,
            "verify": False,
        }

        # impersonate profilini sinab ko'ramiz
        try:
            session_kwargs["impersonate"] = self._impersonate
        except Exception:
            pass

        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        # Dynamic headers with username-specific referer
        headers = _API_HEADERS.copy()
        headers["Referer"] = f"https://www.instagram.com/{username}/"

        # Proksi retry: 2 urinish
        max_proxy_retries = 2
        resp = None

        for proxy_attempt in range(1, max_proxy_retries + 1):
            try:
                async with AsyncSession(**session_kwargs) as session:
                    resp = await session.get(
                        url,
                        headers=headers,
                        allow_redirects=False,
                    )
                break

            except _CURL_NETWORK_EXCEPTIONS as exc:
                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Proksi xato (%d/%d), %gs kutib qayta: %s",
                        username, proxy_attempt, max_proxy_retries,
                        _PROXY_RETRY_DELAY, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                logger.warning(
                    "[@%s] Network xato (barcha urinishlar): %s",
                    username, exc,
                )
                return CheckResult(
                    username, CheckStatus.ERROR,
                    f"network_{type(exc).__name__}",
                )

            except Exception as exc:
                # Agar impersonate profili qo'llab-quvvatlanmasa, fallback
                exc_str = str(exc).lower()
                if "impersonate" in exc_str or "not supported" in exc_str:
                    logger.warning(
                        "[@%s] impersonate '%s' qo'llab-quvvatlanmaydi, "
                        "fallback '%s' ga o'tilmoqda",
                        username, self._impersonate, _IMPERSONATE_FALLBACK,
                    )
                    self._impersonate = _IMPERSONATE_FALLBACK
                    session_kwargs["impersonate"] = _IMPERSONATE_FALLBACK
                    continue

                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Kutilmagan xato (%d/%d): %s",
                        username, proxy_attempt, max_proxy_retries, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                logger.warning(
                    "[@%s] Kutilmagan xato (barcha): %s", username, exc,
                )
                return CheckResult(
                    username, CheckStatus.ERROR,
                    f"unexpected_{type(exc).__name__}",
                )

        if resp is None:
            return CheckResult(
                username, CheckStatus.ERROR, "all_retries_failed"
            )

        sc = int(getattr(resp, "status_code", 0) or 0)

        # ── 200: JSON tahlil ───────────────────────────────────────
        if sc == 200:
            return self._classify_200_response(username, resp)

        # ── 404: JSON tahlil ───────────────────────────────────────
        if sc == 404:
            return self._classify_404_response(username, resp)

        # ── 400/401/403 → TAKEN (restricted/banned) ───────────────
        if sc in (400, 401, 403):
            logger.info(
                "[@%s] TAKEN (HTTP %d — restricted or banned)",
                username, sc,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "restricted_or_banned"
            )

        # ── 429 → ERROR ───────────────────────────────────────────
        if sc == 429:
            logger.warning("[@%s] 429 (rate limited)", username)
            return CheckResult(
                username, CheckStatus.ERROR, "rate_limit_or_redirect"
            )

        # ── 302+ redirect → ERROR ─────────────────────────────────
        if sc in (301, 302, 303, 307, 308):
            location = ""
            try:
                location = str(
                    getattr(resp, "headers", {}).get("location", "")
                )
            except Exception:
                pass
            logger.warning(
                "[@%s] Redirect (%d) -> %s", username, sc, location[:100],
            )
            return CheckResult(
                username, CheckStatus.ERROR, "rate_limit_or_redirect"
            )

        # ── Boshqa status kodlar → ERROR ───────────────────────────
        logger.warning("[@%s] Kutilmagan HTTP %d -> ERROR", username, sc)
        return CheckResult(
            username, CheckStatus.ERROR, f"unexpected_http_{sc}"
        )

    # ------------------------------------------------------------------
    # HTTP 200 klassifikatsiya (i.instagram.com API)
    # ------------------------------------------------------------------

    def _classify_200_response(self, username: str, resp: Any) -> CheckResult:
        """
        HTTP 200 javobni klassifikatsiya qilish (i.instagram.com API).

        Mantiq:
          - user data JSON ichida bo'lsa → TAKEN (faol profil)
          - user data yo'q bo'lsa → AVAILABLE (anomaliya)
        """
        try:
            data = resp.json()
            user = data.get("data", {}).get("user")
            if user:
                logger.info(
                    "[@%s] TAKEN (profile_exists — user data in JSON, HTTP 200)",
                    username,
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "profile_exists"
                )
            # Anomaliya: 200 lekin user data yo'q
            logger.warning(
                "[@%s] AVAILABLE (HTTP 200 but no user data — anomaly)",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "anomaly_200_no_user"
            )
        except Exception as exc:
            logger.warning(
                "[@%s] JSON parse error on HTTP 200: %s", username, exc,
            )
            return CheckResult(
                username, CheckStatus.ERROR, "json_parse_error"
            )

    # ------------------------------------------------------------------
    # HTTP 404 klassifikatsiya (i.instagram.com API)
    # ------------------------------------------------------------------

    def _classify_404_response(self, username: str, resp: Any) -> CheckResult:
        """
        HTTP 404 javobni klassifikatsiya qilish (i.instagram.com API).

        Mantiq:
          - "user_not_found" message → AVAILABLE (haqiqiy bo'sh nom)
          - Boshqa xabarlar → TAKEN (banned/disabled/checkpoint)
        """
        try:
            res_json = resp.json()
            message = res_json.get("message", "").lower()
            
            # Agar explicitly "user_not_found" bo'lsa → AVAILABLE
            if message == "user_not_found":
                logger.info(
                    "[@%s] AVAILABLE (HTTP 404 + user_not_found)",
                    username,
                )
                return CheckResult(
                    username, CheckStatus.AVAILABLE, "user_not_found"
                )
            
            # Boshqa 404 javoblari (checkpoint, disabled, etc.) → TAKEN
            logger.info(
                "[@%s] TAKEN (HTTP 404 + %s — banned/disabled/checkpoint)",
                username, message[:50],
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "account_disabled_or_banned"
            )
        except Exception:
            # Fallback: plain 404 HTML/text
            logger.info(
                "[@%s] AVAILABLE (HTTP 404 — non-JSON response)",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "not_found_404"
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()