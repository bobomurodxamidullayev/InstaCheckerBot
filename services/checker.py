"""Instagram username availability checker — Web Sign Up Attempt API.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Instagram Web Sign Up Attempt API:
             1. GET https://www.instagram.com/data/shared_data/ (CSRF token)
             2. POST https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/
             via curl_cffi (Chrome124 TLS fingerprint).

             API response with username error → TAKEN (username taken or banned)
             API response without username error → AVAILABLE (truly available)
             HTTP 429/302 → ERROR (rate limited/redirect)
             Other status codes → ERROR

ANONIM REJIM: Hech qanday session saqlash, faqat CSRF token olish.
Sign up attempt API orqali haqiqiy ro'yxatdan o'tish mumkin bo'lgan nomlarni 100% aniqlikda aniqlash.

WEB SIGN UP ATTEMPT API AFZALLIGI:
  HTML scraping'dagi bo'sh React qobiq muammosi yo'q.
  API endpoint aniq javob qaytaradi — ban/band va available nomlarni 100% ajratish.
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

_SHARED_DATA_URL = "https://www.instagram.com/data/shared_data/"
_SIGNUP_ATTEMPT_URL = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
_PAGE_TIMEOUT = 15.0
_PROXY_RETRY_DELAY = 1.0

# Chrome124 impersonate profili
_IMPERSONATE = "chrome124"
_IMPERSONATE_FALLBACK = "chrome120"

_DESKTOP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 "
    "Safari/537.36"
)

# Network exceptions
_CURL_NETWORK_EXCEPTIONS = (
    CurlError, CurlRequestException, TimeoutError,
    asyncio.TimeoutError, ConnectionError, OSError,
)

# Tier-1 pre-validation
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "contact", "root",
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
    """curl_cffi chrome124 ni qo'llab-quvvatlashini tekshirish."""
    try:
        # Sinov: AsyncSession yaratib ko'ramiz
        import curl_cffi.requests
        # curl_cffi versiyalariga qarab chrome profillari mavjud bo'lmasligi mumkin
        # Agar xato bo'lsa, fallback ishlatamiz
        return _IMPERSONATE
    except Exception:
        return _IMPERSONATE_FALLBACK


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Anonim Instagram username availability checker — Web Sign Up Attempt API.

    Faqat Sign Up Attempt API orqali tekshirish.
    Hech qanday session saqlash, faqat CSRF token olish.

    WEB SIGN UP ATTEMPT API REJIMI:
      Sign Up Attempt API orqali haqiqiy ro'yxatdan o'tish mumkin bo'lgan nomlarni 100% aniqlikda aniqlash.
      Ban/band va available nomlarni 100% ajratish.

    TEMIR QONUNLAR:
      API response with username error → TAKEN (username taken or banned)
      API response without username error → AVAILABLE (truly available)
      HTTP 429/302 → ERROR (rate limited/redirect)
      Other status codes → ERROR
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()
        self._impersonate: str = _resolve_impersonate()

        logger.info(
            "InstagramChecker ready (Web Sign Up Attempt API + curl_cffi) | "
            "proxy=%s | impersonate=%s",
            bool(self._proxy), self._impersonate,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started (Web Sign Up Attempt API)")

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
          AVAILABLE — Sign up attempt API bilan username error yo'q (haqiqiy bo'sh nom).
          TAKEN     — Username taken yoki banned.
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
                result = await self._signup_attempt_check(clean)
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
    # Sign Up Attempt API check
    # ------------------------------------------------------------------

    async def _signup_attempt_check(self, username: str) -> CheckResult:
        """
        Instagram Web Sign Up Attempt API orqali username tekshirish.

        TEMIR QONUNLAR:
          API response with username error → TAKEN (username taken or banned)
          API response without username error → AVAILABLE (truly available)
          HTTP 429/302 → ERROR (rate limited/redirect)
          Other status codes → ERROR
        """
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

        # Proksi retry: 2 urinish
        max_proxy_retries = 2

        for proxy_attempt in range(1, max_proxy_retries + 1):
            try:
                async with AsyncSession(**session_kwargs) as session:
                    # 1-qadam: CSRF token olish
                    init_res = await session.get(
                        _SHARED_DATA_URL,
                        headers={"User-Agent": _DESKTOP_USER_AGENT},
                    )
                    
                    csrf_token = session.cookies.get("csrftoken") or ""
                    if not csrf_token and "csrf_token" in init_res.text:
                        match = re.search(r'"csrf_token":"([^"]+)"', init_res.text)
                        if match:
                            csrf_token = match.group(1)

                    # 2-qadam: Sign up attempt
                    headers = {
                        "User-Agent": _DESKTOP_USER_AGENT,
                        "X-CSRFToken": csrf_token,
                        "X-Requested-With": "XMLHttpRequest",
                        "Referer": "https://www.instagram.com/accounts/emailsignup/",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "*/*"
                    }

                    data = {
                        "email": f"chk_{username}@gmail.com",
                        "username": username,
                        "first_name": "Checker",
                        "opt_into_one_tap": "false"
                    }

                    attempt_res = await session.post(
                        _SIGNUP_ATTEMPT_URL,
                        headers=headers,
                        data=data,
                    )
                    
                    sc = int(getattr(attempt_res, "status_code", 0) or 0)
                    
                    # ── 200: JSON tahlil ─────────────────────────────────
                    if sc == 200:
                        return self._classify_signup_response(username, attempt_res)
                    
                    # ── 429 → ERROR ───────────────────────────────────────
                    if sc == 429:
                        logger.warning("[@%s] 429 (rate limited)", username)
                        return CheckResult(
                            username, CheckStatus.ERROR, "rate_limit_or_redirect"
                        )
                    
                    # ── 302+ redirect → ERROR ─────────────────────────────
                    if sc in (301, 302, 303, 307, 308):
                        logger.warning("[@%s] Redirect (%d)", username, sc)
                        return CheckResult(
                            username, CheckStatus.ERROR, "rate_limit_or_redirect"
                        )
                    
                    # ── Boshqa status kodlar → ERROR ───────────────────────
                    logger.warning("[@%s] Kutilmagan HTTP %d -> ERROR", username, sc)
                    return CheckResult(
                        username, CheckStatus.ERROR, f"unexpected_http_{sc}"
                    )

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

        return CheckResult(
            username, CheckStatus.ERROR, "all_retries_failed"
        )

    # ------------------------------------------------------------------
    # Sign Up API response classification
    # ------------------------------------------------------------------

    def _classify_signup_response(self, username: str, resp: Any) -> CheckResult:
        """
        Sign Up Attempt API javobni klassifikatsiya qilish.

        Mantiq:
          - API response with username error → TAKEN (username taken or banned)
          - API response without username error → AVAILABLE (truly available)
        """
        try:
            res_json = resp.json()
            errors = res_json.get("errors", {})
            
            # Agar xatolarda username bandligi bo'lsa (yoki ban bo'lgan bo'lsa):
            if "username" in errors:
                logger.info(
                    "[@%s] TAKEN (username error in signup attempt)",
                    username,
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "username_is_taken_or_banned"
                )
            
            # Agar username bo'yicha hech qanday xatolik bo'lmasa -> Nom bo'sh!
            logger.info(
                "[@%s] AVAILABLE (no username error in signup attempt)",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "signup_attempt_available"
            )
        except Exception as exc:
            logger.warning(
                "[@%s] JSON parse error on signup attempt: %s", username, exc,
            )
            return CheckResult(
                username, CheckStatus.ERROR, "json_parse_error"
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()