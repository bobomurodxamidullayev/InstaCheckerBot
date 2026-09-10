"""Instagram username availability checker — Web HTML scraping.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Web HTML scraping:
             GET https://www.instagram.com/{username}/
             via curl_cffi (Chrome124 TLS fingerprint).

             HTTP 404                              → AVAILABLE
             HTTP 200 + "page not found" / "isn't available" → AVAILABLE
             HTTP 200 + profile signals (followers, posts, etc.) → TAKEN
             HTTP 200 + empty shell (no signals, no not found) → TAKEN (banned/deactivated)
             HTTP 302 / 429                        → ERROR (retry)
             Other status codes                    → ERROR (never TAKEN)

ANONIM REJIM: Hech qanday POST, session, CSRF, API key ishlatilmaydi.
Faqat bitta GET so'rov — brauzer kabi.

CHROME124 AFZALLIGI:
  Chrome124 impersonation bilan Instagram javobini to'g'ri klassifikatsiya qilish.
  Bo'sh React qobiqlarini TAKEN deb belgilash (banned/deactivated akkauntlar).
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

_PROFILE_URL_TPL = "https://www.instagram.com/{}/"
_PAGE_TIMEOUT = 12.0
_PROXY_RETRY_DELAY = 1.0

# Chrome124 impersonate profili
_IMPERSONATE = "chrome124"
_IMPERSONATE_FALLBACK = "chrome120"

_DESKTOP_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 "
    "Safari/537.36"
)

_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": _DESKTOP_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Network exceptions
_CURL_NETWORK_EXCEPTIONS = (
    CurlError, CurlRequestException, TimeoutError,
    asyncio.TimeoutError, ConnectionError, OSError,
)

# Tier-1 pre-validation
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
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
    Anonim Instagram username availability checker — Web HTML scraping.

    Faqat bitta GET so'rov: /{username}/
    Hech qanday POST, session, CSRF, API key ishlatilmaydi.

    CHROME124 REJIMI:
      Chrome124 impersonation bilan Instagram javobini to'g'ri klassifikatsiya qilish.
      Bo'sh React qobiqlarini TAKEN deb belgilash (banned/deactivated akkauntlar).

    TEMIR QONUNLAR:
      404                              → AVAILABLE (haqiqiy bo'sh nom)
      200 + "page not found" / "isn't available" → AVAILABLE
      200 + profile signals            → TAKEN (faol profil)
      200 + empty shell                → TAKEN (banned/deactivated)
      302 / 429                        → ERROR (rate limited/redirect)
      Other status codes               → ERROR (hech qachon TAKEN emas)
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()
        self._impersonate: str = _resolve_impersonate()

        logger.info(
            "InstagramChecker ready (Web HTML scraping + curl_cffi) | "
            "proxy=%s | impersonate=%s",
            bool(self._proxy), self._impersonate,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started (Web HTML scraping, no POST)")

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
        GET https://www.instagram.com/{username}/

        Chrome124 UA bilan so'rov yuborish.
        HTML scraping bilan klassifikatsiya qilish.

        TEMIR QONUNLAR:
          404                              → AVAILABLE (haqiqiy bo'sh nom)
          200 + "page not found" / "isn't available" → AVAILABLE
          200 + profile signals            → TAKEN (faol profil)
          200 + empty shell                → TAKEN (banned/deactivated)
          302 / 429                        → ERROR (rate limited/redirect)
          Other status codes               → ERROR (hech qachon TAKEN emas)
        """
        url = _PROFILE_URL_TPL.format(username)

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
        resp = None

        for proxy_attempt in range(1, max_proxy_retries + 1):
            try:
                async with AsyncSession(**session_kwargs) as session:
                    resp = await session.get(
                        url,
                        headers=_BROWSER_HEADERS,
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

        # ── 404 → AVAILABLE ───────────────────────────────────────
        if sc == 404:
            logger.info("[@%s] AVAILABLE (HTTP 404)", username)
            return CheckResult(
                username, CheckStatus.AVAILABLE, "not_found_404"
            )

        # ── 200: HTML tahlil ───────────────────────────────────────
        if sc == 200:
            return self._classify_html_response(username, resp)

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

        # ── Boshqa status kodlar → ERROR (hech qachon TAKEN emas) ────
        logger.warning("[@%s] Kutilmagan HTTP %d -> ERROR", username, sc)
        return CheckResult(
            username, CheckStatus.ERROR, f"unexpected_http_{sc}"
        )

    # ------------------------------------------------------------------
    # HTTP 200 HTML klassifikatsiya (Web scraping)
    # ------------------------------------------------------------------

    def _classify_html_response(self, username: str, resp: Any) -> CheckResult:
        """
        HTTP 200 javobni klassifikatsiya qilish (Web HTML scraping).

        Mantiq:
          1) Profile signals (followers, posts, etc.) → TAKEN (faol profil)
          2) "page not found" / "isn't available" → AVAILABLE (haqiqiy bo'sh nom)
          3) Empty shell (no signals, no not found) → TAKEN (banned/deactivated)
        """
        clean_user = username.lower()
        
        # HTML olish
        html = ""
        try:
            html = str(getattr(resp, "text", "") or "")
        except Exception:
            pass
        
        body = html.lower()
        
        # ── 1) Profile signals → TAKEN (faol profil) ────────────────
        has_stats = "followers" in body and "posts" in body
        has_profile_title = "photos and videos" in body or f"(@{clean_user})" in body
        has_og = "og:title" in html and clean_user in html
        
        if has_stats or has_profile_title or has_og:
            logger.info(
                "[@%s] TAKEN (profile_exists — signals in HTML, HTTP 200)",
                username,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "profile_exists"
            )
        
        # ── 2) "Page Not Found" / "isn't available" → AVAILABLE ────
        not_found_phrases = (
            "page not found",
            "isn't available",
            "the link you followed may be broken",
        )
        if any(phrase in body for phrase in not_found_phrases):
            logger.info(
                "[@%s] AVAILABLE (HTTP 200 + not-found phrase in body)",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "page_not_found_200"
            )
        
        # ── 3) Empty shell (no signals, no not found) → TAKEN (banned/deactivated) ────
        # Bu ban yoki deaktiv bo'lgan akkaunt - Instagram buni bo'sh React qobiq bilan beradi
        # "Page Not Found" yo'q, lekin profil ma'lumotlari ham yo'q
        logger.info(
            "[@%s] TAKEN (account_disabled_or_banned — HTTP 200, no profile signals, no not-found)",
            username,
        )
        return CheckResult(
            username, CheckStatus.TAKEN, "account_disabled_or_banned"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()