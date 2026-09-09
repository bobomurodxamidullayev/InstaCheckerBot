"""Instagram username availability checker — Web Profile Page HTML.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Single browser-like GET request to Instagram profile page:
             GET https://www.instagram.com/{username}/
             via curl_cffi (Chrome TLS fingerprint).

             HTTP 200 + profil mavjud (og:title / title ichida username)
                                              → TAKEN
             HTTP 200 + "Page Not Found" / "Isn't Available"
                                              → AVAILABLE
             HTTP 404                         → AVAILABLE
             HTTP 302 (login redirect) / 429  → ERROR (qayta urinish)

ANONIM REJIM: Hech qanday Instagram akkaunt, session cookie, CSRF token
yoki ichki JSON API endpoint ishlatilmaydi. Oddiy brauzer kabi sahifaga
kirib HTML kontenti tahlil qilinadi.
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
_IMPERSONATE = "chrome124"
_PROXY_RETRY_DELAY = 1.0

_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_BROWSER_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

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

# HTML parsing patterns
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_OG_TITLE_RE = re.compile(
    r'<meta\s+(?:property|name)="og:title"\s+content="(.*?)"',
    re.IGNORECASE,
)
_OG_DESC_RE = re.compile(
    r'<meta\s+property="og:description"\s+content="(.*?)"',
    re.IGNORECASE,
)

# "Page Not Found" / "Isn't Available" detection keywords (case-insensitive)
_NOT_FOUND_PHRASES = (
    "page not found",
    "isn't available",
    "isn\u2019t available",
    "this page isn",
    "content unavailable",
    "sorry, this page",
    "the link you followed may be broken",
)


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
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Anonim Instagram username availability checker — Web Profile Page HTML.

    Hech qanday Instagram akkaunt, session cookie, CSRF token yoki ichki
    JSON API endpoint ishlatilmaydi.

    curl_cffi (Chrome TLS fingerprint) orqali oddiy brauzer kabi profil
    sahifasiga GET so'rov yuboriladi va HTML kontenti tahlil qilinadi.

    QOIDALAR:
      AVAILABLE — HTTP 404 yoki 200 + "Page Not Found" / "Isn't Available".
      TAKEN     — HTTP 200 + og:title / title ichida username ko'rinsa.
      ERROR     — Network/proxy/429/login redirect.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()

        logger.info(
            "InstagramChecker ready (Web Profile Page + curl_cffi) | proxy=%s | mode=anonymous",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info(
            "InstagramChecker started (Web Profile Page HTML, curl_cffi, no API needed)"
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
          AVAILABLE — Username Instagramda mavjud emas (404 / Page Not Found).
          TAKEN     — Profil mavjud (HTTP 200 + profil sahifasi).
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
                result = await self._profile_page_check(clean)
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
    # Profile Page GET (curl_cffi, Chrome TLS, NO API)
    # ------------------------------------------------------------------

    async def _profile_page_check(
        self, username: str
    ) -> CheckResult:
        """
        GET https://www.instagram.com/{username}/
        via curl_cffi (Chrome TLS fingerprint).

        Klassifikatsiya (HTML asosida):
          HTTP 200 + og:title yoki title ichida username → TAKEN
          HTTP 200 + "Page Not Found" / "Isn't Available" → AVAILABLE
          HTTP 404                                        → AVAILABLE
          HTTP 302 (login redirect) / 429                 → ERROR
        """
        url = _PROFILE_URL_TPL.format(username)

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _PAGE_TIMEOUT,
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
                        headers=_BROWSER_HEADERS,
                        allow_redirects=False,
                    )
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
                    "[@%s] Profile page xato (barcha urinishlar): %s",
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
                    "[@%s] Profile page kutilmagan (barcha): %s",
                    username, exc,
                )
                return CheckResult(username, CheckStatus.ERROR, detail)

        if resp is None:
            logger.warning(
                "[@%s] Profile page: barcha %d urinish xato",
                username, max_proxy_retries,
            )
            return CheckResult(
                username, CheckStatus.ERROR, "all_retries_failed"
            )

        sc = int(getattr(resp, "status_code", 0) or 0)

        # ── 429 → ERROR (rate limited) ─────────────────────────────
        if sc == 429:
            logger.warning("[@%s] Profile page 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "page_429")

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
                "[@%s] Profile page redirect (%d) -> %s",
                username, sc, location[:100],
            )
            return CheckResult(
                username, CheckStatus.ERROR, f"redirect_{sc}"
            )

        # ── 404 → AVAILABLE ────────────────────────────────────────
        if sc == 404:
            logger.info(
                "[@%s] AVAILABLE (HTTP 404 — page not found)", username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "not_found_404"
            )

        # ── HTML kontentni olish ───────────────────────────────────
        html = ""
        try:
            html = str(getattr(resp, "text", "") or "")
        except Exception:
            pass

        html_lower = html.lower()

        # ── Login sahifasiga yo'naltirilgan (HTML ichida) → ERROR ──
        if "/accounts/login/" in html_lower and len(html) < 5000:
            logger.warning(
                "[@%s] Profile page: login redirect (HTML ichida)", username,
            )
            return CheckResult(
                username, CheckStatus.ERROR, "login_page_html"
            )

        # ── <title> va og:title ni ajratib olish ──────────────────
        title_m = _TITLE_RE.search(html)
        title = (title_m.group(1).strip() if title_m else "").lower()

        og_title_m = _OG_TITLE_RE.search(html)
        og_title = (og_title_m.group(1).strip() if og_title_m else "").lower()

        og_desc_m = _OG_DESC_RE.search(html)
        og_desc = (og_desc_m.group(1).strip() if og_desc_m else "").lower()

        ul = username.lower()

        # ── HTTP 200: "Page Not Found" / "Isn't Available" → AVAILABLE
        if sc == 200:
            is_not_found = any(
                phrase in title or phrase in html_lower
                for phrase in _NOT_FOUND_PHRASES
            )
            if is_not_found:
                logger.info(
                    "[@%s] AVAILABLE (HTTP 200 but 'Page Not Found' in HTML) | title=%s",
                    username, title[:60],
                )
                return CheckResult(
                    username, CheckStatus.AVAILABLE, "page_not_found_200"
                )

        # ── HTTP 200: profil mavjud → TAKEN ────────────────────────
        if sc == 200:
            # og:title mavjudligi (Instagram faqat haqiqiy profillar uchun beradi)
            has_og_title = bool(og_title_m) and len(og_title) > 0

            # title ichida username yoki (@username) ko'rinishi
            has_username_in_title = (
                f"(@{ul})" in title
                or f"@{ul}" in title
                or ul in title
            )

            # og:description ichida followers/following/posts
            has_social_meta = any(
                w in og_desc for w in ("followers", "following", "posts")
            )

            if has_og_title or has_username_in_title or has_social_meta:
                logger.info(
                    "[@%s] TAKEN (profile_exists) | og_title=%s | title=%s",
                    username,
                    bool(og_title_m),
                    title[:60],
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "profile_exists"
                )

            # Username body ichida va sahifa yetarlicha katta → TAKEN
            if ul in html_lower and len(html) > 10000:
                logger.info(
                    "[@%s] TAKEN (username_in_body, html_len=%d)",
                    username, len(html),
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "profile_exists"
                )

            # 200 lekin hech qanday profil belgisi yo'q → AVAILABLE
            # (bo'sh/stub sahifa, username mavjud emas)
            logger.info(
                "[@%s] AVAILABLE (HTTP 200, no profile signals) | title=%s | html_len=%d",
                username, title[:60], len(html),
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "no_profile_signals_200"
            )

        # ── Boshqa status kodlar → ERROR ───────────────────────────
        logger.warning(
            "[@%s] Noaniq HTTP %d -> ERROR | title=%s | html_len=%d",
            username, sc, title[:60], len(html),
        )
        return CheckResult(
            username, CheckStatus.ERROR, f"unexpected_http_{sc}"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()