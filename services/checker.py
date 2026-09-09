"""Instagram username availability checker — Single GET (?__a=1&__d=dis).

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Single browser-like GET request:
             GET https://www.instagram.com/{username}/?__a=1&__d=dis
             via curl_cffi (Chrome TLS fingerprint).

             HTTP 404                              → AVAILABLE
             HTTP 200 + JSON user data             → TAKEN (active)
             HTTP 200 + HTML profil meta teglari   → TAKEN (active)
             HTTP 200 + bo'sh "Instagram" qobig'i  → TAKEN (banned/disabled)
             HTTP 302 / 429                        → ERROR (qayta urinish)

ANONIM REJIM: Hech qanday POST, session, CSRF, API key ishlatilmaydi.
Faqat bitta GET so'rov — brauzer kabi.
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

_PROFILE_URL_TPL = "https://www.instagram.com/{}/?__a=1&__d=dis"
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
    r'<meta\s+(?:property|name)="og:title"\s+content="([^"]*)"',
    re.IGNORECASE,
)
_OG_DESC_RE = re.compile(
    r'<meta\s+property="og:description"\s+content="([^"]*)"',
    re.IGNORECASE,
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
# Helpers
# ---------------------------------------------------------------------------

def _try_parse_json(resp: Any) -> dict[str, Any] | None:
    """Try to parse JSON from curl_cffi response. Returns None if not JSON."""
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


def _extract_user_from_json(data: dict[str, Any]) -> dict[str, Any] | None:
    """Extract user object from Instagram JSON response."""
    # Format 1: {"graphql": {"user": {...}}}
    graphql = data.get("graphql")
    if isinstance(graphql, dict):
        user = graphql.get("user")
        if isinstance(user, dict):
            return user

    # Format 2: {"data": {"user": {...}}}
    data_block = data.get("data")
    if isinstance(data_block, dict):
        user = data_block.get("user")
        if isinstance(user, dict):
            return user

    # Format 3: {"user": {...}} (to'g'ridan-to'g'ri)
    user = data.get("user")
    if isinstance(user, dict):
        return user

    return None


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Anonim Instagram username availability checker — Single GET.

    Faqat bitta GET so'rov: /{username}/?__a=1&__d=dis
    Hech qanday POST, session, CSRF, API key ishlatilmaydi.

    TEMIR QONUNLAR:
      404                            → AVAILABLE (haqiqiy bo'sh nom)
      200 + JSON/HTML profil data    → TAKEN (faol akkaunt)
      200 + bo'sh Instagram qobig'i → TAKEN (banned/disabled)
      302 / 429                      → ERROR (proksi IP cheklovi)
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()

        logger.info(
            "InstagramChecker ready (Single GET + curl_cffi) | proxy=%s",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started (Single GET, no POST)")

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
          AVAILABLE — 404 (haqiqiy bo'sh nom).
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
    # Single GET check — /{username}/?__a=1&__d=dis
    # ------------------------------------------------------------------

    async def _single_get_check(self, username: str) -> CheckResult:
        """
        GET https://www.instagram.com/{username}/?__a=1&__d=dis

        TEMIR QONUNLAR:
          404 → AVAILABLE
          200 + JSON user data → TAKEN (faol)
          200 + HTML profil meta → TAKEN (faol)
          200 + bo'sh qobiq (faqat "Instagram" title) → TAKEN (banned/disabled)
          302 / 429 → ERROR
        """
        url = _PROFILE_URL_TPL.format(username)

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _PAGE_TIMEOUT,
            "verify": False,
        }
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

        # ── 429 → ERROR ───────────────────────────────────────────
        if sc == 429:
            logger.warning("[@%s] 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "rate_limit_429")

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
                username, CheckStatus.ERROR, f"redirect_{sc}"
            )

        # ── 404 → AVAILABLE ───────────────────────────────────────
        if sc == 404:
            logger.info("[@%s] AVAILABLE (HTTP 404)", username)
            return CheckResult(
                username, CheckStatus.AVAILABLE, "not_found_404"
            )

        # ── 200: JSON yoki HTML tahlil ─────────────────────────────
        if sc == 200:
            return self._classify_200(username, resp)

        # ── Boshqa status kodlar → ERROR ───────────────────────────
        logger.warning("[@%s] Kutilmagan HTTP %d -> ERROR", username, sc)
        return CheckResult(
            username, CheckStatus.ERROR, f"unexpected_http_{sc}"
        )

    # ------------------------------------------------------------------
    # HTTP 200 klassifikatsiya
    # ------------------------------------------------------------------

    def _classify_200(self, username: str, resp: Any) -> CheckResult:
        """
        HTTP 200 javobni klassifikatsiya qilish.

        1) JSON + user data       → TAKEN (faol akkaunt)
        2) HTML + profil meta      → TAKEN (faol akkaunt)
        3) HTML + bo'sh qobiq      → TAKEN (banned/disabled)
        4) HTML + "Page Not Found" → AVAILABLE
        """
        ul = username.lower()

        # ── 1) JSON javobni tekshirish ─────────────────────────────
        json_data = _try_parse_json(resp)

        if json_data is not None:
            user = _extract_user_from_json(json_data)
            if user is not None:
                ig_user = user.get("username", "")
                logger.info(
                    "[@%s] TAKEN (JSON: user=%s)", username, ig_user,
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "profile_exists"
                )

            # JSON bor lekin user null/yo'q → banned/disabled
            # (Instagram ba'zan JSON qaytaradi lekin user: null)
            if "user" in str(json_data).lower():
                logger.info(
                    "[@%s] TAKEN (JSON: user key exists but null — banned/disabled)",
                    username,
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "account_disabled"
                )

        # ── 2) HTML javobni tekshirish ─────────────────────────────
        html = ""
        try:
            html = str(getattr(resp, "text", "") or "")
        except Exception:
            pass

        html_lower = html.lower()

        # Login page redirect (HTML ichida)
        if "/accounts/login/" in html_lower and len(html) < 5000:
            logger.warning("[@%s] Login sahifasi (HTML)", username)
            return CheckResult(
                username, CheckStatus.ERROR, "login_page_html"
            )

        # <title> ni olish
        title_m = _TITLE_RE.search(html)
        title = (title_m.group(1).strip() if title_m else "").lower()

        # og:title
        og_title_m = _OG_TITLE_RE.search(html)
        og_title = (og_title_m.group(1).strip() if og_title_m else "")

        # og:description
        og_desc_m = _OG_DESC_RE.search(html)
        og_desc = (og_desc_m.group(1).strip() if og_desc_m else "").lower()

        # ── "Page Not Found" → AVAILABLE ───────────────────────────
        not_found_phrases = (
            "page not found",
            "the link you followed may be broken",
        )
        if any(p in title for p in not_found_phrases):
            logger.info(
                "[@%s] AVAILABLE (HTTP 200 + 'Page Not Found' in title)",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "page_not_found_200"
            )

        # ── Profil signallari → TAKEN ──────────────────────────────
        # og:title bo'sh bo'lmasa (haqiqiy ism/nom bor)
        has_og_title = bool(og_title)

        # og:description ichida followers VA posts
        has_meta_stats = "followers" in og_desc and "posts" in og_desc

        # title ichida (@username)
        has_at_username = f"(@{ul})" in title

        # "photos and videos" — profil sahifasi belgisi
        has_photos_videos = "photos and videos" in html_lower

        if has_og_title or has_meta_stats or has_at_username or has_photos_videos:
            logger.info(
                "[@%s] TAKEN (profile_exists) | og_title=%s meta_stats=%s (@user)=%s photos=%s",
                username, bool(og_title), has_meta_stats,
                has_at_username, has_photos_videos,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "profile_exists"
            )

        # ── 200 + hech qanday profil belgisi yo'q ─────────────────
        # Title faqat "Instagram" yoki bo'sh → BAN / DEACTIVATED
        # Bu nom AVAILABLE EMAS — akkaunt disabled/banned!
        is_bare_shell = (
            title in ("instagram", "instagram • photos and videos", "")
            or (not has_og_title and not has_meta_stats)
        )

        if is_bare_shell:
            logger.info(
                "[@%s] TAKEN (account_disabled — 200 but bare shell) | title=%s",
                username, title[:60],
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "account_disabled"
            )

        # ── Fallback: noaniq 200 → TAKEN (xavfsiz tomondan) ───────
        logger.warning(
            "[@%s] TAKEN (200 noaniq — xavfsiz tomondan) | title=%s | html_len=%d",
            username, title[:60], len(html),
        )
        return CheckResult(
            username, CheckStatus.TAKEN, "ambiguous_200_safe"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()