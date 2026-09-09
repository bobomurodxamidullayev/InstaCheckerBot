"""Instagram username availability checker — Hybrid (Profile Page + check_username).

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Two-step hybrid check:
             Step 1 (Tezkor): GET https://www.instagram.com/{username}/
               Agar profil signallari (meta stats, profile title) bo'lsa
               → darhol TAKEN.
             Step 2 (Aniq): POST /api/v1/web/accounts/check_username/
               Faqat Step 1 da profil topilmasa ishga tushadi.
               BAN / DEACTIVATED nomlarni ham to'g'ri aniqlaydi.

ANONIM REJIM: Hech qanday Instagram akkaunt yoki session cookie talab etilmaydi.
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

_IMPERSONATE = "chrome124"
_PAGE_TIMEOUT = 12.0
_API_TIMEOUT = 12.0
_PROXY_RETRY_DELAY = 1.0

_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# Step 1 — Profile page
_PROFILE_URL_TPL = "https://www.instagram.com/{}/"

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

# Step 2 — check_username API
_CHECK_USERNAME_URL = "https://www.instagram.com/api/v1/web/accounts/check_username/"

_CHECK_USERNAME_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "X-CSRFToken": "missing",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Content-Type": "application/x-www-form-urlencoded",
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
_OG_DESC_RE = re.compile(
    r'<meta\s+property="og:description"\s+content="(.*?)"',
    re.IGNORECASE,
)

# "Page Not Found" / "Isn't Available" detection phrases
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


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Anonim Instagram username availability checker — Hybrid.

    2 bosqichli tekshiruv:
      Step 1: GET /{username}/ → profil signallari bo'lsa → darhol TAKEN.
      Step 2: POST check_username → aniq AVAILABLE / TAKEN (ban/deactivated ham).

    QOIDALAR:
      AVAILABLE — FAQAT check_username API ``available: true`` tasdiqladi.
      TAKEN     — Profil mavjud YOKI check_username ``username_is_taken``.
      ERROR     — Network/proxy/429/redirect infra muammo.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()

        logger.info(
            "InstagramChecker ready (Hybrid: Profile Page + check_username) | proxy=%s",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started (Hybrid mode)")

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
          AVAILABLE — check_username API tasdiqladi.
          TAKEN     — Profil mavjud yoki check_username rad etdi.
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
                result = await self._hybrid_check(clean)
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
    # Hybrid check: Step 1 -> Step 2
    # ------------------------------------------------------------------

    async def _hybrid_check(self, username: str) -> CheckResult:
        """
        Step 1: Profil sahifasi → TAKEN (agar profil signallari bo'lsa).
        Step 2: check_username API → AVAILABLE / TAKEN (ban/deactivated ham).
        """
        # Step 1 — tezkor profil sahifasi tekshiruvi
        step1 = await self._step1_profile_page(username)
        if step1 is not None:
            return step1

        # Step 1 profil topmadi → Step 2 ga o'tish
        await asyncio.sleep(random.uniform(0.3, 0.8))
        return await self._step2_check_username_api(username)

    # ------------------------------------------------------------------
    # Step 1 — Profile Page GET (tezkor, TAKEN aniqlash)
    # ------------------------------------------------------------------

    async def _step1_profile_page(
        self, username: str
    ) -> CheckResult | None:
        """
        GET https://www.instagram.com/{username}/

        Returns:
          CheckResult(TAKEN) — agar profil signallari topilsa.
          None               — agar profil topilmasa (Step 2 ga o'tish kerak).
          CheckResult(ERROR) — infra muammo (429/redirect/network).
        """
        url = _PROFILE_URL_TPL.format(username)

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _PAGE_TIMEOUT,
            "verify": False,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

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
                        "[@%s] Step1 proksi xato (%d/%d), %gs kutib qayta: %s",
                        username, proxy_attempt, max_proxy_retries,
                        _PROXY_RETRY_DELAY, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                logger.warning(
                    "[@%s] Step1 network xato (barcha urinishlar): %s",
                    username, exc,
                )
                return CheckResult(
                    username, CheckStatus.ERROR,
                    f"step1_network_{type(exc).__name__}",
                )

            except Exception as exc:
                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Step1 kutilmagan xato (%d/%d): %s",
                        username, proxy_attempt, max_proxy_retries, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                logger.warning(
                    "[@%s] Step1 kutilmagan (barcha): %s", username, exc,
                )
                return CheckResult(
                    username, CheckStatus.ERROR,
                    f"step1_unexpected_{type(exc).__name__}",
                )

        if resp is None:
            return CheckResult(
                username, CheckStatus.ERROR, "step1_all_retries_failed"
            )

        sc = int(getattr(resp, "status_code", 0) or 0)

        # 429 → ERROR
        if sc == 429:
            logger.warning("[@%s] Step1: 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "step1_429")

        # Redirect → ERROR
        if sc in (301, 302, 303, 307, 308):
            location = ""
            try:
                location = str(
                    getattr(resp, "headers", {}).get("location", "")
                )
            except Exception:
                pass
            logger.warning(
                "[@%s] Step1: redirect (%d) -> %s",
                username, sc, location[:100],
            )
            return CheckResult(
                username, CheckStatus.ERROR, f"step1_redirect_{sc}"
            )

        # 404 / non-200 → profil topilmadi → Step 2 ga
        if sc == 404:
            logger.info("[@%s] Step1: 404 -> Step 2 ga o'tish", username)
            return None

        # HTML kontentni tahlil qilish (faqat 200 uchun)
        html = ""
        try:
            html = str(getattr(resp, "text", "") or "")
        except Exception:
            pass

        html_lower = html.lower()

        # Login sahifasi → ERROR
        if "/accounts/login/" in html_lower and len(html) < 5000:
            logger.warning("[@%s] Step1: login sahifasi (HTML)", username)
            return CheckResult(
                username, CheckStatus.ERROR, "step1_login_page"
            )

        if sc == 200:
            title_m = _TITLE_RE.search(html)
            title = (title_m.group(1).strip() if title_m else "").lower()

            og_desc_m = _OG_DESC_RE.search(html)
            og_desc = (og_desc_m.group(1).strip() if og_desc_m else "").lower()

            ul = username.lower()

            # "Page Not Found" / "Isn't Available" → profil yo'q → Step 2
            is_not_found = any(
                phrase in title or phrase in html_lower
                for phrase in _NOT_FOUND_PHRASES
            )
            if is_not_found:
                logger.info(
                    "[@%s] Step1: 'Page Not Found' -> Step 2 ga o'tish",
                    username,
                )
                return None

            # Profil signallari: meta teglar bo'yicha TAKEN
            has_meta_stats = "followers" in og_desc and "posts" in og_desc
            has_profile_title = (
                "photos and videos" in html_lower
                or f"(@{ul})" in title
            )

            if has_meta_stats or has_profile_title:
                logger.info(
                    "[@%s] TAKEN (profile_exists) [Step 1] | meta=%s title=%s",
                    username, has_meta_stats, has_profile_title,
                )
                return CheckResult(
                    username, CheckStatus.TAKEN, "profile_exists"
                )

            # 200 lekin profil signallari yo'q → Step 2 ga
            logger.info(
                "[@%s] Step1: 200, no profile signals -> Step 2 ga o'tish | title=%s",
                username, title[:60],
            )
            return None

        # Boshqa status kodlar → Step 2 ga o'tish
        logger.info(
            "[@%s] Step1: HTTP %d (noaniq) -> Step 2 ga o'tish", username, sc,
        )
        return None

    # ------------------------------------------------------------------
    # Step 2 — check_username API (aniq AVAILABLE / TAKEN)
    # ------------------------------------------------------------------

    async def _step2_check_username_api(
        self, username: str
    ) -> CheckResult:
        """
        POST /api/v1/web/accounts/check_username/
        via curl_cffi (Chrome TLS fingerprint).

        BAN / DEACTIVATED nomlarni ham to'g'ri aniqlaydi:
          available: true                           → AVAILABLE
          status: fail / username_is_taken / errors → TAKEN
          429 / login redirect                      → ERROR
        """
        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _API_TIMEOUT,
            "verify": False,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        max_proxy_retries = 2
        resp = None

        for proxy_attempt in range(1, max_proxy_retries + 1):
            try:
                async with AsyncSession(**session_kwargs) as session:
                    resp = await session.post(
                        _CHECK_USERNAME_URL,
                        headers=_CHECK_USERNAME_HEADERS,
                        data=f"username={username}",
                    )
                break

            except _CURL_NETWORK_EXCEPTIONS as exc:
                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Step2 proksi xato (%d/%d), %gs kutib qayta: %s",
                        username, proxy_attempt, max_proxy_retries,
                        _PROXY_RETRY_DELAY, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                logger.warning(
                    "[@%s] Step2 network xato (barcha urinishlar): %s",
                    username, exc,
                )
                return CheckResult(
                    username, CheckStatus.ERROR,
                    f"step2_network_{type(exc).__name__}",
                )

            except Exception as exc:
                if proxy_attempt < max_proxy_retries:
                    logger.warning(
                        "[@%s] Step2 kutilmagan xato (%d/%d): %s",
                        username, proxy_attempt, max_proxy_retries, exc,
                    )
                    await asyncio.sleep(_PROXY_RETRY_DELAY)
                    continue
                logger.warning(
                    "[@%s] Step2 kutilmagan (barcha): %s", username, exc,
                )
                return CheckResult(
                    username, CheckStatus.ERROR,
                    f"step2_unexpected_{type(exc).__name__}",
                )

        if resp is None:
            return CheckResult(
                username, CheckStatus.ERROR, "step2_all_retries_failed"
            )

        sc = int(getattr(resp, "status_code", 0) or 0)

        # 429 → ERROR
        if sc == 429:
            logger.warning("[@%s] Step2: 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "step2_429")

        # Redirect → ERROR
        if sc in (301, 302, 303, 307, 308):
            location = ""
            try:
                location = str(
                    getattr(resp, "headers", {}).get("location", "")
                )
            except Exception:
                pass
            logger.warning(
                "[@%s] Step2: redirect (%d) -> %s",
                username, sc, location[:100],
            )
            return CheckResult(
                username, CheckStatus.ERROR, f"step2_redirect_{sc}"
            )

        # JSON parse
        data = _safe_json_curl(resp)

        if data is None:
            body_preview = ""
            try:
                body_preview = (resp.text or "")[:200]
            except Exception:
                pass
            logger.warning(
                "[@%s] Step2: non-JSON (HTTP %d) | body=%s",
                username, sc, body_preview,
            )
            # Login sahifasi HTML bo'lishi mumkin
            if body_preview and (
                "/accounts/login/" in body_preview.lower()
                or "login" in body_preview.lower()
            ):
                return CheckResult(
                    username, CheckStatus.ERROR, "step2_login_page"
                )
            return CheckResult(
                username, CheckStatus.ERROR, f"step2_non_json_{sc}"
            )

        logger.debug(
            "[@%s] Step2 response: HTTP %d | %s",
            username, sc, json.dumps(data, ensure_ascii=False)[:300],
        )

        # ── AVAILABLE: status=ok va available=true ─────────────────
        if data.get("status") == "ok" and data.get("available") is True:
            logger.info(
                "[@%s] AVAILABLE (check_username: available=true) [Step 2]",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )

        # ── TAKEN: username_is_taken error_type ────────────────────
        error_type = str(data.get("error_type", ""))
        if error_type == "username_is_taken":
            logger.info(
                "[@%s] TAKEN (check_username: username_is_taken) [Step 2]",
                username,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "username_is_taken"
            )

        # ── TAKEN: errors.username mavjud ──────────────────────────
        errors = data.get("errors", {})
        if isinstance(errors, dict) and errors.get("username"):
            username_errors = errors["username"]
            if isinstance(username_errors, list):
                err_detail = "; ".join(
                    e.get("message", str(e)) if isinstance(e, dict) else str(e)
                    for e in username_errors
                )
            else:
                err_detail = str(username_errors)
            logger.info(
                "[@%s] TAKEN (check_username: errors.username=%s) [Step 2]",
                username, err_detail[:100],
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "username_is_taken"
            )

        # ── TAKEN: status=fail (boshqa sabablar) ──────────────────
        if data.get("status") == "fail":
            message = str(data.get("message", ""))
            msg_lower = message.lower()

            # Rate limit
            if any(w in msg_lower for w in ("wait", "try again", "rate")):
                logger.warning(
                    "[@%s] Step2 rate limit: %s", username, message[:80],
                )
                return CheckResult(
                    username, CheckStatus.ERROR, "step2_rate_limit"
                )

            # Checkpoint / spam / IP block → ERROR
            if error_type in (
                "checkpoint_required", "checkpoint_challenge_required",
                "spam", "rate_limit_error", "sentry_block",
                "generic_request_error", "ip_block",
            ):
                logger.warning(
                    "[@%s] Step2 infra block: %s", username, error_type,
                )
                return CheckResult(
                    username, CheckStatus.ERROR, f"step2_block_{error_type}"
                )

            # Boshqa fail → TAKEN (username band)
            logger.info(
                "[@%s] TAKEN (check_username: status=fail, %s) [Step 2]",
                username, error_type or "unknown",
            )
            return CheckResult(
                username, CheckStatus.TAKEN, f"taken_fail_{error_type or 'unknown'}"
            )

        # ── TAKEN: available=false (aniq) ──────────────────────────
        if data.get("available") is False:
            logger.info(
                "[@%s] TAKEN (check_username: available=false) [Step 2]",
                username,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, "username_is_taken"
            )

        # ── Noaniq → ERROR (HECH QACHON fallback AVAILABLE emas!) ─
        logger.warning(
            "[@%s] Step2: noaniq javob -> ERROR | HTTP %d | body=%s",
            username, sc, str(data)[:200],
        )
        return CheckResult(
            username, CheckStatus.ERROR, f"step2_unknown_{sc}"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()