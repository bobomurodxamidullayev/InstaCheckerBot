"""Instagram username availability checker — Hybrid Pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved-word pre-validation (no network).
  Tier 2  — Two-phase Instagram check:
             Phase A: Profile page GET (httpx, bot UA) — fast.
                      Detects existing profiles instantly as TAKEN.
             Phase B: Instagram Mobile API POST (curl_cffi, Chrome TLS).
                      ``i.instagram.com/api/v1/users/check_username/``
                      FAQAT ``available: true`` bo'lganda AVAILABLE.

Status Logic (QATIY):
  AVAILABLE — FAQAT API ``available: true`` qaytarganda.
  TAKEN     — Profile exists, available: false, status: fail, yoki
              boshqa har qanday Instagram rad javobi.
  ERROR     — Network/proxy/429/rate-limit/IP-block.
              HECH QACHON profil topilmaganiga qarab AVAILABLE deb belgilanmaydi!
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
from dataclasses import dataclass
from typing import Any, Optional

import httpx

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

# Phase A — Profile page
_PROFILE_URL_TPL = "https://www.instagram.com/{}/"
_PROFILE_TIMEOUT = 10.0

_BOT_USER_AGENT = "TelegramBot (like TwitterBot)"
_BOT_HEADERS: dict[str, str] = {
    "User-Agent": _BOT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Phase B — Instagram Mobile API (curl_cffi)
_CHECK_USERNAME_URL = "https://i.instagram.com/api/v1/users/check_username/"
_API_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"

_INSTAGRAM_ANDROID_UA = (
    "Instagram 300.0.0.29.110 Android (33/13; 420dpi; 1080x2400; "
    "Xiaomi; M2101K6G; sweet; qcom; en_US; 520287513)"
)
_IG_APP_ID = "936619743392459"

# Network exceptions
_HTTPX_NETWORK_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
    httpx.TimeoutException,
    ConnectionError,
    OSError,
)

_CURL_NETWORK_EXCEPTIONS = (
    CurlError,
    CurlRequestException,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
)

# ---------------------------------------------------------------------------
# Tier-1 pre-validation
# ---------------------------------------------------------------------------

_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")

_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
    "meta", "privacy", "terms", "settings", "profile",
})

# ---------------------------------------------------------------------------
# Profile page detection
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_OG_DESC_RE = re.compile(
    r'<meta\s+property="og:description"\s+content="(.*?)"',
    re.IGNORECASE,
)

_NOT_FOUND_TITLES = frozenset({
    "page not found",
    "page not found • instagram",
    "instagram",
    "sorry, this page isn't available.",
    "content unavailable",
})

# ---------------------------------------------------------------------------
# Infra block kodlari
# ---------------------------------------------------------------------------

_INFRA_ERROR_TYPES: frozenset[str] = frozenset({
    "checkpoint_required", "checkpoint_challenge_required",
    "spam", "rate_limit_error", "generic_request_error", "sentry_block",
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

def _safe_json(resp: Any) -> dict[str, Any] | None:
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
    Hybrid Instagram username availability checker.

    QATIY QOIDALAR:
      AVAILABLE — FAQAT API ``available: true`` qaytarganda.
      TAKEN     — Profil mavjud YOKI API rad etdi (har qanday sabab).
      ERROR     — Faqat infra muammo (network/proxy/429/rate-limit).
                  HECH QACHON profil topilmaganligi = AVAILABLE emas!
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()
        logger.info(
            "InstagramChecker ready | proxy=%s | pipeline=hybrid",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started")

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
          AVAILABLE — API tasdiqladi: hozir ro'yxatdan o'tsa bo'ladi.
          TAKEN     — Olib bo'lmaydi (har qanday sabab).
          ERROR     — Infra muammo (network/proxy/429).
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
                result = await self._tier2_hybrid_check(clean)
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
    # Tier 1
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
    # Tier 2 — Hybrid (Phase A -> Phase B, FALLBACK TAQIQLANADI)
    # ------------------------------------------------------------------

    async def _tier2_hybrid_check(self, username: str) -> CheckResult:
        """
        Phase A: profil sahifasi -> mavjud profil = TAKEN.
        Phase B: check_username API -> AVAILABLE/TAKEN/ERROR.

        FALLBACK TAQIQLANADI: Agar Phase B ishlamasa -> ERROR.
        HECH QACHON profil topilmadi = AVAILABLE emas!
        """
        phase_a = await self._phase_a_profile_check(username)
        if phase_a is not None:
            return phase_a

        # Phase A: profil topilmadi -> Phase B bilan TASDIQLASH SHART
        await asyncio.sleep(random.uniform(0.3, 1.0))
        return await self._phase_b_check_username(username)

    # ------------------------------------------------------------------
    # Phase A — Profile page (httpx, bot UA)
    # ------------------------------------------------------------------

    async def _phase_a_profile_check(
        self, username: str
    ) -> CheckResult | None:
        """
        GET /{username}/ with bot UA.
        Returns TAKEN if profile exists, None if not found, ERROR on infra.
        """
        url = _PROFILE_URL_TPL.format(username)
        try:
            kw: dict[str, Any] = {
                "timeout": _PROFILE_TIMEOUT,
                "follow_redirects": True,
                "http2": False,
            }
            if self._proxy:
                kw["proxy"] = self._proxy
            async with httpx.AsyncClient(**kw) as client:
                resp = await client.get(url, headers=_BOT_HEADERS)
        except _HTTPX_NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] Profile network xato: %s", username, exc)
            return CheckResult(
                username, CheckStatus.ERROR,
                f"profile_network_{type(exc).__name__}",
            )
        except Exception as exc:
            logger.warning("[@%s] Profile kutilmagan xato: %s", username, exc)
            return CheckResult(
                username, CheckStatus.ERROR,
                f"profile_unexpected_{type(exc).__name__}",
            )

        sc = resp.status_code
        if sc == 429:
            return CheckResult(username, CheckStatus.ERROR, "profile_429")

        html = resp.text or ""
        title_m = _TITLE_RE.search(html)
        title = (title_m.group(1).strip() if title_m else "").lower()

        og_m = _OG_DESC_RE.search(html)
        og = (og_m.group(1) if og_m else "").lower()

        ul = username.lower()

        # Profile exists?
        has_at = f"(@{ul})" in title
        has_social = any(w in og for w in ("followers", "following", "posts"))

        if has_at or has_social:
            logger.info("[@%s] TAKEN (profile_exists)", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        # Not found?
        not_found = (
            sc == 404
            or title in _NOT_FOUND_TITLES
            or "page not found" in title
            or "this page isn" in title
            or "content unavailable" in title
        )
        if not_found:
            logger.info("[@%s] Profil topilmadi -> Phase B SHART", username)
            return None  # Phase B MAJBURIY

        # Login page?
        if "login" in title:
            logger.info("[@%s] Login sahifasi -> Phase B SHART", username)
            return None

        # Username in body with substantial HTML?
        if ul in html.lower() and len(html) > 5000:
            logger.info("[@%s] TAKEN (username_in_body)", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        logger.info("[@%s] Noaniq -> Phase B SHART | title=%s", username, title[:50])
        return None

    # ------------------------------------------------------------------
    # Phase B — check_username POST (curl_cffi, Chrome TLS impersonation)
    # ------------------------------------------------------------------

    async def _phase_b_check_username(self, username: str) -> CheckResult:
        """
        POST to i.instagram.com/api/v1/users/check_username/

        QATIY QOIDALAR:
          available: true  -> AVAILABLE (yagona yo'l!)
          available: false -> TAKEN
          status: fail     -> TAKEN
          429 / network    -> ERROR (retry)
          Non-JSON         -> ERROR

        HECH QACHON fallback AVAILABLE yo'q!
        """
        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _API_TIMEOUT,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        try:
            async with AsyncSession(**session_kwargs) as session:
                resp = await session.post(
                    _CHECK_USERNAME_URL,
                    headers={
                        "User-Agent": _INSTAGRAM_ANDROID_UA,
                        "Content-Type": (
                            "application/x-www-form-urlencoded; charset=UTF-8"
                        ),
                        "Accept-Language": "en-US",
                        "X-IG-App-ID": _IG_APP_ID,
                    },
                    data={"username": username},
                )
        except _CURL_NETWORK_EXCEPTIONS as exc:
            detail = f"api_network_{type(exc).__name__}"
            logger.warning("[@%s] check_username xato: %s: %s", username, detail, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"api_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] check_username kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = int(getattr(resp, "status_code", 0) or 0)

        # 429 -> ERROR (retry)
        if sc == 429:
            logger.warning("[@%s] check_username 429", username)
            return CheckResult(username, CheckStatus.ERROR, "api_429")

        # JSON parse
        data = _safe_json(resp)

        if data is None:
            # Non-JSON -> ERROR (xatolik, AVAILABLE emas!)
            logger.warning(
                "[@%s] check_username non-JSON (HTTP %d) -> ERROR",
                username, sc,
            )
            return CheckResult(username, CheckStatus.ERROR, f"non_json_http_{sc}")

        # ── Infra block tekshiruvi ─────────────────────────────────────
        if data.get("status") == "fail":
            et = str(data.get("error_type", ""))
            if et in _INFRA_ERROR_TYPES:
                logger.warning("[@%s] IG block: %s", username, et)
                return CheckResult(username, CheckStatus.ERROR, f"ig_block_{et}")

        if data.get("checkpoint_url") or data.get("lock"):
            logger.warning("[@%s] Checkpoint detected", username)
            return CheckResult(username, CheckStatus.ERROR, "ig_block_checkpoint")

        # ── AVAILABLE: FAQAT available == True ─────────────────────────
        if data.get("available") is True:
            logger.info("[@%s] AVAILABLE (API tasdiqladi: available=true)", username)
            return CheckResult(username, CheckStatus.AVAILABLE, "truly_available")

        # ── TAKEN: available == False ──────────────────────────────────
        if data.get("available") is False:
            error_msg = str(data.get("error", data.get("error_type", "username_is_taken")))
            logger.info("[@%s] TAKEN (available=false, %s)", username, error_msg)
            return CheckResult(username, CheckStatus.TAKEN, error_msg)

        # ── TAKEN: status == fail (infra allaqachon filtrlangan) ───────
        if data.get("status") == "fail":
            error_type = str(data.get("error_type", "unknown"))
            message = str(data.get("message", ""))
            # Rate limit xabari?
            msg_lower = message.lower()
            if "wait" in msg_lower or "try again" in msg_lower:
                logger.warning("[@%s] check_username rate limit: %s", username, message[:60])
                return CheckResult(username, CheckStatus.ERROR, "api_rate_limit")
            logger.info("[@%s] TAKEN (status=fail, %s)", username, error_type)
            return CheckResult(username, CheckStatus.TAKEN, f"fail_{error_type}")

        # ── username_suggestions mavjud -> TAKEN ───────────────────────
        sug = data.get("username_suggestions")
        if isinstance(sug, list) and len(sug) > 0:
            logger.info("[@%s] TAKEN (suggestions mavjud)", username)
            return CheckResult(username, CheckStatus.TAKEN, "username_is_taken")

        # ── Noaniq javob -> ERROR (HECH QACHON AVAILABLE emas!) ───────
        logger.warning(
            "[@%s] Noaniq API javob -> ERROR | body=%s",
            username, str(data)[:150],
        )
        return CheckResult(username, CheckStatus.ERROR, "api_unknown_response")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()