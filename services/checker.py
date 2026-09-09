"""Instagram username availability checker — Authenticated Session Pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Three-phase Instagram check:
             Phase A: Profile page GET (httpx, bot UA) — fast.
                      Detects existing profiles instantly as TAKEN.
             Phase B: Authenticated web_profile_info GET (curl_cffi + session cookie).
                      Confirms user existence in Instagram DB.
             Phase C: Authenticated check_username POST (curl_cffi + session cookie).
                      FAQAT ``available: true`` = AVAILABLE. Boshqa hamma narsa TAKEN.

QATIY QOIDALAR:
  AVAILABLE — FAQAT Phase C ``available: true`` qaytarganda.
  TAKEN     — Profil mavjud, banned, deactivated, cooldown, spam — barchasi TAKEN.
  ERROR     — Faqat infra muammo (network/proxy/429/checkpoint).
  FALLBACK TAQIQLANADI — "profil topilmadi" hech qachon AVAILABLE emas!
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
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

# Phase A — Profile page (public, no auth)
_PROFILE_URL_TPL = "https://www.instagram.com/{}/"
_PROFILE_TIMEOUT = 10.0

_BOT_USER_AGENT = "TelegramBot (like TwitterBot)"
_BOT_HEADERS: dict[str, str] = {
    "User-Agent": _BOT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

# Phase B & C — Authenticated API (curl_cffi + session)
_WEB_PROFILE_URL_TPL = (
    "https://www.instagram.com/api/v1/users/web_profile_info/?username={}"
)
_CHECK_USERNAME_URL = (
    "https://www.instagram.com/api/v1/users/check_username/"
)
_API_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"

_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_IG_APP_ID = "936619743392459"

# Network exceptions
_HTTPX_NETWORK_EXCEPTIONS = (
    httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
    httpx.WriteTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError,
    httpx.TimeoutException, ConnectionError, OSError,
)

_CURL_NETWORK_EXCEPTIONS = (
    CurlError, CurlRequestException, TimeoutError,
    asyncio.TimeoutError, ConnectionError, OSError,
)

# Tier-1 pre-validation
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
    "meta", "privacy", "terms", "settings", "profile",
})

# Profile page detection
_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_OG_DESC_RE = re.compile(
    r'<meta\s+property="og:description"\s+content="(.*?)"',
    re.IGNORECASE,
)
_NOT_FOUND_TITLES = frozenset({
    "page not found", "page not found • instagram", "instagram",
    "sorry, this page isn't available.", "content unavailable",
})

# Infra block kodlari
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
    """Safely parse JSON dict from response."""
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
    Authenticated Instagram username availability checker.

    QATIY QOIDALAR:
      AVAILABLE — FAQAT check_username ``available: true`` qaytarganda.
      TAKEN     — Profil mavjud, banned, deactivated, cooldown, spam.
      ERROR     — Network/proxy/429/checkpoint infra muammo.
      FALLBACK TAQIQLANADI — "profil topilmadi" != AVAILABLE!
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()

        # Session cookie'larni yuklash
        self._session_id = settings.ig_session_id
        self._ds_user_id = settings.ig_ds_user_id
        self._csrf_token = settings.ig_csrf_token
        self._mid = settings.ig_mid
        self._ig_did = settings.ig_did

        has_session = bool(self._session_id and self._csrf_token)
        logger.info(
            "InstagramChecker ready | proxy=%s | session=%s",
            bool(self._proxy), has_session,
        )

    # ------------------------------------------------------------------
    # Session cookie string
    # ------------------------------------------------------------------

    def _cookie_header(self) -> str:
        """Instagram session cookie'larini bitta Cookie header qilib beradi."""
        parts = [
            f"sessionid={self._session_id}",
            f"ds_user_id={self._ds_user_id}",
            f"csrftoken={self._csrf_token}",
        ]
        if self._mid:
            parts.append(f"mid={self._mid}")
        if self._ig_did:
            parts.append(f"ig_did={self._ig_did}")
        return "; ".join(parts)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        has_session = bool(self._session_id and self._csrf_token)
        if not has_session:
            logger.warning(
                "Instagram session cookie'lar sozlanmagan! "
                ".env ga IG_SESSION_ID va IG_CSRF_TOKEN qo'shing."
            )
        logger.info(
            "InstagramChecker started (authenticated=%s)", has_session,
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
          AVAILABLE — API ``available: true`` tasdiqladi.
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
                result = await self._tier2_check(clean)
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
    # Tier 2 — Phase A -> Phase B -> Phase C
    # ------------------------------------------------------------------

    async def _tier2_check(self, username: str) -> CheckResult:
        """
        Phase A: Profil sahifasi -> TAKEN (agar profil mavjud).
        Phase B: web_profile_info (authenticated) -> TAKEN (agar user mavjud).
        Phase C: check_username (authenticated) -> AVAILABLE / TAKEN.

        Phase B 429/ERROR bo'lsa -> Phase C ga o'tadi (to'xtamaydi!).
        HECH QACHON fallback AVAILABLE yo'q!
        """
        # Phase A — profil sahifasi
        phase_a = await self._phase_a_profile_check(username)
        if phase_a is not None:
            return phase_a

        # Phase A: profil topilmadi -> Phase B: authenticated API
        await asyncio.sleep(random.uniform(0.3, 0.8))
        phase_b = await self._phase_b_web_profile_info(username)
        if phase_b is not None:
            # Phase B aniq javob (TAKEN/AVAILABLE) berdi -> ishlatamiz
            if phase_b.status != CheckStatus.ERROR:
                return phase_b
            # Phase B ERROR (429/network) -> Phase C ga o'tamiz
            logger.info(
                "[@%s] Phase B xato (%s) -> Phase C ga o'tilmoqda",
                username, phase_b.error_message,
            )

        # Phase C: check_username (YAKUNIY QAROR)
        await asyncio.sleep(random.uniform(0.3, 0.8))
        return await self._phase_c_check_username(username)

    # ------------------------------------------------------------------
    # Phase A — Profile page (httpx, bot UA, NO AUTH)
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
            logger.info("[@%s] TAKEN (profile_exists) [Phase A]", username)
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
            logger.info("[@%s] Profil topilmadi -> Phase B", username)
            return None

        # Login page?
        if "login" in title:
            logger.info("[@%s] Login sahifasi -> Phase B", username)
            return None

        # Username in body with substantial HTML?
        if ul in html.lower() and len(html) > 5000:
            logger.info("[@%s] TAKEN (username_in_body) [Phase A]", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        logger.info("[@%s] Noaniq -> Phase B | title=%s", username, title[:50])
        return None

    # ------------------------------------------------------------------
    # Phase B — web_profile_info (curl_cffi, AUTHENTICATED)
    # ------------------------------------------------------------------

    async def _phase_b_web_profile_info(
        self, username: str
    ) -> CheckResult | None:
        """
        GET web_profile_info bilan Instagram DB dan user tekshirish.
        Session cookie bilan autentifikatsiya.

        Returns:
          TAKEN     — agar user.data mavjud (profil DB da bor).
          None      — agar user null (profil DB da yo'q) -> Phase C ga o'tish.
          ERROR     — agar network/429/checkpoint.
        """
        url = _WEB_PROFILE_URL_TPL.format(username)

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _API_TIMEOUT,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        headers = {
            "User-Agent": _CHROME_USER_AGENT,
            "X-IG-App-ID": _IG_APP_ID,
            "X-CSRFToken": self._csrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": f"https://www.instagram.com/{username}/",
            "Cookie": self._cookie_header(),
        }

        try:
            async with AsyncSession(**session_kwargs) as session:
                resp = await session.get(url, headers=headers)
        except _CURL_NETWORK_EXCEPTIONS as exc:
            detail = f"wpi_network_{type(exc).__name__}"
            logger.warning("[@%s] web_profile_info xato: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"wpi_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] web_profile_info kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = int(getattr(resp, "status_code", 0) or 0)

        if sc == 429:
            logger.warning("[@%s] web_profile_info 429", username)
            return CheckResult(username, CheckStatus.ERROR, "wpi_429")

        # 404 -> user DB da yo'q -> Phase C ga o'tish
        if sc == 404:
            logger.info("[@%s] web_profile_info 404 -> Phase C", username)
            return None

        data = _safe_json(resp)
        if data is None:
            logger.warning("[@%s] web_profile_info non-JSON (HTTP %d)", username, sc)
            return CheckResult(username, CheckStatus.ERROR, f"wpi_non_json_{sc}")

        # Checkpoint / infra block?
        infra = self._check_infra_block(username, data, "wpi")
        if infra is not None:
            return infra

        # User data mavjud?
        user_data = None
        if isinstance(data.get("data"), dict):
            user_data = data["data"].get("user")
        elif "user" in data:
            user_data = data.get("user")

        if user_data and isinstance(user_data, dict):
            logger.info("[@%s] TAKEN (user found in DB) [Phase B]", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        # User null -> profil DB da yo'q -> Phase C ga o'tish
        if user_data is None and data.get("status") == "ok":
            logger.info("[@%s] User null -> Phase C (check_username)", username)
            return None

        # status: fail
        if data.get("status") == "fail":
            msg = str(data.get("message", ""))
            msg_lower = msg.lower()
            # Rate limit?
            if "wait" in msg_lower or "try again" in msg_lower:
                logger.warning("[@%s] web_profile_info rate limit: %s", username, msg[:60])
                return CheckResult(username, CheckStatus.ERROR, "wpi_rate_limit")
            # Boshqa fail -> user topilmadi -> Phase C
            logger.info("[@%s] web_profile_info fail -> Phase C | %s", username, msg[:60])
            return None

        # Noaniq -> Phase C
        logger.info("[@%s] web_profile_info noaniq -> Phase C", username)
        return None

    # ------------------------------------------------------------------
    # Phase C — check_username (curl_cffi, AUTHENTICATED)
    # ------------------------------------------------------------------

    async def _phase_c_check_username(self, username: str) -> CheckResult:
        """
        POST check_username bilan username ro'yxatdan o'tish mumkinligini tekshirish.
        Session cookie bilan autentifikatsiya.

        QATIY:
          available: true  -> AVAILABLE (YAGONA yo'l!)
          available: false -> TAKEN
          status: fail     -> TAKEN (banned/deleted/cooldown/spam)
          429 / network    -> ERROR
          HECH QACHON fallback AVAILABLE yo'q!
        """
        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _API_TIMEOUT,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        headers = {
            "User-Agent": _CHROME_USER_AGENT,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "X-IG-App-ID": _IG_APP_ID,
            "X-CSRFToken": self._csrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://www.instagram.com/",
            "Cookie": self._cookie_header(),
        }

        try:
            async with AsyncSession(**session_kwargs) as session:
                resp = await session.post(
                    _CHECK_USERNAME_URL,
                    headers=headers,
                    data={"username": username},
                )
        except _CURL_NETWORK_EXCEPTIONS as exc:
            detail = f"cu_network_{type(exc).__name__}"
            logger.warning("[@%s] check_username xato: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"cu_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] check_username kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = int(getattr(resp, "status_code", 0) or 0)

        # 429 -> ERROR
        if sc == 429:
            logger.warning("[@%s] check_username 429", username)
            return CheckResult(username, CheckStatus.ERROR, "cu_429")

        data = _safe_json(resp)
        if data is None:
            logger.warning("[@%s] check_username non-JSON (HTTP %d)", username, sc)
            return CheckResult(username, CheckStatus.ERROR, f"cu_non_json_{sc}")

        # Infra block?
        infra = self._check_infra_block(username, data, "cu")
        if infra is not None:
            return infra

        # ── AVAILABLE: FAQAT available == True ─────────────────────
        if data.get("available") is True:
            logger.info("[@%s] AVAILABLE (check_username: available=true)", username)
            return CheckResult(username, CheckStatus.AVAILABLE, "truly_available")

        # ── TAKEN: available == False ──────────────────────────────
        if data.get("available") is False:
            error_msg = str(
                data.get("error", data.get("error_type", "username_is_taken"))
            )
            logger.info("[@%s] TAKEN (available=false, %s) [Phase C]", username, error_msg)
            return CheckResult(username, CheckStatus.TAKEN, error_msg)

        # ── TAKEN / ERROR: status == fail ──────────────────────────
        if data.get("status") == "fail":
            error_type = str(data.get("error_type", "unknown"))
            message = str(data.get("message", ""))
            msg_lower = message.lower()
            # Rate limit?
            if "wait" in msg_lower or "try again" in msg_lower:
                logger.warning("[@%s] check_username rate limit: %s", username, message[:60])
                return CheckResult(username, CheckStatus.ERROR, "cu_rate_limit")
            # Boshqa fail -> TAKEN (banned/deleted/cooldown)
            logger.info("[@%s] TAKEN (status=fail, %s) [Phase C]", username, error_type)
            return CheckResult(username, CheckStatus.TAKEN, f"fail_{error_type}")

        # ── username_suggestions -> TAKEN ──────────────────────────
        sug = data.get("username_suggestions")
        if isinstance(sug, list) and len(sug) > 0:
            logger.info("[@%s] TAKEN (suggestions) [Phase C]", username)
            return CheckResult(username, CheckStatus.TAKEN, "username_is_taken")

        # ── Noaniq -> ERROR (HECH QACHON AVAILABLE emas!) ─────────
        logger.warning(
            "[@%s] Noaniq API javob -> ERROR | body=%s",
            username, str(data)[:150],
        )
        return CheckResult(username, CheckStatus.ERROR, "cu_unknown_response")

    # ------------------------------------------------------------------
    # Infra block detection
    # ------------------------------------------------------------------

    def _check_infra_block(
        self, username: str, data: dict[str, Any], prefix: str
    ) -> CheckResult | None:
        """checkpoint/spam/sentry_block/feedback_required -> ERROR."""
        # Spam / feedback_required (akkount vaqtincha bloklangan)
        if data.get("spam") is True or data.get("message") == "feedback_required":
            msg = str(data.get("feedback_message", data.get("message", "spam")))
            logger.warning(
                "[@%s] SPAM/FEEDBACK block: %s", username, msg[:80],
            )
            return CheckResult(username, CheckStatus.ERROR, f"{prefix}_spam_block")

        if data.get("status") == "fail":
            et = str(data.get("error_type", ""))
            if et in _INFRA_ERROR_TYPES:
                logger.warning("[@%s] IG block: %s", username, et)
                return CheckResult(username, CheckStatus.ERROR, f"{prefix}_block_{et}")
        if data.get("checkpoint_url") or data.get("lock"):
            logger.warning("[@%s] Checkpoint detected", username)
            return CheckResult(username, CheckStatus.ERROR, f"{prefix}_checkpoint")
        return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()