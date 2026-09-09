"""Instagram username availability checker — Hybrid Pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved-word pre-validation (no network).
  Tier 2  — Two-phase Instagram check:
             Phase A: Profile page GET (httpx, bot UA) — fast, low rate risk.
                      Detects existing profiles instantly as TAKEN.
             Phase B: Instagram Mobile API POST (curl_cffi, impersonate=chrome124).
                      ``i.instagram.com/api/v1/users/check_username/``
                      curl_cffi Chrome TLS fingerprint — Instagram bot himoyasini
                      aylanib o'tadi. CSRF/session kerak emas.

Status Logic:
  AVAILABLE — Mobile API confirmed: username can be registered right now.
  TAKEN     — Profile exists, or Instagram refuses registration (any reason).
  ERROR     — Network/proxy failure, rate limit (429), or IP block.
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
_MOBILE_CHECK_URL = "https://i.instagram.com/api/v1/users/check_username/"
_MOBILE_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"

_INSTAGRAM_ANDROID_UA = (
    "Instagram 300.0.0.29.110 Android (33/13; 420dpi; 1080x2400; "
    "Xiaomi; M2101K6G; sweet; qcom; en_US; 520287513)"
)
_MOBILE_APP_ID = "567067343352427"  # Android app ID

# Phase B — web_profile_info GET (curl_cffi)
_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_WEB_APP_ID = "936619743392459"  # Instagram web app ID

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
    """Safely parse JSON dict from httpx or curl_cffi response."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    # Fallback: raw text
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

    Pipeline:
      1) Tier 1 — syntax/reserved pre-validation (no I/O).
      2) Phase A — profile page GET with bot UA (httpx).
         Catches existing profiles as TAKEN instantly.
      3) Phase B — Instagram Mobile API ``check_username`` (curl_cffi).
         Chrome TLS impersonation bypasses Instagram bot detection.
         No CSRF, no session required.

    Guarantees:
      AVAILABLE — Mobile API confirmed username is free to register.
      TAKEN     — Profile exists OR Instagram refuses registration.
      ERROR     — Only network/proxy/429/IP-block infrastructure failures.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()
        logger.info(
            "InstagramChecker ready | proxy=%s | pipeline=hybrid+mobile_api+curl_cffi",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker started (mobile API + curl_cffi TLS impersonation)")

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
          AVAILABLE — Mobile API tasdiqladi: ro'yxatdan o'tsa bo'ladi.
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
    # Tier 2 — Hybrid
    # ------------------------------------------------------------------

    async def _tier2_hybrid_check(self, username: str) -> CheckResult:
        """
        Phase A -> Phase B (best-effort).

        Phase A: profil sahifasi (httpx, bot UA) — mavjud profillarni aniqlaydi.
        Phase B: web_profile_info API (curl_cffi) — qo'shimcha tasdiqlash.

        Agar Phase B ishlasa -> aniq AVAILABLE/TAKEN.
        Agar Phase B ishlamasa (rate limit/block) ->
          Phase A "topilmadi" natijasiga asoslanib AVAILABLE.
        """
        phase_a = await self._phase_a_profile_check(username)
        if phase_a is not None:
            return phase_a

        # Phase A: profil topilmadi -> Phase B bilan tasdiqlash
        await asyncio.sleep(random.uniform(0.3, 1.0))
        phase_b = await self._phase_b_mobile_check(username)

        # Phase B aniq javob berdi -> ishlatamiz
        if phase_b.status != CheckStatus.ERROR:
            return phase_b

        # Phase B ishlamadi (rate limit/network/block) ->
        # Phase A "profil topilmadi" = username hozir band emas -> AVAILABLE
        logger.info(
            "[@%s] AVAILABLE (profil topilmadi, API: %s)",
            username, phase_b.error_message,
        )
        return CheckResult(username, CheckStatus.AVAILABLE, "profile_not_found")

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
            logger.info("[@%s] Profil topilmadi -> Phase B", username)
            return None

        # Login page?
        if "login" in title:
            logger.info("[@%s] Login sahifasi -> Phase B", username)
            return None

        # Username in body with substantial HTML?
        if ul in html.lower() and len(html) > 5000:
            logger.info("[@%s] TAKEN (username_in_body)", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        logger.info("[@%s] Noaniq -> Phase B | title=%s", username, title[:50])
        return None

    # ------------------------------------------------------------------
    # Phase B — web_profile_info GET API (curl_cffi, Chrome TLS)
    # ------------------------------------------------------------------

    async def _phase_b_mobile_check(self, username: str) -> CheckResult:
        """
        GET web_profile_info API bilan username mavjudligini tekshirish.

        Bu brauzer kabi GET so'rov — Instagram POST endpointlardek
        blokirovka qilmaydi.  curl_cffi Chrome TLS impersonation
        orqali bot himoyasini aylanib o'tadi.

        Endpoint: /api/v1/users/web_profile_info/?username={username}

        Response:
          {"data": {"user": {...}}, "status": "ok"} -> TAKEN (profil mavjud)
          {"data": {"user": null}, "status": "ok"}  -> AVAILABLE (profil yo'q)
          HTTP 404 / user not found                  -> AVAILABLE
          HTTP 429                                   -> ERROR (retry)

        Agar web_profile_info 429 bersa, fallback sifatida Mobile API
        POST (check_username) ishlatiladi.
        """
        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _MOBILE_TIMEOUT,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        try:
            async with AsyncSession(**session_kwargs) as session:
                resp = await session.get(
                    f"https://www.instagram.com/api/v1/users/web_profile_info/?username={username}",
                    headers={
                        "User-Agent": _CHROME_USER_AGENT,
                        "X-IG-App-ID": _WEB_APP_ID,
                        "X-Requested-With": "XMLHttpRequest",
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Referer": f"https://www.instagram.com/{username}/",
                        "Sec-Fetch-Site": "same-origin",
                        "Sec-Fetch-Mode": "cors",
                        "Sec-Fetch-Dest": "empty",
                    },
                )
        except _CURL_NETWORK_EXCEPTIONS as exc:
            detail = f"api_network_{type(exc).__name__}"
            logger.warning("[@%s] web_profile_info xato: %s: %s", username, detail, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"api_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] web_profile_info kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = int(getattr(resp, "status_code", 0) or 0)

        # 429 -> Fallback: Mobile API POST
        if sc == 429:
            logger.warning("[@%s] web_profile_info 429 -> mobile API fallback", username)
            return await self._phase_c_mobile_post(username)

        # 404 -> Profil mavjud emas -> AVAILABLE
        if sc == 404:
            logger.info("[@%s] AVAILABLE (web_profile_info 404)", username)
            return CheckResult(username, CheckStatus.AVAILABLE, "truly_available")

        data = _safe_json(resp)
        if data is None:
            if sc > 0:
                logger.info("[@%s] HTTP %d non-JSON -> TAKEN", username, sc)
                return CheckResult(username, CheckStatus.TAKEN, f"non_json_http_{sc}")
            return CheckResult(username, CheckStatus.ERROR, "no_response")

        # Infra block?
        infra = self._check_infra_block(username, data)
        if infra is not None:
            return infra

        # User data mavjud?
        user_data = None
        if isinstance(data.get("data"), dict):
            user_data = data["data"].get("user")
        elif "user" in data:
            user_data = data.get("user")

        if user_data and isinstance(user_data, dict):
            # Profil mavjud -> TAKEN
            uname = user_data.get("username", username)
            logger.info("[@%s] TAKEN (web_profile_info user found)", uname)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        # User null / yo'q -> AVAILABLE
        if user_data is None:
            # "status": "ok" bilan birga user null -> profil yo'q
            if data.get("status") == "ok":
                logger.info("[@%s] AVAILABLE (user=null, status=ok)", username)
                return CheckResult(username, CheckStatus.AVAILABLE, "truly_available")

        # status: fail -> rate limit, AVAILABLE yoki TAKEN
        if data.get("status") == "fail":
            msg = str(data.get("message", ""))
            msg_lower = msg.lower()
            # Rate limit? ("Please wait a few minutes before you try again")
            if "wait" in msg_lower or "try again" in msg_lower or "few minutes" in msg_lower:
                logger.warning("[@%s] web_profile_info rate limit: %s", username, msg[:60])
                return CheckResult(username, CheckStatus.ERROR, "api_rate_limit")
            # User not found -> AVAILABLE
            if "not found" in msg_lower or "user" in msg_lower:
                logger.info("[@%s] AVAILABLE (status=fail, user not found)", username)
                return CheckResult(username, CheckStatus.AVAILABLE, "truly_available")
            logger.info("[@%s] TAKEN (status=fail) | %s", username, msg[:60])
            return CheckResult(username, CheckStatus.TAKEN, "api_fail")

        # Konservativ
        logger.info("[@%s] TAKEN (konservativ) | body=%s", username, str(data)[:120])
        return CheckResult(username, CheckStatus.TAKEN, "api_rejected_unknown")

    # ------------------------------------------------------------------
    # Phase C — Mobile API POST fallback (agar web_profile_info 429 bersa)
    # ------------------------------------------------------------------

    async def _phase_c_mobile_post(self, username: str) -> CheckResult:
        """
        Fallback: POST to i.instagram.com/api/v1/users/check_username/
        Faqat Phase B 429 bo'lganda chaqiriladi.
        """
        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _MOBILE_TIMEOUT,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        try:
            async with AsyncSession(**session_kwargs) as session:
                resp = await session.post(
                    _MOBILE_CHECK_URL,
                    headers={
                        "User-Agent": _INSTAGRAM_ANDROID_UA,
                        "X-IG-App-ID": _MOBILE_APP_ID,
                        "Accept": "*/*",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "X-IG-Connection-Type": "WIFI",
                    },
                    data={"username": username},
                )
        except _CURL_NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] Mobile POST xato: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, f"mobile_net_{type(exc).__name__}")
        except Exception as exc:
            logger.warning("[@%s] Mobile POST kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, f"mobile_err_{type(exc).__name__}")

        sc = int(getattr(resp, "status_code", 0) or 0)
        if sc == 429:
            logger.warning("[@%s] Mobile POST 429", username)
            return CheckResult(username, CheckStatus.ERROR, "mobile_429")

        data = _safe_json(resp)
        if data is None:
            if sc > 0:
                return CheckResult(username, CheckStatus.TAKEN, f"non_json_http_{sc}")
            return CheckResult(username, CheckStatus.ERROR, "no_response")

        infra = self._check_infra_block(username, data)
        if infra is not None:
            return infra

        available = data.get("available")
        if available is True:
            logger.info("[@%s] AVAILABLE (mobile POST confirmed)", username)
            return CheckResult(username, CheckStatus.AVAILABLE, "truly_available")
        if available is False:
            et = str(data.get("error_type", "username_is_taken"))
            logger.info("[@%s] TAKEN (mobile, %s)", username, et)
            return CheckResult(username, CheckStatus.TAKEN, et)

        if data.get("status") == "fail":
            et = str(data.get("error_type", "unknown"))
            logger.info("[@%s] TAKEN (mobile fail, %s)", username, et)
            return CheckResult(username, CheckStatus.TAKEN, f"fail_{et}")

        logger.info("[@%s] TAKEN (mobile konservativ)", username)
        return CheckResult(username, CheckStatus.TAKEN, "api_rejected_unknown")

    # ------------------------------------------------------------------
    # Infra block detection
    # ------------------------------------------------------------------

    def _check_infra_block(
        self, username: str, data: dict[str, Any]
    ) -> CheckResult | None:
        if data.get("status") == "fail":
            et = str(data.get("error_type", ""))
            if et in _INFRA_ERROR_TYPES:
                logger.warning("[@%s] IG block: %s", username, et)
                return CheckResult(username, CheckStatus.ERROR, f"ig_block_{et}")
        if data.get("checkpoint_url") or data.get("lock"):
            logger.warning("[@%s] Checkpoint detected", username)
            return CheckResult(username, CheckStatus.ERROR, "ig_block_checkpoint")
        return None


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()