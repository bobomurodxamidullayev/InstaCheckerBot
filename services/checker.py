"""Instagram username availability checker — Android Private API Pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Two-phase Instagram check:
             Phase A: Profile page GET (httpx, bot UA) — fast.
                      Detects existing profiles instantly as TAKEN.
             Phase B: Android Private API check_username POST (httpx, HMAC signed).
                      Confirms username availability via Instagram's official
                      mobile signup endpoint. No account/session required.

QATIY QOIDALAR:
  AVAILABLE — FAQAT Phase B ``available: true`` qaytarganda.
  TAKEN     — Profil mavjud, banned, deactivated, cooldown, spam — barchasi TAKEN.
  ERROR     — Faqat infra muammo (network/proxy/429).
  FALLBACK TAQIQLANADI — "profil topilmadi" hech qachon AVAILABLE emas!

ANONIM REJIM: Hech qanday Instagram akkaunt yoki session cookie talab etilmaydi.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import re
import uuid
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote

import httpx

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

# Phase B — Android Private API Lookup (no auth, HMAC signed)
_ANDROID_LOOKUP_URL = "https://i.instagram.com/api/v1/users/lookup/"
_ANDROID_API_TIMEOUT = 12.0

_ANDROID_USER_AGENT = (
    "Instagram 315.0.0.33.109 Android "
    "(33/13; 420dpi; 1080x2400; Xiaomi; M2101K6G; sweet; qcom; en_US; 555627230)"
)
_IG_APP_ID = "936619743392459"

# HMAC-SHA256 signing key (Instagram Android client key)
_IG_SIG_KEY = b"6f9d2207da762a7924e81561f324838ae43fb067"
_IG_SIG_KEY_VERSION = "4"

_ANDROID_HEADERS: dict[str, str] = {
    "User-Agent": _ANDROID_USER_AGENT,
    "X-IG-App-ID": _IG_APP_ID,
    "Accept-Language": "en-US",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-FB-HTTP-Engine": "Liger",
    "X-IG-Connection-Type": "WIFI",
    "X-IG-Capabilities": "3brTvx0=",
    "Accept-Encoding": "gzip, deflate",
}

# Network exceptions
_HTTPX_NETWORK_EXCEPTIONS = (
    httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
    httpx.WriteTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError,
    httpx.TimeoutException, ConnectionError, OSError,
)

# Tier-1 pre-validation
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$ |[^a-zA-Z0-9._]")
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

def _generate_device_id() -> str:
    """Random Android device ID."""
    return f"android-{uuid.uuid4().hex[:16]}"


def _generate_uuid() -> str:
    """Random UUID for request."""
    return str(uuid.uuid4())


def _sign_request_body(payload_dict: dict[str, Any]) -> str:
    """
    Instagram Android API uchun HMAC-SHA256 imzolangan so'rov tanasi.

    Format: signed_body=SIGNATURE.{json_payload}&ig_sig_key_version=4
    """
    raw_json = json.dumps(payload_dict, separators=(",", ":"))
    signature = hmac.new(
        _IG_SIG_KEY, raw_json.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    # URL-encode the JSON payload for form body
    encoded_json = quote(raw_json, safe="")
    return f"signed_body={signature}.{encoded_json}&ig_sig_key_version={_IG_SIG_KEY_VERSION}"


def _safe_json(resp: httpx.Response) -> dict[str, Any] | None:
    """Safely parse JSON dict from httpx response."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    text = resp.text or ""
    text = text.strip()
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
    Anonim Instagram username availability checker — Android Private API.

    Hech qanday Instagram akkaunt yoki session cookie talab etilmaydi.
    HMAC-SHA256 imzolangan Android Mobile API orqali tekshiriladi.

    QATIY QOIDALAR:
      AVAILABLE — FAQAT check_username ``available: true`` qaytarganda.
      TAKEN     — Profil mavjud, banned, deactivated, cooldown, spam.
      ERROR     — Network/proxy/429 infra muammo.
      FALLBACK TAQIQLANADI — "profil topilmadi" != AVAILABLE!
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._in_flight: set[str] = set()

        logger.info(
            "InstagramChecker ready (Android Private API) | proxy=%s | mode=anonymous",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info(
            "InstagramChecker started (Android Private API, no session needed)"
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
    # Tier 2 — Phase A -> Phase B
    # ------------------------------------------------------------------

    async def _tier2_check(self, username: str) -> CheckResult:
        """
        Phase A: Profil sahifasi -> TAKEN (agar profil mavjud).
        Phase B: Android Private API check_username -> AVAILABLE / TAKEN.

        HECH QACHON fallback AVAILABLE yo'q!
        """
        # Phase A — profil sahifasi
        phase_a = await self._phase_a_profile_check(username)
        if phase_a is not None:
            return phase_a

        # Phase A: profil topilmadi -> Phase B: Android API
        await asyncio.sleep(random.uniform(0.3, 0.8))
        return await self._phase_b_android_lookup(username)

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
            logger.info("[@%s] Profil topilmadi -> Phase B (Android API)", username)
            return None

        # Login page?
        if "login" in title:
            logger.info("[@%s] Login sahifasi -> Phase B (Android API)", username)
            return None

        # Username in body with substantial HTML?
        if ul in html.lower() and len(html) > 5000:
            logger.info("[@%s] TAKEN (username_in_body) [Phase A]", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        logger.info("[@%s] Noaniq -> Phase B (Android API) | title=%s", username, title[:50])
        return None

    # ------------------------------------------------------------------
    # Phase B — Android Private API users/lookup (HMAC signed, NO AUTH)
    # ------------------------------------------------------------------

    async def _phase_b_android_lookup(
        self, username: str
    ) -> CheckResult:
        """
        POST users/lookup/ via Instagram Android Private API.
        HMAC-SHA256 signed body, no session/cookie required.

        QATIY:
          user mavjud / user_found: true   -> TAKEN
          404 / "No users found" / user_found: false -> AVAILABLE
          429 / network                    -> ERROR
          HECH QACHON fallback AVAILABLE yo'q!
        """
        # Build signed payload
        device_id = _generate_device_id()
        guid = _generate_uuid()
        waterfall_id = _generate_uuid()

        payload = {
            "_csrftoken": "missing",
            "q": username,
            "device_id": device_id,
            "guid": guid,
            "waterfall_id": waterfall_id,
        }
        signed_body = _sign_request_body(payload)

        try:
            kw: dict[str, Any] = {
                "timeout": _ANDROID_API_TIMEOUT,
                "follow_redirects": False,
                "http2": False,
            }
            if self._proxy:
                kw["proxy"] = self._proxy

            async with httpx.AsyncClient(**kw) as client:
                resp = await client.post(
                    _ANDROID_LOOKUP_URL,
                    headers=_ANDROID_HEADERS,
                    content=signed_body,
                )
        except _HTTPX_NETWORK_EXCEPTIONS as exc:
            detail = f"lookup_network_{type(exc).__name__}"
            logger.warning("[@%s] Lookup API xato: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"lookup_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] Lookup API kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = resp.status_code

        # 429 -> ERROR
        if sc == 429:
            logger.warning("[@%s] Lookup API 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "lookup_429")

        # 404 -> AVAILABLE (user topilmadi)
        if sc == 404:
            logger.info(
                "[@%s] AVAILABLE (Lookup API: HTTP 404, user not found)",
                username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )

        data = _safe_json(resp)
        if data is None:
            logger.warning(
                "[@%s] Lookup API non-JSON (HTTP %d) | body=%s",
                username, sc, (resp.text or "")[:200],
            )
            return CheckResult(
                username, CheckStatus.ERROR, f"lookup_non_json_{sc}"
            )

        logger.debug(
            "[@%s] Lookup API response: HTTP %d | %s",
            username, sc, json.dumps(data, ensure_ascii=False)[:300],
        )

        # ── TAKEN: user kaliti mavjud (profil topildi) ─────────────
        user_data = data.get("user")
        if user_data and isinstance(user_data, dict):
            ig_username = user_data.get("username", username)
            logger.info(
                "[@%s] TAKEN (Lookup: user found, ig_user=%s) [Phase B]",
                username, ig_username,
            )
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        # ── TAKEN: user_found == True (user mavjud) ────────────────
        if data.get("user_found") is True:
            logger.info(
                "[@%s] TAKEN (Lookup: user_found=true) [Phase B]", username,
            )
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        # ── AVAILABLE: user_found == False ─────────────────────────
        if data.get("user_found") is False:
            logger.info(
                "[@%s] AVAILABLE (Lookup: user_found=false)", username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )

        # ── AVAILABLE: "No users found" message ───────────────────
        message = str(data.get("message", "")).lower()
        if "no users found" in message:
            logger.info(
                "[@%s] AVAILABLE (Lookup: 'No users found')", username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )

        # ── status: fail → tahlil qilish ───────────────────────────
        if data.get("status") == "fail":
            error_type = str(data.get("error_type", "unknown_fail"))
            fail_message = str(data.get("message", ""))
            msg_lower = fail_message.lower()

            # Rate limit?
            if "wait" in msg_lower or "try again" in msg_lower:
                logger.warning(
                    "[@%s] Lookup API rate limit: %s", username, fail_message[:80],
                )
                return CheckResult(
                    username, CheckStatus.ERROR, "lookup_rate_limit"
                )

            # Checkpoint / spam block?
            if error_type in (
                "checkpoint_required", "checkpoint_challenge_required",
                "spam", "rate_limit_error", "sentry_block",
                "generic_request_error",
            ):
                logger.warning(
                    "[@%s] Lookup API infra block: %s", username, error_type,
                )
                return CheckResult(
                    username, CheckStatus.ERROR, f"lookup_block_{error_type}"
                )

            # Boshqa fail -> TAKEN (banned/deleted/cooldown — username band)
            logger.info(
                "[@%s] TAKEN (status=fail, %s) [Phase B]",
                username, error_type,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, f"fail_{error_type}"
            )

        # ── Noaniq -> ERROR (HECH QACHON AVAILABLE emas!) ─────────
        logger.warning(
            "[@%s] Noaniq Lookup API javob -> ERROR | body=%s",
            username, str(data)[:200],
        )
        return CheckResult(
            username, CheckStatus.ERROR, "lookup_unknown_response"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()