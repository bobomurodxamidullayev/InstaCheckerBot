"""Instagram username availability checker — Hybrid Pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved-word pre-validation (no network).
  Tier 2  — Two-phase Instagram check:
             Phase A: Profile page GET (bot UA, httpx) — fast, low rate risk.
                      Detects existing profiles instantly as TAKEN.
             Phase B: Signup validation POST (httpx, sticky proxy) — only for
                      "not found" profiles.  Confirms AVAILABLE vs TAKEN.

Status Logic:
  AVAILABLE — Signup endpoint confirmed: username can be registered right now.
  TAKEN     — Profile exists, or Instagram refuses registration (any reason:
              taken/banned/deactivated/cooldown/invalid).
  ERROR     — Network/proxy failure, rate limit (429), or IP block.
              Only infrastructure issues — never Instagram's decision.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse

import httpx

from config import settings
from models.username_log import CheckStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SIGNUP_ATTEMPT_URL = (
    "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
)
_SIGNUP_PAGE_URL = "https://www.instagram.com/accounts/emailsignup/"
_PROFILE_URL_TPL = "https://www.instagram.com/{}/"

_API_TIMEOUT = 12.0
_PROFILE_TIMEOUT = 10.0
_CSRF_TTL = 1800.0  # 30 daqiqa

_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
_BOT_USER_AGENT = "TelegramBot (like TwitterBot)"

_BOT_HEADERS: dict[str, str] = {
    "User-Agent": _BOT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_IG_APP_ID = "936619743392459"

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
# IP/session block kodlari
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

def _safe_json(resp: httpx.Response) -> dict[str, Any] | None:
    """Safely parse JSON dict from httpx response."""
    try:
        data = resp.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    text = (resp.text or "").strip()
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
      3) Phase B — signup attempt POST (httpx, sticky proxy).
         Only called for "not found" profiles. Confirms AVAILABLE vs TAKEN.

    Guarantees:
      AVAILABLE — signup endpoint confirmed username is free to register.
      TAKEN     — profile exists OR Instagram refuses registration.
      ERROR     — only network/proxy/429/IP-block infrastructure failures.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._csrf_token: str | None = None
        self._csrf_fetched_at: float = 0.0
        self._csrf_lock = asyncio.Lock()
        self._in_flight: set[str] = set()
        logger.info(
            "InstagramChecker ready | proxy=%s | pipeline=hybrid",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info("InstagramChecker starting...")
        token = await self._ensure_csrf_token()
        status = "CSRF olingan" if token else "CSRF olinmadi (keyinroq urinadi)"
        logger.info("InstagramChecker started | %s", status)

    async def stop(self) -> None:
        logger.info("InstagramChecker stopped.")

    # ------------------------------------------------------------------
    # Sticky proxy — har bir Phase B uchun yangi IP
    # ------------------------------------------------------------------

    def _make_sticky_proxy(self) -> str | None:
        """
        DataImpulse sticky session proxy URL yaratish.
        ``__sd.{session_id}`` qo'shib, har tekshiruvga yangi IP tayinlash.
        """
        if not self._proxy:
            return None
        try:
            parsed = urlparse(self._proxy)
            if not parsed.username or not parsed.hostname:
                return self._proxy
            sid = uuid.uuid4().hex[:10]
            sticky_user = f"{parsed.username}__sd.{sid}"
            pw = f":{parsed.password}" if parsed.password else ""
            port = f":{parsed.port}" if parsed.port else ""
            return f"{parsed.scheme}://{sticky_user}{pw}@{parsed.hostname}{port}"
        except Exception:
            return self._proxy

    # ------------------------------------------------------------------
    # CSRF token management
    # ------------------------------------------------------------------

    async def _fetch_csrf_once(self) -> str | None:
        """GET signup page -> csrftoken cookie."""
        try:
            client_kw: dict[str, Any] = {
                "timeout": _API_TIMEOUT,
                "follow_redirects": True,
                "http2": False,
            }
            if self._proxy:
                client_kw["proxy"] = self._proxy

            async with httpx.AsyncClient(**client_kw) as client:
                resp = await client.get(
                    _SIGNUP_PAGE_URL,
                    headers={
                        "User-Agent": _CHROME_USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                    },
                )
                csrf = resp.cookies.get("csrftoken")
                if csrf:
                    return csrf

                # Fallback: HTML body
                body = resp.text or ""
                m = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', body)
                if m:
                    return m.group(1)

                logger.warning("CSRF topilmadi (status=%s)", resp.status_code)
                return None

        except _HTTPX_NETWORK_EXCEPTIONS as exc:
            logger.warning("CSRF network xato: %s", exc)
            return None

    async def _ensure_csrf_token(self) -> str | None:
        """Cached CSRF with 30 min TTL, thread-safe."""
        now = time.monotonic()
        if self._csrf_token and (now - self._csrf_fetched_at) < _CSRF_TTL:
            return self._csrf_token

        async with self._csrf_lock:
            now = time.monotonic()
            if self._csrf_token and (now - self._csrf_fetched_at) < _CSRF_TTL:
                return self._csrf_token

            for attempt in range(1, 3):
                token = await self._fetch_csrf_once()
                if token:
                    self._csrf_token = token
                    self._csrf_fetched_at = time.monotonic()
                    return token
                if attempt < 2:
                    await asyncio.sleep(2.0)

            logger.error("CSRF 2 urinishdan keyin olinmadi")
            return self._csrf_token

    def _invalidate_csrf(self) -> None:
        self._csrf_fetched_at = 0.0

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
          AVAILABLE — ro'yxatdan o'tsa bo'ladi.
          TAKEN     — olib bo'lmaydi (har qanday sabab).
          ERROR     — infra muammo (network/proxy/429).
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
                    if "429" in em:
                        await asyncio.sleep(settings.rate_limit_sleep)
                    elif "csrf" in em:
                        self._invalidate_csrf()
                        await asyncio.sleep(2.0)
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
        """Phase A -> Phase B (agar kerak bo'lsa)."""
        phase_a = await self._phase_a_profile_check(username)
        if phase_a is not None:
            return phase_a

        await asyncio.sleep(random.uniform(0.5, 1.5))
        return await self._phase_b_signup_check(username)

    # ------------------------------------------------------------------
    # Phase A — Profile page (httpx, bot UA)
    # ------------------------------------------------------------------

    async def _phase_a_profile_check(
        self, username: str
    ) -> CheckResult | None:
        """
        GET /{username}/ with bot UA.  Instagram bot'larga to'liq SSR HTML beradi.
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
    # Phase B — Signup validation (httpx, sticky proxy, combined GET+POST)
    # ------------------------------------------------------------------

    async def _phase_b_signup_check(self, username: str) -> CheckResult:
        """
        Combined session: GET signup page + POST signup check.

        Bitta httpx.AsyncClient ichida:
          1) GET signup page -> fresh CSRF cookie (avtomatik jar'ga tushadi).
          2) POST signup check -> cookie'lar avtomatik yuboriladi.
        Sticky proxy -> har tekshiruvda yangi IP.
        """
        sticky = self._make_sticky_proxy()
        proxy = sticky or self._proxy

        try:
            kw: dict[str, Any] = {
                "timeout": _API_TIMEOUT,
                "follow_redirects": True,
                "http2": False,
            }
            if proxy:
                kw["proxy"] = proxy

            async with httpx.AsyncClient(**kw) as client:
                # Step 1: GET signup page -> CSRF cookie
                page_resp = await client.get(
                    _SIGNUP_PAGE_URL,
                    headers={
                        "User-Agent": _CHROME_USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                    },
                )

                # CSRF ni cookie jar'dan olish
                csrf = client.cookies.get("csrftoken")
                if not csrf:
                    csrf = page_resp.cookies.get("csrftoken")
                if not csrf:
                    # HTML body fallback
                    body = page_resp.text or ""
                    m = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', body)
                    if m:
                        csrf = m.group(1)
                        client.cookies.set("csrftoken", csrf, domain=".instagram.com")
                if not csrf:
                    csrf = self._csrf_token
                if not csrf:
                    logger.warning("[@%s] CSRF olinmadi", username)
                    return CheckResult(
                        username, CheckStatus.ERROR, "csrf_unavailable"
                    )

                # Keshni yangilash
                self._csrf_token = csrf
                self._csrf_fetched_at = time.monotonic()

                # Tabiiy pauza (forma to'ldirish simulyatsiyasi)
                await asyncio.sleep(random.uniform(1.0, 2.5))

                # Step 2: POST signup check (same client = same IP + cookies)
                resp = await client.post(
                    _SIGNUP_ATTEMPT_URL,
                    headers={
                        "User-Agent": _CHROME_USER_AGENT,
                        "X-CSRFToken": csrf,
                        "X-IG-App-ID": _IG_APP_ID,
                        "X-Requested-With": "XMLHttpRequest",
                        "Referer": _SIGNUP_PAGE_URL,
                        "Accept": "*/*",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Origin": "https://www.instagram.com",
                    },
                    data={
                        "username": username,
                        "opt_into_one_tap": "false",
                    },
                )

        except _HTTPX_NETWORK_EXCEPTIONS as exc:
            detail = f"signup_network_{type(exc).__name__}"
            logger.warning("[@%s] Signup xato: %s: %s", username, detail, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"signup_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] Signup kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = resp.status_code

        # Rate limit -> ERROR (retry)
        if sc == 429:
            logger.warning("[@%s] Signup 429", username)
            return CheckResult(
                username, CheckStatus.ERROR, "signup_rate_limit_429"
            )

        # JSON parse
        data = _safe_json(resp)

        if data is not None:
            # IP block?
            infra = self._check_infra_block(username, data)
            if infra is not None:
                return infra
            return self._classify_signup_response(username, data, sc)

        # Non-JSON -> Instagram javob berdi lekin JSON emas -> TAKEN
        if sc > 0:
            logger.info("[@%s] HTTP %d non-JSON -> TAKEN", username, sc)
            return CheckResult(
                username, CheckStatus.TAKEN, f"non_json_http_{sc}"
            )

        return CheckResult(username, CheckStatus.ERROR, "no_response")

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
                return CheckResult(
                    username, CheckStatus.ERROR, f"ig_block_{et}"
                )
        if data.get("checkpoint_url") or data.get("lock"):
            logger.warning("[@%s] Checkpoint detected", username)
            return CheckResult(
                username, CheckStatus.ERROR, "ig_block_checkpoint"
            )
        return None

    # ------------------------------------------------------------------
    # Response classification
    # ------------------------------------------------------------------

    def _classify_signup_response(
        self,
        username: str,
        data: dict[str, Any],
        http_status: int,
    ) -> CheckResult:
        """
        Signup attempt JSON -> AVAILABLE yoki TAKEN.
        Hech qachon ERROR qaytarmaydi.

        1) errors.username mavjud -> TAKEN.
        2) errors dict lekin username yo'q/bo'sh -> AVAILABLE.
        3) available: true/false -> mos status.
        4) Boshqa -> TAKEN (konservativ).
        """
        errors = data.get("errors")

        if isinstance(errors, dict):
            ue = errors.get("username")
            if isinstance(ue, list) and len(ue) > 0:
                code = "username_error"
                msg = ""
                for err in ue:
                    if isinstance(err, dict):
                        code = err.get("code", "username_error")
                        msg = err.get("message", "")
                        break
                    elif isinstance(err, str):
                        msg = err
                        if "taken" in err.lower() or "available" in err.lower():
                            code = "username_is_taken"
                        elif "invalid" in err.lower():
                            code = "invalid_username"
                        break
                logger.info("[@%s] TAKEN (%s) | %s", username, code, msg[:60])
                return CheckResult(username, CheckStatus.TAKEN, code)

            # Username errors yo'q -> AVAILABLE
            logger.info("[@%s] AVAILABLE (signup confirmed)", username)
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )

        # Fallback: available field
        if data.get("available") is True:
            logger.info("[@%s] AVAILABLE (available=true)", username)
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )
        if data.get("available") is False:
            logger.info("[@%s] TAKEN (available=false)", username)
            return CheckResult(
                username, CheckStatus.TAKEN, "username_is_taken"
            )

        # username_suggestions -> TAKEN
        sug = data.get("username_suggestions")
        if isinstance(sug, list) and len(sug) > 0:
            logger.info("[@%s] TAKEN (suggestions)", username)
            return CheckResult(
                username, CheckStatus.TAKEN, "username_is_taken"
            )

        # Konservativ
        logger.info(
            "[@%s] TAKEN (konservativ) | http=%d body=%s",
            username, http_status, str(data)[:120],
        )
        return CheckResult(username, CheckStatus.TAKEN, "api_rejected_unknown")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()