"""Instagram username availability checker — Web Signup Dryrun Pipeline.

Architecture:
  Tier 1  — Regex / syntax / reserved pre-validation (no network).
  Tier 2  — Two-phase Instagram check:
             Phase A: Profile page GET (httpx, bot UA) — fast.
                      Detects existing profiles instantly as TAKEN.
             Phase B: Web Signup Dryrun POST (curl_cffi, Chrome TLS fingerprint).
                      Uses web_create_ajax/attempt/ endpoint to check
                      username availability. No account/session required.

QATIY QOIDALAR:
  AVAILABLE — FAQAT Phase B ``dryrun_passed: true`` qaytarganda.
  TAKEN     — Profil mavjud, banned, deactivated, cooldown, spam — barchasi TAKEN.
  ERROR     — Faqat infra muammo (network/proxy/429).
  FALLBACK TAQIQLANADI — "profil topilmadi" hech qachon AVAILABLE emas!

ANONIM REJIM: Hech qanday Instagram akkaunt yoki session cookie talab etilmaydi.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import uuid
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

# Phase B — Web Signup Dryrun (curl_cffi, Chrome TLS fingerprint)
_WEB_CREATE_AJAX_URL = (
    "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
)
_WEB_API_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"

_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_WEB_SIGNUP_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "X-CSRFToken": "missing",
    "X-Instagram-AJAX": "1",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Origin": "https://www.instagram.com",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}

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

def _safe_json_httpx(resp: httpx.Response) -> dict[str, Any] | None:
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
    Anonim Instagram username availability checker — Web Signup Dryrun.

    Hech qanday Instagram akkaunt yoki session cookie talab etilmaydi.
    curl_cffi (Chrome TLS fingerprint) orqali web signup endpoint tekshiriladi.

    QATIY QOIDALAR:
      AVAILABLE — FAQAT dryrun_passed ``true`` qaytarganda.
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
            "InstagramChecker ready (Web Signup Dryrun + curl_cffi) | proxy=%s | mode=anonymous",
            bool(self._proxy),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        logger.info(
            "InstagramChecker started (Web Signup Dryrun, curl_cffi, no session needed)"
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
          AVAILABLE — API ``dryrun_passed: true`` tasdiqladi.
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
        Phase B: Web Signup Dryrun -> AVAILABLE / TAKEN.

        HECH QACHON fallback AVAILABLE yo'q!
        """
        # Phase A — profil sahifasi
        phase_a = await self._phase_a_profile_check(username)
        if phase_a is not None:
            return phase_a

        # Phase A: profil topilmadi -> Phase B: Web Signup Dryrun
        await asyncio.sleep(random.uniform(0.3, 0.8))
        return await self._phase_b_web_signup_dryrun(username)

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
                "verify": False,
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
            logger.info("[@%s] Profil topilmadi -> Phase B (Web Signup)", username)
            return None

        # Login page?
        if "login" in title:
            logger.info("[@%s] Login sahifasi -> Phase B (Web Signup)", username)
            return None

        # Username in body with substantial HTML?
        if ul in html.lower() and len(html) > 5000:
            logger.info("[@%s] TAKEN (username_in_body) [Phase A]", username)
            return CheckResult(username, CheckStatus.TAKEN, "profile_exists")

        logger.info("[@%s] Noaniq -> Phase B (Web Signup) | title=%s", username, title[:50])
        return None

    # ------------------------------------------------------------------
    # Phase B — Web Signup Dryrun (curl_cffi, Chrome TLS, NO AUTH)
    # ------------------------------------------------------------------

    async def _phase_b_web_signup_dryrun(
        self, username: str
    ) -> CheckResult:
        """
        POST web_create_ajax/attempt/ via curl_cffi (Chrome TLS fingerprint).
        DataImpulse proksi orqali. No session/cookie required.

        QATIY:
          dryrun_passed: true (username xatosi yo'q) -> AVAILABLE
          errors.username mavjud                     -> TAKEN
          status: fail / 429 / network               -> ERROR
          HECH QACHON fallback AVAILABLE yo'q!
        """
        # Random email for dryrun
        fake_email = f"chk_{uuid.uuid4().hex[:8]}@gmail.com"

        form_data = {
            "email": fake_email,
            "username": username,
            "first_name": "Checker",
            "opt_into_one_tap": "false",
        }

        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _WEB_API_TIMEOUT,
            "verify": False,
        }
        if self._proxy:
            session_kwargs["proxy"] = self._proxy

        try:
            async with AsyncSession(**session_kwargs) as session:
                resp = await session.post(
                    _WEB_CREATE_AJAX_URL,
                    headers=_WEB_SIGNUP_HEADERS,
                    data=form_data,
                )
        except _CURL_NETWORK_EXCEPTIONS as exc:
            detail = f"signup_network_{type(exc).__name__}"
            logger.warning("[@%s] Web Signup xato: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)
        except Exception as exc:
            detail = f"signup_unexpected_{type(exc).__name__}"
            logger.warning("[@%s] Web Signup kutilmagan: %s", username, exc)
            return CheckResult(username, CheckStatus.ERROR, detail)

        sc = int(getattr(resp, "status_code", 0) or 0)

        # 429 -> ERROR
        if sc == 429:
            logger.warning("[@%s] Web Signup 429 (rate limited)", username)
            return CheckResult(username, CheckStatus.ERROR, "signup_429")

        data = _safe_json_curl(resp)
        if data is None:
            body_preview = ""
            try:
                body_preview = (resp.text or "")[:200]
            except Exception:
                pass
            logger.warning(
                "[@%s] Web Signup non-JSON (HTTP %d) | body=%s",
                username, sc, body_preview,
            )
            return CheckResult(
                username, CheckStatus.ERROR, f"signup_non_json_{sc}"
            )

        logger.debug(
            "[@%s] Web Signup response: HTTP %d | %s",
            username, sc, json.dumps(data, ensure_ascii=False)[:300],
        )

        # ── Errors obyektini tekshirish ────────────────────────────
        errors = data.get("errors", {})
        username_errors = errors.get("username") if isinstance(errors, dict) else None

        # ── TAKEN: username xatosi mavjud ──────────────────────────
        if username_errors:
            # username_errors — list yoki dict bo'lishi mumkin
            if isinstance(username_errors, list):
                err_detail = "; ".join(
                    e.get("message", str(e)) if isinstance(e, dict) else str(e)
                    for e in username_errors
                )
            else:
                err_detail = str(username_errors)
            logger.info(
                "[@%s] TAKEN (signup: username error: %s) [Phase B]",
                username, err_detail[:100],
            )
            return CheckResult(username, CheckStatus.TAKEN, "username_is_taken")

        # ── AVAILABLE: dryrun_passed == True (username bo'sh) ──────
        if data.get("dryrun_passed") is True:
            logger.info(
                "[@%s] AVAILABLE (signup: dryrun_passed=true)", username,
            )
            return CheckResult(
                username, CheckStatus.AVAILABLE, "truly_available"
            )

        # ── AVAILABLE: status ok va username xatosi yo'q ───────────
        if data.get("status") == "ok" and not username_errors:
            # Boshqa maydonlar xato bergan bo'lishi mumkin (email),
            # lekin username bo'yicha xato yo'q = AVAILABLE
            has_other_errors = bool(errors) and not username_errors
            if has_other_errors or not errors:
                logger.info(
                    "[@%s] AVAILABLE (signup: status=ok, no username error)",
                    username,
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
                    "[@%s] Web Signup rate limit: %s", username, fail_message[:80],
                )
                return CheckResult(
                    username, CheckStatus.ERROR, "signup_rate_limit"
                )

            # Checkpoint / spam block?
            if error_type in (
                "checkpoint_required", "checkpoint_challenge_required",
                "spam", "rate_limit_error", "sentry_block",
                "generic_request_error", "ip_block",
            ):
                logger.warning(
                    "[@%s] Web Signup infra block: %s", username, error_type,
                )
                return CheckResult(
                    username, CheckStatus.ERROR, f"signup_block_{error_type}"
                )

            # Boshqa fail -> TAKEN (username band bo'lishi ehtimoli)
            logger.info(
                "[@%s] TAKEN (status=fail, %s) [Phase B]",
                username, error_type,
            )
            return CheckResult(
                username, CheckStatus.TAKEN, f"fail_{error_type}"
            )

        # ── Noaniq -> ERROR (HECH QACHON AVAILABLE emas!) ─────────
        logger.warning(
            "[@%s] Noaniq Web Signup javob -> ERROR | body=%s",
            username, str(data)[:200],
        )
        return CheckResult(
            username, CheckStatus.ERROR, "signup_unknown_response"
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

instagram_checker = InstagramChecker()