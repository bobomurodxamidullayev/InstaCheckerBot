"""Instagram username tekshirish servisi — 3-tier pipeline (pure HTML pipeline, no web_profile_info)."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, quote_plus, unquote, urlparse, urlunparse

from curl_cffi import CurlError
from curl_cffi.requests import AsyncSession

try:
    from curl_cffi.requests.exceptions import RequestException
except ImportError:
    from curl_cffi.requests.errors import RequestsError as RequestException  # type: ignore

try:
    from curl_cffi.requests.exceptions import RequestsError
except ImportError:
    try:
        from curl_cffi.requests.errors import RequestsError  # type: ignore
    except ImportError:
        RequestsError = RequestException  # type: ignore

from config import settings
from models.username_log import CheckStatus

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_OEMBED_ENDPOINT = "https://www.instagram.com/api/v1/oembed/?url="
_PROFILE_URL = "https://www.instagram.com/{username}/"

_REQUEST_TIMEOUT = 6.0
_PROFILE_TIMEOUT = 9.0
_DIRECT_PROFILE_TIMEOUT = 7.0
_IMPERSONATE = "chrome124"
_CHROME_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_OEMBED_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "Accept": "application/json",
}

_PROFILE_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

_NETWORK_EXCEPTIONS = (
    RequestsError,
    RequestException,
    CurlError,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
)

# ---------------------------------------------------------------------------
# Tier-1 pre-validation constants
# ---------------------------------------------------------------------------

# Structural patterns Instagram always rejects at registration:
#   ^\.    — starts with a dot
#   \.\.   — two consecutive dots
#   \.$    — ends with a dot
#   [^...] — any char that isn't alphanumeric, dot, or underscore
_INVALID_SYNTAX_RE = re.compile(r"^\.|\.\.|\.$|[^a-zA-Z0-9._]")

# Names reserved by Instagram's own navigation / system routes
_RESERVED_NAMES: frozenset[str] = frozenset({
    "admin", "instagram", "support", "help", "login", "signup",
    "accounts", "explore", "direct", "security", "about", "developer",
})

# ---------------------------------------------------------------------------
# Tier-3 HTML signal constants
# ---------------------------------------------------------------------------

# Substrings in the final redirected URL that mean the handle is gated/taken
# (login wall, checkpoint, age/consent challenge) rather than free.
_TAKEN_URL_MARKERS: tuple[str, ...] = (
    "/accounts/login",
    "/challenge",
    "checkpoint",
    "/accounts/suspended",
)

# Substrings in the HTML body that ONLY appear when Instagram has actually
# rendered a real, registered profile (owner id, profile picture, bio,
# follower meta, or the profile's iOS deep-link). Deliberately narrow:
# generic React-runtime scaffolding like "userID":"0"/"userID":null is
# present on EVERY page — including 404s and never-registered handles — so
# it must never be used as a taken/existence signal.
_TAKEN_BODY_MARKERS: tuple[str, ...] = (
    "instapp:owner_user_id",
    "profile_pic_url",
    "biography",
    "Followers",
    "og:description",
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    """Bitta username tekshiruvi natijasi (handler/DB bilan mos)."""

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

def _make_session_proxy(base_proxy: str | None) -> str | None:
    """
    DataImpulse rotating proxy: bitta check (yoki retry) uchun bitta sticky session ID.
    """
    if not base_proxy:
        return None
    parsed = urlparse(base_proxy.strip())
    if not parsed.hostname or parsed.username is None:
        return base_proxy
    username = unquote(parsed.username)
    password = unquote(parsed.password or "")
    username = re.sub(r"_session[-.][A-Za-z0-9_-]+$", "", username)
    username = re.sub(r"_sid[-.][A-Za-z0-9_-]+$", "", username)
    session_user = f"{username}_session-{secrets.token_hex(8)}"
    auth = f"{quote(session_user, safe='')}:{quote(password, safe='')}"
    host = parsed.hostname
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunparse((
        parsed.scheme or "http",
        f"{auth}@{host}",
        parsed.path, parsed.params, parsed.query, parsed.fragment,
    ))


def _body_text(response: Any) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str):
        return text
    content = getattr(response, "content", b"")
    if isinstance(content, (bytes, bytearray)):
        try:
            return bytes(content).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return str(content or "")


def _parse_json_body(response: Any) -> dict[str, Any] | None:
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    text = _body_text(response).strip()
    if not text or text[0] not in "{[":
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


# ---------------------------------------------------------------------------
# Main checker class
# ---------------------------------------------------------------------------

class InstagramChecker:
    """
    Instagram username mavjudligini 3-bosqichli pipeline orqali tekshiradi.

    Tier 1 — Pre-validation regex     (so'rovsiz lahzali rad etish)
    Tier 2 — oEmbed GET               (faol ochiq profilni tezkor aniqlash)
    Tier 3 — Pure HTML inspection GET (yakuniy, deterministik qaror)

    Tier 3 SPA-aware qat'iy qoida bilan ishlaydi:
      • TAKEN   — (a) login/challenge/checkpoint redirect, YOKI (b) tanada
                  aniq profil belgisi bor: owner_user_id, profile_pic_url,
                  biography, Followers/og:description meta, profilning
                  "instagram://user?username=..." deep-link'i, YOKI username
                  o'zi qo'shtirnoqda + real user-object kaliti ("id":,
                  "has_blocked_viewer", "is_verified") bilan birga uchrasa —
                  bu OG teglari yashirilgan, lekin SPA bootstrap holatida
                  minimal user record qolgan bloklangan/band akkauntlarni
                  ushlaydi. Umumiy React runtime kalitlari (masalan har bir
                  sahifada uchraydigan "userID":"0"/null) signal sifatida
                  ISHLATILMAYDI.
      • AVAILABLE — yuqoridagi TAKEN belgilarining birortasi ham topilmasa.
                  Instagram bu SPA'da har doim HTTP 200 va umumiy,
                  username'ga bog'liq bo'lmagan app-shell qaytaradi — na
                  band, na haqiqatan bo'sh username uchun ishonchli aniq
                  "not found" matni kafolatlanmaydi, shuning uchun yuqoridagi
                  aniq belgilarning yo'qligi endi yetarli va yagona
                  AVAILABLE signali hisoblanadi.
      • ERROR faqat tarmoq/transport darajasidagi tiklab bo'lmaydigan
        xatolarda qaytariladi.
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=html_only",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (pure-HTML pipeline) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    # ------------------------------------------------------------------
    # Session helpers
    # ------------------------------------------------------------------

    def _session_kwargs(
        self,
        proxy: str | None,
        timeout: float = _REQUEST_TIMEOUT,
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": timeout,
            "max_clients": 1,
            "verify": False,
            "allow_redirects": True,
            "headers": _OEMBED_HEADERS,
        }
        if proxy:
            kwargs["proxy"] = proxy
        return kwargs

    async def _request(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        headers: dict[str, str],
        data: dict[str, str] | None = None,
        allow_redirects: bool = True,
        timeout: float = _REQUEST_TIMEOUT,
    ) -> Any:
        fn = session.post if method.upper() == "POST" else session.get
        return await fn(
            url,
            headers=headers,
            data=data,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False,
            impersonate=_IMPERSONATE,
        )

    # ------------------------------------------------------------------
    # Public entry-point
    # ------------------------------------------------------------------

    async def check_username(
        self,
        username: str,
        max_retries: int = 1,
    ) -> CheckResult:
        username_clean = username.strip().lstrip("@").lower()

        # ----------------------------------------------------------------
        # TIER 1 — Pre-validation (instant, no network)
        # ----------------------------------------------------------------
        tier1 = self._tier1_prevalidate(username_clean)
        if tier1 is not None:
            status, reason = tier1
            logger.info(
                "[@%s] TIER-1 rejected → %s (%s)", username_clean, status.value, reason
            )
            return CheckResult(
                username=username_clean,
                status=status,
                error_message=reason,
                attempts=0,
            )

        if username_clean in self._checking_usernames:
            logger.warning("[@%s] Parallel tekshiruv — davom etiladi.", username_clean)

        self._checking_usernames.add(username_clean)
        attempts = 0
        try:
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )
            attempts = 1
            result = await self._funnel_check(
                username_clean,
                _make_session_proxy(self._base_proxy),
            )
            if result.get("kind") == "ok":
                status = result["status"]
                source = result.get("source", "unknown")
                reason = result.get("reason")
                logger.info("[@%s] %s (%s)", username_clean, status.value, source)
                return CheckResult(
                    username=username_clean,
                    status=status,
                    error_message=reason,
                    attempts=attempts,
                )
            last_error = result.get("error", "network or verification failure")
            logger.warning("[@%s] verification failed → ERROR", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=str(last_error),
                attempts=attempts,
            )
        except Exception as exc:
            logger.exception("[@%s] Ushlanmagan xato → ERROR", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=f"{type(exc).__name__}: {exc}",
                attempts=max(attempts, 1),
            )
        finally:
            self._checking_usernames.discard(username_clean)

    # ------------------------------------------------------------------
    # TIER 1 — Pre-validation (no network)
    # ------------------------------------------------------------------

    def _tier1_prevalidate(
        self, username: str
    ) -> tuple[CheckStatus, str] | None:
        """
        Instant rejection without making any network requests.
        Returns (status, reason) if the username must be rejected,
        or None to proceed to network checks.
        """
        # Instagram requires 1–30 chars
        if len(username) < 1 or len(username) > 30:
            return CheckStatus.TAKEN, "invalid_length"

        # Structural syntax: leading/trailing/consecutive dots, illegal chars
        if _INVALID_SYNTAX_RE.search(username):
            return CheckStatus.TAKEN, "invalid_syntax"

        # Short handles with a dot are always rejected by Instagram
        # (e.g. uz.n, a.bc — len ≤ 4 and contains '.')
        if "." in username and len(username) <= 4:
            return CheckStatus.TAKEN, "invalid_syntax"

        # Reserved system / navigation names
        if username in _RESERVED_NAMES:
            return CheckStatus.TAKEN, "reserved"

        return None

    # ------------------------------------------------------------------
    # TIER 2 — oEmbed (fast active-profile gate)
    # ------------------------------------------------------------------

    async def _try_oembed(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        """
        Returns kind="ok" (TAKEN) when oEmbed confirms an active public account.
        Returns kind="check_required" to fall through to the HTML tier —
        oEmbed only ever confirms positives, it never proves availability
        (private, banned, deactivated, and checkpointed accounts all fail
        oEmbed too, same as a truly free handle).
        """
        profile_url = f"https://www.instagram.com/{username}/"
        oembed_url = f"{_OEMBED_ENDPOINT}{quote_plus(profile_url)}"
        try:
            resp = await self._request(session, "GET", oembed_url, _OEMBED_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            return {
                "kind": "check_required",
                "error": f"oEmbed network error; falling through: {exc}",
            }

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 200:
            payload = _parse_json_body(resp)
            if payload and ("author_name" in payload or "author_id" in payload):
                return {
                    "kind": "ok",
                    "status": CheckStatus.TAKEN,
                    "source": "oembed_active",
                    "reason": "oembed_active",
                }
            return {
                "kind": "check_required",
                "error": "oEmbed 200 but no account identity — falling through",
            }
        return {
            "kind": "check_required",
            "error": f"oEmbed status {status_code}; falling through to html",
        }

    # ------------------------------------------------------------------
    # TIER 3 — Pure HTML inspection (definitive, deterministic gate)
    # ------------------------------------------------------------------

    async def _try_html(
        self,
        session: AsyncSession,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Fetches the public profile page and applies a strict, ordered
        decision rule. This is the final word — it never returns an
        "indeterminate" outcome; every branch resolves to TAKEN, AVAILABLE,
        or a transport-level ERROR.
        """
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        response = None
        try:
            response = await self._request(
                session,
                "GET",
                profile_url,
                _PROFILE_HEADERS,
                timeout=_PROFILE_TIMEOUT,
            )
        except _NETWORK_EXCEPTIONS as exc:
            if proxy:
                try:
                    async with AsyncSession(
                        **self._session_kwargs(None, _DIRECT_PROFILE_TIMEOUT)
                    ) as direct_session:
                        response = await self._request(
                            direct_session,
                            "GET",
                            profile_url,
                            _PROFILE_HEADERS,
                            timeout=_DIRECT_PROFILE_TIMEOUT,
                        )
                except _NETWORK_EXCEPTIONS as direct_error:
                    return {
                        "kind": "error",
                        "error": f"HTML tier proxy+direct failed: {direct_error}",
                    }
            else:
                return {"kind": "error", "error": f"HTML tier network error: {exc}"}

        if response is None:
            return {"kind": "error", "error": "HTML tier: no response object"}

        response_url = str(getattr(response, "url", ""))
        status_code = int(getattr(response, "status_code", 0) or 0)
        html = _body_text(response)

        # A proxy-triggered checkpoint/challenge redirect is a proxy artifact,
        # not a verdict — retry once directly before deciding anything.
        if proxy and ("checkpoint" in response_url or "challenge" in response_url):
            try:
                async with AsyncSession(
                    **self._session_kwargs(None, _DIRECT_PROFILE_TIMEOUT)
                ) as direct_session:
                    response = await self._request(
                        direct_session,
                        "GET",
                        profile_url,
                        _PROFILE_HEADERS,
                        timeout=_DIRECT_PROFILE_TIMEOUT,
                    )
                response_url = str(getattr(response, "url", ""))
                status_code = int(getattr(response, "status_code", 0) or 0)
                html = _body_text(response)
            except _NETWORK_EXCEPTIONS:
                pass  # keep the proxy-fetched response and decide with what we have

        return self._classify_html(username, status_code, response_url, html)

    def _classify_html(
        self,
        username: str,
        status_code: int,
        response_url: str,
        html: str,
    ) -> dict[str, Any]:
        """
        Deterministic SPA-aware rule:
          1. Redirect/gate URL → TAKEN.
          2. A definite profile marker → TAKEN:
               - any `_TAKEN_BODY_MARKERS` hit, OR
               - the profile's iOS deep-link, OR
               - the username itself appears quoted in the payload
                 alongside a real user-object key ("id":,
                 "has_blocked_viewer", or "is_verified") — this catches
                 accounts (including banned/held ones) whose OpenGraph
                 tags are suppressed but whose SPA bootstrap state still
                 embeds a minimal user record for that exact username.
          3. Anything else → AVAILABLE. Instagram's SPA returns HTTP 200
             with a generic, username-agnostic app shell both for a plain
             404 and for a genuinely unclaimed handle, and does not
             reliably include literal not-found copy in the raw SSR
             payload — so the absence of every marker above is now the
             sole and sufficient signal for availability.
        """
        # ---- 1. Redirect / gate URL ----
        if any(marker in response_url for marker in _TAKEN_URL_MARKERS):
            logger.info("[@%s] html → TAKEN (redirect_gate: %s)", username, response_url)
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "html_redirect_gate",
                "reason": "login_or_checkpoint_redirect",
            }

        # ---- 2. Definite profile markers ----
        deep_link_marker = f"instagram://user?username={username.lower()}"
        ownership_markers = (*_TAKEN_BODY_MARKERS, deep_link_marker)
        hit = next((m for m in ownership_markers if m in html), None)

        username_lower = username.lower()
        quoted_username_hit = (
            f'"{username_lower}"' in html.lower()
            and (
                '"id":' in html
                or '"has_blocked_viewer"' in html
                or '"is_verified"' in html
            )
        )

        if hit is not None or quoted_username_hit:
            marker_detail = hit if hit is not None else "quoted_username+user_object_key"
            logger.info("[@%s] html → TAKEN (marker=%r)", username, marker_detail)
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "html_body_marker",
                "reason": "profile_active_private_or_banned",
            }

        # ---- 3. No definite profile marker anywhere → available ----
        logger.info(
            "[@%s] html → AVAILABLE (status=%d, no definite profile marker)",
            username, status_code,
        )
        return {
            "kind": "ok",
            "status": CheckStatus.AVAILABLE,
            "source": "html_no_profile_marker",
            "reason": "truly_available",
        }

    # ------------------------------------------------------------------
    # Funnel: Tier 1 → Tier 2 → Tier 3
    # ------------------------------------------------------------------

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            # ---- TIER 2: oEmbed (fast active-profile gate) ----
            oembed = await self._try_oembed(session, username)
            if oembed["kind"] == "ok":
                return oembed
            if oembed["kind"] not in ("check_required",):
                return oembed  # propagate unexpected errors

            # ---- TIER 3: Pure HTML inspection (definitive) ----
            return await self._try_html(session, username, proxy)


instagram_checker = InstagramChecker()