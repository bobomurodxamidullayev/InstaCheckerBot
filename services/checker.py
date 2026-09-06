"""
services/checker.py — Instagram username tekshirish servisi.

Funnel:
  1) Tezkor filtr: topsearch aniq match -> TAKEN
  2) Asosiy hakam: Instagram Android App API
       POST https://i.instagram.com/api/v1/users/check_username/
       available: true  -> AVAILABLE
       available: false -> TAKEN (faol, deactive, ban, 14 kun lock)
  3) Zaxira (faqat tarmoq xatosi bo'lsa): profil GET HTML marker
       marker bor -> TAKEN
       404 / marker yo'q -> AVAILABLE

Klient: curl_cffi AsyncSession (impersonate=chrome124, verify=False).
Timeout 20s. DataImpulse: har urinishda yangi _session-{id} (yangi IP).
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, unquote, urlparse, urlunparse

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

# ─── Konstantlar ──────────────────────────────────────────────────────────────

_TOPSEARCH_URL = (
    "https://www.instagram.com/web/search/topsearch/?context=blended&query={query}"
)
_PROFILE_URL = "https://www.instagram.com/{username}/"

# Instagram Android App rasmiy username tekshiruv endpointi
_APP_CHECK_URL = "https://i.instagram.com/api/v1/users/check_username/"

# Android App User-Agent — bu endpoint faqat app so'rovlariga javob beradi
_APP_USER_AGENT = (
    "Instagram 269.0.0.18.75 Android (30/11; 480dpi; 1080x2176; "
    "Xiaomi; laurel_sprout; qcom; ru_RU; 314665256)"
)

_MAX_RETRIES = 3
_REQUEST_TIMEOUT = 20.0
_IMPERSONATE = "chrome124"
_BACKOFF_BASE = 2.0
_BACKOFF_CAP = 30.0

_JSON_HEADERS: dict[str, str] = {
    "Accept": "application/json",
    "Referer": "https://www.instagram.com/",
}

_HTML_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml",
    "Referer": "https://www.instagram.com/",
    "Upgrade-Insecure-Requests": "1",
}

_APP_CHECK_HEADERS: dict[str, str] = {
    "User-Agent": _APP_USER_AGENT,
    "Accept-Language": "en-US",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "Accept": "*/*",
    "X-IG-Capabilities": "3brTvw==",
    "X-IG-Connection-Type": "WIFI",
}

_SEARCH_HEADERS = _JSON_HEADERS
_PROFILE_HEADERS = _HTML_HEADERS

_NETWORK_EXCEPTIONS = (
    RequestsError,
    RequestException,
    CurlError,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
)

_USERNAME_RE = re.compile(r"^[a-z0-9._]{1,30}$")

_PROFILE_NOT_FOUND_MARKERS = (
    "sorry, this page isn't available",
    "the link you followed may be broken",
    "page not found",
    "this page isn't available",
)


# ─── Natija dataclass ──────────────────────────────────────────────────────────

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


# ─── Yordamchi funksiyalar ─────────────────────────────────────────────────────

def _make_session_proxy(base_proxy: str | None) -> str | None:
    """
    DataImpulse rotating proxy: har urinishda yangi sessiya ID.
    Kirish:  http://{login}__cr.us:pass@gw.dataimpulse.com:823
    Chiqish: http://{login}__cr.us_session-{id}:pass@gw.dataimpulse.com:823
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


def _backoff_delay(attempt: int) -> float:
    """HTTP 429 uchun exponential backoff (+ kichik jitter)."""
    delay = min(_BACKOFF_BASE * (2 ** (attempt - 1)), _BACKOFF_CAP)
    delay = min(delay, float(settings.rate_limit_sleep))
    return delay + random.uniform(0.15, 0.75)


def _header_get(headers: Any, name: str) -> str:
    if not headers:
        return ""
    try:
        value = headers.get(name) or headers.get(name.lower()) or headers.get(name.title())
    except Exception:
        return ""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return " ".join(str(v) for v in value)
    return str(value)


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


def _is_wrong_origin(response: Any) -> bool:
    """Proxy Instagram o'rniga Google yoki boshqa host qaytarsa — retry."""
    final_url = str(getattr(response, "url", "") or "").lower()
    location = _header_get(getattr(response, "headers", None), "location").lower()
    snippet = _body_text(response)[:800].lower()
    server = _header_get(getattr(response, "headers", None), "server").lower()
    return any((
        "www.google.com" in final_url,
        "google.com/" in location,
        "accounts.google" in location,
        "sorry/index" in snippet,
        "<title>google</title>" in snippet,
        server == "gws",
    ))


def _og_meta_content(html: str, property_name: str) -> str:
    patterns = (
        rf'property=["\']{re.escape(property_name)}["\'][^>]*content=["\']([^"\']*)["\']',
        rf'content=["\']([^"\']*)["\'][^>]*property=["\']{re.escape(property_name)}["\']',
    )
    for pattern in patterns:
        m = re.search(pattern, html, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _html_proves_existing_profile(html: str, username: str, final_url: str = "") -> bool:
    """HTML ichida haqiqiy profil markerlari borligini tekshiradi."""
    if not html or len(html.strip()) < 400:
        return False
    lower = html.lower()
    url = (final_url or "").lower()
    if "/accounts/login" in url or "/challenge" in url:
        return False
    if any(m in lower for m in _PROFILE_NOT_FOUND_MARKERS):
        return False
    target = username.strip().lstrip("@").lower()
    if not target:
        return False
    og_desc = _og_meta_content(html, "og:description").lower()
    if og_desc and any(w in og_desc for w in ("follower", "following", "posts")):
        return True
    user_re = re.escape(target)
    if re.search(rf'"username"\s*:\s*"{user_re}"', html, re.IGNORECASE):
        if re.search(r'"full_name"\s*:\s*"(?:\\.|[^"\\])+"', html):
            return True
        if re.search(r'"biography"\s*:\s*"(?:\\.|[^"\\])+"', html):
            return True
        if re.search(r'"edge_followed_by"\s*:\s*\{\s*"count"\s*:\s*\d+', html):
            return True
    if "log in to instagram" in lower or "login_form" in lower:
        return False
    if re.search(
        rf'content=["\'"]https://(?:www\.)?instagram\.com/{user_re}/["\']',
        html, re.IGNORECASE,
    ):
        return True
    return False


def _exact_username_in_search(payload: dict[str, Any], username: str) -> bool:
    users = payload.get("users")
    if not isinstance(users, list):
        return False
    target = username.lower()
    for item in users:
        if not isinstance(item, dict):
            continue
        user = item.get("user")
        if not isinstance(user, dict):
            continue
        if str(user.get("username") or "").strip().lower() == target:
            return True
    return False


def _classify_app_check(
    status_code: int,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Android App check_username endpointi javobini tahlil qiladi.

    available: true  -> AVAILABLE (nom haqiqatan bo'sh)
    available: false -> TAKEN (faol, deactive, ban, spam-lock — barchasi false beradi)
    status: fail     -> TAKEN
    429              -> retry
    JSON emas        -> retry
    """
    if status_code == 429:
        return {"kind": "retry", "rate_limited": True,
                "error": "HTTP 429 Rate Limited (app check)"}

    if payload is None:
        return {"kind": "retry", "rate_limited": False,
                "error": f"App check JSON emas (HTTP {status_code})"}

    # available: true -> AVAILABLE
    available = payload.get("available")
    if available is True:
        return {"kind": "ok", "status": CheckStatus.AVAILABLE, "source": "app_check"}

    # status: fail yoki available: false -> TAKEN
    if available is False:
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "app_check"}

    status_field = str(payload.get("status") or "").lower()
    if status_field == "fail":
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "app_check"}

    # username_is_taken matnini ham tekshir
    blob = json.dumps(payload, ensure_ascii=False).lower()
    if "username_is_taken" in blob or "username_held" in blob:
        return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "app_check"}

    # Noma'lum holat — ehtiyot tomoni: retry
    return {"kind": "retry", "rate_limited": False,
            "error": f"App check noma'lum javob (HTTP {status_code}): {list(payload.keys())}"}


# ─── Asosiy tekshiruvchi sinf ──────────────────────────────────────────────────

class InstagramChecker:
    """
    Instagram username mavjudligini tekshiradi.

    Funnel:
      1) topsearch exact match  -> TAKEN
      2) Android App API        -> AVAILABLE / TAKEN
      3) Zaxira (tarmoq xato)   -> profil GET HTML marker -> TAKEN / AVAILABLE
    """

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=topsearch+app_check_username",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (topsearch + Android App API) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    def _get_session_proxy(self) -> str | None:
        """Har chaqiruvda yangi DataImpulse sessiya ID = yangi IP."""
        return _make_session_proxy(self._base_proxy)

    def _session_kwargs(self, proxy: str | None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _REQUEST_TIMEOUT,
            "max_clients": 1,
            "verify": False,
            "allow_redirects": True,
            "headers": _HTML_HEADERS,
        }
        if proxy:
            kwargs["proxy"] = proxy
        return kwargs

    async def check_username(
        self,
        username: str,
        max_retries: int = _MAX_RETRIES,
    ) -> CheckResult:
        """
        Username holatini tekshiradi.
        Qaytadi: CheckResult — result.to_dict() -> {"status": "available"|"taken"|"error", ...}
        """
        username_clean = username.strip().lstrip("@").lower()

        if not _USERNAME_RE.fullmatch(username_clean):
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message="Noto'g'ri username formati",
                attempts=0,
            )

        if username_clean in self._checking_usernames:
            logger.warning("[@%s] Parallel tekshiruv bloklandi.", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message="Parallel tekshiruv bloklandi",
                attempts=0,
            )

        self._checking_usernames.add(username_clean)
        try:
            return await self._check_with_retries(username_clean, max_retries)
        except Exception as exc:
            logger.exception("[@%s] Ushlanmagan xato", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=f"{type(exc).__name__}: {exc}",
                attempts=max_retries,
            )
        finally:
            self._checking_usernames.discard(username_clean)

    async def _check_with_retries(self, username: str, max_retries: int) -> CheckResult:
        last_error = "Noma'lum xato"

        for attempt in range(1, max_retries + 1):
            session_proxy = self._get_session_proxy()
            skip_topsearch = attempt > 1
            logger.debug(
                "[@%s] Urinish %d/%d | skip_topsearch=%s",
                username, attempt, max_retries, skip_topsearch,
            )

            delay = (
                random.uniform(settings.check_delay_min, settings.check_delay_max)
                if attempt == 1
                else random.uniform(0.35, 0.9)
            )
            await asyncio.sleep(delay)

            try:
                result = await self._funnel_check(
                    username, session_proxy, skip_topsearch=skip_topsearch
                )
            except _NETWORK_EXCEPTIONS as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("[@%s] Tarmoq xatosi [%s] (%d/%d): %s",
                               username, type(exc).__name__, attempt, max_retries, exc)
                continue
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning("[@%s] Kutilmagan xato [%s] (%d/%d): %s",
                               username, type(exc).__name__, attempt, max_retries, exc)
                continue

            if result["kind"] == "ok":
                status: CheckStatus = result["status"]
                source = result.get("source", "unknown")
                logger.info("[@%s] %s (%s)", username, status.value, source)
                return CheckResult(username=username, status=status, attempts=attempt)

            last_error = str(result.get("error") or last_error)

            if result.get("rate_limited"):
                delay = _backoff_delay(attempt)
                logger.warning("[@%s] HTTP 429 | backoff %.1fs | %d/%d",
                               username, delay, attempt, max_retries)
                await asyncio.sleep(delay)
                continue

            logger.warning("[@%s] %s (%d/%d)", username, last_error, attempt, max_retries)

        logger.error("[@%s] Barcha %d urinish muvaffaqiyatsiz | %s",
                     username, max_retries, last_error)
        return CheckResult(
            username=username,
            status=CheckStatus.ERROR,
            error_message=last_error,
            attempts=max_retries,
        )

    async def _request(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        headers: dict[str, str],
        data: dict[str, str] | None = None,
    ) -> Any:
        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": _REQUEST_TIMEOUT,
            "allow_redirects": True,
            "verify": False,
            "impersonate": _IMPERSONATE,
        }
        if method == "POST":
            return await session.post(url, data=data or {}, **kwargs)
        return await session.get(url, **kwargs)

    # ── 1-bosqich: topsearch ──────────────────────────────────────────────────

    async def _try_topsearch(
        self,
        session: AsyncSession,
        username: str,
        search_url: str,
    ) -> dict[str, Any]:
        """
        kind=ok       -> TAKEN (aniq match topildi)
        kind=continue -> JSON OK, match yo'q — keyingi bosqichga
        kind=skip     -> tarmoq/429 xato — keyingi bosqichga
        """
        try:
            resp = await self._request(session, "GET", search_url, _SEARCH_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] topsearch xato: %s", username, exc)
            return {"kind": "skip", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(resp):
            return {"kind": "skip", "error": "Proxy noto'g'ri origin (topsearch)"}

        sc = int(getattr(resp, "status_code", 0) or 0)
        if sc == 429:
            logger.warning("[@%s] topsearch HTTP 429", username)
            return {"kind": "skip", "rate_limited": True,
                    "error": "HTTP 429 Rate Limited (topsearch)"}

        payload = _parse_json_body(resp)
        if payload is None:
            return {"kind": "skip", "error": f"topsearch JSON emas (HTTP {sc})"}

        if _exact_username_in_search(payload, username):
            logger.debug("[@%s] topsearch: exact match -> TAKEN", username)
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "topsearch"}

        logger.debug("[@%s] topsearch: match yo'q -> app check", username)
        return {"kind": "continue"}

    # ── 2-bosqich: Android App API ────────────────────────────────────────────

    async def _try_app_check(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        POST https://i.instagram.com/api/v1/users/check_username/
        Android App User-Agent bilan.

        kind=ok (AVAILABLE) -> available: true
        kind=ok (TAKEN)     -> available: false / status: fail
        kind=retry          -> 429 / tarmoq xato / JSON emas
        """
        # Sticky sessiya: GET va POST bir xil IP dan — bu yerda faqat POST bor
        sticky_proxy = _make_session_proxy(self._base_proxy) if self._base_proxy else proxy
        kwargs = self._session_kwargs(sticky_proxy)
        async with AsyncSession(**kwargs) as session:
            try:
                resp = await self._request(
                    session,
                    "POST",
                    _APP_CHECK_URL,
                    _APP_CHECK_HEADERS,
                    data={"username": username},
                )
            except _NETWORK_EXCEPTIONS as exc:
                logger.warning("[@%s] app check tarmoq/timeout/SSL: %s", username, exc)
                return {"kind": "retry", "rate_limited": True,
                        "error": f"{type(exc).__name__}: {exc}"}

            if _is_wrong_origin(resp):
                return {"kind": "retry", "rate_limited": False,
                        "error": "Proxy noto'g'ri origin (app check)"}

            sc = int(getattr(resp, "status_code", 0) or 0)
            payload = _parse_json_body(resp)
            logger.debug(
                "[@%s] app check POST -> HTTP %d | available=%s | status=%s",
                username, sc,
                payload.get("available") if payload else None,
                payload.get("status") if payload else None,
            )
            return _classify_app_check(sc, payload)

    # ── 3-bosqich: Profil GET zaxira ──────────────────────────────────────────

    async def _try_profile_fallback(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        App check 429 yoki tarmoq xatosi bo'lganda profil GET zaxirasi.

        kind=ok (TAKEN)
          source=profile_marker       -> HTML da faol profil teglari topildi
          source=profile_deactive_200 -> HTTP 200 lekin marker yo'q
                                         (deactive / banned akkauntlar shunday beradi)
        kind=ok (AVAILABLE)
          source=profile_404          -> HTTP 404 yoki "Page Not Found"
        kind=skip -> tarmoq/429 xato, ham bo'lmadi -> yuqori qatlamga
        """
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        sticky_proxy = _make_session_proxy(self._base_proxy) if self._base_proxy else proxy
        kwargs = self._session_kwargs(sticky_proxy)
        async with AsyncSession(**kwargs) as session:
            try:
                resp = await self._request(session, "GET", profile_url, _PROFILE_HEADERS)
            except _NETWORK_EXCEPTIONS as exc:
                logger.warning("[@%s] profil GET zaxira tarmoq/SSL: %s", username, exc)
                return {"kind": "skip", "error": f"{type(exc).__name__}: {exc}"}

            if _is_wrong_origin(resp):
                return {"kind": "skip", "error": "Proxy noto'g'ri origin (profile fallback)"}

            sc = int(getattr(resp, "status_code", 0) or 0)
            if sc == 429:
                return {"kind": "skip", "rate_limited": True,
                        "error": "HTTP 429 Rate Limited (profile fallback)"}

            html = _body_text(resp)
            final_url = str(getattr(resp, "url", "") or "")

            # ── Faol profil markerlari bor -> TAKEN ───────────────────────────
            if _html_proves_existing_profile(html, username, final_url):
                logger.info("[@%s] profil zaxira: marker topildi -> TAKEN", username)
                return {"kind": "ok", "status": CheckStatus.TAKEN,
                        "source": "profile_marker"}

            # ── HTTP 404 yoki "Page Not Found" -> AVAILABLE ───────────────────
            lower = html.lower()
            is_page_not_found = (
                sc == 404
                or "sorry, this page isn't available" in lower
                or "page not found" in lower
                or "the link you followed may be broken" in lower
            )
            if is_page_not_found:
                logger.info("[@%s] profil zaxira: 404/Page Not Found -> AVAILABLE", username)
                return {"kind": "ok", "status": CheckStatus.AVAILABLE,
                        "source": "profile_404"}

            # ── HTTP 200 lekin marker yo'q -> TAKEN (deactive/banned) ─────────
            # Instagram mavjud bo'lmagan nomlar 404 beradi.
            # 200 + marker yo'q = akkaunt o'chiq (deactive/ban/lock).
            if sc == 200:
                logger.info(
                    "[@%s] profil zaxira: HTTP 200, marker yo'q -> TAKEN (deactive/ban)",
                    username,
                )
                return {"kind": "ok", "status": CheckStatus.TAKEN,
                        "source": "profile_deactive_200"}

            # ── Noma'lum status -> TAKEN (ehtiyot tomoni) ─────────────────────
            logger.info(
                "[@%s] profil zaxira: HTTP %d noma'lum -> TAKEN (xavfsiz)", username, sc,
            )
            return {"kind": "ok", "status": CheckStatus.TAKEN,
                    "source": "profile_deactive_200"}

    # ── Asosiy funnel ─────────────────────────────────────────────────────────

    async def _funnel_check(
        self,
        username: str,
        proxy: str | None,
        skip_topsearch: bool = False,
    ) -> dict[str, Any]:
        """
        1) topsearch exact match   -> TAKEN
        2) Android App API check   -> AVAILABLE / TAKEN
        3) App 429 yoki tarmoq xato bo'lsa darhol profil GET zaxirasi:
             marker       -> TAKEN  (source: profile_marker)
             404/not found-> AVAILABLE  (source: profile_404)
             200/no marker-> TAKEN  (source: profile_deactive_200)
             zaxira ham skip -> TAKEN (hech qachon ERROR emas)
        """
        search_url = _TOPSEARCH_URL.format(query=quote(username, safe="._"))

        # ── 1-bosqich: topsearch ──────────────────────────────────────────────
        if not skip_topsearch:
            kwargs = self._session_kwargs(proxy)
            async with AsyncSession(**kwargs) as session:
                ts = await self._try_topsearch(session, username, search_url)
            if ts["kind"] == "ok":
                return ts
            # skip yoki continue — app check ga o't
        else:
            logger.debug("[@%s] retry: topsearch o'tkazildi", username)

        # ── 2-bosqich: Android App API ────────────────────────────────────────
        app_result = await self._try_app_check(username, proxy)

        if app_result["kind"] == "ok":
            return app_result

        # App check xato (429 yoki tarmoq) -> DARHOL profil GET zaxirasi
        # Loop ga qaytmaslik uchun bu yerda hal qilinadi
        err_msg = app_result.get("error", "app check xato")
        is_rate = app_result.get("rate_limited", False)
        logger.info(
            "[@%s] app check %s (%s) -> profil GET zaxirasi",
            username,
            "HTTP 429" if is_rate else "xato",
            err_msg,
        )

        # ── 3-bosqich: profil GET zaxira ──────────────────────────────────────
        fallback = await self._try_profile_fallback(username, proxy)
        if fallback["kind"] == "ok":
            return fallback

        # Profil zaxira ham skip/xato bo'ldi -> TAKEN (eng xavfsiz tomon)
        # Foydalanuvchi hech qachon ERROR ko'rmasin
        logger.warning(
            "[@%s] profil zaxira ham xato (%s) -> TAKEN (xavfsiz yopish)",
            username, fallback.get("error"),
        )
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "ultimate_fallback",
        }


instagram_checker = InstagramChecker()
