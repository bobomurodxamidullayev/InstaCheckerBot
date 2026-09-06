"""
services/checker.py — Instagram username tekshirish servisi.

Gibrid (funnel):
  1) Tezkor filtr: topsearch aniq match YOKI profil HTML markerlari -> TAKEN
  2) Hakam: POST api/v1/web/accounts/web_create_ajax/attempt/
       errors.username (taken / held_by_instagram / har qanday username xato)
         -> TAKEN (mavjud, deactive, ban, 14 kun lock)
       username xatosi yo'q (email xatosi mumkin) yoki status=ok
         -> AVAILABLE
  3) Fallback: signup API tarmoq/429 + profil aniq 404 -> AVAILABLE

Klient: curl_cffi AsyncSession (impersonate=chrome124, verify=False).
Timeout 20s. DataImpulse: har urinishda yangi `_session-{id}` (yangi IP).
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
except ImportError:  # pragma: no cover — versiya farqi
    from curl_cffi.requests.errors import RequestsError as RequestException  # type: ignore

try:
    from curl_cffi.requests.exceptions import RequestsError
except ImportError:  # pragma: no cover
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
_SIGNUP_URL = "https://www.instagram.com/accounts/emailsignup/"
_SIGNUP_ATTEMPT_URL = (
    "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
)
_MAX_RETRIES = 3
_REQUEST_TIMEOUT = 20.0
_IMPERSONATE = "chrome124"
_BACKOFF_BASE = 2.0
_BACKOFF_CAP = 30.0
_IG_APP_ID = "936619743392459"

# Faqat kerakli Accept — rasmlar/og'ir scriptlar yuklanmasin.
_JSON_HEADERS: dict[str, str] = {
    "Accept": "application/json",
    "Referer": "https://www.instagram.com/",
}

_HTML_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml",
    "Referer": "https://www.instagram.com/",
    "Upgrade-Insecure-Requests": "1",
}

_SEARCH_HEADERS = _JSON_HEADERS
_PROFILE_HEADERS = _HTML_HEADERS
_SIGNUP_PAGE_HEADERS = _HTML_HEADERS

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


# ─── Yordamchi Funksiyalar ─────────────────────────────────────────────────────

def _make_session_proxy(base_proxy: str | None) -> str | None:
    """
    DataImpulse rotating proxy: har urinishda yangi sessiya ID.

    Kirish:  http://{login}__cr.us:pass@gw.dataimpulse.com:823
    Chiqish: http://{login}__cr.us_session-{id}:pass@gw.dataimpulse.com:823

    Yangi sessiya ID = majburiy yangi residential IP (429/sticky IP oldini oladi).
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

    return urlunparse(
        (
            parsed.scheme or "http",
            f"{auth}@{host}",
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


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

    google_marks = (
        "www.google.com" in final_url,
        "google.com/" in location,
        "accounts.google" in location,
        "sorry/index" in snippet,
        "<title>google</title>" in snippet,
        "gws" == server,
    )
    return any(google_marks)


_PROFILE_NOT_FOUND_MARKERS = (
    "sorry, this page isn't available",
    "the link you followed may be broken",
    "page not found",
    "this page isn't available",
)


def _og_meta_content(html: str, property_name: str) -> str:
    patterns = (
        rf'property=["\']{re.escape(property_name)}["\'][^>]*content=["\']([^"\']*)["\']',
        rf'content=["\']([^"\']*)["\'][^>]*property=["\']{re.escape(property_name)}["\']',
    )
    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return ""


def _html_proves_existing_profile(html: str, username: str, final_url: str = "") -> bool:
    """
    Profil GET ni TAKEN deb belgilash uchun qat'iy HTML isboti.
    HTTP 200 yetarli emas: login/redirect/404 ham 200 qaytarishi mumkin.
    """
    if not html or len(html.strip()) < 400:
        return False

    lower = html.lower()
    url = (final_url or "").lower()
    if "/accounts/login" in url or "/challenge" in url:
        return False
    if any(marker in lower for marker in _PROFILE_NOT_FOUND_MARKERS):
        return False

    target = username.strip().lstrip("@").lower()
    if not target:
        return False

    og_desc = _og_meta_content(html, "og:description").lower()
    if og_desc and any(word in og_desc for word in ("follower", "following", "posts")):
        return True

    user_re = re.escape(target)
    if re.search(rf'"username"\s*:\s*"{user_re}"', html, re.IGNORECASE):
        if re.search(r'"full_name"\s*:\s*"(?:\\.|[^"\\])+"', html):
            return True
        if re.search(r'"biography"\s*:\s*"(?:\\.|[^"\\])+"', html):
            return True
        if re.search(r'"edge_followed_by"\s*:\s*\{\s*"count"\s*:\s*\d+', html):
            return True

    looks_like_login = (
        "log in to instagram" in lower
        or "/accounts/login" in lower
        or "login_form" in lower
    )
    if looks_like_login:
        return False

    if re.search(
        rf'content=["\'"]https://(?:www\.)?instagram\.com/{user_re}/["\']',
        html,
        re.IGNORECASE,
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
        found = str(user.get("username") or "").strip().lower()
        if found == target:
            return True
    return False


def _extract_csrftoken(response: Any, session: Any) -> str:
    if response is None and session is None:
        return ""

    for jar in (getattr(response, "cookies", None), getattr(session, "cookies", None)):
        if jar is None:
            continue
        try:
            token = jar.get("csrftoken")
        except Exception:
            token = None
        if token:
            return str(token)

    if response is None:
        return ""

    headers = getattr(response, "headers", None)
    raw_values: list[str] = []
    if headers is not None:
        getter = getattr(headers, "get_list", None)
        if callable(getter):
            raw_values.extend(getter("set-cookie") or getter("Set-Cookie") or [])
        else:
            raw = headers.get("set-cookie") or headers.get("Set-Cookie")
            if raw:
                raw_values.append(str(raw))
    for value in raw_values:
        match = re.search(r"csrftoken=([^;]+)", value, re.IGNORECASE)
        if match:
            return match.group(1)

    html = _body_text(response)
    match = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', html)
    if match:
        return match.group(1)
    match = re.search(r"csrf_token=([^&\"']+)", html)
    if match:
        return match.group(1)
    return ""


def _html_is_page_not_found(html: str, status_code: int, final_url: str = "") -> bool:
    """Profil aniq 404 / Page Not Found ekanini tekshiradi (login sahifa emas)."""
    if status_code == 404:
        return True
    url = (final_url or "").lower()
    if "/accounts/login" in url or "/challenge" in url:
        return False
    lower = (html or "").lower()
    return any(marker in lower for marker in _PROFILE_NOT_FOUND_MARKERS)


def _signup_attempt_headers(csrf: str) -> dict[str, str]:
    """
    web_create_ajax/attempt/ uchun kerakli headerlar.
    Referer: emailsignup sahifasi — Instagram validatsiyasi uchun muhim.
    """
    return {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRFToken": csrf or "missing",
        "X-IG-App-ID": _IG_APP_ID,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.instagram.com/accounts/emailsignup/",
        "Origin": "https://www.instagram.com",
    }


def _signup_attempt_body(username: str) -> dict[str, str]:
    """
    web_create_ajax/attempt/ uchun POST body.
    email — tasodifiy (real email shart emas, tekshiruv uchun kerak).
    """
    return {
        "email": f"chk_{secrets.token_hex(6)}@gmail.com",
        "username": username,
        "first_name": "Checker",
        "opt_into_one_tap": "false",
    }


def _username_error_entries(payload: dict[str, Any]) -> list[Any]:
    errors = payload.get("errors")
    if not isinstance(errors, dict):
        return []
    raw = errors.get("username")
    if raw is None or raw is False:
        return []
    if isinstance(raw, list):
        return raw
    return [raw]


def _username_error_codes(entries: list[Any]) -> set[str]:
    codes: set[str] = set()
    for item in entries:
        if isinstance(item, dict):
            code = str(item.get("code") or item.get("error_type") or "").strip().lower()
            if code:
                codes.add(code)
        elif item:
            codes.add(str(item).strip().lower())
    return codes


def _classify_signup_attempt(
    status_code: int,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    web_create_ajax/attempt/ javobi tahlili:

    TAKEN holati:
      - errors.username mavjud -> TAKEN (username_is_taken, username_held_by_instagram,
        deactive, ban, 14 kunlik lock — barchasi shu xato orqali keladi)
      - username_suggestions ro'yxati -> TAKEN
      - JSON ichida "username_is_taken" / "username_held_by_instagram" matni -> TAKEN

    AVAILABLE holati:
      - errors.username yo'q (email xatosi bo'lishi mumkin — bu normal) -> AVAILABLE
      - status == "ok" -> AVAILABLE

    RETRY holati:
      - HTTP 429 -> rate_limited=True
      - JSON emas -> retry
    """
    if status_code == 429:
        return {
            "kind": "retry",
            "rate_limited": True,
            "error": "HTTP 429 Rate Limited (signup attempt)",
        }

    if payload is None:
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": f"signup attempt JSON emas (HTTP {status_code})",
        }

    # 1) errors.username bo'limi — asosiy hakam
    username_errors = _username_error_entries(payload)
    if username_errors:
        codes = _username_error_codes(username_errors)
        logger.debug("signup attempt username errors=%s", codes or username_errors)
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    # 2) username_suggestions bo'lsa — nom band
    suggestions = payload.get("username_suggestions")
    if isinstance(suggestions, list) and suggestions:
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    # 3) JSON ichida known TAKEN kodlari (ba'zi javoblarda errors tuzilmasi yo'q)
    blob = json.dumps(payload, ensure_ascii=False).lower()
    if "username_is_taken" in blob or "username_held_by_instagram" in blob:
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    # 4) Username xatosi yo'q => AVAILABLE
    #    (email xatosi bo'lishi mumkin — bu normal, username bo'sh ekanini bildiradi)
    return {"kind": "ok", "status": CheckStatus.AVAILABLE}


# ─── Asosiy tekshiruvchi sinf ──────────────────────────────────────────────────

class InstagramChecker:
    """Instagram username mavjudligini topsearch + web_create_ajax/attempt/ orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | client=curl_cffi/%s | api=topsearch+web_create_ajax/attempt",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
            _IMPERSONATE,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (funnel: topsearch + web_create_ajax/attempt, curl_cffi/%s) | proxy=%s",
            _IMPERSONATE,
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

        Qaytadi: CheckResult (status / username / error_message).
        Dict: result.to_dict()
          {"status": "available"|"taken"|"error", "username": ..., "error": str|None}
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
            logger.warning(
                "[@%s] Allaqachon tekshirilmoqda, takroriy so'rov bloklandi.",
                username_clean,
            )
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
            logger.exception("[@%s] Event loop xavfsizligi: ushlanmagan xato", username_clean)
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
            # Har urinishda majburiy yangi DataImpulse sessiya (yangi IP).
            session_proxy = self._get_session_proxy()
            skip_topsearch = attempt > 1
            logger.debug(
                "[@%s] Urinish %d/%d | yangi proxy sessiya | skip_topsearch=%s",
                username,
                attempt,
                max_retries,
                skip_topsearch,
            )

            if attempt == 1:
                await asyncio.sleep(
                    random.uniform(settings.check_delay_min, settings.check_delay_max)
                )
            else:
                await asyncio.sleep(random.uniform(0.35, 0.9))

            try:
                result = await self._funnel_check(
                    username,
                    session_proxy,
                    skip_topsearch=skip_topsearch,
                )
            except _NETWORK_EXCEPTIONS as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "[@%s] Tarmoq/SSL xatosi [%s] (urinish %d/%d): %s",
                    username,
                    type(exc).__name__,
                    attempt,
                    max_retries,
                    exc,
                )
                continue
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "[@%s] Kutilmagan xato [%s] (urinish %d/%d): %s",
                    username,
                    type(exc).__name__,
                    attempt,
                    max_retries,
                    exc,
                )
                continue

            if result["kind"] == "ok":
                status: CheckStatus = result["status"]
                source = result.get("source", "signup_attempt")
                logger.info("[@%s] %s (%s)", username, status.value, source)
                return CheckResult(
                    username=username,
                    status=status,
                    attempts=attempt,
                )

            last_error = str(result.get("error") or last_error)

            if result.get("rate_limited"):
                delay = _backoff_delay(attempt)
                logger.warning(
                    "[@%s] HTTP 429 | yangi IP + backoff %.1fs | urinish %d/%d",
                    username,
                    delay,
                    attempt,
                    max_retries,
                )
                await asyncio.sleep(delay)
                continue

            logger.warning(
                "[@%s] %s (urinish %d/%d)",
                username,
                last_error,
                attempt,
                max_retries,
            )

        logger.error(
            "[@%s] Barcha %d urinish muvaffaqiyatsiz | Oxirgi xato: %s",
            username,
            max_retries,
            last_error,
        )
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

    async def _try_topsearch(
        self,
        session: AsyncSession,
        username: str,
        search_url: str,
    ) -> dict[str, Any]:
        """
        kind=ok      -> TAKEN (aniq username match topildi)
        kind=continue -> JSON OK, aniq match yo'q — keyingi bosqichga o't
        kind=skip    -> timeout/429/SSL/noto'g'ri javob — profil GET bosqichiga o't
        """
        try:
            search_resp = await self._request(session, "GET", search_url, _SEARCH_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] topsearch tarmoq/timeout/SSL: %s — profil GET", username, exc)
            return {"kind": "skip", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(search_resp):
            logger.warning("[@%s] topsearch noto'g'ri origin — profil GET", username)
            return {"kind": "skip", "error": "Proxy noto'g'ri origin (topsearch)"}

        search_status = int(getattr(search_resp, "status_code", 0) or 0)
        if search_status == 429:
            logger.warning("[@%s] topsearch HTTP 429 — yangi IP + profil GET", username)
            return {"kind": "skip", "rate_limited": True, "error": "HTTP 429 Rate Limited (topsearch)"}

        payload = _parse_json_body(search_resp)
        if payload is None:
            logger.warning(
                "[@%s] topsearch JSON emas (HTTP %d) — profil GET",
                username,
                search_status,
            )
            return {"kind": "skip", "error": f"topsearch JSON emas (HTTP {search_status})"}

        if _exact_username_in_search(payload, username):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "topsearch"}

        logger.debug(
            "[@%s] topsearch da aniq match yo'q | users=%d | profil GET",
            username,
            len(payload.get("users") or []) if isinstance(payload.get("users"), list) else 0,
        )
        return {"kind": "continue"}

    async def _try_profile_get(
        self,
        session: AsyncSession,
        username: str,
        profile_url: str,
    ) -> dict[str, Any]:
        """
        kind=ok       -> TAKEN (HTML da qat'iy profil markerlari bo'lsa)
        kind=continue -> login/404/bo'sh/marker yo'q — signup_attempt ga o't
        kind=skip     -> timeout/429/SSL — signup_attempt ga o't
        """
        try:
            html_resp = await self._request(session, "GET", profile_url, _PROFILE_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] profil GET tarmoq/timeout/SSL: %s — signup attempt", username, exc)
            return {"kind": "skip", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(html_resp):
            logger.warning("[@%s] profil GET noto'g'ri origin — signup attempt", username)
            return {"kind": "skip", "error": "Proxy noto'g'ri origin (profile GET)"}

        html_status = int(getattr(html_resp, "status_code", 0) or 0)
        if html_status == 429:
            logger.warning("[@%s] profil GET HTTP 429 — yangi IP + signup attempt", username)
            return {"kind": "skip", "rate_limited": True, "error": "HTTP 429 Rate Limited (profile GET)"}

        html = _body_text(html_resp)
        final_url = str(getattr(html_resp, "url", "") or "")
        if html_status == 200 and _html_proves_existing_profile(html, username, final_url):
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "profile GET",
                "response": html_resp,
            }

        logger.debug(
            "[@%s] profil GET HTTP %d, qat'iy marker yo'q | signup attempt tasdiqlash",
            username,
            html_status,
        )
        # html, html_status, final_url — fallback uchun saqlanadi
        return {
            "kind": "continue",
            "response": html_resp,
            "html": html,
            "html_status": html_status,
            "final_url": final_url,
        }

    async def _finish_with_signup(
        self,
        username: str,
        session: AsyncSession,
        profile_result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Profil GET natijasiga qarab:
        - ok      -> TAKEN qaytaradi
        - continue -> signup attempt POST bilan tasdiqlaydi
        - skip    -> yangi IP bilan signup attempt POST
        """
        if profile_result["kind"] == "ok":
            return profile_result

        if profile_result["kind"] == "continue":
            prior_resp = profile_result.get("response")
            classified = await self._signup_attempt_in_session(session, username, prior_resp)

            # 429 -> yangi IP bilan bir marta qayta urinish
            if classified.get("rate_limited"):
                logger.warning(
                    "[@%s] signup attempt HTTP 429 | yangi proxy IP, qayta urinish",
                    username,
                )
                return await self._signup_attempt_fresh(username, self._get_session_proxy())

            # Fallback: signup attempt ham muvaffaqiyatsiz + profil aniq 404 -> AVAILABLE
            if classified["kind"] == "retry":
                html = profile_result.get("html", "")
                html_status = profile_result.get("html_status", 0)
                final_url = profile_result.get("final_url", "")
                if _html_is_page_not_found(html, html_status, final_url):
                    logger.info(
                        "[@%s] Fallback: signup API xato + profil 404 -> AVAILABLE",
                        username,
                    )
                    return {
                        "kind": "ok",
                        "status": CheckStatus.AVAILABLE,
                        "source": "fallback_404",
                    }

            return classified

        # kind=skip — profil GET o'tkazildi, yangi IP bilan signup attempt
        logger.info("[@%s] profil GET o'tkazildi, yangi IP bilan signup attempt", username)
        return await self._signup_attempt_fresh(username, self._get_session_proxy())

    async def _signup_attempt_fresh(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """Yangi sessiya/IP bilan faqat signup attempt POST."""
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            return await self._signup_attempt_in_session(session, username, None)

    async def _signup_attempt_in_session(
        self,
        session: AsyncSession,
        username: str,
        prior_response: Any,
    ) -> dict[str, Any]:
        """
        1) emailsignup sahifasini GET qilib csrftoken oladi.
        2) web_create_ajax/attempt/ ga POST yuboradi.
        3) Javobni _classify_signup_attempt() bilan tahlil qiladi.

        TAKEN:     errors.username mavjud (username_is_taken, username_held_by_instagram,
                   deactive, ban, 14 kun lock — barchasi shu bo'lim orqali keladi)
        AVAILABLE: username xatosi yo'q (email xatosi mumkin — bu normal)
        """
        # Qadam 1: CSRF token olish uchun emailsignup sahifasini GET
        try:
            signup_resp = await self._request(
                session, "GET", _SIGNUP_URL, _SIGNUP_PAGE_HEADERS
            )
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] emailsignup GET tarmoq/timeout/SSL: %s", username, exc)
            return {
                "kind": "retry",
                "rate_limited": True,
                "error": f"{type(exc).__name__}: {exc}",
            }

        if _is_wrong_origin(signup_resp):
            return {
                "kind": "retry",
                "rate_limited": False,
                "error": "Proxy noto'g'ri origin (emailsignup GET)",
            }

        signup_status = int(getattr(signup_resp, "status_code", 0) or 0)
        if signup_status == 429:
            return {
                "kind": "retry",
                "rate_limited": True,
                "error": "HTTP 429 Rate Limited (emailsignup GET)",
            }

        # CSRF token: cookies -> Set-Cookie header -> HTML -> random fallback
        csrf = (
            _extract_csrftoken(signup_resp, session)
            or _extract_csrftoken(prior_response, session)
            or secrets.token_hex(16)
        )
        logger.debug("[@%s] csrf_token=%s...", username, csrf[:8] if csrf else "—")

        # Qadam 2: web_create_ajax/attempt/ ga POST
        attempt_headers = _signup_attempt_headers(csrf)
        attempt_body = _signup_attempt_body(username)
        try:
            attempt_resp = await self._request(
                session,
                "POST",
                _SIGNUP_ATTEMPT_URL,
                attempt_headers,
                data=attempt_body,
            )
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] signup attempt POST tarmoq/timeout/SSL: %s", username, exc)
            return {
                "kind": "retry",
                "rate_limited": True,
                "error": f"{type(exc).__name__}: {exc}",
            }

        if _is_wrong_origin(attempt_resp):
            return {
                "kind": "retry",
                "rate_limited": False,
                "error": "Proxy noto'g'ri origin (signup attempt POST)",
            }

        status_code = int(getattr(attempt_resp, "status_code", 0) or 0)
        payload = _parse_json_body(attempt_resp)
        logger.debug(
            "[@%s] signup attempt POST -> HTTP %d | payload_keys=%s",
            username,
            status_code,
            list(payload.keys()) if isinstance(payload, dict) else None,
        )

        # Qadam 3: Natijani tasnifla
        classified = _classify_signup_attempt(status_code, payload)
        if classified["kind"] == "ok":
            classified["source"] = "signup_attempt"
        return classified

    async def _funnel_check(
        self,
        username: str,
        proxy: str | None,
        skip_topsearch: bool = False,
    ) -> dict[str, Any]:
        """
        Funnel (bosqichma-bosqich):
        1) topsearch aniq match -> TAKEN
        2) Profil GET HTML markerlari -> TAKEN
        3) web_create_ajax/attempt/ POST -> TAKEN yoki AVAILABLE
        4) Fallback (signup xato + profil 404) -> AVAILABLE
        """
        search_url = _TOPSEARCH_URL.format(query=quote(username, safe="._"))
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        current_proxy = proxy

        if not skip_topsearch:
            kwargs = self._session_kwargs(current_proxy)
            async with AsyncSession(**kwargs) as session:
                search_result = await self._try_topsearch(session, username, search_url)
                if search_result["kind"] == "ok":
                    return search_result
                if search_result["kind"] == "continue":
                    profile_result = await self._try_profile_get(session, username, profile_url)
                    return await self._finish_with_signup(username, session, profile_result)

            current_proxy = self._get_session_proxy()
            logger.info("[@%s] topsearch o'tkazildi, yangi IP bilan profil GET", username)
        else:
            logger.info("[@%s] retry: topsearch o'tkazildi, profil GET", username)

        kwargs = self._session_kwargs(current_proxy)
        async with AsyncSession(**kwargs) as session:
            profile_result = await self._try_profile_get(session, username, profile_url)
            return await self._finish_with_signup(username, session, profile_result)


instagram_checker = InstagramChecker()
