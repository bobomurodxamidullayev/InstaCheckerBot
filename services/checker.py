"""
services/checker.py — Instagram username tekshirish servisi.

3-bosqichli funnel (bitta sticky proxy sessiyasi):
  1) Topsearch exact match -> TAKEN
  2) Web registration attempt -> TAKEN / AVAILABLE (haqiqiy hakam)
  3) HTML fallback faqat Tier 2 429 / SSL / tarmoq xatosida

Hech qachon foydalanuvchiga uncaught ERROR (429, SSL, timeout) qaytmaydi:
tarmoq xatosi fallback ga, fallback ham yiqilsa xavfsiz TAKEN.
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

_TOPSEARCH_URL = (
    "https://www.instagram.com/web/search/topsearch/?context=blended&query={query}"
)
_SIGNUP_PAGE_URL = "https://www.instagram.com/accounts/emailsignup/"
_SIGNUP_ATTEMPT_URL = (
    "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
)
_PROFILE_URL = "https://www.instagram.com/{username}/"

_REQUEST_TIMEOUT = 20.0
_IMPERSONATE = "chrome124"
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_JSON_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_UA,
    "Accept": "application/json",
    "Referer": "https://www.instagram.com/",
}

_HTML_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Referer": "https://www.instagram.com/",
    "Upgrade-Insecure-Requests": "1",
}

_SIGNUP_POST_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_UA,
    "X-IG-App-ID": "936619743392459",
    "X-ASBD-ID": "129477",
    "X-Requested-With": "XMLHttpRequest",
    "Referer": "https://www.instagram.com/accounts/emailsignup/",
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Origin": "https://www.instagram.com",
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

_USERNAME_RE = re.compile(r"^[a-z0-9._]{1,30}$")

_PAGE_NOT_FOUND_MARKERS = (
    "page not found",
    "sorry, this page isn't available",
    "the link you followed may be broken",
    "<title>page not found",
)

_USERNAME_TAKEN_CODES = (
    "username_is_taken",
    "username_held_by_someone",
    "username_unavailable",
    "username_held_for_someone",
    "username_taken",
)


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


def _make_session_proxy(base_proxy: str | None) -> str | None:
    """
    DataImpulse rotating proxy: bitta check uchun bitta sticky session ID.
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
    """Proxy Instagram o'rniga Google yoki boshqa host qaytarsa — bu bosqichni o'tkaz."""
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


def _csrf_from_session(session: Any) -> str:
    cookies = getattr(session, "cookies", None)
    if not cookies:
        return ""
    try:
        value = cookies.get("csrftoken")
        if value:
            return str(value)
    except Exception:
        pass
    try:
        for cookie in cookies:
            name = getattr(cookie, "name", None)
            if name is None and isinstance(cookie, (tuple, list)) and cookie:
                name = cookie[0]
            if str(name).lower() != "csrftoken":
                continue
            value = getattr(cookie, "value", None)
            if value is None and isinstance(cookie, (tuple, list)) and len(cookie) > 1:
                value = cookie[1]
            if value:
                return str(value)
    except Exception:
        pass
    return ""


def _csrf_from_html(html: str) -> str:
    match = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', html)
    if match:
        return match.group(1)
    match = re.search(r"csrftoken=([A-Za-z0-9_-]+)", html, re.IGNORECASE)
    return match.group(1) if match else ""


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


def _html_has_page_not_found(html: str, status_code: int) -> bool:
    if status_code == 404:
        return True
    lower = html.lower()
    return any(marker in lower for marker in _PAGE_NOT_FOUND_MARKERS)


def _html_has_profile_metadata(html: str) -> bool:
    """Faol profil metama'lumoti — bo'sh SPA 404 shell dan farqlash uchun."""
    if not html:
        return False
    if "edge_followed_by" in html:
        return True
    if '"graphql":{"user":' in html or '"graphql": {"user":' in html:
        return True
    og_desc = _og_meta_content(html, "og:description").lower()
    if og_desc and any(word in og_desc for word in ("follower", "following", "posts")):
        return True
    if re.search(r"\bFollowers\b", html) and re.search(r"\bFollowing\b", html):
        return True
    return False


def _html_has_active_profile_marker(html: str) -> bool:
    if "edge_followed_by" in html:
        return True
    if '"graphql":{"user":' in html or '"graphql": {"user":' in html:
        return True
    og_desc = _og_meta_content(html, "og:description").lower()
    if og_desc and any(word in og_desc for word in ("follower", "following", "posts")):
        return True
    return False


def _is_login_or_challenge(html: str, final_url: str, location: str = "") -> bool:
    url = f"{final_url} {location}".lower()
    if "/accounts/login" in url or "/challenge" in url:
        return True
    lower = html.lower()
    return any((
        "login_form" in lower,
        "log in to instagram" in lower,
        "checkpoint_required" in lower,
        "challenge_required" in lower,
    ))


def _classify_profile_fallback(
    status_code: int,
    html: str,
    final_url: str,
    location: str = "",
) -> dict[str, Any]:
    """
    Tier 3 tartibi:
      1) Haqiqiy AVAILABLE markerlari (404 / Page Not Found) + profil meta yo'q
      2) Faol profil markerlari
      3) Login/challenge yoki 200 + Page Not Found yo'q -> TAKEN (deactive/ban)
    """
    has_not_found = _html_has_page_not_found(html, status_code)
    has_profile_meta = _html_has_profile_metadata(html)

    if has_not_found and not has_profile_meta:
        return {
            "kind": "ok",
            "status": CheckStatus.AVAILABLE,
            "source": "fallback_404",
        }

    if _html_has_active_profile_marker(html):
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "fallback_active_marker",
        }

    if _is_login_or_challenge(html, final_url, location):
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "fallback_deactive_200",
        }

    if status_code == 200 and not has_not_found:
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "fallback_deactive_200",
        }

    return {
        "kind": "ok",
        "status": CheckStatus.TAKEN,
        "source": "fallback_deactive_200",
    }


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


def _username_error_blob(errors: Any) -> str:
    if errors is None:
        return ""
    try:
        return json.dumps(errors, ensure_ascii=False).lower()
    except Exception:
        return str(errors).lower()


def _classify_signup_attempt(
    status_code: int,
    payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    kind=ok        -> TAKEN / AVAILABLE
    kind=fallback  -> 429 / SSL yo'q, lekin javob ishonchsiz — HTML ga o't
    """
    if status_code == 429:
        return {"kind": "fallback", "error": "HTTP 429 Rate Limited (signup)"}

    if payload is None:
        return {
            "kind": "fallback",
            "error": f"Signup JSON emas (HTTP {status_code})",
        }

    errors = payload.get("errors")
    has_username_error = isinstance(errors, dict) and bool(errors.get("username"))
    blob = _username_error_blob(errors if errors is not None else payload)
    taken_code = has_username_error or any(code in blob for code in _USERNAME_TAKEN_CODES)

    if taken_code:
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "signup_taken",
        }

    status_field = str(payload.get("status") or "").lower()
    username_field_missing = not (isinstance(errors, dict) and "username" in errors)

    if status_field == "ok" and username_field_missing:
        return {
            "kind": "ok",
            "status": CheckStatus.AVAILABLE,
            "source": "signup_available",
        }

    if payload.get("dryrun_passed") is True:
        return {
            "kind": "ok",
            "status": CheckStatus.AVAILABLE,
            "source": "signup_available",
        }

    return {
        "kind": "fallback",
        "error": f"Signup noma'lum javob (HTTP {status_code}): {list(payload.keys())}",
    }


class InstagramChecker:
    """Instagram username mavjudligini 3-bosqichli funnel orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=topsearch+signup+html",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (topsearch + web signup) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

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
        max_retries: int = 1,  # noqa: ARG002 — API mosligi; 429 loop yo'q
    ) -> CheckResult:
        """
        Username holatini tekshiradi.
        Instagram tarmoq/429 xatolari hech qachon CheckStatus.ERROR qaytarmaydi.
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
            logger.warning("[@%s] Parallel tekshiruv — davom etiladi.", username_clean)

        self._checking_usernames.add(username_clean)
        try:
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )
            sticky_proxy = _make_session_proxy(self._base_proxy)
            result = await self._funnel_check(username_clean, sticky_proxy)
            status: CheckStatus = result["status"]
            source = result.get("source", "unknown")
            logger.info("[@%s] %s (%s)", username_clean, status.value, source)
            return CheckResult(username=username_clean, status=status, attempts=1)
        except Exception:
            logger.exception("[@%s] Ushlanmagan xato -> TAKEN", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.TAKEN,
                error_message=None,
                attempts=1,
            )
        finally:
            self._checking_usernames.discard(username_clean)

    async def _request(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        headers: dict[str, str],
        data: dict[str, str] | str | None = None,
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

    async def _warm_csrf(self, session: AsyncSession, username: str) -> str:
        try:
            resp = await self._request(session, "GET", _SIGNUP_PAGE_URL, _HTML_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] CSRF warmup xato: %s", username, exc)
            return _csrf_from_session(session) or "missing"

        token = _csrf_from_session(session) or _csrf_from_html(_body_text(resp))
        return token or "missing"

    async def _try_topsearch(
        self,
        session: AsyncSession,
        username: str,
        search_url: str,
    ) -> dict[str, Any]:
        """
        kind=ok       -> TAKEN (aniq match)
        kind=continue -> match yo'q yoki 429/xato — Tier 2 ga
        """
        try:
            resp = await self._request(session, "GET", search_url, _JSON_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] topsearch xato: %s", username, exc)
            return {"kind": "continue", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(resp):
            logger.warning("[@%s] topsearch noto'g'ri origin", username)
            return {"kind": "continue", "error": "Proxy noto'g'ri origin (topsearch)"}

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 429:
            logger.warning("[@%s] topsearch HTTP 429 -> Tier 2", username)
            return {"kind": "continue", "error": "HTTP 429 Rate Limited (topsearch)"}

        payload = _parse_json_body(resp)
        if payload is None:
            return {"kind": "continue", "error": f"topsearch JSON emas (HTTP {status_code})"}

        if _exact_username_in_search(payload, username):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "topsearch"}

        return {"kind": "continue"}

    async def _try_signup_attempt(
        self,
        session: AsyncSession,
        username: str,
        csrf_token: str,
    ) -> dict[str, Any]:
        """
        kind=ok       -> TAKEN / AVAILABLE
        kind=fallback -> 429 / SSL / ishonchsiz javob
        """
        headers = {
            **_SIGNUP_POST_HEADERS,
            "X-CSRFToken": csrf_token or "missing",
        }
        rnd = secrets.token_hex(4)
        body = (
            f"email=test_valid_check_{rnd}@gmail.com"
            f"&username={quote(username, safe='._')}"
            f"&first_name=&opt_into_one_tap=false"
        )
        try:
            resp = await self._request(
                session, "POST", _SIGNUP_ATTEMPT_URL, headers, data=body,
            )
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] signup tarmoq/SSL: %s", username, exc)
            return {"kind": "fallback", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(resp):
            return {"kind": "fallback", "error": "Proxy noto'g'ri origin (signup)"}

        status_code = int(getattr(resp, "status_code", 0) or 0)
        payload = _parse_json_body(resp)
        logger.debug(
            "[@%s] signup POST -> HTTP %d | status=%s | errors=%s",
            username,
            status_code,
            payload.get("status") if payload else None,
            list((payload.get("errors") or {}).keys())
            if payload and isinstance(payload.get("errors"), dict)
            else None,
        )
        return _classify_signup_attempt(status_code, payload)

    async def _try_profile_fallback(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        try:
            resp = await self._request(session, "GET", profile_url, _HTML_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] profil GET zaxira tarmoq/SSL: %s", username, exc)
            return {"kind": "skip", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(resp):
            return {"kind": "skip", "error": "Proxy noto'g'ri origin (profile fallback)"}

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 429:
            return {"kind": "skip", "error": "HTTP 429 Rate Limited (profile fallback)"}

        html = _body_text(resp)
        final_url = str(getattr(resp, "url", "") or "")
        location = _header_get(getattr(resp, "headers", None), "location")
        classified = _classify_profile_fallback(status_code, html, final_url, location)
        logger.info(
            "[@%s] profil zaxira HTTP %d -> %s (%s)",
            username,
            status_code,
            classified["status"].value,
            classified["source"],
        )
        return classified

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        search_url = _TOPSEARCH_URL.format(query=quote(username, safe="._"))
        kwargs = self._session_kwargs(proxy)

        async with AsyncSession(**kwargs) as session:
            csrf_token = await self._warm_csrf(session, username)

            topsearch = await self._try_topsearch(session, username, search_url)
            if topsearch["kind"] == "ok":
                return topsearch

            signup = await self._try_signup_attempt(session, username, csrf_token)
            if signup["kind"] == "ok":
                return signup

            logger.info(
                "[@%s] signup fallback (%s) -> HTML",
                username,
                signup.get("error", "noma'lum"),
            )

            fallback = await self._try_profile_fallback(session, username)
            if fallback.get("kind") == "ok":
                return fallback

            logger.warning(
                "[@%s] profil zaxira ham xato (%s) -> TAKEN",
                username,
                fallback.get("error"),
            )
            return {
                "kind": "ok",
                "status": CheckStatus.TAKEN,
                "source": "ultimate_fallback",
            }


instagram_checker = InstagramChecker()
