"""
services/checker.py — Instagram username tekshirish servisi.

Gibrid (funnel):
  1) Tezkor filtr: topsearch aniq match yoki profil GET HTTP 200 -> TAKEN
  2) Tasdiqlash: 404 / topilmagan nom -> POST web/accounts/check_username/
       available=true  -> AVAILABLE
       available=false / username_is_taken -> TAKEN (ban, deactive, 14 kun lock)
       429 -> yangi rotating proxy IP, 1 marta qayta urinish

Klient: curl_cffi AsyncSession (impersonate=chrome124, verify=False).
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
_CHECK_USERNAME_URL = (
    "https://www.instagram.com/api/v1/web/accounts/check_username/"
)
_MAX_RETRIES = 3
_REQUEST_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"
_BACKOFF_BASE = 2.0
_BACKOFF_CAP = 30.0
_IG_APP_ID = "936619743392459"

_SEARCH_HEADERS: dict[str, str] = {
    "Accept": "*/*",
    "Referer": "https://www.instagram.com/",
}

_PROFILE_HEADERS: dict[str, str] = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Referer": "https://www.instagram.com/",
    "Upgrade-Insecure-Requests": "1",
}

_SIGNUP_PAGE_HEADERS: dict[str, str] = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Referer": "https://www.instagram.com/",
    "Upgrade-Insecure-Requests": "1",
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
    Chiqish: http://{login}__cr.us_session.{hex}:pass@gw.dataimpulse.com:823
    """
    if not base_proxy:
        return None

    parsed = urlparse(base_proxy.strip())
    if not parsed.hostname or parsed.username is None:
        return base_proxy

    username = unquote(parsed.username)
    password = unquote(parsed.password or "")

    username = re.sub(r"_session\.[0-9a-fA-F]+$", "", username)
    username = re.sub(r"_sid\.[0-9a-fA-F]+$", "", username)

    session_user = f"{username}_session.{secrets.token_hex(8)}"
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


def _check_username_headers(csrf: str) -> dict[str, str]:
    return {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-CSRFToken": csrf,
        "X-IG-App-ID": _IG_APP_ID,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": _SIGNUP_URL,
        "Origin": "https://www.instagram.com",
    }


def _classify_signup_check(status_code: int, payload: dict[str, Any] | None) -> dict[str, Any]:
    if status_code == 429:
        return {
            "kind": "retry",
            "rate_limited": True,
            "error": "HTTP 429 Rate Limited (check_username)",
        }

    if payload is None:
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": f"check_username JSON emas (HTTP {status_code})",
        }

    if payload.get("available") is True:
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if payload.get("available") is False:
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    if payload.get("username_is_taken") is True:
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    errors = payload.get("errors")
    if isinstance(errors, dict) and errors.get("username"):
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    blob = json.dumps(payload, ensure_ascii=False).lower()
    if "username_is_taken" in blob:
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    return {
        "kind": "retry",
        "rate_limited": False,
        "error": f"check_username noaniq javob HTTP {status_code}",
    }


# ─── Asosiy tekshiruvchi sinf ──────────────────────────────────────────────────

class InstagramChecker:
    """Instagram username mavjudligini topsearch JSON (+ profil zaxira) orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | client=curl_cffi/%s | api=topsearch+check_username",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
            _IMPERSONATE,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (funnel: topsearch + check_username, curl_cffi/%s) | proxy=%s",
            _IMPERSONATE,
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    def _get_session_proxy(self) -> str | None:
        return _make_session_proxy(self._base_proxy)

    def _session_kwargs(self, proxy: str | None) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _REQUEST_TIMEOUT,
            "max_clients": 1,
            "verify": False,
            "allow_redirects": True,
            "headers": _SEARCH_HEADERS,
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
            session_proxy = self._get_session_proxy()
            logger.debug("[@%s] Urinish %d/%d | yangi proxy sessiya", username, attempt, max_retries)

            if attempt == 1:
                await asyncio.sleep(
                    random.uniform(settings.check_delay_min, settings.check_delay_max)
                )
            else:
                await asyncio.sleep(random.uniform(0.35, 0.9))

            try:
                result = await self._funnel_check(username, session_proxy)
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
                source = result.get("source", "topsearch")
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
                    "[@%s] HTTP 429 | backoff %.1fs | urinish %d/%d",
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

    async def _funnel_check(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        1) topsearch / profil GET — band bo'lsa darhol TAKEN.
        2) 404 / topilmagan — check_username POST (AVAILABLE faqat available=true).
        """
        kwargs = self._session_kwargs(proxy)
        search_url = _TOPSEARCH_URL.format(query=quote(username, safe="._"))
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))

        async with AsyncSession(**kwargs) as session:
            search_resp = await session.get(
                search_url,
                headers=_SEARCH_HEADERS,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
                impersonate=_IMPERSONATE,
            )

            if _is_wrong_origin(search_resp):
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": "Proxy noto'g'ri origin (topsearch)",
                }

            search_status = int(getattr(search_resp, "status_code", 0) or 0)
            if search_status == 429:
                return {
                    "kind": "retry",
                    "rate_limited": True,
                    "error": "HTTP 429 Rate Limited (topsearch)",
                }

            payload = _parse_json_body(search_resp)
            if payload is None:
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": f"topsearch JSON emas (HTTP {search_status})",
                }

            if _exact_username_in_search(payload, username):
                return {
                    "kind": "ok",
                    "status": CheckStatus.TAKEN,
                    "source": "topsearch",
                }

            logger.debug(
                "[@%s] topsearch da aniq match yo'q | users=%d | profil GET",
                username,
                len(payload.get("users") or []) if isinstance(payload.get("users"), list) else 0,
            )

            html_resp = await session.get(
                profile_url,
                headers=_PROFILE_HEADERS,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
                impersonate=_IMPERSONATE,
            )

            if _is_wrong_origin(html_resp):
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": "Proxy noto'g'ri origin (profile GET)",
                }

            html_status = int(getattr(html_resp, "status_code", 0) or 0)
            if html_status == 429:
                return {
                    "kind": "retry",
                    "rate_limited": True,
                    "error": "HTTP 429 Rate Limited (profile GET)",
                }

            if html_status == 200:
                return {
                    "kind": "ok",
                    "status": CheckStatus.TAKEN,
                    "source": "profile GET",
                }

            logger.debug(
                "[@%s] 1-bosqich o'tkazdi (HTTP %d) | check_username tasdiqlash",
                username,
                html_status,
            )

            classified = await self._signup_check_in_session(session, username, html_resp)

        if classified.get("rate_limited"):
            new_proxy = self._get_session_proxy()
            logger.warning(
                "[@%s] check_username HTTP 429 | yangi proxy IP, 1 marta qayta urinish",
                username,
            )
            return await self._signup_check_fresh(username, new_proxy)

        return classified

    async def _signup_check_fresh(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """429 dan keyin yangi sessiya/IP bilan faqat check_username."""
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            return await self._signup_check_in_session(session, username, None)

    async def _signup_check_in_session(
        self,
        session: AsyncSession,
        username: str,
        prior_response: Any,
    ) -> dict[str, Any]:
        signup_resp = await session.get(
            _SIGNUP_URL,
            headers=_SIGNUP_PAGE_HEADERS,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            impersonate=_IMPERSONATE,
        )

        if _is_wrong_origin(signup_resp):
            return {
                "kind": "retry",
                "rate_limited": False,
                "error": "Proxy noto'g'ri origin (signup GET)",
            }

        signup_status = int(getattr(signup_resp, "status_code", 0) or 0)
        if signup_status == 429:
            return {
                "kind": "retry",
                "rate_limited": True,
                "error": "HTTP 429 Rate Limited (signup GET)",
            }

        csrf = (
            _extract_csrftoken(signup_resp, session)
            or _extract_csrftoken(prior_response, session)
            or secrets.token_hex(16)
        )
        check_resp = await session.post(
            _CHECK_USERNAME_URL,
            data={"username": username},
            headers=_check_username_headers(csrf),
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            impersonate=_IMPERSONATE,
        )

        if _is_wrong_origin(check_resp):
            return {
                "kind": "retry",
                "rate_limited": False,
                "error": "Proxy noto'g'ri origin (check_username)",
            }

        status_code = int(getattr(check_resp, "status_code", 0) or 0)
        payload = _parse_json_body(check_resp)
        logger.debug(
            "[@%s] check_username POST -> HTTP %d available=%s",
            username,
            status_code,
            None if payload is None else payload.get("available"),
        )
        classified = _classify_signup_check(status_code, payload)
        if classified["kind"] == "ok":
            classified["source"] = "check_username"
        return classified


instagram_checker = InstagramChecker()
