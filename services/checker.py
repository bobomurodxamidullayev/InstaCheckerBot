"""
services/checker.py — Instagram username tekshirish servisi.

Asosiy yo'l: GET /api/v1/users/web_profile_info/?username=...
  404 / "user not found"     -> available
  200 + data.user            -> taken  (banned/deactivated ham)
  400 / 403 (claim/restrict) -> taken
  429                        -> yangi DataImpulse sessiya + backoff

Zaxira: HTML profil GET (login-wall / noaniq javob).

Klient: curl_cffi AsyncSession (impersonate=chrome124, verify=False).

VPS:
    pip install "curl_cffi>=0.7.1"
    pip install -r requirements.txt
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

_PROFILE_URL = "https://www.instagram.com/{username}/"
_WEB_PROFILE_INFO_URL = (
    "https://www.instagram.com/api/v1/users/web_profile_info/?username={username}"
)
_IG_APP_ID = "936619743392459"
_MAX_RETRIES = 3
_REQUEST_TIMEOUT = 12.0
_IMPERSONATE = "chrome124"
_BACKOFF_BASE = 2.0
_BACKOFF_CAP = 30.0
_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_COMMON_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_UA,
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}

_PROFILE_HEADERS: dict[str, str] = {
    **_COMMON_HEADERS,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
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
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_OG_TYPE_RE = re.compile(
    r'''<meta[^>]+(?:property|name)=["']og:type["'][^>]+content=["']([^"']+)["']'''
    r'''|<meta[^>]+content=["']([^"']+)["'][^>]+(?:property|name)=["']og:type["']''',
    re.IGNORECASE,
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


def _response_snippet(response: Any, limit: int = 800) -> str:
    text = getattr(response, "text", None)
    if isinstance(text, str) and text:
        return text[:limit]
    content = getattr(response, "content", b"")
    if isinstance(content, (bytes, bytearray)):
        try:
            return bytes(content[:limit]).decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return str(content)[:limit]


def _html_text(response: Any) -> str:
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


def _is_wrong_origin(response: Any) -> bool:
    """
    verify=False tufayli proxy Google (yoki boshqa host) sertifikatini
    o'tkazib yuborsa, javob Instagram emas — qayta urinish kerak.
    """
    final_url = str(getattr(response, "url", "") or "").lower()
    location = _header_get(getattr(response, "headers", None), "location").lower()
    snippet = _response_snippet(response).lower()
    server = _header_get(getattr(response, "headers", None), "server").lower()

    google_marks = (
        "www.google.com" in final_url,
        "google.com/" in location,
        "accounts.google" in location,
        "sorry/index" in snippet,
        "<title>google</title>" in snippet,
        "gws" == server,
    )
    if any(google_marks):
        return True

    if snippet and "instagram" not in snippet and "meta" in snippet:
        if "og:site_name" in snippet and "instagram" not in snippet:
            return True
    return False


def _is_login_wall(response: Any, body: str) -> bool:
    final_url = str(getattr(response, "url", "") or "").lower()
    if "/accounts/login" in final_url:
        return True
    lowered = body.lower()
    markers = (
        "login_required",
        "checkpoint_required",
        "please wait a few minutes",
        "suspicious activity",
    )
    return any(marker in lowered for marker in markers) and "web_profile_info" not in final_url


def _parse_json_body(response: Any) -> dict[str, Any] | None:
    try:
        data = response.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass

    text = _html_text(response).strip()
    if not text or text[0] not in "{[":
        return None
    try:
        data = json.loads(text)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _json_message(payload: dict[str, Any]) -> str:
    return str(payload.get("message") or payload.get("error") or "").strip()


def _is_user_not_found(payload: dict[str, Any]) -> bool:
    msg = _json_message(payload).lower()
    if "user not found" in msg:
        return True
    if payload.get("status") == "fail" and "not found" in msg:
        return True
    return False


def _extract_user(payload: dict[str, Any]) -> Any:
    data = payload.get("data")
    if isinstance(data, dict) and "user" in data:
        return data.get("user")
    if "user" in payload:
        return payload.get("user")
    return None


def _api_headers(username: str) -> dict[str, str]:
    return {
        **_COMMON_HEADERS,
        "Accept": "*/*",
        "X-IG-App-ID": _IG_APP_ID,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": _PROFILE_URL.format(username=username),
        "Origin": "https://www.instagram.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }


def _has_real_profile_html(html: str, username: str) -> bool:
    """Faqat aniq profil metateglari — bo'sh React shell bunda yo'q."""
    if not html:
        return False

    lowered = html.lower()
    uname = username.lower()

    og_type = None
    og_match = _OG_TYPE_RE.search(html)
    if og_match:
        og_type = (og_match.group(1) or og_match.group(2) or "").strip().lower()
    if og_type == "profile":
        return True
    if re.search(r'"og:type"\s*:\s*"profile"', lowered):
        return True

    if "instapp:owner_user_id" in lowered:
        return True

    title_match = _TITLE_RE.search(html)
    if title_match:
        title = re.sub(r"\s+", " ", title_match.group(1))
        if re.search(rf"\(@{re.escape(uname)}\)", title, re.IGNORECASE):
            return True

    return False


def _classify_api_response(
    status_code: int,
    payload: dict[str, Any] | None,
    response: Any,
    body: str,
) -> dict[str, Any]:
    """
    web_profile_info javobi.
    kind: ok | retry | fallback
    """
    if status_code == 429:
        return {
            "kind": "retry",
            "rate_limited": True,
            "error": "HTTP 429 Rate Limited (web_profile_info)",
        }

    if status_code >= 500:
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": f"HTTP {status_code} (web_profile_info server)",
        }

    if _is_login_wall(response, body) and not payload:
        return {
            "kind": "fallback",
            "error": "Login-wall (web_profile_info)",
        }

    if status_code == 404:
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if payload and _is_user_not_found(payload):
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if payload:
        user = _extract_user(payload)
        if isinstance(user, dict) and (user.get("id") or user.get("pk") or user.get("username")):
            return {"kind": "ok", "status": CheckStatus.TAKEN}
        if user is None and status_code == 200:
            return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if status_code in (400, 403):
        if payload and _is_user_not_found(payload):
            return {"kind": "ok", "status": CheckStatus.AVAILABLE}
        if _is_login_wall(response, body):
            return {
                "kind": "fallback",
                "error": f"HTTP {status_code} login/checkpoint",
            }
        # Username claim qilingan, banned yoki cheklangan
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    if status_code == 200 and payload is None:
        return {
            "kind": "fallback",
            "error": "web_profile_info JSON emas",
        }

    return {
        "kind": "fallback",
        "error": f"web_profile_info noaniq HTTP {status_code}",
    }


def _classify_profile_html(
    status_code: int,
    html: str,
    username: str,
    final_url: str,
) -> dict[str, Any]:
    if status_code == 429:
        return {
            "kind": "retry",
            "rate_limited": True,
            "error": "HTTP 429 Rate Limited (profile GET)",
        }

    if status_code >= 500:
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": f"HTTP {status_code} (HTML server)",
        }

    if _has_real_profile_html(html, username):
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    if "/accounts/login" in (final_url or "").lower():
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": "HTML login redirect",
        }

    return {"kind": "ok", "status": CheckStatus.AVAILABLE}


# ─── Asosiy tekshiruvchi sinf ──────────────────────────────────────────────────

class InstagramChecker:
    """Instagram username mavjudligini web_profile_info orqali tekshiruvchi sinf."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | client=curl_cffi/%s | api=web_profile_info",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
            _IMPERSONATE,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (web_profile_info, curl_cffi) | proxy=%s",
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
            "headers": _COMMON_HEADERS,
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
                result = await self._attempt_check(username, session_proxy)
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
                source = result.get("source", "api")
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

    async def _attempt_check(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Bitta yangi proxy sessiya: avval web_profile_info, kerak bo'lsa HTML fallback.
        """
        kwargs = self._session_kwargs(proxy)
        api_url = _WEB_PROFILE_INFO_URL.format(username=quote(username, safe="._"))
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))

        async with AsyncSession(**kwargs) as session:
            api_resp = await session.get(
                api_url,
                headers=_api_headers(username),
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )

            if _is_wrong_origin(api_resp):
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": "Proxy noto'g'ri origin (Google/boshqa host) qaytardi",
                }

            status_code = int(getattr(api_resp, "status_code", 0) or 0)
            body = _html_text(api_resp)
            payload = _parse_json_body(api_resp)
            logger.debug(
                "[@%s] API GET -> HTTP %d json=%s body=%dB",
                username,
                status_code,
                bool(payload),
                len(body),
            )

            classified = _classify_api_response(status_code, payload, api_resp, body)
            if classified["kind"] == "ok":
                classified["source"] = "web_profile_info"
                return classified
            if classified["kind"] == "retry":
                return classified

            logger.info(
                "[@%s] API fallback HTML | %s",
                username,
                classified.get("error"),
            )

            html_resp = await session.get(
                profile_url,
                headers=_PROFILE_HEADERS,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )

        if _is_wrong_origin(html_resp):
            return {
                "kind": "retry",
                "rate_limited": False,
                "error": "Proxy noto'g'ri origin (HTML fallback)",
            }

        html_status = int(getattr(html_resp, "status_code", 0) or 0)
        html = _html_text(html_resp)
        final_url = str(getattr(html_resp, "url", "") or "")
        html_result = _classify_profile_html(html_status, html, username, final_url)
        if html_result["kind"] == "ok":
            html_result["source"] = "html_fallback"
        return html_result


instagram_checker = InstagramChecker()
