"""
services/checker.py — Instagram username tekshirish servisi.

Asosiy yo'l: POST /api/v1/web/accounts/web_create_ajax/attempt/
  username_is_taken / username error -> taken  (banned/deactivated ham)
  status=ok va username xatosi yo'q  -> available
  429                                -> yangi DataImpulse sessiya + backoff

Zaxira: CSRF/challenge bo'lsa web_profile_info, so'ng HTML profil GET.
  Eslatma: profile 404 banned akkauntni AVAILABLE deb KO'RSATMAYDI.

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

_PROFILE_URL = "https://www.instagram.com/{username}/"
_SIGNUP_URL = "https://www.instagram.com/accounts/emailsignup/"
_ATTEMPT_URL = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
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

_USERNAME_TAKEN_MARKERS: tuple[str, ...] = (
    "username_is_taken",
    "this username isn't available",
    "this username is not available",
    "username isn't available",
    "username is not available",
    "имя пользователя занято",
    "username is taken",
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


def _extract_csrftoken(response: Any, session: Any) -> str | None:
    for jar in (getattr(response, "cookies", None), getattr(session, "cookies", None)):
        if jar is None:
            continue
        try:
            token = jar.get("csrftoken")
        except Exception:
            token = None
        if token:
            return str(token)

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

    html = _html_text(response)
    match = re.search(r'"csrf_token"\s*:\s*"([^"]+)"', html)
    if match:
        return match.group(1)
    match = re.search(r"csrf_token=([^&\"']+)", html)
    if match:
        return match.group(1)
    return None


def _username_error_blob(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    if payload.get("username_is_taken"):
        parts.append("username_is_taken")
    errors = payload.get("errors")
    if isinstance(errors, dict) and "username" in errors:
        parts.append(json.dumps(errors.get("username"), ensure_ascii=False))
    parts.append(_json_message(payload))
    error_type = str(payload.get("error_type") or "")
    if error_type:
        parts.append(error_type)
    return " ".join(parts).lower()


def _has_username_taken_signal(payload: dict[str, Any], body: str) -> bool:
    blob = f"{_username_error_blob(payload)} {body}".lower()
    if payload.get("username_is_taken") is True:
        return True
    errors = payload.get("errors")
    if isinstance(errors, dict) and errors.get("username"):
        return True
    return any(marker in blob for marker in _USERNAME_TAKEN_MARKERS)


def _attempt_headers(csrf: str) -> dict[str, str]:
    return {
        **_COMMON_HEADERS,
        "Accept": "*/*",
        "X-IG-App-ID": _IG_APP_ID,
        "X-CSRFToken": csrf or "",
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": _SIGNUP_URL,
        "Origin": "https://www.instagram.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }


def _classify_attempt_response(
    status_code: int,
    payload: dict[str, Any] | None,
    response: Any,
    body: str,
) -> dict[str, Any]:
    """
    Registration attempt JSON.
    kind: ok | retry | fallback
    """
    if status_code == 429:
        return {
            "kind": "retry",
            "rate_limited": True,
            "error": "HTTP 429 Rate Limited (web_create_ajax/attempt)",
        }

    if status_code >= 500:
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": f"HTTP {status_code} (attempt server)",
        }

    if _is_login_wall(response, body):
        return {
            "kind": "fallback",
            "error": "Login/challenge (attempt API)",
        }

    if payload is None:
        return {
            "kind": "fallback",
            "error": f"Attempt JSON emas (HTTP {status_code})",
        }

    if _has_username_taken_signal(payload, body):
        return {"kind": "ok", "status": CheckStatus.TAKEN}

    errors = payload.get("errors") if isinstance(payload.get("errors"), dict) else {}
    has_username_error = bool(errors.get("username")) if isinstance(errors, dict) else False
    status_ok = str(payload.get("status") or "").lower() == "ok"

    if status_ok and not has_username_error:
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if status_code == 200 and not has_username_error and payload.get("username_is_taken") is False:
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    msg = _json_message(payload).lower()
    if any(token in msg for token in ("csrf", "checkpoint", "challenge", "login_required")):
        return {
            "kind": "fallback",
            "error": f"Attempt CSRF/challenge: {msg[:120]}",
        }

    return {
        "kind": "fallback",
        "error": f"Attempt noaniq javob HTTP {status_code}",
    }


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
    *,
    trust_not_found: bool = True,
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
        if not trust_not_found:
            return {
                "kind": "fallback",
                "error": "web_profile_info 404 (banned bo'lishi mumkin)",
            }
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if payload and _is_user_not_found(payload):
        if not trust_not_found:
            return {
                "kind": "fallback",
                "error": "web_profile_info user not found (banned bo'lishi mumkin)",
            }
        return {"kind": "ok", "status": CheckStatus.AVAILABLE}

    if payload:
        user = _extract_user(payload)
        if isinstance(user, dict) and (user.get("id") or user.get("pk") or user.get("username")):
            return {"kind": "ok", "status": CheckStatus.TAKEN}
        if user is None and status_code == 200:
            if not trust_not_found:
                return {
                    "kind": "fallback",
                    "error": "web_profile_info user=null (banned bo'lishi mumkin)",
                }
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
    *,
    taken_only: bool = False,
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

    if taken_only:
        return {
            "kind": "retry",
            "rate_limited": False,
            "error": "HTML da profil yo'q — AVAILABLE deb belgilanmadi (banned xavfi)",
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
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | client=curl_cffi/%s | api=web_create_ajax/attempt",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
            _IMPERSONATE,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (registration attempt, curl_cffi) | proxy=%s",
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
        Bitta yangi proxy sessiya:
        1) signup GET (CSRF) + web_create_ajax/attempt POST
        2) CSRF/challenge -> web_profile_info (faqat TAKEN ishonchli)
        3) HTML profil GET (faqat aniq profil metategi = TAKEN)
        """
        kwargs = self._session_kwargs(proxy)
        api_url = _WEB_PROFILE_INFO_URL.format(username=quote(username, safe="._"))
        profile_url = _PROFILE_URL.format(username=quote(username, safe="._"))
        form_data = {
            "email": f"chk_{username[:6]}@gmail.com",
            "username": username,
            "first_name": "Test",
            "opt_into_one_tap": "false",
        }

        async with AsyncSession(**kwargs) as session:
            signup_resp = await session.get(
                _SIGNUP_URL,
                headers=_PROFILE_HEADERS,
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
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

            csrf = _extract_csrftoken(signup_resp, session) or ""
            attempt_resp = await session.post(
                _ATTEMPT_URL,
                data=form_data,
                headers=_attempt_headers(csrf),
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )

            if int(getattr(attempt_resp, "status_code", 0) or 0) == 429:
                return {
                    "kind": "retry",
                    "rate_limited": True,
                    "error": "HTTP 429 Rate Limited (web_create_ajax/attempt)",
                }

            if _is_wrong_origin(attempt_resp):
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": "Proxy noto'g'ri origin (attempt POST)",
                }

            attempt_status = int(getattr(attempt_resp, "status_code", 0) or 0)
            attempt_body = _html_text(attempt_resp)
            attempt_json = _parse_json_body(attempt_resp)
            logger.debug(
                "[@%s] attempt POST -> HTTP %d json=%s csrf=%s",
                username,
                attempt_status,
                bool(attempt_json),
                "ha" if csrf else "yo'q",
            )

            classified = _classify_attempt_response(
                attempt_status, attempt_json, attempt_resp, attempt_body
            )
            if classified["kind"] == "ok":
                classified["source"] = "web_create_ajax/attempt"
                return classified
            if classified["kind"] == "retry":
                return classified

            logger.info(
                "[@%s] Attempt fallback | %s",
                username,
                classified.get("error"),
            )

            api_resp = await session.get(
                api_url,
                headers=_api_headers(username),
                timeout=_REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )

            if not _is_wrong_origin(api_resp):
                api_status = int(getattr(api_resp, "status_code", 0) or 0)
                api_body = _html_text(api_resp)
                api_json = _parse_json_body(api_resp)
                api_classified = _classify_api_response(
                    api_status,
                    api_json,
                    api_resp,
                    api_body,
                    trust_not_found=False,
                )
                if api_classified["kind"] == "ok":
                    api_classified["source"] = "web_profile_info"
                    return api_classified
                if api_classified["kind"] == "retry":
                    return api_classified

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
        html_result = _classify_profile_html(
            html_status, html, username, final_url, taken_only=True
        )
        if html_result["kind"] == "ok":
            html_result["source"] = "html_fallback"
        return html_result


instagram_checker = InstagramChecker()
