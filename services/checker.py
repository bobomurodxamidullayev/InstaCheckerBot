"""
services/checker.py — Instagram username tekshirish servisi.

HTTP klient: curl_cffi.requests.AsyncSession (impersonate=chrome124).
httpx o'rniga curl-impersonate ishlatiladi — VPS da SSL handshake
failure va server tomonidagi TLS uzilishlarini bartaraf qilish uchun.

VPS o'rnatish (venv ichida):
    pip install "curl_cffi>=0.7.1"
    # yoki butun loyiha:
    pip install -r requirements.txt
"""
from __future__ import annotations

import asyncio
import logging
import random
import re
import secrets
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import quote, unquote, urlparse, urlunparse

from curl_cffi import CurlError
from curl_cffi.requests import AsyncSession
from curl_cffi.requests.exceptions import RequestException

from config import settings
from models.username_log import CheckStatus

logger = logging.getLogger(__name__)

# ─── Konstantlar ──────────────────────────────────────────────────────────────

_SIGNUP_URL = "https://www.instagram.com/accounts/emailsignup/"
_ATTEMPT_URL = "https://www.instagram.com/api/v1/web/accounts/web_create_ajax/attempt/"
_MAX_RETRIES = 3
_REQUEST_TIMEOUT = 12.0  # soniya — qat'iy timeout (connect+read)
_IMPERSONATE = "chrome124"
_BACKOFF_BASE = 2.0
_BACKOFF_CAP = 30.0

# Impersonate Chrome 124 TLS fingerprintini beradi; UA ni qo'lda bermaymiz.
_BASE_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

_NETWORK_EXCEPTIONS = (
    RequestException,
    CurlError,
    TimeoutError,
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
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

    Kirish:  http://user:pass@gw.dataimpulse.com:823
    Chiqish: http://user_session.{random_hex}:pass@gw.dataimpulse.com:823
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

    netloc = f"{auth}@{host}"
    return urlunparse(
        (parsed.scheme or "http", netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def _backoff_delay(attempt: int) -> float:
    """HTTP 429 uchun exponential backoff (+ kichik jitter)."""
    delay = min(_BACKOFF_BASE * (2 ** (attempt - 1)), _BACKOFF_CAP)
    delay = min(delay, float(settings.rate_limit_sleep))
    return delay + random.uniform(0.15, 0.75)


def _extract_csrftoken(response: Any) -> str | None:
    cookies = getattr(response, "cookies", None)
    if cookies is not None:
        token = cookies.get("csrftoken")
        if token:
            return str(token)

    headers = getattr(response, "headers", None)
    if not headers:
        return None

    values: list[str] = []
    getter = getattr(headers, "get_list", None)
    if callable(getter):
        values.extend(getter("set-cookie") or getter("Set-Cookie") or [])
    else:
        raw = headers.get("set-cookie") or headers.get("Set-Cookie")
        if raw:
            values.append(str(raw))

    for value in values:
        match = re.search(r"csrftoken=([^;]+)", value)
        if match:
            return match.group(1)
    return None


# ─── Asosiy tekshiruvchi sinf ──────────────────────────────────────────────────

class InstagramChecker:
    """Instagram username mavjudligini curl_cffi orqali tekshiruvchi sinf."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | client=curl_cffi/%s",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
            _IMPERSONATE,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (curl_cffi) | proxy=%s",
            bool(self._base_proxy),
        )

    async def stop(self) -> None:
        logger.info("InstagramChecker to'xtatildi.")

    def _get_session_proxy(self) -> str | None:
        return _make_session_proxy(self._base_proxy)

    async def check_username(
        self,
        username: str,
        max_retries: int = _MAX_RETRIES,
    ) -> CheckResult:
        """
        Username holatini tekshiradi.

        Qaytadi: CheckResult (status / username / error_message).
        Dict kerak bo'lsa: result.to_dict()
          {"status": "available"|"taken"|"error", "username": ..., "error": str|None}
        """
        username_clean = username.strip().lstrip("@").lower()

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
            last_error = "Noma'lum xato"

            for attempt in range(1, max_retries + 1):
                session_proxy = self._get_session_proxy()
                logger.debug("[@%s] Urinish %d/%d", username_clean, attempt, max_retries)

                if attempt == 1:
                    await asyncio.sleep(
                        random.uniform(settings.check_delay_min, settings.check_delay_max)
                    )
                else:
                    await asyncio.sleep(random.uniform(0.4, 1.0))

                try:
                    result = await self._attempt_check(
                        username_clean, session_proxy
                    )
                except _NETWORK_EXCEPTIONS as exc:
                    last_error = f"{type(exc).__name__}: {exc}"
                    logger.warning(
                        "[@%s] Tarmoq/SSL xatosi [%s] (urinish %d/%d): %s",
                        username_clean,
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
                        username_clean,
                        type(exc).__name__,
                        attempt,
                        max_retries,
                        exc,
                    )
                    continue

                if result["kind"] == "ok":
                    status = result["status"]
                    logger.info("[@%s] %s", username_clean, status.value)
                    return CheckResult(
                        username=username_clean,
                        status=status,
                        attempts=attempt,
                    )

                last_error = result["error"]
                if result.get("rate_limited"):
                    delay = _backoff_delay(attempt)
                    logger.warning(
                        "[@%s] HTTP 429 | backoff %.1fs | urinish %d/%d",
                        username_clean,
                        delay,
                        attempt,
                        max_retries,
                    )
                    await asyncio.sleep(delay)
                    continue

                logger.warning(
                    "[@%s] %s (urinish %d/%d)",
                    username_clean,
                    last_error,
                    attempt,
                    max_retries,
                )

            logger.error(
                "[@%s] Barcha %d urinish muvaffaqiyatsiz | Oxirgi xato: %s",
                username_clean,
                max_retries,
                last_error,
            )
            return CheckResult(
                username=username_clean,
                status=CheckStatus.ERROR,
                error_message=last_error,
                attempts=max_retries,
            )
        finally:
            self._checking_usernames.discard(username_clean)

    async def _attempt_check(
        self,
        username: str,
        proxy: str | None,
    ) -> dict[str, Any]:
        """
        Bitta proxy sessiyasi bilan GET (csrf) + POST (attempt).
        Istisnolar tashqariga chiqadi — chaqiruvchi ushlaydi.
        """
        session_kwargs: dict[str, Any] = {
            "impersonate": _IMPERSONATE,
            "timeout": _REQUEST_TIMEOUT,
            "max_clients": 1,
        }
        if proxy:
            session_kwargs["proxy"] = proxy

        async with AsyncSession(**session_kwargs) as session:
            resp_get = await session.get(_SIGNUP_URL, headers=_BASE_HEADERS)

            if resp_get.status_code == 429:
                return {
                    "kind": "retry",
                    "rate_limited": True,
                    "error": "HTTP 429 Rate Limited (GET)",
                }

            csrftoken = _extract_csrftoken(resp_get)
            if not csrftoken:
                jar = getattr(session, "cookies", None)
                if jar is not None:
                    csrftoken = jar.get("csrftoken")

            if not csrftoken:
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": "csrftoken topilmadi",
                }

            post_headers = {
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9",
                "X-CSRFToken": str(csrftoken),
                "X-Requested-With": "XMLHttpRequest",
                "Referer": _SIGNUP_URL,
                "Origin": "https://www.instagram.com",
                "Content-Type": "application/x-www-form-urlencoded",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            }

            form_data = {
                "email": f"test{random.randint(100000, 999999)}@gmail.com",
                "username": username,
                "first_name": "Tester",
                "opt_into_one_tap": "false",
            }

            resp_post = await session.post(
                _ATTEMPT_URL,
                data=form_data,
                headers=post_headers,
            )

            status_code = resp_post.status_code
            logger.debug("[@%s] POST HTTP %d", username, status_code)

            if status_code == 429:
                return {
                    "kind": "retry",
                    "rate_limited": True,
                    "error": "HTTP 429 Rate Limited (POST)",
                }

            try:
                json_data = resp_post.json()
            except Exception as exc:
                return {
                    "kind": "retry",
                    "rate_limited": False,
                    "error": f"JSON tahlil xatosi: {exc} (HTTP {status_code})",
                }

            username_is_taken = bool(json_data.get("username_is_taken", False))
            errors = json_data.get("errors") or {}

            if username_is_taken or "username" in errors:
                return {"kind": "ok", "status": CheckStatus.TAKEN}

            if status_code == 200 and "username" not in errors:
                return {"kind": "ok", "status": CheckStatus.AVAILABLE}

            return {
                "kind": "retry",
                "rate_limited": False,
                "error": f"Kutilmagan JSON javob: {json_data}",
            }


instagram_checker = InstagramChecker()
