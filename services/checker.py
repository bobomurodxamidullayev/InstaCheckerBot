"""
services/checker.py — Instagram username tekshirish servisi.

2-bosqichli funnel (login cookie / CSRF shart emas):
  1) Topsearch exact match -> TAKEN
  2) GET /{username}/embed/captioned/ -> AVAILABLE / TAKEN

web_profile_info va web_create_ajax/attempt ishlatilmaydi.
Tarmoq/proxy xatosida bitta yangi sticky IP bilan qayta uriniladi;
aks holda xavfsiz TAKEN. Foydalanuvchiga ERROR qaytmaydi.
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
_EMBED_URL = "https://www.instagram.com/{username}/embed/captioned/"

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

_EMBED_HEADERS: dict[str, str] = {
    "User-Agent": _CHROME_UA,
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

_USERNAME_RE = re.compile(r"^[a-z0-9._]{1,30}$")

_PAGE_NOT_FOUND_MARKERS = (
    "page not found",
    "sorry, this page isn't available",
    "the link you followed may be broken",
)

_EMBED_EXISTS_MARKERS = (
    "watch on instagram",
    "view more on instagram",
    "caption",
    "avatar",
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


def _html_has_page_not_found(html: str) -> bool:
    lower = html.lower()
    return any(marker in lower for marker in _PAGE_NOT_FOUND_MARKERS)


def _html_has_embed_exists_marker(html: str, username: str) -> bool:
    lower = html.lower()
    if f"instagram.com/{username.lower()}" in lower:
        return True
    return any(marker in lower for marker in _EMBED_EXISTS_MARKERS)


def _classify_embed(status_code: int, html: str, username: str) -> dict[str, Any]:
    """
    Tartib:
      1) 404 yoki Page Not Found -> AVAILABLE
      2) 200 + faol embed markerlari -> TAKEN
      3) 200 / redirect, Page Not Found yo'q -> TAKEN (deactive/ban)
    """
    if status_code == 429:
        return {"kind": "retry", "error": "HTTP 429 Rate Limited (embed)"}

    if status_code == 404 or _html_has_page_not_found(html):
        return {
            "kind": "ok",
            "status": CheckStatus.AVAILABLE,
            "source": "embed_404",
        }

    if status_code == 200 and _html_has_embed_exists_marker(html, username):
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "embed_exists",
        }

    if status_code == 200 or status_code in (301, 302, 303, 307, 308):
        return {
            "kind": "ok",
            "status": CheckStatus.TAKEN,
            "source": "embed_deactive",
        }

    return {
        "kind": "retry",
        "error": f"embed noma'lum HTTP {status_code}",
    }


class InstagramChecker:
    """Instagram username mavjudligini topsearch + embed orqali tekshiradi."""

    def __init__(self, proxy_url: str | None = None) -> None:
        self._base_proxy: str | None = proxy_url or (
            settings.proxy_url if settings.proxy_enabled else None
        )
        self._checking_usernames: set[str] = set()
        logger.info(
            "InstagramChecker tayyor | proxy=%s | concurrent=%d | api=topsearch+embed",
            "ha" if self._base_proxy else "yo'q",
            settings.concurrent_limit,
        )

    async def start(self) -> None:
        logger.info(
            "InstagramChecker ishga tushdi (topsearch + embed) | proxy=%s",
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
            "headers": _EMBED_HEADERS,
        }
        if proxy:
            kwargs["proxy"] = proxy
        return kwargs

    async def check_username(
        self,
        username: str,
        max_retries: int = 1,
    ) -> CheckResult:
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
        extra_tries = 1 if max_retries >= 1 else 0
        attempts = 0
        try:
            await asyncio.sleep(
                random.uniform(settings.check_delay_min, settings.check_delay_max)
            )
            for attempt in range(1, 2 + extra_tries):
                attempts = attempt
                sticky_proxy = _make_session_proxy(self._base_proxy)
                result = await self._funnel_check(username_clean, sticky_proxy)
                if result.get("kind") == "ok":
                    status: CheckStatus = result["status"]
                    source = result.get("source", "unknown")
                    logger.info("[@%s] %s (%s)", username_clean, status.value, source)
                    return CheckResult(
                        username=username_clean,
                        status=status,
                        attempts=attempt,
                    )
                logger.warning(
                    "[@%s] tarmoq/proxy xato (%s) | urinish %d",
                    username_clean,
                    result.get("error"),
                    attempt,
                )
            logger.warning("[@%s] ikkala urinish ham xato -> TAKEN", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.TAKEN,
                error_message=None,
                attempts=attempts,
            )
        except Exception:
            logger.exception("[@%s] Ushlanmagan xato -> TAKEN", username_clean)
            return CheckResult(
                username=username_clean,
                status=CheckStatus.TAKEN,
                error_message=None,
                attempts=max(attempts, 1),
            )
        finally:
            self._checking_usernames.discard(username_clean)

    async def _request(
        self,
        session: AsyncSession,
        method: str,
        url: str,
        headers: dict[str, str],
    ) -> Any:
        return await session.get(
            url,
            headers=headers,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
            verify=False,
            impersonate=_IMPERSONATE,
        )

    async def _try_topsearch(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        search_url = _TOPSEARCH_URL.format(query=quote(username, safe="._"))
        try:
            resp = await self._request(session, "GET", search_url, _JSON_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] topsearch xato -> embed: %s", username, exc)
            return {"kind": "continue"}

        if _is_wrong_origin(resp):
            logger.warning("[@%s] topsearch noto'g'ri origin -> embed", username)
            return {"kind": "continue"}

        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 429:
            logger.warning("[@%s] topsearch HTTP 429 -> embed", username)
            return {"kind": "continue"}

        payload = _parse_json_body(resp)
        if payload is None:
            return {"kind": "continue"}

        if _exact_username_in_search(payload, username):
            return {"kind": "ok", "status": CheckStatus.TAKEN, "source": "topsearch"}

        return {"kind": "continue"}

    async def _try_embed(
        self,
        session: AsyncSession,
        username: str,
    ) -> dict[str, Any]:
        embed_url = _EMBED_URL.format(username=quote(username, safe="._"))
        try:
            resp = await self._request(session, "GET", embed_url, _EMBED_HEADERS)
        except _NETWORK_EXCEPTIONS as exc:
            logger.warning("[@%s] embed tarmoq/SSL: %s", username, exc)
            return {"kind": "retry", "error": f"{type(exc).__name__}: {exc}"}

        if _is_wrong_origin(resp):
            return {"kind": "retry", "error": "Proxy noto'g'ri origin (embed)"}

        status_code = int(getattr(resp, "status_code", 0) or 0)
        html = _body_text(resp)
        classified = _classify_embed(status_code, html, username)
        if classified.get("kind") == "ok":
            logger.info(
                "[@%s] embed HTTP %d -> %s (%s)",
                username,
                status_code,
                classified["status"].value,
                classified["source"],
            )
        return classified

    async def _funnel_check(self, username: str, proxy: str | None) -> dict[str, Any]:
        kwargs = self._session_kwargs(proxy)
        async with AsyncSession(**kwargs) as session:
            topsearch = await self._try_topsearch(session, username)
            if topsearch["kind"] == "ok":
                return topsearch
            return await self._try_embed(session, username)


instagram_checker = InstagramChecker()
