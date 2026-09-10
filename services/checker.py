import re
from enum import Enum
from dataclasses import dataclass
from typing import Optional
from curl_cffi.requests import AsyncSession

class UsernameStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    TAKEN = "TAKEN"
    ERROR = "ERROR"

@dataclass
class CheckResult:
    status: UsernameStatus
    reason: Optional[str] = None

class InstagramChecker:
    def __init__(self, proxy: Optional[str] = None, timeout: int = 12):
        self.proxy = proxy
        self.timeout = timeout

    async def start(self):
        pass

    async def stop(self):
        pass

    async def close(self):
        pass

    async def check(self, username: str) -> CheckResult:
        clean_user = username.strip().lower()

        # 1. Tier 1: Sintaksis va Rezerv qoidalar
        if not re.match(r"^[a-zA-Z0-9._]{1,30}$", clean_user) or clean_user.endswith(".") or ".." in clean_user:
            return CheckResult(status=UsernameStatus.TAKEN, reason="invalid_syntax")

        reserved = {"admin", "instagram", "support", "help", "contact", "root", "explore"}
        if clean_user in reserved:
            return CheckResult(status=UsernameStatus.TAKEN, reason="reserved")

        # 2. Tier 2: Veb HTML tekshiruvi (GET)
        url = f"https://www.instagram.com/{clean_user}/"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document"
        }

        try:
            async with AsyncSession(impersonate="chrome124", verify=False) as session:
                response = await session.get(
                    url,
                    headers=headers,
                    proxy=self.proxy,
                    timeout=self.timeout
                )

                # HTTP 404 qaytsa -> 100% bo'sh
                if response.status_code == 404:
                    return CheckResult(status=UsernameStatus.AVAILABLE)

                if response.status_code == 200:
                    html = response.text.lower()

                    # 1-shart: Faol profil (Mavjud akkaunt)
                    has_stats = "followers" in html and "posts" in html
                    has_profile_title = "photos and videos" in html or f"(@{clean_user})" in html
                    has_og_title = "og:title" in html and clean_user in html
                    if has_stats or has_profile_title or has_og_title:
                        return CheckResult(status=UsernameStatus.TAKEN, reason="profile_exists")

                    # 2-shart: Haqiqiy mavjud bo'lmagan (Bo'sh) nom
                    not_found_markers = [
                        "page not found",
                        "the link you followed may be broken",
                        "isn't available",
                        "<title>page not found"
                    ]
                    if any(marker in html for marker in not_found_markers):
                        return CheckResult(status=UsernameStatus.AVAILABLE)

                    # 3-shart: "Page Not Found" yo'q, lekin profil belgilari ham yo'q -> BAN/DEAKTIV
                    return CheckResult(status=UsernameStatus.TAKEN, reason="account_banned_or_disabled")

                # Cheklovlar yoki qayta yo'naltirish
                if response.status_code in (429, 302):
                    return CheckResult(status=UsernameStatus.ERROR, reason="rate_limited_or_redirect")

                return CheckResult(status=UsernameStatus.ERROR, reason=f"http_{response.status_code}")

        except Exception as e:
            return CheckResult(status=UsernameStatus.ERROR, reason=str(e))

# Global singleton instansiya
instagram_checker = InstagramChecker()
