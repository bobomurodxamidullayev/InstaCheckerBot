import asyncio
import re
import httpx

PROXY = "http://3796663a059d5e8762d2__cr.us:e0a68eea892e58fd@gw.dataimpulse.com:823"

# Telegram / WhatsApp bot User-Agent'i (Instagram bularga to'liq SSR meta beradi)
BOT_HEADERS = {
    "User-Agent": "TelegramBot (like TwitterBot)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

async def inspect(username):
    async with httpx.AsyncClient(proxy=PROXY, timeout=10.0, http2=False, follow_redirects=True) as client:
        r = await client.get(f"https://www.instagram.com/{username}/", headers=BOT_HEADERS)
        html = r.text

        title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
        title = title_match.group(1) if title_match else "TITLE_NOT_FOUND"

        og_desc = re.search(r'<meta property="og:description" content="(.*?)"', html, re.IGNORECASE)
        desc = og_desc.group(1) if og_desc else "OG_DESC_NOT_FOUND"

        print(f"=== {username} ===")
        print(f"Status: {r.status_code}")
        print(f"<title>: {title}")
        print(f"og:description: {desc[:60]}")
        print(f"Contains username in text: {username.lower() in html.lower()}")

async def main():
    await inspect("cristiano")
    print("-" * 40)
    await inspect("salom201203120321321")

asyncio.run(main())