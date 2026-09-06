"""
bot.py — Asosiy entry point (Production-Ready v5).

Mas'uliyatlar:
1. Windows SelectorEventLoop (aiomysql uchun MAJBURIY)
2. Logging sozlash
3. Config va DB tekshirish
4. Bot va Dispatcher yaratish (barqaror TCPConnector)
5. Middleware ro'yxatdan o'tkazish
6. Handler routerlarni ulash
7. Instagram checker lifecycle boshqaruvi
8. Polling ishga tushirish (WinError 10054 va DNS xatolariga chidamli)
"""
# ─── MUHIM: from __future__ eng birinchi bo'lishi shart (Python qoidasi) ───────
from __future__ import annotations

# ─── Windows ProactorEventLoop → SelectorEventLoop (aiomysql deadlock fixi) ───
# Python 3.10+ da Windows birlamchi asyncio.ProactorEventLoop.
# aiomysql MySQL handshake da ProactorEventLoop bilan qotib qoladi (TimeoutError).
# SelectorEventLoop to'g'ri ishlaydi — barcha import lardan oldin o'rnatiladi.
#
# asyncmy ham shu muammoga ega — shuning uchun aiomysql ga o'tildi.
# Bu satr bot.py da ENG BIRINCHI bo'lishi SHART.
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
# ──────────────────────────────────────────────────────────────────────────────

import logging

import aiohttp
from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.enums import ParseMode

from config import settings
from database import close_db, init_db
from handlers import all_routers
from middlewares import AdminOnlyMiddleware
from services.checker import instagram_checker

# ─── Logging Sozlash ───────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("bot.log", encoding="utf-8"),
    ],
)
# Shovqinli loglarni kamaytirish
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("curl_cffi").setLevel(logging.WARNING)
logging.getLogger("aiomysql").setLevel(logging.WARNING)
logging.getLogger("aiohttp").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


# ─── Bot va Dispatcher Yaratish ────────────────────────────────────────────────

def create_telegram_session() -> AiohttpSession:
    """
    Windows WinError 10054 / uzilgan keepalive uchun barqaror TCPConnector.

    Sozlamalar:
      - ttl_dns_cache=300: DNS keshini 5 daqiqa saqlash (takroriy DNS so'rovlar yo'q)
      - keepalive_timeout=30: 30 soniya harakatsizlikdan keyin keepalive uzilib qoladi
      - enable_cleanup_closed=True: yopilgan ulanishlar avtomatik tozalanadi
      - force_close=False: keepalive ishlashiga ruxsat beriladi (tezlik uchun)
    """
    session = AiohttpSession(timeout=60.0)
    session._connector_type = aiohttp.TCPConnector
    session._connector_init.update(
        {
            "ttl_dns_cache": 300,
            "keepalive_timeout": 30.0,
            "enable_cleanup_closed": True,
            "force_close": False,
            "limit": 20,
        }
    )
    return session


def create_bot() -> Bot:
    """Aiogram Bot obyektini yaratadi."""
    return Bot(
        token=settings.bot_token,
        session=create_telegram_session(),
        default=DefaultBotProperties(parse_mode=ParseMode.HTML),
    )


def create_dispatcher() -> Dispatcher:
    """
    Dispatcher yaratadi, middleware va routerlarni ulaydi.

    Middleware tartib:
    - AdminOnlyMiddleware → barcha update'larga (message, callback_query, inline, ...)
      birinchi bo'lib qo'llaniladi.
    """
    dispatcher = Dispatcher()

    # Global middleware — Admin filtri (barcha update turlariga)
    dispatcher.update.middleware(AdminOnlyMiddleware())

    # Routerlarni tartib bilan ro'yxatdan o'tkazish
    for router in all_routers:
        dispatcher.include_router(router)

    return dispatcher


# ─── Lifecycle Hooks ───────────────────────────────────────────────────────────

async def on_startup(bot: Bot) -> None:
    """Bot ishga tushganda bir marta bajariladi."""
    logger.info("=" * 60)
    logger.info("Instagram Username Checker Bot ishga tushmoqda...")
    logger.info("Admin ID: %s", settings.admin_id)
    logger.info(
        "Proxy: %s",
        settings.proxy_url if settings.proxy_enabled else "Yo'q (direct rejim)",
    )
    logger.info(
        "Concurrent limit: %d (%s rejim)",
        settings.concurrent_limit,
        "proxy" if settings.proxy_enabled else "direct",
    )

    # 1. Ma'lumotlar bazasini tekshirish va jadvallarni yaratish
    await init_db()

    # 2. Instagram HTTP client ni ishga tushirish
    await instagram_checker.start()

    # 3. Adminga bot ishga tushganligi haqida xabar
    try:
        mode_text = (
            f"🔀 Proxy rejim: <code>{settings.proxy_url}</code>"
            if settings.proxy_enabled
            else "🌐 Direct rejim (proxysiz)"
        )
        await bot.send_message(
            chat_id=settings.admin_id,
            text=(
                "✅ <b>Bot muvaffaqiyatli ishga tushdi!</b>\n\n"
                f"{mode_text}\n"
                f"⚡ Concurrent limit: <b>{settings.concurrent_limit}</b>\n\n"
                "<i>/help komandasini yuboring</i>"
            ),
        )
    except Exception as exc:
        logger.warning("Adminga xabar yuborishda xatolik: %s", exc)

    logger.info("Bot tayyor ✅")
    logger.info("=" * 60)


async def on_shutdown(bot: Bot) -> None:
    """Bot to'xtaganda tozalash ishlarini bajaradi."""
    logger.info("Bot to'xtatilmoqda...")

    # Instagram checker ni yopish
    await instagram_checker.stop()

    # DB ulanishini yopish
    await close_db()

    # Bot sessiyasini yopish
    await bot.session.close()

    logger.info("Bot to'xtatildi. Xayr! 👋")


# ─── Asosiy Funksiya ───────────────────────────────────────────────────────────

async def main() -> None:
    """Botni ishga tushiruvchi asosiy funksiya."""
    bot = create_bot()
    dispatcher = create_dispatcher()

    # Lifecycle hook'larni ro'yxatdan o'tkazish
    dispatcher.startup.register(on_startup)
    dispatcher.shutdown.register(on_shutdown)

    logger.info(
        "Polling boshlanmoqda... | Platform: %s | EventLoop: %s",
        sys.platform,
        type(asyncio.get_event_loop()).__name__,
    )

    # Long-polling bilan ishga tushirish
    # handle_signals=True: Ctrl+C va SIGTERM ni to'g'ri boshqaradi
    await dispatcher.start_polling(
        bot,
        skip_updates=True,
        handle_signals=True,
        polling_timeout=30,
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Ctrl+C bosildi — bot to'xtatildi.")
    except Exception as exc:
        logger.critical("Kutilmagan kritik xato: %s", exc, exc_info=True)
        sys.exit(1)
