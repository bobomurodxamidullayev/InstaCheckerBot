"""
database.py — Async MySQL baza ulanishi va sessiya boshqaruvi.
Production-Ready v5 (aiomysql driver, Windows-safe):

  ASOSIY O'ZGARISHLAR (v4 → v5):
  - asyncmy OLIB TASHLANDI — Windows ProactorEventLoop da qotib qolishni keltirib
    chiqaradi. aiomysql + SelectorEventLoop bundan xoli.
  - _build_engine_url() endi asyncmy URL → aiomysql ga konvertatsiya qiladi.
  - connect_args: autocommit False, charset utf8mb4, connect_timeout=10.
  - pool_pre_ping=True + pool_recycle=3600 (1 soat).
  - health_check() asyncio.wait_for bilan non-blocking.
  - init_db() timeout=15s, xato bo'lsa davom etish (graceful fallback).
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from config import settings
from models.username_log import Base, CheckStatus, UsernameLog

logger = logging.getLogger(__name__)

# ─── Sozlamalar ───────────────────────────────────────────────────────────────
_DB_INIT_TIMEOUT = 5.0       # init_db() uchun maksimum kutish vaqti (soniya)
_DB_QUERY_TIMEOUT = 10.0      # oddiy query uchun timeout
_POOL_SIZE = 10               # asosiy pool hajmi
_MAX_OVERFLOW = 5             # qo'shimcha dinamik ulanishlar
_POOL_RECYCLE = 300           # ulanish yashash muddati (soniya, 5 daqiqa)
_POOL_TIMEOUT = 5.0           # pool dan bo'sh ulanish kutish vaqti


# ─── Engine URL normalizatsiyasi ─────────────────────────────────────────────

def _build_engine_url(raw_url: str) -> str:
    """
    URL dagi asyncmy ni aiomysql ga almashtiradi.
    Windows muhitida aiomysql SelectorEventLoop bilan to'g'ri ishlaydi.
    asyncmy esa Windows ProactorEventLoop da handshake da qotib qoladi.
    """
    url = raw_url
    if "mysql+asyncmy://" in url:
        url = url.replace("mysql+asyncmy://", "mysql+aiomysql://")
        logger.info("DB driver: asyncmy -> aiomysql (avtomatik almashtirish, Windows fixi)")
    
    if "@localhost:" in url:
        url = url.replace("@localhost:", "@127.0.0.1:")
        
    return url


# ─── Engine yaratish ──────────────────────────────────────────────────────────

_engine_url = _build_engine_url(settings.database_url)

engine = create_async_engine(
    _engine_url,
    poolclass=NullPool,
    echo=False,
    connect_args={
        # aiomysql uchun aniq ulanish timeout (soniya)
        "connect_timeout": 5,
        "charset": "utf8mb4",
        # autocommit=False: SQLAlchemy o'zi tranzaksiyani boshqaradi
        "autocommit": False,
    },
)

AsyncSessionFactory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


# ─── Auto-Migration ───────────────────────────────────────────────────────────

async def _run_migration() -> None:
    """Barcha jadvallarni yaratadi (agar mavjud bo'lmasa)."""
    # Tezkor tekshiruv (sessiyani darhol qaytaradi)
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    
    # Jadvallarni yaratish
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def init_db() -> None:
    """
    Bot ishga tushganda chaqiriladi.

    Kafolatlar:
      - Timeout bo'lsa (5s) — faqat ogohlantirish, bot davom etadi.
      - Ulanish xatosi bo'lsa — KRITIK log, istisno ko'tariladi (DB siz bot bema'ni).
      - Asosiy bot oqimini bloklamaydigan: asyncio.wait_for orqali cheklangan.
    """
    logger.info(
        "Ma'lumotlar bazasi tekshirilmoqda... | host=%s port=%s db=%s driver=aiomysql",
        settings.db_host, settings.db_port, settings.db_name,
    )
    try:
        await asyncio.wait_for(_run_migration(), timeout=_DB_INIT_TIMEOUT)
        logger.info("Jadvallar tayyor (auto-migration muvaffaqiyatli) ✅")
    except asyncio.TimeoutError:
        logger.warning(
            "Baza tekshiruvi timeout (%.1fs) — bot ishga tushishda davom etadi. "
            "Jadval qulfi yoki sekin ulanish bo'lishi mumkin. "
            "Keyingi SQL so'rovlarda ulanish avtomatik qayta urinadi.",
            _DB_INIT_TIMEOUT,
        )
    except Exception as exc:
        import traceback
        logger.critical(
            "Baza bilan ulanishda xatolik: %s\nTraceback:\n%s\n"
            "Tekshiring: DB_HOST=%s DB_PORT=%s DB_NAME=%s",
            exc,
            traceback.format_exc(),
            settings.db_host,
            settings.db_port,
            settings.db_name,
        )
        raise  # DB ulanishi kritik — bot to'xtatiladi


# ─── Session Context Manager ──────────────────────────────────────────────────

@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Async context manager: sessiya yaratadi, muvaffaqiyatli bo'lsa commit,
    xato bo'lsa rollback qiladi.

    Ishlatish:
        async with get_session() as session:
            session.add(obj)
    """
    async with AsyncSessionFactory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# ─── CRUD Funksiyalari ────────────────────────────────────────────────────────

async def save_result(
    session_id: str,
    username: str,
    status: CheckStatus,
    error_message: str | None = None,
) -> UsernameLog:
    """Bitta tekshiruv natijasini bazaga yozadi."""
    async with get_session() as db_session:
        log_entry = UsernameLog(
            session_id=session_id,
            username=username.lower().strip(),
            status=status,
            error_message=error_message,
        )
        db_session.add(log_entry)
    return log_entry


async def bulk_save_results(session_id: str, results: list) -> int:
    """
    Bulk sessiya natijalarini bitta tranzaksiyada yozadi.

    Samaradorlik: barcha ob'yektlar bitta session.commit() orqali saqlanadi.
    Qaytaradi: yozilgan qatorlar soni.
    """
    if not results:
        return 0

    async with AsyncSessionFactory() as session:
        try:
            log_entries = [
                UsernameLog(
                    session_id=session_id,
                    username=str(result.username).lower().strip(),
                    status=result.status,
                    error_message=result.error_message,
                )
                for result in results
            ]
            session.add_all(log_entries)
            await session.commit()
            
            logger.info(
                "Ommaviy saqlash: session_id=%s | yozildi=%d",
                session_id, len(results),
            )
            return len(results)
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_session_results(session_id: str) -> list[UsernameLog]:
    """Sessiya bo'yicha barcha natijalarni qaytaradi."""
    async with get_session() as db_session:
        result = await db_session.execute(
            select(UsernameLog)
            .where(UsernameLog.session_id == session_id)
            .order_by(UsernameLog.checked_at)
        )
        return list(result.scalars().all())


async def get_available_usernames(session_id: str) -> list[str]:
    """Sessiyaning faqat AVAILABLE usernamelarini qaytaradi."""
    async with get_session() as db_session:
        result = await db_session.execute(
            select(UsernameLog.username)
            .where(
                UsernameLog.session_id == session_id,
                UsernameLog.status == CheckStatus.AVAILABLE,
            )
            .order_by(UsernameLog.checked_at)
        )
        return list(result.scalars().all())


async def health_check() -> bool:
    """
    DB ulanish sifatini tekshiradi. Non-blocking, xatolarni ushlaydigan.
    Qaytaradi: True — sog'lom, False — muammo bor.
    """
    try:
        async with AsyncSessionFactory() as session:
            await asyncio.wait_for(
                session.execute(text("SELECT 1")),
                timeout=5.0,
            )
        return True
    except asyncio.TimeoutError:
        logger.warning("DB health check timeout (5s)")
        return False
    except Exception as exc:
        logger.warning("DB health check muvaffaqiyatsiz: %s", exc)
        return False


async def close_db() -> None:
    """Bot to'xtaganda barcha ulanishlarni yopadi."""
    await engine.dispose()
    logger.info("Ma'lumotlar bazasi ulanishi yopildi.")
