"""
services/queue_manager.py — Bulk tekshiruv navbat va parallel ishlov berish.
Production-Ready v5:

  ASOSIY O'ZGARISHLAR (v4 → v5):
  - asyncio.Semaphore: concurrent limit to'g'ri boshqariladi (2 ta oqim proxy bilan)
  - Jitter: har so'rov oldin random.uniform(check_delay_min, check_delay_max) kutiladi
    Natija: so'rovlar bir vaqtda proxyga urilmaydi (thundering herd yo'q)
  - DB yozuvi: asyncio.create_task orqali non-blocking (natija bloklanmaydi)
  - Telegram progress: throttle + debounce, flood limit himoyasi
  - asyncio.gather return_exceptions=True + len(results) == total kafolati
  - Barcha istisno turlari ushlanadi, natija har doim keladi
"""
from __future__ import annotations

import asyncio
import io
import logging
import random
import time
import uuid
from dataclasses import dataclass

from aiogram import Bot
from aiogram.exceptions import TelegramBadRequest, TelegramNetworkError, TelegramRetryAfter

from config import settings
from database import bulk_save_results
from models.username_log import CheckStatus
from services.checker import CheckResult, instagram_checker
from utils.formatters import format_check_result, format_progress_bar, format_summary

logger = logging.getLogger(__name__)

# ─── Telegram progress throttle sozlamalari ────────────────────────────────────
# Telegram edit_message_text uchun max 1 req/2s (flood limit 30 req/min)
_PROGRESS_THROTTLE_INTERVAL = 3.0   # soniya: minimum yangilanishlar orasidagi vaqt
_PROGRESS_DEBOUNCE_BATCH = 5        # har N ta natijadan keyin majburiy yangilash

# ─── DB yozuv timeout ─────────────────────────────────────────────────────────
_DB_SAVE_TIMEOUT = 15.0  # soniya

# ─── TXT report preview ───────────────────────────────────────────────────────
AVAILABLE_MESSAGE_PREVIEW_LIMIT = 15


# ─── Natija dataclass ──────────────────────────────────────────────────────────

@dataclass
class BulkSessionResult:
    """Bulk tekshiruv sessiyasining yakuniy natijasi."""
    session_id: str
    total: int
    available_count: int
    taken_count: int
    error_count: int
    available_usernames: list
    taken_usernames: list
    error_results: list     # [(username, error_message), ...]


# ─── Yordamchi funksiyalar ────────────────────────────────────────────────────

def _normalize_username(username: str) -> str:
    return username.strip().lstrip("@").lower()


# ─── Throttled progress yangilovchi ──────────────────────────────────────────

class _ProgressThrottle:
    """
    Telegram flood limitidan himoya qiluvchi progress yangilovchi.

    Qoidalar:
      - Oxirgi yuborishdan beri _PROGRESS_THROTTLE_INTERVAL o'tmasa — skip.
      - Har _PROGRESS_DEBOUNCE_BATCH natijadan keyin majburiy yuborish.
      - Yakuniy (current == total) har doim yuboriladi.
    """

    def __init__(self) -> None:
        self._last_sent_at: float = 0.0
        self._last_sent_count: int = 0

    def should_update(self, current: int, total: int) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_sent_at

        # Har doim: yakuniy natija
        if current == total:
            return True

        # Har N natijadan keyin majburiy
        if (current - self._last_sent_count) >= _PROGRESS_DEBOUNCE_BATCH:
            return True

        # Vaqt bo'yicha throttle
        if elapsed >= _PROGRESS_THROTTLE_INTERVAL:
            return True

        return False

    def mark_sent(self, current: int) -> None:
        self._last_sent_at = time.monotonic()
        self._last_sent_count = current


# ─── Asosiy bulk check funksiyasi ─────────────────────────────────────────────

async def run_bulk_check(
    usernames: list,
    bot: Bot,
    chat_id: int,
    progress_message_id: int,
) -> BulkSessionResult:
    """
    Usernamelar ro'yxatini parallel tarzda tekshiradi.

    Kafolatlar:
      - Har bir username (AVAILABLE/TAKEN/ERROR) natijasi results ga tushadi.
      - len(results) == len(usernames) har doim.
      - DB yozuvi muvaffaqiyatsiz bo'lsa ham foydalanuvchiga natijalar yuboriladi.
      - Telegram progress yangilanishlari flood limitga tushmasligi uchun throttle.
      - Jitter: har so'rov oldin check_delay_min/max kutish (proxy rate limit himoyasi).
    """
    session_id = str(uuid.uuid4())
    total = len(usernames)

    logger.info(
        "Bulk tekshiruv boshlandi | session_id=%s | jami=%d | concurrent=%d",
        session_id, total, settings.concurrent_limit,
    )

    semaphore = asyncio.Semaphore(settings.concurrent_limit)
    results_lock = asyncio.Lock()
    progress_lock = asyncio.Lock()
    throttle = _ProgressThrottle()

    completed_count = 0
    results: list[CheckResult] = []

    async def check_one(index: int, username: str) -> None:
        """
        Bitta username ni semafor ostida tekshiradi.
        Jitter: birinchi so'rovda ham minimal kechikish qo'shiladi
        (barcha so'rovlar bir vaqtda borishini oldini oladi).
        KAFOLAT: istisno bo'lsa ham ERROR CheckResult sifatida results ga yoziladi.
        """
        nonlocal completed_count

        try:
            async with semaphore:
                # Jitter: har so'rov oldin tasodifiy kechikish
                # Bu proxyga bir vaqtda ko'plab so'rov borishini oldini oladi
                jitter_delay = random.uniform(
                    settings.check_delay_min * (index % settings.concurrent_limit),
                    settings.check_delay_max * (index % settings.concurrent_limit + 1),
                )
                # Minimal jitter (0.3-0.8s) birinchi batch uchun ham
                base_jitter = random.uniform(0.3, 0.8)
                await asyncio.sleep(max(base_jitter, jitter_delay * 0.3))

                result = await instagram_checker.check_username(username)

        except Exception as exc:
            logger.exception(
                "check_username ichki istisno: @%s -- %s", username, exc
            )
            result = CheckResult(
                username=_normalize_username(username),
                status=CheckStatus.ERROR,
                error_message=f"ichki istisno: {type(exc).__name__}: {exc}",
            )

        async with results_lock:
            completed_count += 1
            results.append(result)
            current = completed_count

        logger.info(
            "Tekshirildi [%d/%d]: @%s -> %s | Xato: %s",
            current, total,
            result.username,
            result.status.value,
            result.error_message,
        )

        # Progress yangilash (throttle bilan, progress_lock da xavfsiz)
        async with progress_lock:
            if throttle.should_update(current, total):
                throttle.mark_sent(current)
                await _update_progress_message(
                    bot=bot,
                    chat_id=chat_id,
                    message_id=progress_message_id,
                    results=list(results),
                    completed=current,
                    total=total,
                )

    # Barcha tasklarni bir vaqtda ishga tushirish (index bilan jitter hisoblash uchun)
    tasks = [asyncio.create_task(check_one(i, u)) for i, u in enumerate(usernames)]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Yo'qolgan natijalarni to'ldirish (xavfsizlik qatlami)
    await _ensure_complete_results(usernames, results)

    if len(results) != total:
        logger.error(
            "KRITIK: results=%d, total=%d — natijalar yo'qoldi!",
            len(results), total,
        )

    # DB ga saqlash (non-blocking — asyncio.create_task orqali, main oqimni bloklamas)
    asyncio.create_task(
        _save_to_db_safe(session_id=session_id, results=results)
    )

    # Natijalarni hisoblash
    available = [r.username for r in results if r.status == CheckStatus.AVAILABLE]
    taken = [r.username for r in results if r.status == CheckStatus.TAKEN]
    error_results = [
        (r.username, r.error_message or "noma'lum xato")
        for r in results if r.status == CheckStatus.ERROR
    ]

    logger.info(
        "Sessiya yakunlandi | session_id=%s | results=%d/%d | "
        "avail=%d taken=%d err=%d",
        session_id, len(results), total,
        len(available), len(taken), len(error_results),
    )

    session_result = BulkSessionResult(
        session_id=session_id,
        total=total,
        available_count=len(available),
        taken_count=len(taken),
        error_count=len(error_results),
        available_usernames=available,
        taken_usernames=taken,
        error_results=error_results,
    )

    await _deliver_final_report(
        bot=bot,
        chat_id=chat_id,
        message_id=progress_message_id,
        session_result=session_result,
    )

    return session_result


# ─── DB saqlash (xavfsiz, non-blocking) ───────────────────────────────────────

async def _save_to_db_safe(session_id: str, results: list[CheckResult]) -> None:
    """
    Natijalarni DB ga saqlaydi. Timeout yoki xato bo'lsa ham asosiy oqimni
    bloklamaydi — faqat log yoziladi.
    """
    try:
        await asyncio.wait_for(
            bulk_save_results(session_id, results),
            timeout=_DB_SAVE_TIMEOUT,
        )
        logger.info("DB saqlash muvaffaqiyatli: session_id=%s", session_id)
    except asyncio.TimeoutError:
        logger.warning(
            "DB saqlash timeout (%.1fs): session_id=%s — "
            "natijalar foydalanuvchiga yuborilgan, lekin DB da yo'q.",
            _DB_SAVE_TIMEOUT, session_id,
        )
    except Exception as exc:
        import traceback
        logger.error(
            "DB saqlashda xatolik: session_id=%s — %s\n%s",
            session_id, exc, traceback.format_exc()
        )


# ─── Yo'qolgan natijalarni to'ldirish ─────────────────────────────────────────

async def _ensure_complete_results(
    usernames: list, results: list[CheckResult]
) -> None:
    """Har bir kiritilgan username uchun natija borligini kafolatlaydi."""
    seen = {r.username for r in results}
    for raw in usernames:
        name = _normalize_username(raw)
        if name in seen:
            continue
        logger.error("Natija yo'qolgan, ERROR qo'shildi: @%s", name)
        results.append(
            CheckResult(
                username=name,
                status=CheckStatus.ERROR,
                error_message="natija yo'qolgan (gather xatosi)",
            )
        )
        seen.add(name)


# ─── Progress yangilash (Telegram) ────────────────────────────────────────────

async def _update_progress_message(
    bot: Bot,
    chat_id: int,
    message_id: int,
    results: list[CheckResult],
    completed: int,
    total: int,
) -> None:
    """
    Telegram dagi progress xabarini yangilaydi.

    TelegramRetryAfter ushlanadi va ko'rsatilgan vaqt kutiladi.
    Boshqa xatolar sessiyani to'xtatmaydi.
    """
    try:
        progress_text = format_progress_bar(completed=completed, total=total)
        recent = results[-5:]
        recent_results_text = "\n".join(format_check_result(r) for r in recent)
        text = (
            "🔍 <b>Tekshirilmoqda...</b>\n\n"
            + progress_text + "\n\n"
            + "<b>So'nggi natijalar:</b>\n"
            + recent_results_text
        )
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=text,
            parse_mode="HTML",
        )
    except TelegramRetryAfter as exc:
        # Flood limit: ko'rsatilgan vaqt kutish
        logger.warning(
            "Telegram RetryAfter %ds: progress yangilash kechiktirildi.",
            exc.retry_after,
        )
        await asyncio.sleep(exc.retry_after + 1)
    except (TelegramBadRequest, TelegramNetworkError):
        pass  # Xabar o'chirilgan yoki network xatosi — o'tkazib yuboramiz
    except Exception as exc:
        logger.debug("Progress yangilashda kutilmagan xato: %s", exc)


# ─── Yakuniy hisobot yuborish ─────────────────────────────────────────────────

async def _deliver_final_report(
    bot: Bot,
    chat_id: int,
    message_id: int,
    session_result: BulkSessionResult,
) -> None:
    """
    Yakuniy xulosa xabari va .txt hisobotni Telegramga yuboradi.
    DB yozuvi muvaffaqiyatsiz bo'lsa ham chaqiriladi.
    """
    preview, extra_available = preview_available_usernames(
        session_result.available_usernames
    )
    summary_text = format_summary(
        total=session_result.total,
        available=session_result.available_count,
        taken=session_result.taken_count,
        errors=session_result.error_count,
        session_id=session_result.session_id,
        available_usernames=preview,
        extra_available=extra_available,
    )

    # Avval progress xabarini yakuniy xulosa bilan almashtirishga harakat
    summary_sent = False
    try:
        await bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_id,
            text=summary_text,
            parse_mode="HTML",
        )
        summary_sent = True
    except TelegramRetryAfter as exc:
        await asyncio.sleep(exc.retry_after + 1)
        try:
            await bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_id,
                text=summary_text,
                parse_mode="HTML",
            )
            summary_sent = True
        except Exception as e:
            logger.error("Yakuniy xabarni tahrirlashda xato (retry so'nra): %s", e)
    except Exception as e:
        logger.error("Yakuniy xabarni tahrirlashda xato: %s", e)

    # Tahrirlash muvaffaqiyatsiz bo'lsa — yangi xabar yuborish
    if not summary_sent:
        for send_attempt in range(1, 3):
            try:
                await bot.send_message(
                    chat_id=chat_id,
                    text=summary_text,
                    parse_mode="HTML",
                )
                summary_sent = True
                break
            except TelegramRetryAfter as exc:
                logger.warning("send_message RetryAfter %ds", exc.retry_after)
                await asyncio.sleep(exc.retry_after + 1)
            except Exception as e:
                logger.error(
                    "Yakuniy xabarni yuborishda xato (urinish %d/2): %s",
                    send_attempt, e,
                )
                if send_attempt < 2:
                    await asyncio.sleep(2.0)

    # TXT hisobotni yuborish (max 2 urinish)
    txt_buffer = create_report_txt(session_result)
    txt_bytes = txt_buffer.getvalue()
    filename = f"report_{session_result.session_id[:8]}.txt"
    caption = f"📊 Tekshiruv hisoboti (Jami: {session_result.total} ta)"

    from aiogram.types import BufferedInputFile

    for doc_attempt in range(1, 3):
        try:
            await bot.send_document(
                chat_id=chat_id,
                document=BufferedInputFile(file=txt_bytes, filename=filename),
                caption=caption,
            )
            break
        except TelegramRetryAfter as exc:
            logger.warning("send_document RetryAfter %ds", exc.retry_after)
            await asyncio.sleep(exc.retry_after + 1)
        except Exception as e:
            logger.error(
                "report.txt yuborishda xato (urinish %d/2): %s", doc_attempt, e
            )
            if doc_attempt < 2:
                await asyncio.sleep(2.0)


# ─── Preview va TXT yaratish ───────────────────────────────────────────────────

def preview_available_usernames(usernames: list) -> tuple[list, int]:
    """
    Telegram xabari 4096 belgidan oshmasligi uchun
    faqat dastlabki AVAILABLE_MESSAGE_PREVIEW_LIMIT ta nomni qaytaradi.

    Qaytaradi: (preview_list, extra_count)
    """
    extra = max(0, len(usernames) - AVAILABLE_MESSAGE_PREVIEW_LIMIT)
    return usernames[:AVAILABLE_MESSAGE_PREVIEW_LIMIT], extra


def create_report_txt(session_result: BulkSessionResult) -> io.BytesIO:
    """
    Barcha natijalarni (AVAILABLE, TAKEN, ERROR) chiroyli formatda
    BytesIO buferiga UTF-8 da yozadi.
    """
    from datetime import datetime

    sid = session_result.session_id
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "=" * 60
    dash = "-" * 60

    lines: list[str] = [
        sep,
        "          INSTAGRAM USERNAME CHECKER REPORT          ",
        sep,
        f"Sessiya ID : {sid}",
        f"Sana/Vaqt  : {now}",
        f"Jami       : {session_result.total} ta",
        f"Mavjud     : {session_result.available_count} ta",
        f"Band       : {session_result.taken_count} ta",
        f"Xatolik    : {session_result.error_count} ta",
        sep,
        "",
        f"[ MAVJUD / BO'SH USERNAMELAR ({session_result.available_count}) ]",
    ]

    if session_result.available_usernames:
        lines.extend(session_result.available_usernames)
    else:
        lines.append("(Mavjud emas)")

    lines += ["", dash, "", f"[ BAND USERNAMELAR ({session_result.taken_count}) ]"]

    if session_result.taken_usernames:
        lines.extend(session_result.taken_usernames)
    else:
        lines.append("(Mavjud emas)")

    lines += ["", dash]

    if session_result.error_results:
        lines += ["", f"[ XATOLIK BO'LGANLAR ({session_result.error_count}) ]"]
        for username, reason in session_result.error_results:
            lines.append(f"{username} -> {reason}")
        lines.append("")

    lines.append(sep)

    content = "\n".join(lines) + "\n"
    buffer = io.BytesIO(content.encode("utf-8"))
    buffer.name = f"report_{sid[:8]}.txt"
    return buffer
