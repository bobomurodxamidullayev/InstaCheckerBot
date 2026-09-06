"""
handlers/bulk_check.py — Bulk username tekshirish handler.

Qo'llab-quvvatlangan input turlari:
1. Matnli xabar — har qatorda bitta username (2+ qator bo'lsa bulk sifatida qabul qilinadi)
2. .txt fayl — har qatorda bitta username, UTF-8, max MAX_USERNAMES (100)

Oqim:
1. Usernamalarni qabul qilish va validatsiya qilish
2. Limit tekshirish (max MAX_USERNAMES)
3. Progress xabari yuborish
4. Bulk tekshiruvni ishga tushirish
5. Yakuniy hisobot + available.txt faylini yuborish
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from aiogram import Bot, F, Router
from aiogram.types import Document, Message

from services.queue_manager import run_bulk_check
from utils.formatters import (
    format_validation_error,
)

logger = logging.getLogger(__name__)

router = Router(name="bulk_check")

# Bitta xabar yoki faylda qabul qilinadigan username chegarasi
MAX_USERNAMES = 100
MIN_USERNAMES = 1
LIMIT_EXCEEDED_TEXT = (
    "Bitta so'rovda ko'pi bilan 100 ta username tekshirish mumkin"
)

# Instagram username validatsiya pattern
# Qoidalar: 1–30 belgi, lotin harflari, raqamlar, nuqta (.) va pastki chiziq (_)
_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._]{1,30}$")


# ─── Yordamchi Funksiyalar ─────────────────────────────────────────────────────

def parse_usernames(text: str) -> tuple[list[str], list[str]]:
    """
    Matndan username'larni ajratib oladi.

    Har bir qatorda bitta username bo'lishi kutiladi.
    @ belgisi olib tashlanadi.

    Qaytaradi:
        (valid_list, invalid_list)
    """
    valid: list[str] = []
    invalid: list[str] = []

    for line in text.splitlines():
        raw = line.strip().lstrip("@").lower()
        if not raw:
            continue  # Bo'sh qatorlar e'tiborsiz
        if _USERNAME_PATTERN.match(raw):
            if raw not in valid:  # Takrorlanishlarni olib tashlash
                valid.append(raw)
        else:
            invalid.append(raw)

    return valid, invalid


def _apply_username_limit(usernames: list[str]) -> tuple[list[str], bool]:
    """
    1 tadan MAX_USERNAMES tagacha qabul qiladi.
    100 dan oshsa, faqat birinchi 100 tasi qoladi va ogohlantirish kerakligini bildiradi.
    """
    if len(usernames) > MAX_USERNAMES:
        return usernames[:MAX_USERNAMES], True
    return usernames, False


async def _run_and_report(
    bot: Bot,
    chat_id: int,
    message_id: int,
    usernames: list[str],
) -> None:
    """
    Bulk tekshiruvni ishga tushiradi va yakuniy hisobotni yuboradi.
    Progress xabari message_id dagi xabarni yangilab boradi.
    """
    try:
        await run_bulk_check(
            usernames=usernames,
            bot=bot,
            chat_id=chat_id,
            progress_message_id=message_id,
        )
    except Exception as exc:
        logger.exception("Bulk tekshiruvda kutilmagan xatolik")
        await bot.send_message(
            chat_id=chat_id,
            text=f"⚠️ <b>Xatolik yuz berdi:</b>\n<code>{exc}</code>",
            parse_mode="HTML",
        )


# ─── Matnli Bulk Check Handler ─────────────────────────────────────────────────

@router.message(F.text & ~F.text.startswith("/"))
async def handle_text_bulk(message: Message, bot: Bot) -> None:
    """
    Har qatorda username yozilgan matnli xabarni qayta ishlaydi.
    Bitta qator bo'lsa — yagona tekshiruv, 2+ qator bo'lsa — bulk.
    """
    if not message.text:
        return

    valid_usernames, invalid_usernames = parse_usernames(message.text)

    # Hech qanday to'g'ri username topilmasa (minimal chegara: 1)
    if len(valid_usernames) < MIN_USERNAMES:
        if invalid_usernames:
            await message.answer(
                format_validation_error(invalid_usernames),
                parse_mode="HTML",
            )
        return  # Bo'sh xabar — e'tiborsiz

    # Noto'g'ri formatdagi usernamalar haqida ogohlantirish
    if invalid_usernames:
        await message.answer(
            format_validation_error(invalid_usernames),
            parse_mode="HTML",
        )

    # Limit tekshirish (max 100)
    valid_usernames, over_limit = _apply_username_limit(valid_usernames)
    if over_limit:
        await message.answer(LIMIT_EXCEEDED_TEXT)

    # Yagona username — /check komandasiga yo'naltirish (oddiyroq UI)
    if len(valid_usernames) == 1:
        from services.checker import instagram_checker
        from utils.formatters import format_single_result

        wait_msg = await message.answer(
            f"🔍 <code>@{valid_usernames[0]}</code> tekshirilmoqda...",
            parse_mode="HTML",
        )
        result = await instagram_checker.check_username(valid_usernames[0])
        await wait_msg.edit_text(format_single_result(result), parse_mode="HTML")
        return

    # Bulk mode
    progress_msg = await message.answer(
        f"🚀 <b>{len(valid_usernames)} ta username tekshirilmoqda...</b>\n\n"
        f"[░░░░░░░░░░] 0/{len(valid_usernames)} (0%)",
        parse_mode="HTML",
    )

    await _run_and_report(
        bot=bot,
        chat_id=message.chat.id,
        message_id=progress_msg.message_id,
        usernames=valid_usernames,
    )


# ─── .txt Fayl Handler ─────────────────────────────────────────────────────────

@router.message(F.document)
async def handle_file_bulk(message: Message, bot: Bot) -> None:
    """
    .txt fayl yuborilganda uni o'qib, ichidagi usernamelarni tekshiradi.

    Fayl tekshiruvlari:
    - Faqat .txt kengaytma
    - Max 50KB hajm
    - UTF-8 encoding
    """
    document: Optional[Document] = message.document
    if not document:
        return

    # Faqat .txt fayllar
    if not (document.file_name or "").lower().endswith(".txt"):
        await message.answer(
            "❌ Faqat <b>.txt</b> formatdagi fayllar qabul qilinadi.\n"
            "Har qatorda bitta username bo'lsin.",
            parse_mode="HTML",
        )
        return

    # Fayl hajmi tekshiruvi (max 50KB)
    max_size_bytes = 50 * 1024  # 50 KB
    if document.file_size and document.file_size > max_size_bytes:
        await message.answer(
            f"❌ Fayl hajmi juda katta (max 50KB). "
            f"Faylingiz: {document.file_size // 1024}KB",
        )
        return

    # Faylni yuklash
    loading_msg = await message.answer("📥 Fayl yuklanmoqda...")
    try:
        file_info = await bot.get_file(document.file_id)
        file_bytes = await bot.download_file(file_info.file_path)
        raw_text = file_bytes.read().decode("utf-8", errors="replace")
    except Exception as exc:
        await loading_msg.edit_text(f"❌ Faylni yuklashda xatolik: {exc}")
        return

    # Username'larni parse qilish
    valid_usernames, invalid_usernames = parse_usernames(raw_text)

    if not valid_usernames:
        await loading_msg.edit_text(
            "❌ Faylda hech qanday to'g'ri formatdagi username topilmadi.\n\n"
            "Format: har qatorda bitta username (@ belgisisiz).",
        )
        return

    info_parts = [f"📄 Fayl o'qildi: <b>{document.file_name}</b>"]
    if invalid_usernames:
        info_parts.append(f"⚠️ {len(invalid_usernames)} ta noto'g'ri username o'tkazib yuborildi.")

    # Limit tekshirish (max 100, min 1)
    valid_usernames, over_limit = _apply_username_limit(valid_usernames)
    if over_limit:
        info_parts.append(LIMIT_EXCEEDED_TEXT)

    info_parts.append(
        f"\n🚀 <b>{len(valid_usernames)} ta username tekshirilmoqda...</b>\n"
        f"[░░░░░░░░░░] 0/{len(valid_usernames)} (0%)"
    )

    progress_msg = await loading_msg.edit_text(
        "\n".join(info_parts), parse_mode="HTML"
    )

    await _run_and_report(
        bot=bot,
        chat_id=message.chat.id,
        message_id=progress_msg.message_id,
        usernames=valid_usernames,
    )
