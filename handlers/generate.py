"""
handlers/generate.py — Random username generatsiya va tekshirish handler.

Komanda: /generate <uzunlik> [soni]

Misollar:
  /generate 5       → 5 harfli 20 ta random username generatsiya va tekshirish
  /generate 4 10    → 4 harfli 10 ta username

Oqim:
1. Parametrlarni validatsiya qilish
2. Username'larni generatsiya qilish
3. Generatsiya natijalari haqida xabar yuborish
4. Bulk tekshiruvni ishga tushirish
5. Natijalar + available.txt
"""

from __future__ import annotations

import logging

from aiogram import Bot, Router
from aiogram.filters import Command
from aiogram.types import Message

from config import settings
from handlers.bulk_check import _run_and_report
from services.generator import generate_usernames, validate_length

logger = logging.getLogger(__name__)

router = Router(name="generate")


@router.message(Command("generate"))
async def handle_generate(message: Message, bot: Bot) -> None:
    """
    /generate <uzunlik> [soni] komandasini qayta ishlaydi.

    Parametrlar:
        uzunlik — Username uzunligi (3–15)
        soni    — Generatsiya soni (ixtiyoriy, default GENERATOR_DEFAULT_COUNT)
    """
    parts = (message.text or "").split()

    # Parametrlarni parse qilish
    if len(parts) < 2:
        await message.answer(
            "❌ <b>Foydalanish:</b>\n"
            "<code>/generate uzunlik [soni]</code>\n\n"
            "<b>Misollar:</b>\n"
            "• <code>/generate 5</code> — 5 harfli 20 ta username\n"
            "• <code>/generate 4 10</code> — 4 harfli 10 ta username\n\n"
            "<i>Uzunlik: 3–15 | Soni: 1–100</i>",
            parse_mode="HTML",
        )
        return

    # uzunlik parametrini o'qish
    try:
        length = int(parts[1])
    except ValueError:
        await message.answer(
            "❌ Uzunlik butun son bo'lishi kerak.\n"
            "<i>Misol: /generate 5</i>",
            parse_mode="HTML",
        )
        return

    # uzunlik ni validatsiya qilish
    is_valid, error_msg = validate_length(length)
    if not is_valid:
        await message.answer(
            f"{error_msg}\n<i>To'g'ri diapazon: 3–15</i>",
            parse_mode="HTML",
        )
        return

    # soni parametrini o'qish (ixtiyoriy)
    count = settings.generator_default_count
    if len(parts) >= 3:
        try:
            count = int(parts[2])
            if count < 1:
                count = 1
            elif count > settings.bulk_max_usernames:
                await message.answer(
                    f"⚠️ Soni ko'pi bilan <b>{settings.bulk_max_usernames}</b> bo'lishi mumkin.\n"
                    f"{settings.bulk_max_usernames} ta generatsiya qilinadi.",
                    parse_mode="HTML",
                )
                count = settings.bulk_max_usernames
        except ValueError:
            await message.answer(
                "❌ Soni butun son bo'lishi kerak.\n"
                "<i>Misol: /generate 5 10</i>",
                parse_mode="HTML",
            )
            return

    # Username'larni generatsiya qilish
    usernames = generate_usernames(length=length, count=count)

    if not usernames:
        await message.answer("❌ Username generatsiya qilishda xatolik yuz berdi.")
        return

    # Generatsiya haqida xabar va bulk tekshiruvni boshlash
    progress_msg = await message.answer(
        f"🎲 <b>{len(usernames)} ta random username generatsiya qilindi</b>\n"
        f"📏 Uzunlik: <b>{length}</b> belgi\n\n"
        f"🔍 Tekshirilmoqda...\n"
        f"[░░░░░░░░░░] 0/{len(usernames)} (0%)",
        parse_mode="HTML",
    )

    logger.info(
        "Generator ishga tushdi | uzunlik=%d | soni=%d", length, len(usernames)
    )

    await _run_and_report(
        bot=bot,
        chat_id=message.chat.id,
        message_id=progress_msg.message_id,
        usernames=usernames,
    )
