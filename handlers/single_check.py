"""
handlers/single_check.py — Yagona username tekshirish handler.

Komandalar:
- /check <username>  — Bitta username ni tezkor tekshiradi
- /start             — Xush kelibsiz xabari va ko'rsatmalar
- /help              — Barcha mavjud komandalar ro'yxati
"""

from __future__ import annotations

import logging
import re

from aiogram import Router
from aiogram.filters import Command, CommandStart
from aiogram.types import Message

from services.checker import instagram_checker
from utils.formatters import format_single_result

logger = logging.getLogger(__name__)

# Bu router bot.py da ro'yxatdan o'tkaziladi
router = Router(name="single_check")

# Instagram username validatsiya pattern (Instagram qoidalariga mos)
_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.]{1,30}$")


# ─── /start ────────────────────────────────────────────────────────────────────

@router.message(CommandStart())
async def handle_start(message: Message) -> None:
    """Bot bilan tanishish va ko'rsatmalar xabari."""
    text = (
        "👋 <b>Instagram Username Checker botiga xush kelibsiz!</b>\n\n"
        "🔍 <b>Mavjud komandalar:</b>\n\n"
        "• <code>/check username</code> — Bitta username tekshirish\n"
        "• <code>/generate uzunlik [soni]</code> — Random username generatsiya\n"
        "• <code>/help</code> — Batafsil ko'rsatmalar\n\n"
        "📋 <b>Bulk tekshirish:</b>\n"
        "Bir xabarda bir necha username yuborish (har qatorda bitta):\n"
        "<code>user1\nuser2\nuser3</code>\n\n"
        "📄 Yoki <b>.txt fayl</b> yuborish (max 30 username)\n\n"
        "<i>Barcha tekshiruv natijalari bazaga saqlanadi.</i>"
    )
    await message.answer(text, parse_mode="HTML")


# ─── /help ─────────────────────────────────────────────────────────────────────

@router.message(Command("help"))
async def handle_help(message: Message) -> None:
    """Batafsil foydalanish ko'rsatmalari."""
    text = (
        "📖 <b>Foydalanish ko'rsatmalari</b>\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "🔹 <b>Yagona tekshirish:</b>\n"
        "<code>/check testusername</code>\n\n"
        "🔹 <b>Bulk tekshirish (matn orqali):</b>\n"
        "Xabarda har qatorda bir username yozing:\n"
        "<code>user1\nuser2\nuser3</code>\n\n"
        "🔹 <b>Bulk tekshirish (.txt fayl):</b>\n"
        ".txt fayl yuborish (har qatorda bir username, max 30)\n\n"
        "🔹 <b>Random generator:</b>\n"
        "<code>/generate 5</code> — 5 harfli 20 ta random username\n"
        "<code>/generate 4 10</code> — 4 harfli 10 ta username\n\n"
        "━━━━━━━━━━━━━━━━━━━━\n"
        "📊 <b>Natija belgilari:</b>\n"
        "✅ — Mavjud (bo'sh, ro'yxatdan o'tish mumkin)\n"
        "❌ — Band (allaqachon ishlatilgan)\n"
        "⚠️ — Xatolik (network, rate-limit va h.k.)\n\n"
        "<i>Bulk tekshiruv yakunlangach available username'lar .txt faylda yuboriladi.</i>"
    )
    await message.answer(text, parse_mode="HTML")


# ─── /check ────────────────────────────────────────────────────────────────────

@router.message(Command("check"))
async def handle_single_check(message: Message) -> None:
    """
    /check <username> komandasini qayta ishlaydi.

    Validatsiya → tekshirish → natijani ko'rsatish.
    """
    # Komandadan username ajratib olamiz
    parts = message.text.split(maxsplit=1) if message.text else []

    if len(parts) < 2 or not parts[1].strip():
        await message.answer(
            "❌ <b>Foydalanish:</b> <code>/check username</code>\n\n"
            "<i>Misol: /check testuser123</i>",
            parse_mode="HTML",
        )
        return

    username = parts[1].strip().lstrip("@")

    # Username formatini tekshirish
    if not _USERNAME_PATTERN.match(username):
        await message.answer(
            f"❌ <b>Noto'g'ri username format:</b> <code>{username}</code>\n\n"
            "Username faqat harflar (a-z), raqamlar (0-9), nuqta (.) "
            "va pastki chiziq (_) dan iborat bo'lishi kerak.\n"
            "Uzunlik: 1–30 belgi.",
            parse_mode="HTML",
        )
        return

    # Tekshiruv boshlanganligi haqida xabar
    wait_msg = await message.answer(
        f"🔍 <code>@{username}</code> tekshirilmoqda...",
        parse_mode="HTML",
    )

    try:
        result = await instagram_checker.check_username(username)
        response_text = format_single_result(result)
        await wait_msg.edit_text(response_text, parse_mode="HTML")

        logger.info(
            "Yagona tekshiruv | @%s → %s", username, result.status.value
        )

    except Exception as exc:
        logger.exception("Yagona tekshiruvda kutilmagan xatolik: @%s", username)
        await wait_msg.edit_text(
            f"⚠️ <b>Xatolik yuz berdi:</b>\n<code>{exc}</code>",
            parse_mode="HTML",
        )
