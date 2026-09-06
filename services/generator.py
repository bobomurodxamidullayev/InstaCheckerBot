"""
services/generator.py — Random Instagram username generatori.

Instagram username qoidalari:
- Faqat harflar (a-z), raqamlar (0-9) va pastki chiziq (_)
- Uzunlik: 1–30 belgi
- Username raqam bilan boshlanmasligi tavsiya etiladi

Charset tanlovlari (.env GENERATOR_CHARSET):
- "letters"              → faqat a-z
- "alphanumeric"         → a-z + 0-9 (default)
- "alphanumeric_underscore" → a-z + 0-9 + _
"""

from __future__ import annotations

import random
import string
from typing import Literal

from config import settings

# ─── Belgilar To'plami ─────────────────────────────────────────────────────────

_CHARSETS: dict[str, str] = {
    "letters": string.ascii_lowercase,
    "alphanumeric": string.ascii_lowercase + string.digits,
    "alphanumeric_underscore": string.ascii_lowercase + string.digits + "_",
}

# Username har doim harf bilan boshlanishi kerak (Instagram qoidasi)
_FIRST_CHAR_POOL = string.ascii_lowercase


def get_charset() -> str:
    """Konfiguratsiyadan tanlangan belgilar to'plamini qaytaradi."""
    return _CHARSETS.get(settings.generator_charset, _CHARSETS["alphanumeric"])


# ─── Generator Funksiyalari ────────────────────────────────────────────────────

def generate_username(length: int) -> str:
    """
    Berilgan uzunlikdagi bitta random username generatsiya qiladi.

    Birinchi belgi har doim harf bo'ladi (raqam bilan boshlanmaslik uchun).
    Qolgan belgilar tanlangan charset dan olinadi.
    """
    if length < 3:
        length = 3
    if length > 15:
        length = 15

    charset = get_charset()
    first_char = random.choice(_FIRST_CHAR_POOL)
    rest = "".join(random.choices(charset, k=length - 1))
    return first_char + rest


def generate_usernames(length: int, count: int) -> list[str]:
    """
    Berilgan uzunlik va sonda noyob random username'lar ro'yxatini generatsiya qiladi.

    Agar count > imkon bo'lgan noyob kombinatsiyalar sonidan ko'p bo'lsa,
    takrorlanishlar oldini olish uchun set ishlatiladi.

    Parametrlar:
        length: Username uzunligi (3–15)
        count:  Generatsiya qilish soni (1–100)

    Qaytaradi:
        Noyob usernamelar ro'yxati
    """
    # Maksimal qiymatlarni cheklaymiz
    count = min(count, settings.generator_default_count * 5)

    generated: set[str] = set()
    max_attempts = count * 20  # Cheksiz loopdan himoya

    attempt = 0
    while len(generated) < count and attempt < max_attempts:
        username = generate_username(length)
        generated.add(username)
        attempt += 1

    return list(generated)


def validate_length(length: int) -> tuple[bool, str]:
    """
    Foydalanuvchi kiritgan uzunlikni tekshiradi.

    Qaytaradi:
        (True, "") — to'g'ri
        (False, xato_xabari) — noto'g'ri
    """
    if length < 3:
        return False, "❌ Uzunlik kamida 3 bo'lishi kerak."
    if length > 15:
        return False, "❌ Uzunlik ko'pi bilan 15 bo'lishi mumkin."
    return True, ""
