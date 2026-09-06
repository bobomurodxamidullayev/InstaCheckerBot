"""
middlewares/auth.py — Admin-only autentifikatsiya middleware.

Faqat ADMIN_ID ga mos keluvchi foydalanuvchidan kelgan barcha update'lar
o'tkaziladi. Boshqa barcha foydalanuvchilarning so'rovlari "silent drop"
(jim rad etish) bilan e'tiborsiz qoldiriladi — hech qanday javob qaytmaydi.

Bu middleware barcha handler'lardan OLDIN ishlaydi (global middleware).
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware
from aiogram.types import TelegramObject, User

from config import settings

logger = logging.getLogger(__name__)


class AdminOnlyMiddleware(BaseMiddleware):
    """
    Faqat Super Admin (ADMIN_ID) dan kelgan so'rovlarni o'tkazuvchi middleware.

    Ishlash mantig'i:
    1. Har qanday Telegram update'dan from_user ni oladi.
    2. from_user.id != ADMIN_ID bo'lsa — handler chaqirilmaydi (silent drop).
    3. from_user topilmasa (channel post va h.k.) ham o'tkazilmaydi.
    """

    async def __call__(
        self,
        handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
        event: TelegramObject,
        data: dict[str, Any],
    ) -> Any:
        # Aiogram 3 da event_from_user context variable orqali olinadi
        user: User | None = data.get("event_from_user")

        if user is None or user.id != settings.admin_id:
            # Ruxsatsiz so'rovni log qilamiz (debug darajasida)
            if user is not None:
                logger.debug(
                    "Ruxsatsiz so'rov rad etildi | user_id=%s | username=@%s",
                    user.id,
                    user.username or "N/A",
                )
            # Handler chaqirilmaydi — update e'tiborsiz qoldiriladi
            return None

        # Admin tasdiqlandi — keyingi handler ga o'tish
        return await handler(event, data)
