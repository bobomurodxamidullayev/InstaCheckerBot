"""
handlers/__init__.py — Handlers paketi.

Barcha routerlarni import qiladi. bot.py da shu modul ishlatiladi.
"""

from handlers.bulk_check import router as bulk_check_router
from handlers.generate import router as generate_router
from handlers.single_check import router as single_check_router

# Tartibi muhim: /check komandasi matnli xabardan oldin tekshirilishi kerak
all_routers = [
    single_check_router,   # /start, /help, /check — komandalar birinchi
    generate_router,       # /generate
    bulk_check_router,     # Matnli xabar va .txt fayl — oxirgi (fallback)
]

__all__ = ["all_routers"]
