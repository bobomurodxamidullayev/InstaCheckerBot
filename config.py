"""
config.py — Markazlashgan konfiguratsiya moduli.

Pydantic Settings orqali .env faylidan barcha sozlamalarni o'qiydi.
Global `settings` obyekti butun loyiha bo'ylab import qilinadi.

v5 o'zgarishlari:
  - database_url: mysql+asyncmy → mysql+aiomysql (Windows driver fixi)
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Barcha konfiguratsiya sozlamalari."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ─── Telegram ──────────────────────────────────────────────
    bot_token: str = Field(..., description="Telegram Bot Token (BotFather dan)")
    admin_id: int = Field(..., description="Yagona Super Admin Telegram User ID")

    # ─── Database ──────────────────────────────────────────────
    db_host: str = Field(default="127.0.0.1")
    db_port: int = Field(default=3306)
    db_name: str = Field(default="instachecker")
    db_user: str = Field(default="root")
    db_pass: str = Field(default="")

    # ─── Proxy ─────────────────────────────────────────────────
    proxy_url: Optional[str] = Field(
        default=None,
        description="Rotating residential proxy URL. Bo'sh bo'lsa — direct ulanish.",
    )

    # ─── Checker ───────────────────────────────────────────────
    check_delay_min: float = Field(default=1.5, ge=0.5)
    check_delay_max: float = Field(default=3.5, ge=1.0)
    concurrent_limit_proxy: int = Field(default=2, ge=1, le=50)
    concurrent_limit_direct: int = Field(default=1, ge=1, le=10)
    rate_limit_sleep: float = Field(default=30.0, ge=5.0)

    # ─── Generator ─────────────────────────────────────────────
    generator_charset: str = Field(default="alphanumeric")
    generator_default_count: int = Field(default=20, ge=1, le=100)

    # ─── Bulk Check ────────────────────────────────────────────
    bulk_max_usernames: int = Field(default=100, ge=1, le=100)

    # ─── Computed Properties ───────────────────────────────────

    @property
    def proxy_enabled(self) -> bool:
        """Proxy sozlamasi kiritilganligini tekshiradi."""
        return bool(self.proxy_url and self.proxy_url.strip())

    @property
    def concurrent_limit(self) -> int:
        """Joriy rejimga mos parallel request chegarasini qaytaradi."""
        return self.concurrent_limit_proxy if self.proxy_enabled else self.concurrent_limit_direct

    @property
    def database_url(self) -> str:
        """
        SQLAlchemy async MySQL connection string.
        MUHIM: mysql+aiomysql ishlatiladi (asyncmy EMAS).
        Windows SelectorEventLoop + aiomysql = muammosiz ishlaydi.
        """
        return (
            f"mysql+aiomysql://{self.db_user}:{self.db_pass}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
            f"?charset=utf8mb4"
        )

    @field_validator("check_delay_max")
    @classmethod
    def delay_max_must_be_gte_min(cls, max_val: float, info) -> float:
        min_val = info.data.get("check_delay_min", 0)
        if max_val < min_val:
            raise ValueError(
                f"CHECK_DELAY_MAX ({max_val}) CHECK_DELAY_MIN ({min_val}) dan katta bo'lishi kerak"
            )
        return max_val

    @field_validator("generator_charset")
    @classmethod
    def validate_charset(cls, value: str) -> str:
        allowed = {"letters", "alphanumeric", "alphanumeric_underscore"}
        if value not in allowed:
            raise ValueError(f"GENERATOR_CHARSET qiymati {allowed} dan biri bo'lishi kerak")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Settings singleton — bitta obyekt butun dastur hayoti davomida ishlatiladi."""
    return Settings()


# Qulaylik uchun to'g'ridan-to'g'ri import qilinadigan global obyekt
settings: Settings = get_settings()
