"""
models/username_log.py — SQLAlchemy ORM modeli.

username_logs jadvali — tekshirilgan usernamelarning to'liq tarixi.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Enum, Index, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Barcha SQLAlchemy modellari uchun umumiy asosiy klass."""
    pass


class CheckStatus(str, enum.Enum):
    """Username tekshiruv natijasi."""
    AVAILABLE = "AVAILABLE"   # ✅ Mavjud (band emas)
    TAKEN = "TAKEN"           # ❌ Band (ro'yxatdan o'tilgan)
    ERROR = "ERROR"           # ⚠️ Xatolik (network, rate-limit va h.k.)


class UsernameLog(Base):
    """
    username_logs jadvali.

    Har bir tekshiruv qatori sessiya UUID si bilan birlashtiriladi,
    shu tariqa bir bulk operatsiyaning barcha natijalarini birga olish mumkin.
    """

    __tablename__ = "username_logs"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    # Bir bulk tekshiruv sessiyasining UUID4 identifikatori
    session_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    # Tekshirilgan Instagram username
    username: Mapped[str] = mapped_column(String(50), nullable=False)

    # Tekshiruv natijasi
    status: Mapped[CheckStatus] = mapped_column(
        Enum(CheckStatus, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )

    # Qo'shimcha xatolik ma'lumoti (faqat status=ERROR holatida)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Tekshirilgan vaqt (server vaqti, UTC)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, server_default=func.now()
    )

    # Qidiruv tezligi uchun qo'shimcha indekslar
    __table_args__ = (
        Index("idx_username_status", "username", "status"),
        Index("idx_session_status", "session_id", "status"),
    )

    def __repr__(self) -> str:
        return f"<UsernameLog id={self.id} username={self.username!r} status={self.status}>"
