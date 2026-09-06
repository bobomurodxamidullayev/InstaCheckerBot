"""
utils/formatters.py -- Telegram xabar formatlash yordamchi funksiyalari.

Barcha natija ko'rinish mantig'i shu modulda markazlashgan.
Emoji, HTML formatting, progress bar va yig'indi hisobot formatlari.
"""
from __future__ import annotations

from services.checker import CheckResult
from models.username_log import CheckStatus


def format_check_result(result: CheckResult) -> str:
    """
    Bitta tekshiruv natijasini chiroyli formatda qaytaradi.
    Misollar:
        ✅ @testuser — Mavjud (bo'sh)
        ❌ @instagram — Band
        ⚠️ @error123 — Xatolik: Timeout
    """
    if result.status == CheckStatus.AVAILABLE:
        return f"✅ <code>@{result.username}</code> — <b>Mavjud (bo'sh)</b>"
    elif result.status == CheckStatus.TAKEN:
        return f"❌ <code>@{result.username}</code> — Band"
    else:
        error_short = (result.error_message or "Noma'lum xatolik")[:50]
        return f"⚠️ <code>@{result.username}</code> — Xatolik: {error_short}"


def format_progress_bar(completed: int, total: int, bar_length: int = 10) -> str:
    """
    Matnli progress bar formatlaydi.
    Misol: [████████░░] 8/10 (80%)
    """
    if total == 0:
        return "[░░░░░░░░░░] 0/0"
    fraction = completed / total
    filled = int(bar_length * fraction)
    empty = bar_length - filled
    bar = "█" * filled + "░" * empty
    percent = int(fraction * 100)
    return f"[{bar}] {completed}/{total} ({percent}%)"


def format_summary(
    total: int,
    available: int,
    taken: int,
    errors: int,
    session_id: str,
    available_usernames: list = None,
    extra_available: int = 0,
) -> str:
    """
    Bulk tekshiruv sessiyasining yakuniy hisobot xabarini formatlaydi.

    Arifmetika: available + taken + errors == total bo'lishi kafolatlanadi.
    Bo'sh topilgan nomlar xabarning o'zida ko'rsatiladi (bosiladigan).
    extra_available > 0 bo'lsa, qolgan nomlar faylda ekani yoziladi.
    """
    if available_usernames is None:
        available_usernames = []

    lines = [
        "📊 <b>Tekshiruv yakunlandi!</b>",
        "",
        f"🔢 <b>Jami tekshirildi:</b> {total}",
        f"✅ <b>Mavjud (bo'sh):</b> {available}",
        f"❌ <b>Band:</b> {taken}",
        f"⚠️ <b>Xatolik:</b> {errors}",
    ]

    # Mavjud username'larni xabarda ko'rsatish (preview queue_manager dan keladi)
    if available_usernames or extra_available > 0:
        lines.append("")
        lines.append("🎉 <b>Mavjud (bo'sh) usernamelar:</b>")
        for uname in available_usernames:
            lines.append(f"• <code>@{uname}</code>")
        if extra_available > 0:
            lines.append(f"<i>...va yana {extra_available} ta nom biriktirilgan faylda</i>")
    else:
        lines.append("")
        lines.append("😔 Mavjud username topilmadi.")

    lines.append("")
    lines.append(f"<i>Sessiya ID: <code>{session_id[:8]}...</code></i>")
    return "\n".join(lines)


def format_single_result(result: CheckResult) -> str:
    """Bitta /check komandasiga kengaytirilgan javob xabari."""
    if result.status == CheckStatus.AVAILABLE:
        return (
            f"✅ <b>Mavjud!</b>\n\n"
            f"Instagram username: <code>@{result.username}</code>\n"
            f"Holat: <b>Bo'sh — ro'yxatdan o'tish mumkin</b> 🎉"
        )
    elif result.status == CheckStatus.TAKEN:
        return (
            f"❌ <b>Band!</b>\n\n"
            f"Instagram username: <code>@{result.username}</code>\n"
            f"Holat: <b>Allaqachon ro'yxatdan o'tilgan</b>"
        )
    else:
        error_text = result.error_message or "Noma'lum xatolik"
        return (
            f"⚠️ <b>Xatolik!</b>\n\n"
            f"Instagram username: <code>@{result.username}</code>\n"
            f"Sabab: {error_text}\n\n"
            f"<i>Keyinroq qayta urinib ko'ring yoki proxy sozlamalarini tekshiring.</i>"
        )


def format_validation_error(invalid_usernames: list) -> str:
    """Noto'g'ri formatdagi username'lar haqida xabar qaytaradi."""
    sample = ", ".join(f"<code>{u}</code>" for u in invalid_usernames[:5])
    if len(invalid_usernames) > 5:
        sample += f" va yana {len(invalid_usernames) - 5} ta"
    return (
        f"⚠️ <b>Quyidagi usernamelar noto'g'ri formatda:</b>\n{sample}\n\n"
        f"<i>Instagram username faqat harflar (a-z), raqamlar (0-9), "
        f"nuqta (.) va pastki chiziq (_) dan iborat bo'lishi kerak.</i>"
    )


def format_limit_warning(submitted: int, max_allowed: int) -> str:
    """Limit oshganini bildiruvchi xabar."""
    return (
        f"⚠️ <b>Siz {submitted} ta username yubordingiz.</b>\n"
        f"Bir sessiyada ko'pi bilan <b>{max_allowed} ta</b> tekshirish mumkin.\n\n"
        f"Faqat birinchi {max_allowed} ta tekshiriladi."
    )
