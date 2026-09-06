#!/usr/bin/env bash
# ==============================================================
#  run.sh — InstaChekerBot Ishga Tushirish Skripti
#
#  Foydalanish:
#    chmod +x run.sh
#    ./run.sh
#
#  Nima qiladi:
#    1. Python 3.10+ versiyasini tekshiradi
#    2. Virtual environment yaratadi (yo'q bo'lsa)
#    3. requirements.txt ni o'rnatadi
#    4. .env faylining mavjudligini tekshiradi
#    5. Botni fon rejimida (nohup) ishga tushiradi
# ==============================================================

set -euo pipefail

# ─── Ranglar (terminal chiqishi uchun) ────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warning() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ─── Loyiha Katalogi ──────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
info "Loyiha katalogi: $SCRIPT_DIR"

# ─── 1. Python Versiyasini Tekshirish ─────────────────────────
info "Python versiyasi tekshirilmoqda..."

PYTHON_BIN=""
for cmd in python3.12 python3.11 python3.10 python3; do
    if command -v "$cmd" &>/dev/null; then
        VERSION=$("$cmd" -c "import sys; print(sys.version_info[:2])")
        MAJOR=$("$cmd" -c "import sys; print(sys.version_info.major)")
        MINOR=$("$cmd" -c "import sys; print(sys.version_info.minor)")
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON_BIN="$cmd"
            success "Python $("$cmd" --version) topildi: $cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    error "Python 3.10 yoki undan yuqori versiya topilmadi!\n" \
          "O'rnatish: sudo apt install python3.11 python3.11-venv"
fi

# ─── 2. Virtual Environment ───────────────────────────────────
VENV_DIR=".venv"

if [ ! -d "$VENV_DIR" ]; then
    info "Virtual environment yaratilmoqda: $VENV_DIR"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    success "Virtual environment yaratildi."
else
    info "Virtual environment mavjud: $VENV_DIR"
fi

# venv aktivatsiya
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
success "Virtual environment faollashtirildi."

# ─── 3. Dependencies O'rnatish ────────────────────────────────
info "requirements.txt o'rnatilmoqda..."

if [ ! -f "requirements.txt" ]; then
    error "requirements.txt topilmadi! Loyiha fayllarini tekshiring."
fi

pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
success "Barcha kutubxonalar o'rnatildi."

# ─── 4. .env Faylini Tekshirish ───────────────────────────────
info ".env fayli tekshirilmoqda..."

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        warning ".env fayli topilmadi!"
        echo ""
        echo "  Quyidagi buyruqni bajaring:"
        echo -e "  ${YELLOW}cp .env.example .env${NC}"
        echo "  Keyin .env faylini to'ldiring (BOT_TOKEN, ADMIN_ID, DB_* va h.k.)"
        echo ""
        error ".env fayli yo'q — bot ishga tushirilmadi."
    else
        error ".env va .env.example ikkisi ham topilmadi!"
    fi
fi

# Majburiy o'zgaruvchilarni tekshirish
check_env_var() {
    local var_name="$1"
    local value
    value=$(grep -E "^${var_name}=" .env | cut -d'=' -f2- | tr -d '"' | tr -d "'")
    if [ -z "$value" ] || [ "$value" = "your_mysql_password" ] || \
       [[ "$value" == *"xxxx"* ]] || [[ "$value" == *"123456789:AAF"* ]]; then
        warning "$var_name hali to'ldirilmagan ko'rinadi."
        return 1
    fi
    return 0
}

ALL_OK=true
for var in BOT_TOKEN ADMIN_ID DB_HOST DB_NAME DB_USER; do
    if ! check_env_var "$var"; then
        ALL_OK=false
    fi
done

if [ "$ALL_OK" = false ]; then
    echo ""
    warning ".env faylida ba'zi o'zgaruvchilar to'ldirilmagan."
    read -rp "Baribir davom etasizmi? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        error "Bekor qilindi. .env faylini to'ldiring va qayta ishga tushiring."
    fi
else
    success ".env fayli tekshirildi — majburiy o'zgaruvchilar mavjud."
fi

# ─── 5. Eski Process ni To'xtatish (ixtiyoriy) ───────────────
PID_FILE="bot.pid"

if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        warning "Eski bot jarayoni topildi (PID: $OLD_PID). To'xtatilmoqda..."
        kill "$OLD_PID"
        sleep 2
        success "Eski jarayon to'xtatildi."
    fi
    rm -f "$PID_FILE"
fi

# ─── 6. Botni Fon Rejimida Ishga Tushirish ────────────────────
LOG_FILE="bot_output.log"

info "Bot fon rejimida ishga tushirilmoqda..."
nohup "$VENV_DIR/bin/python" bot.py >> "$LOG_FILE" 2>&1 &
BOT_PID=$!
echo "$BOT_PID" > "$PID_FILE"

# Bir necha soniya kutib, jarayon ishlayotganligini tekshirish
sleep 3
if kill -0 "$BOT_PID" 2>/dev/null; then
    success "Bot muvaffaqiyatli ishga tushdi!"
    echo ""
    echo -e "  ${GREEN}PID:${NC}      $BOT_PID"
    echo -e "  ${GREEN}Log fayl:${NC} $LOG_FILE"
    echo -e "  ${GREEN}PID fayl:${NC} $PID_FILE"
    echo ""
    echo -e "  Logni kuzatish uchun:"
    echo -e "  ${YELLOW}tail -f $LOG_FILE${NC}"
    echo ""
    echo -e "  Botni to'xtatish uchun:"
    echo -e "  ${YELLOW}kill \$(cat $PID_FILE)${NC}"
else
    error "Bot ishga tushmadi! Log faylini tekshiring: $LOG_FILE"
fi

# ─── Systemd Tavsiyasi ────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${YELLOW}[TAVSIYA]${NC} Doimiy servis uchun systemd ishlatishingiz mumkin:"
echo ""
echo "  sudo nano /etc/systemd/system/instachecker.service"
echo ""
cat << 'EOF'
  [Unit]
  Description=Instagram Username Checker Telegram Bot
  After=network.target mysql.service

  [Service]
  Type=simple
  User=YOUR_USERNAME
  WorkingDirectory=/path/to/InstaChekerBot
  ExecStart=/path/to/InstaChekerBot/.venv/bin/python bot.py
  Restart=on-failure
  RestartSec=5
  StandardOutput=journal
  StandardError=journal

  [Install]
  WantedBy=multi-user.target
EOF
echo ""
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable instachecker"
echo "  sudo systemctl start instachecker"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
