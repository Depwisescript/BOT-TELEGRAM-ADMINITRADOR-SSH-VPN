#!/bin/bash

# =========================================================
# INSTALADOR UNIVERSAL: BOT TELEGRAM DEPWISE SSH
# =========================================================
# Este script instalará dependencias, configurará el bot 
# y preparará el entorno de gestión SSH.
# =========================================================

# Colores para la terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Verificar usuario root
if [ "$EUID" -ne 0 ]; then
  log_error "Por favor, ejecuta este script como root (sudo bash instalador.sh)"
  exit 1
fi

clear
echo -e "${GREEN}=================================================="
echo -e "       CONFIGURACIÓN BOT TELEGRAM DEPWISE"
echo -e "==================================================${NC}"

# Pedir datos de configuración
read -p "Introduce el TOKEN de tu Bot de Telegram: " BOT_TOKEN
read -p "Introduce tu Chat ID de Telegram (Super Admin): " ADMIN_ID

if [ -z "$BOT_TOKEN" ] || [ -z "$ADMIN_ID" ]; then
    log_error "Error: El Token y el Chat ID son obligatorios."
    exit 1
fi

log_info "Instalando dependencias del sistema..."
apt update && apt install -y python3 python3-pip curl

log_info "Instalando librería pyTelegramBotAPI..."
pip3 install pytelegrambotapi requests --break-system-packages 2>/dev/null || pip3 install pytelegrambotapi requests

# Crear directorio del proyecto
PROJECT_DIR="/opt/depwise_bot"
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# ---------------------------------------------------------
# 1. Crear el Script Gestor de SSH (Bash)
# ---------------------------------------------------------
log_info "Creando gestor de usuarios SSH..."
cat << 'EOF' > ssh_manager.sh
#!/bin/bash
set -euo pipefail

# Función para crear usuario
# Uso: ./ssh_manager.sh crear_user <nombre> <pass> <dias>
crear_user() {
    local USER=$1
    local PASS=$2
    local DAYS=$3
    
    # Calcular fecha de expiración
    # Formato AAAA-MM-DD
    local EXP_DATE=$(date -d "+$DAYS days" +%Y-%m-%d)
    
    # Crear usuario con directorio home y shell bash
    if id "$USER" &>/dev/null; then
        echo "ERROR: El usuario ya existe."
        return 1
    fi
    
    useradd -m -s /bin/bash -e "$EXP_DATE" "$USER"
    echo "$USER:$PASS" | chpasswd
    
    echo "SUCCESS: Usuario $USER creado. Expira: $EXP_DATE"
}

# Función para eliminar usuario
eliminar_user() {
    local USER=$1
    if id "$USER" &>/dev/null; then
        userdel -r "$USER"
        echo "SUCCESS: Usuario $USER eliminado."
    else
        echo "ERROR: El usuario no existe."
        return 1
    fi
}

case "$1" in
    crear_user) crear_user "$2" "$3" "$4" ;;
    eliminar_user) eliminar_user "$2" ;;
    *) echo "Uso: $0 {crear_user|eliminar_user} ..." ;;
esac
EOF
chmod +x ssh_manager.sh

# ---------------------------------------------------------
# 2. Crear el Bot de Python
# ---------------------------------------------------------
log_info "Creando script del bot de Telegram..."
cat << EOF > depwise_bot.py
import telebot
import subprocess
import json
import os
import requests
import string
import random

# Configuración inicial
TOKEN = '$BOT_TOKEN'
SUPER_ADMIN = $ADMIN_ID
PROJECT_DIR = '$PROJECT_DIR'
ADMINS_FILE = os.path.join(PROJECT_DIR, 'admins.json')

bot = telebot.TeleBot(TOKEN)

# Cargar administradores
if not os.path.exists(ADMINS_FILE):
    with open(ADMINS_FILE, 'w') as f:
        json.dump({"admins": {}}, f)

def get_admins():
    with open(ADMINS_FILE, 'r') as f:
        return json.load(f)

def save_admins(data):
    with open(ADMINS_FILE, 'w') as f:
        json.dump(data, f)

def is_admin(chat_id):
    if chat_id == SUPER_ADMIN:
        return True
    data = get_admins()
    return str(chat_id) in data['admins']

def get_public_ip():
    try:
        return requests.get('https://ipapi.co/ip/').text.strip()
    except:
        return "IP no detectada"

# Comandos
@bot.message_handler(commands=['start', 'menu'])
def send_welcome(message):
    chat_id = message.chat.id
    if not is_admin(chat_id):
        bot.reply_to(message, "❌ Acceso Denegado. No eres administrador.")
        return
    
    text = "🚀 **BOT TELEGRAM DEPWISE**\n\n"
    text += "Comandos disponibles:\n"
    text += "• /crear [nombre] [dias] - Crear nuevo SSH\n"
    text += "• /eliminar [nombre] - Eliminar SSH\n"
    
    if chat_id == SUPER_ADMIN:
        text += "\n👑 **Funciones de Super Admin:**\n"
        text += "• /add_admin [id] [nombre] - Agregar administrador\n"
        text += "• /del_admin [id] - Eliminar administrador\n"
    
    bot.send_message(chat_id, text, parse_mode='Markdown')

@bot.message_handler(commands=['crear'])
def handle_crear(message):
    chat_id = message.chat.id
    if not is_admin(chat_id): return
    
    args = message.text.split()
    if len(args) < 2:
        bot.reply_to(message, "⚠️ Uso: /crear [nombre] [dias (opcional para Super Admin)]")
        return

    username = args[1]
    
    # Gestión de días
    days = 3 # Default
    if len(args) >= 3:
        try:
            requested_days = int(args[2])
            if chat_id == SUPER_ADMIN or get_admins()['admins'].get(str(chat_id), {}).get('unlimited', False):
                days = requested_days
            else:
                bot.reply_to(message, "⚠️ Solo puedes crear usuarios de 3 días.")
                days = 3
        except ValueError:
            bot.reply_to(message, "⚠️ Días inválidos. Usando 3 días.")

    # Generar password aleatorio
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    ip = get_public_ip()

    # Ejecutar script bash
    cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'crear_user', username, password, str(days)]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if "SUCCESS" in result.stdout:
        msg = f"✅ **BOT TELEGRAM DEPWISE**\n"
        msg += f"━━━━━━━━━━━━━━━━━━━━━━\n"
        msg += f"📍 **IP Pública:** `{ip}`\n"
        msg += f"👤 **Usuario:** `{username}`\n"
        msg += f"🔑 **Password:** `{password}`\n"
        msg += f"⏳ **Duración:** `{days} días`\n"
        msg += f"━━━━━━━━━━━━━━━━━━━━━━\n"
        msg += f"ℹ️ *TODOS LOS PUERTO Y CONEXIONES ACTIVOS EN EL CANAL @Depwise2*"
        bot.send_message(chat_id, msg, parse_mode='Markdown')
    else:
        bot.reply_to(message, f"❌ Error: {result.stdout or result.stderr}")

@bot.message_handler(commands=['eliminar'])
def handle_eliminar(message):
    chat_id = message.chat.id
    if not is_admin(chat_id): return
    
    args = message.text.split()
    if len(args) < 2:
        bot.reply_to(message, "⚠️ Uso: /eliminar [nombre]")
        return

    username = args[1]
    cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_user', username]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if "SUCCESS" in result.stdout:
        bot.send_message(chat_id, f"🗑️ Usuario `{username}` eliminado correctamente.")
    else:
        bot.reply_to(message, f"❌ Error: {result.stdout or result.stderr}")

@bot.message_handler(commands=['add_admin'])
def handle_add_admin(message):
    if message.chat.id != SUPER_ADMIN: return
    
    args = message.text.split()
    if len(args) < 3:
        bot.reply_to(message, "⚠️ Uso: /add_admin [id] [nombre]")
        return
    
    new_id = args[1]
    name = args[2]
    
    data = get_admins()
    data['admins'][new_id] = {"name": name, "unlimited": False}
    save_admins(data)
    
    bot.reply_to(message, f"✅ Admin `{name}` ({new_id}) agregado.")

# Iniciar
print("Bot Depwise encendido...")
bot.infinity_polling()
EOF

# ---------------------------------------------------------
# 3. Crear Servicio Systemd (Opcional pero recomendado)
# ---------------------------------------------------------
log_info "Configurando servicio para ejecución automática..."
cat << EOF > /etc/systemd/system/depwise.service
[Unit]
Description=Bot Telegram Depwise SSH
After=network.target

[Service]
ExecStart=/usr/bin/python3 $PROJECT_DIR/depwise_bot.py
WorkingDirectory=$PROJECT_DIR
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable depwise.service
systemctl start depwise.service

echo -e "${GREEN}=================================================="
echo -e "       INSTALACIÓN COMPLETADA CON ÉXITO"
echo -e "=================================================="
echo -e "Tu bot DEPWISE ya está funcionando como servicio."
echo -e "Usa /start en Telegram para interactuar.${NC}"
echo -e "Ruta del proyecto: $PROJECT_DIR"
