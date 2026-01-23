#!/bin/bash

# =========================================================
# INSTALADOR UNIVERSAL V3.4: BOT TELEGRAM DEPWISE SSH 💎
# =========================================================
# - FIX: IP Fija e Imborrable (Deteccion Automatica)
# - FIX: Info Personalizada con Soporte Markdown (Copiable)
# - Mantiene: V3.3 Fixes, Broadcast, Alias, y Unicode Escapes
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

if [ "$EUID" -ne 0 ]; then
  log_error "Por favor, ejecuta este script como root"
  exit 1
fi

clear
echo -e "${GREEN}=================================================="
echo -e "       CONFIGURACION BOT DEPWISE V3.4"
echo -e "==================================================${NC}"

read -p "Introduce el TOKEN de tu Bot de Telegram: " BOT_TOKEN
read -p "Introduce tu Chat ID de Telegram (Super Admin): " ADMIN_ID

if [ -z "$BOT_TOKEN" ] || [ -z "$ADMIN_ID" ]; then
    log_error "Error: Datos incompletos."
    exit 1
fi

log_info "Instalando dependencias..."
apt update && apt install -y python3 python3-pip curl python3-requests
pip3 install pytelegrambotapi --break-system-packages --upgrade 2>/dev/null || pip3 install pytelegrambotapi --upgrade

PROJECT_DIR="/opt/depwise_bot"
mkdir -p $PROJECT_DIR
cd $PROJECT_DIR

# Verificación de herramientas
if ! command -v python3 &> /dev/null; then
    log_error "Python3 no se instaló correctamente."
    exit 1
fi

# ---------------------------------------------------------
# 1. Script Gestor SSH
# ---------------------------------------------------------
cat << 'EOF' > ssh_manager.sh
#!/bin/bash
crear_user() { 
    local EXP_DATE=$(date -d "+$3 days" +%Y-%m-%d)
    if id "$1" &>/dev/null; then echo "ERROR: Ya existe."; return 1; fi
    useradd -m -s /bin/bash -e "$EXP_DATE" "$1"
    echo "$1:$2" | chpasswd
    echo "SUCCESS: $1|$2|$EXP_DATE"
}
eliminar_user() {
    if id "$1" &>/dev/null; then userdel -f -r "$1"; echo "SUCCESS"; else echo "ERROR"; fi
}
listar_users() {
    echo "USERS_LIST:"
    cut -d: -f1,7 /etc/passwd | grep "/bin/bash" | cut -d: -f1 | while read user; do
        exp=$(chage -l "$user" | grep "Account expires" | cut -d: -f2)
        if [[ "$exp" != *"never"* ]]; then echo "- $user (Vence:$exp)"; fi
    done
}
case "$1" in
    crear_user) crear_user "$2" "$3" "$4" ;;
    eliminar_user) eliminar_user "$2" ;;
    listar_users) listar_users ;;
esac
EOF
chmod +x ssh_manager.sh

# ---------------------------------------------------------
# 2. Bot de Python V3.4 (PRO CUSTOM)
# ---------------------------------------------------------
log_info "Creando bot V3.4 (Static IP + Selectable Info)..."
cat << EOF > depwise_bot.py
# -*- coding: utf-8 -*-
import telebot
from telebot import types
import subprocess
import json
import os
import requests
import string
import random
import time

# Iconos Unicode Escaped
ICON_CHECK = u'\U00002705'
ICON_USER = u'\U0001F464'
ICON_DEL = u'\U0001F5D1\U0000FE0F'
ICON_INFO = u'\U0001F4E1'
ICON_GEAR = u'\U00002699\U0000FE0F'
ICON_WRITE = u'\U0001F4DD'
ICON_TIME = u'\U000023F3'
ICON_PIN = u'\U0001F4CD'
ICON_KEY = u'\U0001F511'
ICON_MIC = u'\U0001F4E2'
ICON_BACK = u'\U0001F519'
ICON_PLUS = u'\U00002795'
ICON_MINUS = u'\U00002796'
ICON_GEM = u'\U0001F48E'
ICON_MEGA = u'\U0001F4E3'
ICON_DEV = u'\U0001F4BB'

TOKEN = '$BOT_TOKEN'
SUPER_ADMIN = int('$ADMIN_ID')
PROJECT_DIR = '$PROJECT_DIR'
DATA_FILE = os.path.join(PROJECT_DIR, 'bot_data.json')

bot = telebot.TeleBot(TOKEN)

def get_public_ip():
    urls = ['https://api.ipify.org', 'https://ifconfig.me/ip', 'https://icanhazip.com']
    for url in urls:
        try:
            return requests.get(url, timeout=5).text.strip()
        except:
            continue
    return "IP No Detectada"

def load_data():
    if not os.path.exists(DATA_FILE):
        default = {"admins": {}, "extra_info": "Puertos: 22, 80, 443", "user_history": []}
        save_data(default); return default
    data = json.load(open(DATA_FILE))
    if 'extra_info' not in data: data['extra_info'] = "Sin informacion adicional."
    return data

def save_data(data):
    with open(DATA_FILE, 'w') as f: json.dump(data, f)

def is_admin(chat_id):
    if chat_id == SUPER_ADMIN: return True
    return str(chat_id) in load_data().get('admins', {})

def main_menu(chat_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton(ICON_USER + " Crear SSH", callback_data="menu_crear"),
        types.InlineKeyboardButton(ICON_DEL + " Eliminar SSH", callback_data="menu_eliminar"),
        types.InlineKeyboardButton(ICON_INFO + " Info Servidor", callback_data="menu_info")
    )
    if chat_id == SUPER_ADMIN:
        markup.add(
            types.InlineKeyboardButton(ICON_MEGA + " Mensaje Global", callback_data="menu_broadcast"),
            types.InlineKeyboardButton(ICON_GEAR + " Ajustes Pro", callback_data="menu_admins")
        )
    bot.send_message(chat_id, ICON_GEM + " **BOT TELEGRAM DEPWISE V3.4**", parse_mode='Markdown', reply_markup=markup)

@bot.message_handler(commands=['start', 'menu'])
def handle_start(message):
    data = load_data()
    if message.chat.id not in data['user_history']:
        data['user_history'].append(message.chat.id); save_data(data)
    main_menu(message.chat.id)

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    chat_id = call.message.chat.id
    bot.answer_callback_query(call.id)
    if call.data == "menu_crear":
        msg = bot.send_message(chat_id, ICON_WRITE + " **Nombre del usuario:**")
        bot.register_next_step_handler(msg, process_username)
    elif call.data == "menu_eliminar":
        res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'listar_users'], capture_output=True, text=True)
        users = res.stdout.replace("USERS_LIST:", "").strip() or "Vacio"
        msg = bot.send_message(chat_id, ICON_USER + " **USUARIOS REGISTRADOS:**\n" + users + "\n\nEscribe el nombre:")
        bot.register_next_step_handler(msg, process_delete)
    elif call.data == "menu_info":
        ip = get_public_ip()
        extra = load_data().get('extra_info', '')
        text = ICON_INFO + " **DATOS DEL SERVIDOR**\n\n"
        text += ICON_PIN + " **IP Fija:** \`" + ip + "\` (Copiable)\n"
        text += "------------------\n" + extra
        bot.send_message(chat_id, text, parse_mode='Markdown')
        main_menu(chat_id)
    elif call.data == "menu_broadcast" and chat_id == SUPER_ADMIN:
        msg = bot.send_message(chat_id, ICON_MEGA + " **MENSAJE GLOBAL:**\nEscribe el texto:")
        bot.register_next_step_handler(msg, process_broadcast)
    elif call.data == "menu_admins" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup(row_width=1)
        markup.add(
            types.InlineKeyboardButton("➕ Anadir Admin", callback_data="admin_add"),
            types.InlineKeyboardButton("🗑️ Eliminar Admin", callback_data="admin_del"),
            types.InlineKeyboardButton("📝 Editar Info Extra", callback_data="set_edit_info"),
            types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
        )
        bot.send_message(chat_id, ICON_GEAR + " **AJUSTES AVANZADOS**", reply_markup=markup)
    elif call.data == "set_edit_info":
        msg = bot.send_message(chat_id, "Escribe la info extra (Dominios, Puertos, Notas).\nTIP: Usa \`texto\` para hacerlo copiable.")
        bot.register_next_step_handler(msg, process_save_info)
    elif call.data == "admin_add":
        msg = bot.send_message(chat_id, "ID del Admin:")
        bot.register_next_step_handler(msg, process_admin_id)
    elif call.data == "admin_del":
        data = load_data(); admins = data.get('admins', {})
        text = "ADMINS:\n"
        for aid, val in admins.items(): text += "- \`" + aid + "\` (" + val.get('alias','-') + ")\n"
        bot.send_message(chat_id, text + "\nID a borrar:")
        bot.register_next_step_handler(call.message, process_admin_del)
    elif call.data == "back_main": main_menu(chat_id)

def process_save_info(message):
    data = load_data(); data['extra_info'] = message.text; save_data(data)
    bot.send_message(message.chat.id, ICON_CHECK + " Info Guardada."); main_menu(message.chat.id)

def process_admin_id(message):
    aid = message.text.strip()
    msg = bot.send_message(message.chat.id, "Sobrenombre:")
    bot.register_next_step_handler(msg, lambda m: finalize_admin(m, aid))

def finalize_admin(message, aid):
    data = load_data(); data['admins'][aid] = {"alias": message.text.strip()}; save_data(data)
    bot.send_message(message.chat.id, ICON_CHECK + " OK."); main_menu(message.chat.id)

def process_admin_del(message):
    data = load_data(); aid = message.text.strip()
    if aid in data['admins']: del data['admins'][aid]; save_data(data); bot.send_message(message.chat.id, "Borrado.")
    else: bot.send_message(message.chat.id, "No hallado.")
    main_menu(message.chat.id)

def process_username(message):
    user = message.text.strip()
    if message.chat.id == SUPER_ADMIN:
        msg = bot.send_message(message.chat.id, ICON_TIME + " **Dias?**")
        bot.register_next_step_handler(msg, lambda m: finalize_ssh(m, user))
    else: finalize_ssh(message, user, 3 if not is_admin(message.chat.id) else 7)

def finalize_ssh(message, user, days=None):
    if days is None:
        try: days = int(message.text)
        except: days = 3
    pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'crear_user', user, pwd, str(days)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if "SUCCESS" in res.stdout:
        ip = get_public_ip()
        extra = load_data().get('extra_info', '')
        dt = res.stdout.strip().split('|')[2]
        msg = ICON_CHECK + " **BOT TELEGRAM DEPWISE**\n--------------------------------------\n"
        msg += ICON_PIN + " **HOST IP:** \`" + ip + "\` (Copiable)\n"
        if extra: msg += extra + "\n"
        msg += "**USER:** \`" + user + "\`\n**PASS:** \`" + pwd + "\`\n"
        msg += "**VENCE:** " + dt + " (" + str(days) + " dias)\n--------------------------------------\n"
        msg += ICON_MIC + " @Depwise2 | " + ICON_DEV + " @Dan3651"
        bot.send_message(message.chat.id, msg, parse_mode='Markdown')
    else: bot.send_message(message.chat.id, "Error: " + res.stdout)
    main_menu(message.chat.id)

def process_broadcast(message):
    ids = load_data().get('user_history', [])
    for uid in ids:
        try: bot.send_message(uid, ICON_MEGA + " **AVISO:**\n\n" + message.text, parse_mode='Markdown'); time.sleep(0.1)
        except: pass
    bot.send_message(message.chat.id, "Completado."); main_menu(message.chat.id)

def process_delete(message):
    subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_user', message.text.strip()])
    bot.send_message(message.chat.id, "Hecho."); main_menu(message.chat.id)

if __name__ == "__main__":
    while True:
        try: bot.infinity_polling(timeout=50)
        except Exception: time.sleep(10)
EOF

# ---------------------------------------------------------
# 3. Crear Servicio Systemd
# ---------------------------------------------------------
log_info "Configurando servicio systemd..."
cat << EOF > /etc/systemd/system/depwise.service
[Unit]
Description=Bot Telegram Depwise SSH
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python3 $PROJECT_DIR/depwise_bot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------
# 4. Reiniciar Servicio
# ---------------------------------------------------------
systemctl daemon-reload
systemctl enable depwise.service
systemctl restart depwise.service

echo -e "${GREEN}=================================================="
echo -e "       INSTALACION V3.4 COMPLETADA 💎"
echo -e "=================================================="
echo -e "IP Estatica y Markdown activados con exito.${NC}"
