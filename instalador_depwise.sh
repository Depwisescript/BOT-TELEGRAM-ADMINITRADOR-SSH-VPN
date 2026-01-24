#!/bin/bash

# =========================================================
# INSTALADOR UNIVERSAL V5.0: BOT TELEGRAM DEPWISE SSH 💎
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

PROJECT_DIR="/opt/depwise_bot"
ENV_FILE="$PROJECT_DIR/.env"

# Cargar configuración previa si existe
if [ -f "$ENV_FILE" ]; then
    source "$ENV_FILE"
    log_info "Se detectó una configuración previa."
elif [ -f "$PROJECT_DIR/depwise_bot.py" ]; then
    # Migración: Extraer de la versión anterior si no hay .env
    OLD_TOKEN=$(grep "TOKEN =" "$PROJECT_DIR/depwise_bot.py" | cut -d"'" -f2)
    OLD_ADMIN=$(grep "SUPER_ADMIN = int" "$PROJECT_DIR/depwise_bot.py" | grep -o '[0-9]\+')
    log_info "Migrando datos de versión anterior..."
fi

echo -e "${GREEN}=================================================="
echo -e "       CONFIGURACION BOT DEPWISE V5.0"
echo -e "==================================================${NC}"

read -p "Introduce el TOKEN [$OLD_TOKEN]: " BOT_TOKEN
BOT_TOKEN=${BOT_TOKEN:-$OLD_TOKEN}

read -p "Introduce tu Chat ID [$OLD_ADMIN]: " ADMIN_ID
ADMIN_ID=${ADMIN_ID:-$OLD_ADMIN}

if [ -z "$BOT_TOKEN" ] || [ -z "$ADMIN_ID" ]; then
    log_error "Error: Datos incompletos."
    exit 1
fi

# Guardar para futuras actualizaciones
mkdir -p "$PROJECT_DIR"
echo "OLD_TOKEN=\"$BOT_TOKEN\"" > "$ENV_FILE"
echo "OLD_ADMIN=\"$ADMIN_ID\"" >> "$ENV_FILE"

log_info "Instalando dependencias..."
apt update && apt install -y python3 python3-pip curl python3-requests file
pip3 install pytelegrambotapi --break-system-packages --upgrade 2>/dev/null || pip3 install pytelegrambotapi --upgrade

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
contar_conexiones() {
    echo "ONLINE_LIST:"
    ps aux | grep sshd | grep -v root | grep -v grep | awk '{print $1}' | sort | uniq -c | while read count user; do
        echo "- $user: $count conectado(s)"
    done
}
instalar_slowdns() {
    local DOMAIN="$1"
    local PORT="$2"
    local LOG="/tmp/slowdns_install.log"
    echo "Iniciando instalacion limpia..." > "$LOG"
    
    # 1. Detectar Arquitectura
    echo "Detectando arquitectura..." >> "$LOG"
    local ARCH_RAW=$(uname -m)
    local ARCH=""
    case "$ARCH_RAW" in
        x86_64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l|armv6l) ARCH="arm" ;;
        i386|i686) ARCH="386" ;;
        *) ARCH="amd64" ;; # Default
    esac
    
    # 2. Asegurar binario (Fuentes Reales)
    IS_BIN() { [ -f "/usr/bin/slowdns-server" ] && file "/usr/bin/slowdns-server" | grep -q "ELF"; }
    
    if ! IS_BIN; then
        echo "Descargando binario para $ARCH..." >> "$LOG"
        rm -f /usr/bin/slowdns-server
        
        local BIN_NAME="dnstt-server-linux-$ARCH"
        local MIRRORS=(
            "https://dnstt.network/$BIN_NAME"
            "https://github.com/bugfloyd/dnstt-deploy/raw/main/bin/$BIN_NAME"
            "https://raw.githubusercontent.com/Dan3651/scripts/main/slowdns-server"
        )
        
        for url in "${MIRRORS[@]}"; do
            echo "Probando fuente: $url" >> "$LOG"
            curl -L -k -s -f -o /usr/bin/slowdns-server "$url"
            if IS_BIN; then 
                echo "¡Binario verificado correctamente!" >> "$LOG"
                break
            else
                rm -f /usr/bin/slowdns-server
            fi
        done
        
        chmod +x /usr/bin/slowdns-server
    fi
    
    if ! IS_BIN; then
        local ERR="No se pudo obtener un binario compatible para $ARCH."
        echo "ERROR: $ERR" >> "$LOG"
        echo "$ERR"
        return 1
    fi
    
    # 3. Generar Claves
    echo "Generando certificados locales..." >> "$LOG"
    mkdir -p /etc/slowdns
    [ ! -s "/etc/slowdns/server.pub" ] && rm -f /etc/slowdns/server*
    
    if [ ! -f "/etc/slowdns/server.pub" ]; then
        /usr/bin/slowdns-server -gen-key -privkey-file /etc/slowdns/server.key -pubkey-file /etc/slowdns/server.pub > /tmp/slowdns_gen.log 2>&1
        if [ $? -ne 0 ]; then
            local BIN_ERR=$(cat /tmp/slowdns_gen.log)
            local ERR="Fallo al ejecutar binario ($BIN_ERR)"
            echo "ERROR: $ERR" >> "$LOG"
            echo "$ERR"
            return 1
        fi
    fi
    
    if [ -f "/etc/slowdns/server.pub" ]; then
        echo "Configurando Red y Servicio..." >> "$LOG"
        
        # 4. Redirección de Puertos (iptables)
        # Limpiar previas
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null
        iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
        
        # 5. Crear Servicio Systemd
        cat <<INNER_EOF > /etc/systemd/system/slowdns.service
[Unit]
Description=SlowDNS Depwise Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/slowdns
ExecStart=/usr/bin/slowdns-server -udp :5300 -privkey-file /etc/slowdns/server.key $DOMAIN 127.0.0.1:$PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
INNER_EOF
        
        systemctl daemon-reload
        systemctl enable slowdns > /dev/null 2>&1
        systemctl restart slowdns > /dev/null 2>&1
        
        echo "Instalacion finalizada con exito." >> "$LOG"
        local PUB_KEY=$(cat /etc/slowdns/server.pub)
        echo "SLOWDNS_SUCCESS: $PUB_KEY|$DOMAIN|$PORT"
    else
        local ERR="Error critico en la clave publica."
        echo "ERROR: $ERR" >> "$LOG"
        echo "$ERR"
        return 1
    fi
}
eliminar_slowdns() {
    # 1. Detener y eliminar servicio agresivamente
    systemctl stop slowdns > /dev/null 2>&1
    systemctl disable slowdns > /dev/null 2>&1
    rm -f /etc/systemd/system/slowdns.service
    systemctl daemon-reload
    
    # 2. Limpiar Iptables (todas las ocurrencias)
    while iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null; do :; done
    
    # 3. Limpiar Claves y archivos
    rm -rf /etc/slowdns
    rm -f /tmp/slowdns_install.log
    rm -f /tmp/slowdns_gen.log
    echo "SLOWDNS_REMOVED"
}
case "$1" in
    crear_user) crear_user "$2" "$3" "$4" ;;
    eliminar_user) eliminar_user "$2" ;;
    listar_users) listar_users ;;
    contar_conexiones) contar_conexiones ;;
    instalar_slowdns) instalar_slowdns "$2" "$3" ;;
    eliminar_slowdns) eliminar_slowdns ;;
esac
EOF
chmod +x ssh_manager.sh

# ---------------------------------------------------------
# 2. Bot de Python V5.0 (PRO CUSTOM)
# ---------------------------------------------------------
log_info "Creando bot V5.0 (Static IP + Selectable Info)..."
cat << 'EOF' > depwise_bot.py
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
import threading
import html as html_lib

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
ICON_X = u'\U0000274C'
ICON_LOCK = u'\U0001F512'
ICON_UNLOCK = u'\U0001F232'

TOKEN = 'CONF_TOKEN'
SUPER_ADMIN = int('CONF_ADMIN')
PROJECT_DIR = 'CONF_DIR'
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
        default = {"admins": {}, "extra_info": "Puertos: 22, 80, 443", "user_history": [], "public_access": True, "ssh_owners": {}}
        save_data(default); return default
    try:
        data = json.load(open(DATA_FILE))
        if 'extra_info' not in data: data['extra_info'] = "Sin informacion adicional."
        if 'public_access' not in data: data['public_access'] = True
        if 'ssh_owners' not in data: data['ssh_owners'] = {}
        if 'slowdns' not in data: data['slowdns'] = {}
        return data
    except:
        return {"admins": {}, "extra_info": "Error al cargar", "user_history": [], "public_access": True, "ssh_owners": {}}

def save_data(data):
    with open(DATA_FILE, 'w') as f: json.dump(data, f)

def safe_format(text):
    if not text: return ""
    # Escapar HTML básico
    res = html_lib.escape(text)
    # Convertir backticks en <code> para copia rápida
    import re
    res = re.sub(r'`([^`]+)`', r'<code>\1</code>', res)
    return res

# Rastreo de mensajes para limpieza
USER_STEPS = {}

def is_admin(chat_id):
    if chat_id == SUPER_ADMIN: return True
    return str(chat_id) in load_data().get('admins', {})

def delete_user_msg(message):
    try: bot.delete_message(message.chat.id, message.message_id)
    except: pass

def main_menu(chat_id, message_id=None):
    data = load_data()
    is_sa = (chat_id == SUPER_ADMIN)
    is_adm = is_admin(chat_id)
    
    if not data.get('public_access', True) and not is_adm:
        text = ICON_LOCK + " <b>SISTEMA PRIVADO</b>\nEl bot está restringido por el administrador."
        if message_id:
            try: bot.edit_message_text(text, chat_id, message_id, parse_mode='HTML')
            except: bot.send_message(chat_id, text, parse_mode='HTML')
        else:
            bot.send_message(chat_id, text, parse_mode='HTML')
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton(ICON_USER + " Crear SSH", callback_data="menu_crear"),
        types.InlineKeyboardButton(ICON_DEL + " Eliminar SSH", callback_data="menu_eliminar"),
        types.InlineKeyboardButton(ICON_INFO + " Info Servidor", callback_data="menu_info")
    )
    if is_sa:
        markup.add(
            types.InlineKeyboardButton(ICON_MEGA + " Mensaje Global", callback_data="menu_broadcast"),
            types.InlineKeyboardButton(ICON_GEAR + " Monitor Online", callback_data="menu_online")
        )
        markup.add(
            types.InlineKeyboardButton(ICON_GEAR + " Protocolos", callback_data="menu_protocols"),
            types.InlineKeyboardButton(ICON_GEAR + " Ajustes Pro", callback_data="menu_admins")
        )
    
    text = ICON_GEM + " <b>BOT TELEGRAM DEPWISE V5.0</b>\n"
    if not data.get('public_access', True): text += ICON_LOCK + " <i>Acceso Público: Desactivado</i>\n"
    
    if message_id:
        try: bot.edit_message_text(text, chat_id, message_id, parse_mode='HTML', reply_markup=markup)
        except:
            msg = bot.send_message(chat_id, text, parse_mode='HTML', reply_markup=markup)
            USER_STEPS[chat_id] = msg.message_id
    else:
        msg = bot.send_message(chat_id, text, parse_mode='HTML', reply_markup=markup)
        USER_STEPS[chat_id] = msg.message_id

@bot.message_handler(commands=['start', 'menu'])
def handle_start(message):
    data = load_data()
    if message.chat.id not in data['user_history']:
        data['user_history'].append(message.chat.id); save_data(data)
    main_menu(message.chat.id)

@bot.callback_query_handler(func=lambda call: True)
def callback_query(call):
    chat_id = call.message.chat.id
    msg_id = call.message.message_id
    bot.answer_callback_query(call.id)
    
    if call.data == "menu_crear":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_WRITE + " <b>Nombre del usuario:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_username)
    elif call.data == "menu_eliminar":
        is_sa = (chat_id == SUPER_ADMIN)
        data = load_data()
        if is_sa:
            res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'listar_users'], capture_output=True, text=True)
            users = res.stdout.replace("USERS_LIST:", "").strip() or "Vacio"
        else:
            # Filtrar solo los del usuario actual (aplica a Admins secundarios y usuarios normales)
            owners = data.get('ssh_owners', {})
            user_list = [u for u, owner in owners.items() if str(owner) == str(chat_id)]
            users = "\n".join(["- " + u for u in user_list]) if user_list else "Vacio"
            
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_USER + " <b>ELIMINAR TUS USUARIOS:</b>\n" + users + "\n\nEscribe el nombre:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_delete)
    elif call.data == "menu_info":
        ip = get_public_ip()
        data = load_data()
        extra = data.get('extra_info', '')
        text = ICON_INFO + " <b>DATOS DEL SERVIDOR</b>\n\n"
        text += ICON_PIN + " <b>IP Fija:</b> <code>" + ip + "</code> \n"
        
        # Datos SlowDNS si existen
        sdns = data.get('slowdns', {})
        if sdns.get('key'):
            text += "\n🚀 <b>SLOWDNS CONFIG:</b>\n"
            text += "<b>Dominio:</b> <code>" + sdns.get('ns','') + "</code>\n"
            text += "<b>Key:</b> <code>" + sdns.get('key','') + "</code>\n"
            
        text += "------------------\n" + safe_format(extra)
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "menu_broadcast" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_MEGA + " <b>MENSAJE GLOBAL:</b>\nEscribe el mensaje:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_broadcast)
    elif call.data == "menu_online" and chat_id == SUPER_ADMIN:
        res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'contar_conexiones'], capture_output=True, text=True)
        online = res.stdout.replace("ONLINE_LIST:", "").strip() or "Ningun usuario conectado."
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_GEAR + " <b>MONITOR USUARIOS ONLINE</b>\n\n" + online, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "menu_protocols" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup(row_width=1)
        markup.add(
            types.InlineKeyboardButton("🚀 Instalar SlowDNS", callback_data="install_slowdns"),
            types.InlineKeyboardButton(ICON_DEL + " Eliminar SlowDNS", callback_data="remove_slowdns"),
            types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
        )
        bot.edit_message_text(ICON_GEAR + " <b>GESTIÓN DE PROTOCOLOS</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "remove_slowdns" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "🗑️ Desinstalando...")
        bot.edit_message_text("⏳ <b>Desinstalando SlowDNS...</b>\nLimpiando archivos y reglas de red.", chat_id, msg_id, parse_mode='HTML')
        
        # Ejecutar en Hilo Separado
        threading.Thread(target=run_removal_async, args=(chat_id, msg_id)).start()
    elif call.data == "install_slowdns" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        sent = bot.edit_message_text("Introduce el <b>Dominio NS</b> para SlowDNS:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        # Aseguramos que el manejador se registre sobre el mensaje editado
        bot.register_next_step_handler(sent, process_slowdns_ns)
    elif call.data == "update_slowdns_log" and chat_id == SUPER_ADMIN:
        update_install_log(chat_id, msg_id)
    elif call.data == "menu_admins" and chat_id == SUPER_ADMIN:
        show_pro_settings(chat_id, msg_id)
    elif call.data == "toggle_public" and chat_id == SUPER_ADMIN:
        data = load_data(); data['public_access'] = not data.get('public_access', True); save_data(data)
        show_pro_settings(chat_id, msg_id)
    elif call.data == "set_edit_info":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text("Escribe la info extra.\nTIP: Usa `texto` para hacerlo copiable.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_save_info)
    elif call.data == "admin_add":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text("ID del Admin:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_admin_id)
    elif call.data == "admin_del":
        data = load_data(); admins = data.get('admins', {})
        text = "ADMINS:\n"
        for aid, val in admins.items(): text += "- <code>" + aid + "</code> (" + val.get('alias','-') + ")\n"
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(text + "\nID a borrar:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_admin_del)
    elif call.data == "back_main":
        bot.clear_step_handler_by_chat_id(chat_id=chat_id)
        main_menu(chat_id, msg_id)

def show_pro_settings(chat_id, message_id):
    data = load_data()
    status = (ICON_UNLOCK + " Acceso Publico: ON") if data.get('public_access', True) else (ICON_LOCK + " Acceso Publico: OFF")
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton(status, callback_data="toggle_public"),
        types.InlineKeyboardButton(ICON_PLUS + " Añadir Admin", callback_data="admin_add"),
        types.InlineKeyboardButton(ICON_DEL + " Eliminar Admin", callback_data="admin_del"),
        types.InlineKeyboardButton(ICON_WRITE + " Editar Info Extra", callback_data="set_edit_info"),
        types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
    )
    bot.edit_message_text(ICON_GEAR + " <b>AJUSTES AVANZADOS</b>", chat_id, message_id, reply_markup=markup, parse_mode='HTML')

def process_save_info(message):
    delete_user_msg(message)
    data = load_data(); data['extra_info'] = message.text; save_data(data)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_admin_id(message):
    delete_user_msg(message)
    aid = message.text.strip()
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
    bot.edit_message_text("Sobrenombre:", message.chat.id, USER_STEPS.get(message.chat.id), reply_markup=markup, parse_mode='HTML')
    bot.register_next_step_handler(message, lambda m: finalize_admin(m, aid))

def finalize_admin(message, aid):
    delete_user_msg(message)
    data = load_data(); data['admins'][aid] = {"alias": message.text.strip()}; save_data(data)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_admin_del(message):
    delete_user_msg(message)
    data = load_data(); aid = message.text.strip()
    if aid in data['admins']: del data['admins'][aid]; save_data(data)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_username(message):
    delete_user_msg(message)
    user = message.text.strip()
    if message.chat.id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_TIME + " <b>Dias?</b>", message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(message, lambda m: finalize_ssh(m, user))
    else: finalize_ssh(message, user, 3 if not is_admin(message.chat.id) else 7)

def finalize_ssh(message, user, days=None):
    delete_user_msg(message)
    if days is None:
        try: days = int(message.text)
        except: days = 3
    pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
    cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'crear_user', user, pwd, str(days)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if "SUCCESS" in res.stdout:
        ip = get_public_ip()
        extra = load_data().get('extra_info', '')
        # Extraer fecha de res.stdout
        try: dt = res.stdout.strip().split('|')[2]
        except: dt = "Indefinida"
        
        msg = ICON_CHECK + " <b>BOT TELEGRAM DEPWISE V5.0</b>\n--------------------------------------\n"
        msg += ICON_PIN + " <b>HOST IP:</b> <code>" + ip + "</code> \n"
        if extra: msg += safe_format(extra) + "\n"
        msg += "<b>USER:</b> <code>" + user + "</code> \n<b>PASS:</b> <code>" + pwd + "</code> \n"
        
        # Datos SlowDNS si existen
        data = load_data()
        sdns = data.get('slowdns', {})
        if sdns.get('key'):
            msg += "\n🚀 <b>SLOWDNS CONFIG:</b>\n"
            msg += "<b>Dominio:</b> <code>" + sdns.get('ns','') + "</code>\n"
            msg += "<b>Key:</b> <code>" + sdns.get('key','') + "</code>\n"
            
        msg += "<b>VENCE:</b> " + dt + " (" + str(days) + " dias)\n--------------------------------------\n"
        msg += ICON_MIC + " @Depwise2 | " + ICON_DEV + " @Dan3651"
        
        # Registrar dueño
        data = load_data()
        data['ssh_owners'][user] = str(message.chat.id)
        save_data(data)

        if USER_STEPS.get(message.chat.id):
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver al Menú", callback_data="back_main"))
            try: bot.edit_message_text(msg, message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML', reply_markup=markup)
            except: bot.send_message(message.chat.id, msg, parse_mode='HTML', reply_markup=markup)
        else:
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver al Menú", callback_data="back_main"))
            msg_obj = bot.send_message(message.chat.id, msg, parse_mode='HTML', reply_markup=markup)
            USER_STEPS[message.chat.id] = msg_obj.message_id
    else:
        # Manejo de Error Detallado
        error_detail = res.stdout.strip() or res.stderr.strip() or "Error desconocido al crear usuario."
        if "Ya existe" in error_detail:
            error_msg = ICON_X + " <b>ESE USUARIO YA ESTÁ EN USO</b>"
        else:
            safe_detail = html_lib.escape(error_detail)
            error_msg = ICON_X + " <b>FALLO AL CREAR:</b>\n<code>" + safe_detail + "</code>"
            
        try:
            bot.edit_message_text(error_msg, message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML')
        except:
            bot.send_message(message.chat.id, error_msg, parse_mode='HTML')
        time.sleep(4)
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_slowdns_ns(message):
    delete_user_msg(message)
    ns = message.text.strip()
    if not ns: return
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
    sent = bot.edit_message_text("Introduce el <b>Puerto Local</b> (ej: 22 o 80):", message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML', reply_markup=markup)
    bot.register_next_step_handler(sent, lambda m: process_slowdns_port(m, ns))

def process_slowdns_port(message, ns):
    delete_user_msg(message)
    port = message.text.strip()
    chat_id = message.chat.id
    msg_id = USER_STEPS.get(chat_id)
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("🔄 Actualizar Estado", callback_data="update_slowdns_log"))
    bot.edit_message_text("⏳ <b>Instalando SlowDNS...</b>\n\nPresiona el botón para ver el progreso real.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    
    # Ejecutar en Hilo Separado
    threading.Thread(target=run_installation_async, args=(chat_id, msg_id, ns, port)).start()

def update_install_log(chat_id, msg_id):
    log_file = "/tmp/slowdns_install.log"
    content = "Esperando reporte del servidor..."
    if os.path.exists(log_file):
        with open(log_file, 'r') as f: content = f.read().strip()
    
    # Escapar contenido para Telegram HTML
    safe_content = html_lib.escape(content)
    label = "⏳ <b>PROGRESO DE INSTALACIÓN:</b>\n\n<code>" + safe_content + "</code>"
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("🔄 Actualizar Estado", callback_data="update_slowdns_log"))
    
    try: bot.edit_message_text(label, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    except: pass

def run_installation_async(chat_id, msg_id, ns, port):
    # Ejecutar Instalación
    try:
        res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'instalar_slowdns', ns, port], capture_output=True, text=True)
        
        if "SLOWDNS_SUCCESS" in res.stdout:
            parts = res.stdout.replace("SLOWDNS_SUCCESS:", "").strip().split('|')
            key = parts[0]
            
            data = load_data()
            data['slowdns'] = {"ns": ns, "port": port, "key": key}
            save_data(data)
            
            msg = "✅ <b>SlowDNS Instalado con Éxito</b>\n\n"
            msg += "🌐 <b>NS:</b> <code>" + ns + "</code>\n"
            msg += "🔑 <b>KEY:</b> <code>" + key + "</code>\n\n"
            msg += "Los datos también están en <b>Info Servidor</b>."
            
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver al Menú", callback_data="back_main"))
            bot.edit_message_text(msg, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        else:
            err = res.stdout.strip() or res.stderr.strip() or ("Servidor fallo (Code: " + str(res.returncode) + ")")
            safe_err = html_lib.escape(err)
            bot.edit_message_text("❌ <b>Error en Instalación:</b>\n<code>" + safe_err + "</code>", chat_id, msg_id, parse_mode='HTML')
            time.sleep(4)
            main_menu(chat_id, msg_id)
    except Exception as e:
        safe_e = html_lib.escape(str(e))
        bot.edit_message_text("❌ <b>Fallo Critico:</b>\n<code>" + safe_e + "</code>", chat_id, msg_id, parse_mode='HTML')

def run_removal_async(chat_id, msg_id):
    try:
        # Ejecutar Desinstalación técnica
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_slowdns'])
        
        # Limpiar Base de Datos
        data = load_data()
        data['slowdns'] = {}
        save_data(data)
        
        bot.edit_message_text("✅ <b>SlowDNS Desinstalado</b>\n\nTodos los archivos y reglas de red han sido eliminados correctamente.", chat_id, msg_id, parse_mode='HTML')
        time.sleep(3)
        main_menu(chat_id, msg_id)
    except Exception as e:
        safe_e = html_lib.escape(str(e))
        bot.edit_message_text("❌ <b>Error al Desinstalar:</b>\n<code>" + safe_e + "</code>", chat_id, msg_id, parse_mode='HTML')

def process_broadcast(message):
    delete_user_msg(message)
    ids = load_data().get('user_history', [])
    for uid in ids:
        if uid == SUPER_ADMIN: continue
        try: bot.send_message(uid, ICON_MEGA + " <b>AVISO:</b>\n\n" + message.text, parse_mode='HTML'); time.sleep(0.1)
        except: pass
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_delete(message):
    delete_user_msg(message)
    user_to_del = message.text.strip()
    is_sa = (message.chat.id == SUPER_ADMIN)
    data = load_data()
    owners = data.get('ssh_owners', {})
    
    # Validar permiso: Solo el Super Admin se salta esto.
    # Admins secundarios y usuarios deben ser dueños.
    if not is_sa:
        if owners.get(user_to_del) != str(message.chat.id):
            main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
            return

    subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_user', user_to_del])
    # Limpiar de la bd si existía
    if user_to_del in owners: del data['ssh_owners'][user_to_del]; save_data(data)
    
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

if __name__ == "__main__":
    while True:
        try: bot.infinity_polling(timeout=50)
        except Exception: time.sleep(10)
EOF

# Inyectar Variables Dinámicas de forma segura
sed -i "s|CONF_TOKEN|$BOT_TOKEN|g" depwise_bot.py
sed -i "s|CONF_ADMIN|$ADMIN_ID|g" depwise_bot.py
sed -i "s|CONF_DIR|$PROJECT_DIR|g" depwise_bot.py

chmod +x depwise_bot.py

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
echo -e "       INSTALACION V5.0 COMPLETADA 💎"
echo -e "=================================================="
echo -e "IP Estatica y Markdown activados con exito.${NC}"
