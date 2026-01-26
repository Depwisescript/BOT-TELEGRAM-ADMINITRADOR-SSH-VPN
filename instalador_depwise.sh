#!/bin/bash
set -euo pipefail

# =========================================================
# INSTALADOR UNIVERSAL V6.5: BOT TELEGRAM DEPWISE SSH 💎
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
echo -e "       CONFIGURACION BOT DEPWISE V6.5"
echo -e "==================================================${NC}"

read -p "Introduce el TOKEN [${OLD_TOKEN:-}]: " BOT_TOKEN
BOT_TOKEN=${BOT_TOKEN:-${OLD_TOKEN:-}}

read -p "Introduce tu Chat ID [${OLD_ADMIN:-}]: " ADMIN_ID
ADMIN_ID=${ADMIN_ID:-${OLD_ADMIN:-}}

if [ -z "$BOT_TOKEN" ] || [ -z "$ADMIN_ID" ]; then
    log_error "Error: Datos incompletos."
    exit 1
fi

# Guardar para futuras actualizaciones
mkdir -p "$PROJECT_DIR"
echo "OLD_TOKEN=\"$BOT_TOKEN\"" > "$ENV_FILE"
echo "OLD_ADMIN=\"$ADMIN_ID\"" >> "$ENV_FILE"

log_info "Instalando dependencias (Core + Build Tools)..."
apt update && apt install -y python3 python3-pip curl python3-requests file net-tools lsof cmake make gcc g++ git
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
# ---------------------------------------------------------
# 1. Script Gestor SSH (Generacion Modular)
# ---------------------------------------------------------
echo "#!/bin/bash" > ssh_manager.sh
echo "set -euo pipefail" >> ssh_manager.sh

# --- BLOQUE COMUN ---
cat << 'ENDFUNC' >> ssh_manager.sh

crear_user() { 
    # Desactivar strict mode temporalmente para manejar errores manualmente
    set +e
    
    local USER=$1
    local PASS=$2
    local DAYS=$3
    
    if [ -z "$USER" ] || [ -z "$PASS" ] || [ -z "$DAYS" ]; then
        echo "ERROR: Faltan argumentos (User: $USER, Days: $DAYS)"
        set -e
        return 1
    fi

    # Calcular fecha expiracion
    local EXP_DATE=$(date -d "+$DAYS days" +%Y-%m-%d)
    if [ $? -ne 0 ]; then
        echo "ERROR: Fallo al calcular fecha (date command)"
        set -e
        return 1
    fi
    
    # Check existencia
    if id "$USER" &>/dev/null; then 
        echo "ERROR: El usuario $USER ya existe."
        set -e
        return 1
    fi
    
    # Crear usuario
    # Capturamos stderr para ver por que falla
    local ADD_OUT
    ADD_OUT=$(useradd -m -s /bin/bash -e "$EXP_DATE" "$USER" 2>&1)
    local ADD_RET=$?
    
    if [ $ADD_RET -ne 0 ]; then
        echo "ERROR: useradd fallo ($ADD_RET): $ADD_OUT"
        set -e
        return 1
    fi
    
    # Asignar password
    echo "$USER:$PASS" | chpasswd
    if [ $? -ne 0 ]; then
        echo "ERROR: chpasswd fallo. Eliminando usuario..."
        userdel -f -r "$USER"
        set -e
        return 1
    fi
    
    # Verificar exito final
    if id "$USER" &>/dev/null; then
        echo "SUCCESS: $USER|$PASS|$EXP_DATE"
    else
        echo "ERROR: Fallo desconocido al verificar usuario creado"
    fi
    
    # Reactivar strict mode
    set -e
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
ENDFUNC

# --- BLOQUE SLOWDNS ---
cat << 'ENDFUNC' >> ssh_manager.sh
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
    
    # 2. Asegurar binario
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
        
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
        iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
        
        # Systemd con ECHO
        echo "[Unit]" > /etc/systemd/system/slowdns.service
        echo "Description=SlowDNS Depwise Service" >> /etc/systemd/system/slowdns.service
        echo "After=network.target" >> /etc/systemd/system/slowdns.service
        echo "[Service]" >> /etc/systemd/system/slowdns.service
        echo "Type=simple" >> /etc/systemd/system/slowdns.service
        echo "User=root" >> /etc/systemd/system/slowdns.service
        echo "WorkingDirectory=/etc/slowdns" >> /etc/systemd/system/slowdns.service
        echo "ExecStart=/usr/bin/slowdns-server -udp :5300 -privkey-file /etc/slowdns/server.key $DOMAIN 127.0.0.1:$PORT" >> /etc/systemd/system/slowdns.service
        echo "Restart=always" >> /etc/systemd/system/slowdns.service
        echo "RestartSec=3" >> /etc/systemd/system/slowdns.service
        echo "[Install]" >> /etc/systemd/system/slowdns.service
        echo "WantedBy=multi-user.target" >> /etc/systemd/system/slowdns.service
        
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
    systemctl stop slowdns > /dev/null 2>&1
    systemctl disable slowdns > /dev/null 2>&1
    rm -f /etc/systemd/system/slowdns.service
    systemctl daemon-reload
    while iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null; do :; done
    rm -rf /etc/slowdns
    rm -f /tmp/slowdns_install.log
    rm -f /tmp/slowdns_gen.log
    echo "SLOWDNS_REMOVED"
}
ENDFUNC

# --- BLOQUE PROXYDT ---
cat << 'ENDFUNC' >> ssh_manager.sh
instalar_proxydt() {
    echo "Iniciando instalación de ProxyCracked (No Token)..." > /tmp/proxydt_install.log
    
    # helper para instalar libssl1.1 si falta
    install_legacy_libs() {
        if ! ldconfig -p | grep -q libssl.so.1.1; then
            echo "Detectada falta de libssl.so.1.1, instalando..." >> /tmp/proxydt_install.log
            local LIB_URL=""
            local ARCH=$(uname -m)
            
            if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm"* ]]; then
                 LIB_URL="http://ports.ubuntu.com/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.23_arm64.deb"
            else
                 # AMD64 Default
                 LIB_URL="http://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.24_amd64.deb"
            fi
            
            wget -q "$LIB_URL" -O /tmp/libssl1.1.deb
            dpkg -i /tmp/libssl1.1.deb >> /tmp/proxydt_install.log 2>&1
            rm -f /tmp/libssl1.1.deb
        else
             echo "libssl.so.1.1 encontrada." >> /tmp/proxydt_install.log
        fi
    }
    
    # Instalar Dependencias Legacy
    install_legacy_libs

    # Detectar arquitectura
    local ARCH=$(uname -m)
    local BIN_NAME="proxydt"
    echo "Arquitectura detectada: $ARCH" >> /tmp/proxydt_install.log
    
    # Lista de Miras (Mirrors)
    declare -a MIRRORS=(
        "https://raw.githubusercontent.com/mauvadao4g/ProxyDtunel/main/proxy"
        "https://raw.githubusercontent.com/mauvadao4g/ProxyDtunel/main/DT%201.2.3/proxy"
        "https://github.com/zahidbd2/udp-zivpn/releases/download/latest/udp-zivpn-linux-amd64"
        "https://github.com/Penguinehis/ProxyCracked/raw/main/proxy"
    )
    
    # Si es ARM, preferir binarios específicos si están disponibles
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm"* ]]; then
        MIRRORS=("https://github.com/zahidbd2/udp-zivpn/releases/download/latest/udp-zivpn-linux-arm64" "${MIRRORS[@]}")
    fi

    echo "Eliminando versiones previas..." >> /tmp/proxydt_install.log
    rm -f /usr/bin/proxydt /usr/bin/proxy
    
    local SUCCESS=false
    for URL in "${MIRRORS[@]}"; do
        echo "Intentando descargar de: $URL" >> /tmp/proxydt_install.log
        if curl -L -s -f -o /usr/bin/proxydt "$URL"; then
            chmod +x /usr/bin/proxydt
            # Crear symlink 'proxy' para compatibilidad con manual
            ln -sf /usr/bin/proxydt /usr/bin/proxy
            SUCCESS=true
            echo "Descarga exitosa desde: $URL" >> /tmp/proxydt_install.log
            break
        fi
    done
    
    if [ "$SUCCESS" = true ]; then
        echo "PROXYDT_SUCCESS|Cracked-NoToken"
    else
        echo "ERROR: Falló la descarga desde todos los espejos."
        return 1
    fi
}

abrir_puerto_proxydt() {
    local PORT=$1
    local TOKEN=$2 # Ignorado en version cracked
    local OPTIONS=$3
    local SERVICE_NAME="proxydt-$PORT"
    local SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"

    # Verificar si el puerto ya está en uso
    # Usamos -n -P para evitar resolucion DNS que congela el bot
    if lsof -n -P -i :$PORT -sTCP:LISTEN -t >/dev/null; then
        echo "ERROR: El puerto $PORT ya está ocupado."
        return 1
    fi

    echo "[Unit]" > "$SERVICE_FILE"
    echo "Description=ProxyDT (Cracked) on port $PORT" >> "$SERVICE_FILE"
    echo "After=network.target" >> "$SERVICE_FILE"
    echo "[Service]" >> "$SERVICE_FILE"
    echo "Type=simple" >> "$SERVICE_FILE"
    # Actualizado para binario mauvadao4g/ProxyDtunel
    echo "ExecStart=/usr/bin/proxydt -proxy_port 0.0.0.0:$PORT -msg SSHTFREE" >> "$SERVICE_FILE"
    echo "Restart=always" >> "$SERVICE_FILE"
    echo "RestartSec=3" >> "$SERVICE_FILE"
    echo "[Install]" >> "$SERVICE_FILE"
    echo "WantedBy=multi-user.target" >> "$SERVICE_FILE"

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    systemctl restart "$SERVICE_NAME"

    # Verificar si arrancó correctamente
    sleep 1
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        echo "PROXYDT_PORT_OPEN|$PORT"
    else
        echo "ERROR: Falló al iniciar. LOGS SISTEMA:"
        journalctl -u "$SERVICE_NAME" --no-pager -n 10
        
        # Limpieza si falla
        systemctl stop "$SERVICE_NAME"
        systemctl disable "$SERVICE_NAME"
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        return 1
    fi
}

cerrar_puerto_proxydt() {
    local PORT=$1
    local SERVICE_NAME="proxydt-$PORT"
    systemctl stop "$SERVICE_NAME"
    systemctl disable "$SERVICE_NAME"
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    echo "PROXYDT_PORT_CLOSED|$PORT"
}

eliminar_proxydt() {
    systemctl list-units --all | grep proxydt- | awk '{print $1}' | while read svc; do
        systemctl stop "$svc" && systemctl disable "$svc"
        rm -f "/etc/systemd/system/$svc"
    done
    rm -f /usr/bin/proxydt
    systemctl daemon-reload
    echo "PROXYDT_REMOVED"
}
ENDFUNC

# --- BLOQUE BANNER ---
cat << 'ENDFUNC' >> ssh_manager.sh
configurar_banner() {
    local BANNER_FILE="/etc/ssh/banner_depwise"
    echo -e "$1" > "$BANNER_FILE"
    if ! grep -q "^Banner $BANNER_FILE" /etc/ssh/sshd_config; then
        sed -i "/^#Banner/d" /etc/ssh/sshd_config
        sed -i "/^Banner/d" /etc/ssh/sshd_config
        echo "Banner $BANNER_FILE" >> /etc/ssh/sshd_config
    fi
    systemctl restart ssh
    echo "BANNER_UPDATED"
}

eliminar_banner() {
    local BANNER_FILE="/etc/ssh/banner_depwise"
    sed -i "/^Banner $BANNER_FILE/d" /etc/ssh/sshd_config
    rm -f "$BANNER_FILE"
    systemctl restart ssh
    echo "BANNER_REMOVED"
}
ENDFUNC

# --- BLOQUE ZIVPN ---
cat << 'ENDFUNC' >> ssh_manager.sh
instalar_zivpn() {
    local ARCH_RAW=$(uname -m)
    local BIN_URL=""
    [[ "$ARCH_RAW" == "x86_64" ]] && BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"
    [[ "$ARCH_RAW" == "arm64" || "$ARCH_RAW" == "aarch64" ]] && BIN_URL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"
    
    if [[ -z "$BIN_URL" ]]; then echo "ERROR: Arquitectura no soportada"; return 1; fi

    echo "Bajando binario Zivpn..." > /tmp/zivpn_install.log
    curl -L -s -f -o /usr/local/bin/zivpn "$BIN_URL"
    chmod +x /usr/local/bin/zivpn
    mkdir -p /etc/zivpn
    curl -L -s -f -o /etc/zivpn/config.json "https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json"
    
    openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 -subj "/C=US/ST=CA/L=LA/O=Zivpn/CN=zivpn" -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"
    
    echo "[Unit]" > /etc/systemd/system/zivpn.service
    echo "Description=zivpn VPN Server" >> /etc/systemd/system/zivpn.service
    echo "After=network.target" >> /etc/systemd/system/zivpn.service
    echo "[Service]" >> /etc/systemd/system/zivpn.service
    echo "Type=simple" >> /etc/systemd/system/zivpn.service
    echo "User=root" >> /etc/systemd/system/zivpn.service
    echo "WorkingDirectory=/etc/zivpn" >> /etc/systemd/system/zivpn.service
    echo "ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json" >> /etc/systemd/system/zivpn.service
    echo "Restart=always" >> /etc/systemd/system/zivpn.service
    echo "RestartSec=3" >> /etc/systemd/system/zivpn.service
    echo "Environment=ZIVPN_LOG_LEVEL=info" >> /etc/systemd/system/zivpn.service
    echo "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW" >> /etc/systemd/system/zivpn.service
    echo "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW" >> /etc/systemd/system/zivpn.service
    echo "[Install]" >> /etc/systemd/system/zivpn.service
    echo "WantedBy=multi-user.target" >> /etc/systemd/system/zivpn.service

    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl restart zivpn.service
    
    local DEV=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -A PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
    
    echo "ZIVPN_SUCCESS"
}

eliminar_zivpn() {
    systemctl stop zivpn.service && systemctl disable zivpn.service
    rm -f /etc/systemd/system/zivpn.service
    rm -rf /etc/zivpn
    rm -f /usr/local/bin/zivpn
    local DEV=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    iptables -t nat -D PREROUTING -i "$DEV" -p udp --dport 6000:19999 -j DNAT --to-destination :5667 || true
    systemctl daemon-reload
    echo "ZIVPN_REMOVED"
}
ENDFUNC

# --- BLOQUE ZIVPN PASS ---
# Se mantiene la inyeccion de python
cat << 'ENDFUNC' >> ssh_manager.sh
gestionar_zivpn_pass() {
    local ACTION=$1
    local PASS=$2
    local FILE="/etc/zivpn/config.json"
    local TEMP_SCRIPT="/tmp/zivpn_pass_manager.py"
    
    if [[ ! -f "$FILE" ]]; then 
        echo "ERROR: ZIVPN no está instalado."
        return 1
    fi
    
    cat > "$TEMP_SCRIPT" << 'PYTHON_EOF'
import json, sys
config_file = sys.argv[1]
action = sys.argv[2]
password = sys.argv[3]
try:
    with open(config_file, 'r') as f: data = json.load(f)
    if 'auth' not in data: data['auth'] = {}
    if 'mode' in data: data['auth']['mode'] = data.pop('mode')
    if 'config' in data:
        old_config = data.pop('config')
        if 'config' not in data['auth']: data['auth']['config'] = old_config
    data['auth']['mode'] = "passwords"
    if 'config' not in data['auth']: data['auth']['config'] = []
    if action == "add":
        if password not in data['auth']['config']: data['auth']['config'].append(password)
    elif action == "del":
        data['auth']['config'] = [p for p in data['auth']['config'] if p != password]
    with open(config_file, 'w') as f: json.dump(data, f, indent=4)
    print("SUCCESS")
except Exception as e:
    print(f"ERROR: {str(e)}", file=sys.stderr); sys.exit(1)
PYTHON_EOF
    
    local RESULT=$(python3 "$TEMP_SCRIPT" "$FILE" "$ACTION" "$PASS" 2>&1)
    rm -f "$TEMP_SCRIPT"
    
    if [[ "$RESULT" != "SUCCESS" ]]; then
        echo "ERROR: $RESULT"
        return 1
    fi
    
    systemctl restart zivpn.service
    local WAIT_COUNT=0
    while [ $WAIT_COUNT -lt 10 ]; do
        if systemctl is-active zivpn.service > /dev/null 2>&1; then break; fi
        sleep 0.5
        WAIT_COUNT=$((WAIT_COUNT + 1))
    done
    if ! systemctl is-active zivpn.service > /dev/null 2>&1; then
        echo "ERROR: Servicio ZIVPN no se pudo reiniciar correctamente"
        return 1
    fi
    echo "ZIVPN_PASS_UPDATED"
}

monitor_zivpn() {
    echo "ZIVPN_LIST:"
    ss -u -n -p | grep "zivpn" | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | while read count ip; do
        echo "- IP:$ip ($count sesion)"
    done
}
ENDFUNC

# --- BLOQUE BADVPN ---
cat << 'ENDFUNC' >> ssh_manager.sh
instalar_badvpn() {
    set -x 
    # Check rapido si ya existe, intentar reparar
    if [ -f "/usr/bin/badvpn-udpgw" ]; then
        echo "Binario detectado. Reconfigurando servicio..."
    fi
    # Compilar si no existe (Deps ya instaladas globalmente)
    if [ ! -f "/usr/bin/badvpn-udpgw" ]; then
        rm -rf /tmp/build_badvpn
        mkdir -p /tmp/build_badvpn
        cd /tmp/build_badvpn
        wget --no-check-certificate https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz
        if [ ! -f "1.999.130.tar.gz" ]; then echo "ERROR: Fallo descarga fuente"; return 1; fi
        tar xf 1.999.130.tar.gz
        cd badvpn-1.999.130
        cmake -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
        make install
        if [ ! -f "/usr/local/bin/badvpn-udpgw" ] && [ ! -f "/usr/bin/badvpn-udpgw" ]; then
             find /tmp/build_badvpn -name badvpn-udpgw -exec cp {} /usr/bin/ \;
        fi
        [ -f "/usr/local/bin/badvpn-udpgw" ] && cp /usr/local/bin/badvpn-udpgw /usr/bin/
        cd $PROJECT_DIR
        rm -rf /tmp/build_badvpn
    fi
    
    if [ ! -f "/usr/bin/badvpn-udpgw" ]; then
        echo "ERROR: Fallo compilacion badvpn (Binario no encontrado)"
        return 1
    fi
    
    echo "[Unit]" > /etc/systemd/system/badvpn.service
    echo "Description=BadVPN UDPGW Service" >> /etc/systemd/system/badvpn.service
    echo "After=network.target" >> /etc/systemd/system/badvpn.service
    echo "[Service]" >> /etc/systemd/system/badvpn.service
    echo "Type=simple" >> /etc/systemd/system/badvpn.service
    echo "User=root" >> /etc/systemd/system/badvpn.service
    echo "ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10" >> /etc/systemd/system/badvpn.service
    echo "Restart=always" >> /etc/systemd/system/badvpn.service
    echo "[Install]" >> /etc/systemd/system/badvpn.service
    echo "WantedBy=multi-user.target" >> /etc/systemd/system/badvpn.service

    systemctl daemon-reload
    systemctl enable badvpn > /dev/null 2>&1
    systemctl restart badvpn > /dev/null 2>&1
    echo "BADVPN_SUCCESS"
    set +x
}

eliminar_badvpn() {
    systemctl stop badvpn > /dev/null 2>&1
    systemctl disable badvpn > /dev/null 2>&1
    rm -f /etc/systemd/system/badvpn.service
    rm -f /usr/bin/badvpn-udpgw
    systemctl daemon-reload
    echo "BADVPN_REMOVED"
}
ENDFUNC

# --- BLOQUE STUNNEL REMOVIDO POR SOLICITUD ---


# --- BLOQUE DROPBEAR ---
cat << 'ENDFUNC' >> ssh_manager.sh
instalar_dropbear() {
    set -x
    local PORT=$1
    apt-get update -y > /dev/null 2>&1
    apt-get install dropbear -y > /dev/null 2>&1
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null ; then echo "ERROR: Puerto $PORT ocupado"; return 1; fi
    systemctl stop dropbear > /dev/null 2>&1
    echo "[Unit]" > /lib/systemd/system/dropbear.service
    echo "Description=Dropbear SSH Daemon" >> /lib/systemd/system/dropbear.service
    echo "After=network.target" >> /lib/systemd/system/dropbear.service
    echo "[Service]" >> /lib/systemd/system/dropbear.service
    echo "Type=simple" >> /lib/systemd/system/dropbear.service
    echo "ExecStart=/usr/sbin/dropbear -F -p $PORT -K 60" >> /lib/systemd/system/dropbear.service
    echo "KillMode=process" >> /lib/systemd/system/dropbear.service
    echo "Restart=always" >> /lib/systemd/system/dropbear.service
    echo "[Install]" >> /lib/systemd/system/dropbear.service
    echo "WantedBy=multi-user.target" >> /lib/systemd/system/dropbear.service
    systemctl daemon-reload
    systemctl enable dropbear > /dev/null 2>&1
    systemctl restart dropbear > /dev/null 2>&1
    sleep 2
    if systemctl is-active dropbear > /dev/null 2>&1; then echo "DROPBEAR_SUCCESS|$PORT"; else echo "ERROR: Fallo arranque servicio"; fi
    set +x
}

eliminar_dropbear() {
    systemctl stop dropbear > /dev/null 2>&1
    apt-get purge dropbear -y > /dev/null 2>&1
    rm -f /etc/dropbear
    echo "DROPBEAR_REMOVED"
}
ENDFUNC

# --- CASE PRINCIPAL ---
cat << 'ENDFUNC' >> ssh_manager.sh
case "$1" in
    crear_user) crear_user "$2" "$3" "$4" ;;
    eliminar_user) eliminar_user "$2" ;;
    listar_users) listar_users ;;
    contar_conexiones) contar_conexiones ;;
    instalar_slowdns) instalar_slowdns "$2" "$3" ;;
    eliminar_slowdns) eliminar_slowdns ;;
    instalar_proxydt) instalar_proxydt ;;
    abrir_puerto_proxydt) abrir_puerto_proxydt "$2" "$3" "$4" ;;
    cerrar_puerto_proxydt) cerrar_puerto_proxydt "$2" ;;
    eliminar_proxydt) eliminar_proxydt ;;
    configurar_banner) configurar_banner "$2" ;;
    eliminar_banner) eliminar_banner ;;
    instalar_zivpn) instalar_zivpn ;;
    gestionar_zivpn_pass) gestionar_zivpn_pass "$2" "$3" ;;
    monitor_zivpn) monitor_zivpn ;;
    eliminar_zivpn) eliminar_zivpn ;;
    instalar_badvpn) instalar_badvpn ;;
    eliminar_badvpn) eliminar_badvpn ;;
    instalar_dropbear) instalar_dropbear "$2" ;;
    eliminar_dropbear) eliminar_dropbear ;;
esac
ENDFUNC
chmod +x ssh_manager.sh


# ---------------------------------------------------------
# 2. Bot de Python V6.5 (PRO CUSTOM)
# ---------------------------------------------------------
log_info "Creando bot V6.5 (Static IP + Zivpn Support)..."
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
from datetime import datetime, timedelta

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
ICON_PHONE = u'\U0001F4DE'
ICON_SHIELD = u'\U0001F6E1'
ICON_BEAR = u'\U0001F43B'

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
        default = {
            "admins": {}, 
            "extra_info": "Puertos: 22, 80, 443", 
            "user_history": [], 
            "public_access": True, 
            "ssh_owners": {},
            "cloudflare_domain": "",
            "proxydt": {"ports": {}, "token": "dummy"},
            "slowdns": {},
            "zivpn_users": {},
            "zivpn_owners": {},
            "badvpn": False,
            "dropbear": 0
        }
        save_data(default); return default
    try:
        data = json.load(open(DATA_FILE))
        if 'extra_info' not in data: data['extra_info'] = "Sin informacion adicional."
        if 'public_access' not in data: data['public_access'] = True
        if 'ssh_owners' not in data: data['ssh_owners'] = {}
        if 'slowdns' not in data: data['slowdns'] = {}
        if 'proxydt' not in data: data['proxydt'] = {"ports": {}, "token": "V55cFY8zTictLCPfviiuX5DHjs15"}
        if 'zivpn_users' not in data: data['zivpn_users'] = {}
        if 'zivpn_owners' not in data: data['zivpn_owners'] = {}
        if 'cloudflare_domain' not in data: data['cloudflare_domain'] = ""
        # Nuevos protocolos
        if 'badvpn' not in data: data['badvpn'] = False
        if 'dropbear' not in data: data['dropbear'] = 0
        
        if data['proxydt'].get('token') == "": data['proxydt']['token'] = "V55cFY8zTictLCPfviiuX5DHjs15"
        return data
    except:
        return {
            "admins": {}, 
            "extra_info": "Error al cargar", 
            "user_history": [], 
            "public_access": True, 
            "ssh_owners": {}, 
            "proxydt": {"ports": {}, "token": "V55cFY8zTictLCPfviiuX5DHjs15"}, 
            "zivpn_users": {},
            "zivpn_owners": {},
            "cloudflare_domain": ""
        }

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
    elif is_adm:
        markup.add(
            types.InlineKeyboardButton(ICON_GEAR + " Monitor Online", callback_data="menu_online")
        )
    
    text = ICON_GEM + " <b>BOT TELEGRAM DEPWISE V6.5</b>\n"
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
        markup.add(types.InlineKeyboardButton("👤 Cliente SSH", callback_data="crear_ssh"))
        markup.add(types.InlineKeyboardButton("🛰️ Acceso ZIVPN", callback_data="crear_zivpn"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_WRITE + " <b>¿Qué deseas crear?</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "crear_ssh":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_crear"))
        bot.edit_message_text(ICON_WRITE + " <b>Nombre del usuario SSH:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_username)
    elif call.data == "crear_zivpn":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_crear"))
        bot.edit_message_text("🔑 <b>Introduce el Password para ZIVPN:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_zivpn_pass)
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
        bot.edit_message_text(ICON_USER + " <b>ELIMINAR ACCESOS:</b>\n\n<b>SSH:</b>\n" + users + "\n\nEscribe nombre:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_delete)
    elif call.data == "menu_info":
        ip = get_public_ip()
        data = load_data()
        extra = data.get('extra_info', '')
        domain = data.get('cloudflare_domain', '')
        
        text = ICON_INFO + " <b>DATOS DEL SERVIDOR</b>\n\n"
        text += ICON_PIN + " <b>IP Fija:</b> <code>" + ip + "</code> \n"
        
        # Mostrar dominio Cloudflare si existe
        if domain:
            text += "🌐 <b>Dominio:</b> <code>" + domain + "</code> \n"
        
        # Datos SlowDNS si existen
        sdns = data.get('slowdns', {})
        if sdns.get('key'):
            text += "\n🚀 <b>SLOWDNS CONFIG:</b>\n"
            text += "<b>Dominio:</b> <code>" + sdns.get('ns','') + "</code>\n"
            text += "<b>Key:</b> <code>" + sdns.get('key','') + "</code>\n"
            
        # Datos ProxyDT / Websock
        pdt = data.get('proxydt', {})
        ports = pdt.get('ports', {})
        if ports:
            text += "\n🛰️ <b>PROXYDT / WEBSOCK:</b>\n"
            for p, opt in ports.items():
                text += f"• Puerto: <code>{p}</code> ({opt})\n"
        
        # Datos ZIVPN si está instalado
        zivpn_users = data.get('zivpn_users', {})
        if zivpn_users:
            text += "\n📡 <b>UDP ZIVPN:</b>\n"
            text += "<b>Puerto Interno:</b> <code>5667</code>\n"
            text += "<b>Rango Externo:</b> <code>6000-19999</code>\n"
            text += f"<b>Passwords Activos:</b> {len(zivpn_users)}\n"

        text += "------------------\n" + safe_format(extra)
        
        # Info de Nuevos Protocolos
        if data.get('badvpn'): text += "\n" + ICON_PHONE + " <b>BadVPN:</b> <code>7300</code> (Activo)"
        if data.get('dropbear'): text += "\n" + ICON_BEAR + " <b>Dropbear:</b> <code>" + str(data.get('dropbear')) + "</code>"

        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "menu_broadcast" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_MEGA + " <b>MENSAJE GLOBAL:</b>\nEscribe el mensaje:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_broadcast)
    elif call.data == "menu_online" and is_admin(chat_id):
        # SSH Monitor
        res_ssh = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'contar_conexiones'], capture_output=True, text=True)
        raw_ssh = res_ssh.stdout.replace("ONLINE_LIST:", "").strip()
        
        # Zivpn Monitor - Mostrar passwords activos
        data = load_data()
        zivpn_users = data.get('zivpn_users', {})
        zivpn_owners = data.get('zivpn_owners', {})

        if chat_id == SUPER_ADMIN:
            online_ssh = raw_ssh or "Sin conexiones SSH."
            # Super Admin ve todos los passwords ZIVPN
            if zivpn_users:
                online_zi = "<b>Passwords Activos:</b>\n"
                for pwd, exp in zivpn_users.items():
                    owner_id = zivpn_owners.get(pwd, 'Desconocido')
                    online_zi += f"- <code>{pwd}</code> (Vence: {exp}, Owner: {owner_id})\n"
            else:
                online_zi = "Sin passwords Zivpn activos."
        else:
            # Admins secundarios y usuarios normales
            owners = data.get('ssh_owners', {})
            lines = raw_ssh.split('\n')
            filtered = [l for l in lines if l.strip() and owners.get(l.split(':')[0].strip('- ').strip()) == str(chat_id)]
            online_ssh = "\n".join(filtered) if filtered else "Sin conexiones tuyas."
            
            # Filtrar solo passwords ZIVPN propios
            my_zivpn = {pwd: exp for pwd, exp in zivpn_users.items() if zivpn_owners.get(pwd) == str(chat_id)}
            if my_zivpn:
                online_zi = "<b>Tus Passwords ZIVPN:</b>\n"
                for pwd, exp in my_zivpn.items():
                    online_zi += f"- <code>{pwd}</code> (Vence: {exp})\n"
            else:
                online_zi = "No tienes passwords ZIVPN activos."

        text = ICON_GEAR + " <b>MONITOR DE CONEXIONES</b>\n\n"
        text += "🔒 <b>SSH:</b>\n" + online_ssh + "\n\n"
        text += "🛰️ <b>ZIVPN UDP:</b>\n" + online_zi
            
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "menu_protocols" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup(row_width=1)
        markup.add(
            types.InlineKeyboardButton("🚀 Instalar SlowDNS", callback_data="install_slowdns"),
            types.InlineKeyboardButton("🛰️ ProxyDT-Go / Websock", callback_data="menu_proxydt"),
            types.InlineKeyboardButton("📡 UDP ZIVPN (Nuevo)", callback_data="zivpn_install"),
            types.InlineKeyboardButton(ICON_PHONE + " BadVPN (Llamadas)", callback_data="badvpn_menu"),
            types.InlineKeyboardButton(ICON_BEAR + " Dropbear (SSH Mini)", callback_data="dropbear_menu"),
            types.InlineKeyboardButton(ICON_DEL + " Eliminar SlowDNS", callback_data="remove_slowdns"),
            types.InlineKeyboardButton(ICON_DEL + " Eliminar ProxyDT / Websock", callback_data="proxydt_remove"),
            types.InlineKeyboardButton(ICON_DEL + " Eliminar UDP ZIVPN", callback_data="zivpn_remove"),
            types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
        )
        bot.edit_message_text(ICON_GEAR + " <b>GESTIÓN DE PROTOCOLOS</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "badvpn_menu":
        # BadVPN Handlers
        d = load_data()
        is_installed = d.get('badvpn')
        st = "INSTALADO (7300)" if is_installed else "NO INSTALADO"
        
        markup = types.InlineKeyboardMarkup()
        if not is_installed:
            markup.add(types.InlineKeyboardButton("Instalar BadVPN", callback_data="run_badvpn"))
            # Boton de emergencia por si quedo basura
            markup.add(types.InlineKeyboardButton("Forzar Limpieza", callback_data="del_badvpn"))
        else:
            markup.add(types.InlineKeyboardButton("Reinstalar / Reparar", callback_data="run_badvpn"))
            markup.add(types.InlineKeyboardButton("Desinstalar BadVPN", callback_data="del_badvpn"))
            
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        bot.edit_message_text(f"{ICON_PHONE} <b>BadVPN UDPGW</b>\nEstado: {st}", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "run_badvpn":
        # Menu de espera con boton de actualizar
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🔄 Actualizar Progreso", callback_data="log_badvpn"))
        bot.edit_message_text("⏳ <b>Instalando BadVPN (Compilando)...</b>\nEsto puede tardar unos minutos.\nPulsa abajo para ver el avance.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        
        threading.Thread(target=install_badvpn_thread, args=(chat_id, msg_id)).start()

    elif call.data == "log_badvpn":
        update_log_view(chat_id, msg_id, "/tmp/badvpn_install.log", "log_badvpn")

    elif call.data == "del_badvpn":
        bot.answer_callback_query(call.id, "🗑️ Eliminando...")
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_badvpn'])
        d = load_data(); d['badvpn'] = False; save_data(d)
        main_menu(chat_id, msg_id)

    elif call.data == "dropbear_menu":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Instalar Dropbear", callback_data="ask_dropbear"),
                   types.InlineKeyboardButton("Eliminar Dropbear", callback_data="del_dropbear"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        bot.edit_message_text(f"{ICON_BEAR} <b>Dropbear SSH</b>\nSSH ligero alternativo.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "ask_dropbear":
        markup = types.InlineKeyboardMarkup(); markup.add(types.InlineKeyboardButton("Cancelar", callback_data="menu_protocols"))
        bot.edit_message_text("Puerto para Dropbear (ej: 90):", chat_id, msg_id, reply_markup=markup)
        bot.register_next_step_handler(call.message, run_dropbear)
    elif call.data == "del_dropbear":
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_dropbear'])
        d = load_data(); d['dropbear'] = 0; save_data(d)
        bot.answer_callback_query(call.id, "🗑️ Eliminado")
        main_menu(chat_id, msg_id)
    elif call.data == "proxydt_remove" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "🗑️ Desinstalando ProxyDT...")
        threading.Thread(target=run_proxydt_removal, args=(chat_id, msg_id)).start()
    elif call.data == "zivpn_install" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "⬇️ Instalando ZIVPN...")
        threading.Thread(target=run_zivpn_install, args=(chat_id, msg_id)).start()
    elif call.data == "zivpn_remove" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "🗑️ Eliminando ZIVPN...")
        threading.Thread(target=run_zivpn_removal, args=(chat_id, msg_id)).start()
    elif call.data == "menu_proxydt" and chat_id == SUPER_ADMIN:
        show_proxydt_menu(chat_id, msg_id)
    elif call.data == "proxydt_install" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "⬇️ Descargando Proxy Cracked...")
        threading.Thread(target=run_proxydt_install, args=(chat_id, msg_id)).start()
    elif call.data == "proxydt_open" and chat_id == SUPER_ADMIN:
        bot.edit_message_text("Introduce el <b>Puerto</b> a abrir:", chat_id, msg_id, parse_mode='HTML')
        bot.register_next_step_handler(call.message, process_proxydt_port)
    elif call.data == "proxydt_close" and chat_id == SUPER_ADMIN:
        data = load_data()
        ports = data['proxydt'].get('ports', {})
        if not ports:
            bot.answer_callback_query(call.id, "No hay puertos abiertos.")
            return
        text = "<b>CERRAR PUERTO:</b>\nEscribe el puerto a cerrar:"
        bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML')
        bot.register_next_step_handler(call.message, process_proxydt_close)
    elif call.data.startswith("pdt_opt_") and chat_id == SUPER_ADMIN:
        # Lógica de opciones ProxyDT integrada en el handler principal
        parts = call.data.split('_')
        port = parts[2]
        opt = parts[3]
        if opt == "none": opt = ""
        
        data = load_data()
        tk = data['proxydt']['token']
        
        res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'abrir_puerto_proxydt', port, tk, opt], capture_output=True, text=True)
        if "PROXYDT_PORT_OPEN" in res.stdout:
            data['proxydt']['ports'][port] = opt or "Normal"
            save_data(data)
            bot.answer_callback_query(call.id, f"✅ Puerto {port} abierto.")
        else:
            # Mostrar error real en un mensaje
            err_msg = res.stdout.strip() or "Error desconocido."
            bot.answer_callback_query(call.id, "❌ Fallo al abrir puerto.")
            bot.send_message(chat_id, f"❌ <b>Error al abrir ProxyDT:</b>\n<code>{html_lib.escape(err_msg)}</code>", parse_mode='HTML')
        show_proxydt_menu(chat_id, msg_id)
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
    elif call.data == "menu_banner" and chat_id == SUPER_ADMIN:
        show_banner_menu(chat_id, msg_id)
    elif call.data == "banner_edit" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="menu_banner"))
        bot.edit_message_text("📝 <b>Introduce el nuevo Banner:</b>\nPuedes usar texto plano o ASCII-Art. Se cargará al conectar por SSH.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_banner_save)
    elif call.data == "banner_remove" and chat_id == SUPER_ADMIN:
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_banner'])
        bot.answer_callback_query(call.id, "✅ Banner eliminado correctamente.")
        show_banner_menu(chat_id, msg_id)
    elif call.data == "admin_add":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text("ID del Admin:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_admin_id)
    elif call.data == "set_domain" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_admins"))
        bot.edit_message_text("🌐 <b>Configura tu Dominio Cloudflare:</b>\n\nIntroduce el dominio (ej: vpn.tudominio.com)\nO escribe 'borrar' para eliminarlo.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_domain)
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
    domain_status = f"🌐 Dominio: {data.get('cloudflare_domain', 'No configurado')}"
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton(status, callback_data="toggle_public"),
        types.InlineKeyboardButton(ICON_PLUS + " Añadir Admin", callback_data="admin_add"),
        types.InlineKeyboardButton(ICON_DEL + " Eliminar Admin", callback_data="admin_del"),
        types.InlineKeyboardButton(ICON_WRITE + " Editar Info Extra", callback_data="set_edit_info"),
        types.InlineKeyboardButton(domain_status, callback_data="set_domain"),
        types.InlineKeyboardButton(ICON_MEGA + " Banner SSH (Nuevo)", callback_data="menu_banner"),
        types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
    )
    bot.edit_message_text(ICON_GEAR + " <b>AJUSTES AVANZADOS</b>", chat_id, message_id, reply_markup=markup, parse_mode='HTML')

def process_save_info(message):
    delete_user_msg(message)
    data = load_data(); data['extra_info'] = message.text; save_data(data)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_domain(message):
    delete_user_msg(message)
    domain = message.text.strip().lower()
    data = load_data()
    if domain == 'borrar':
        data['cloudflare_domain'] = ""
        save_data(data)
        bot.send_message(message.chat.id, "✅ <b>Dominio eliminado correctamente.</b>", parse_mode='HTML')
    else:
        data['cloudflare_domain'] = domain
        save_data(data)
        bot.send_message(message.chat.id, f"✅ <b>Dominio configurado:</b> <code>{domain}</code>", parse_mode='HTML')
    show_pro_settings(message.chat.id, USER_STEPS.get(message.chat.id))

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

# Primera definicion de finalize_ssh removida por duplicidad (Usando la version de la linea 1500)


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

# --- PROXYDT-GO BOT LOGIC ---
def show_proxydt_menu(chat_id, msg_id):
    data = load_data()
    ports = data.get('proxydt', {}).get('ports', {})
    text = "🛰️ <b>GESTIÓN PROXYDT-GO / WEBSOCK</b>\n\n"
    if ports:
        text += "<b>Puertos Activos:</b>\n"
        for p, opt in ports.items(): text += f"• <code>{p}</code> ({opt})\n"
    else:
        text += "<i>No hay puertos activos.</i>\n"
    
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("⬇️ Instalar Binario Cracked", callback_data="proxydt_install"),
        types.InlineKeyboardButton("🟢 Abrir Puerto", callback_data="proxydt_open"),
        types.InlineKeyboardButton("🔴 Cerrar Puerto", callback_data="proxydt_close"),
        types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols")
    )
    if msg_id:
        try: bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        except: bot.send_message(chat_id, text, parse_mode='HTML', reply_markup=markup)
    else:
        bot.send_message(chat_id, text, parse_mode='HTML', reply_markup=markup)

def run_proxydt_install(chat_id, msg_id):
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'instalar_proxydt'], capture_output=True, text=True)
    if "PROXYDT_SUCCESS" in res.stdout:
        ver = res.stdout.split('|')[1]
        bot.edit_message_text(f"✅ <b>ProxyDT-Go Instalado</b>\nVersión: <code>{ver}</code>", chat_id, msg_id, parse_mode='HTML')
    else:
        bot.edit_message_text("❌ <b>Error al instalar ProxyDT-Go.</b>", chat_id, msg_id, parse_mode='HTML')
    time.sleep(3)
    show_proxydt_menu(chat_id, msg_id)

def process_proxydt_port(message):
    delete_user_msg(message)
    port = message.text.strip()
    chat_id = message.chat.id
    
    # Feedback inmediato para que no se congele
    bot.send_message(chat_id, f"⏳ <b>Procesando Puerto {port}...</b>\nEl bot te avisará cuando esté listo.", parse_mode='HTML')
    
    # Ejecutar en segundo plano (Thread)
    threading.Thread(target=run_proxydt_port_async, args=(chat_id, port)).start()

def run_proxydt_port_async(chat_id, port):
    try:
        # Token y Opciones son ignorados por el script updated
        res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'abrir_puerto_proxydt', port, "dummy_token", "dummy_opt"], capture_output=True, text=True)
        
        if "PROXYDT_PORT_OPEN" in res.stdout:
            data = load_data()
            data['proxydt']['ports'][port] = "Cracked"
            save_data(data)
            try: bot.send_message(chat_id, f"✅ <b>Puerto {port} Abierto con Éxito.</b>", parse_mode='HTML')
            except: pass
        else:
            err_msg = res.stdout.strip() or "Error desconocido."
            try: bot.send_message(chat_id, f"❌ <b>Fallo al abrir puerto {port}:</b>\n<pre>{html_lib.escape(err_msg)}</pre>", parse_mode='HTML')
            except: pass
    except Exception as e:
        bot.send_message(chat_id, f"❌ <b>Error Critico Bot:</b>\n{str(e)}")

    # Refrescar menú si es posible
    try: show_proxydt_menu(chat_id, None)
    except: pass

def process_proxydt_close(message):
    delete_user_msg(message)
    port = message.text.strip()
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'cerrar_puerto_proxydt', port], capture_output=True, text=True)
    if "PROXYDT_PORT_CLOSED" in res.stdout:
        data = load_data()
        if port in data['proxydt']['ports']: del data['proxydt']['ports'][port]
        save_data(data)
    show_proxydt_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def run_proxydt_removal(chat_id, msg_id):
    try:
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_proxydt'])
        data = load_data()
        data['proxydt']['ports'] = {}
        save_data(data)
        bot.edit_message_text("✅ <b>ProxyDT-Go Desinstalado</b>\nBinario y servicios eliminados con éxito.", chat_id, msg_id, parse_mode='HTML')
        time.sleep(3)
        main_menu(chat_id, msg_id)
    except Exception as e:
        safe_e = html_lib.escape(str(e))
        bot.edit_message_text(f"❌ <b>Error:</b>\n<code>{safe_e}</code>", chat_id, msg_id, parse_mode='HTML')

# --- SSH BANNER BOT LOGIC ---
def show_banner_menu(chat_id, msg_id):
    banner_file = "/etc/ssh/banner_depwise"
    current = "<i>No hay banner configurado.</i>"
    if os.path.exists(banner_file):
        with open(banner_file, 'r') as f:
            raw_content = f.read().strip()
            # Escapamos el contenido para que Telegram no intente procesar etiquetas HTML internas
            current = f"<code>{html_lib.escape(raw_content)}</code>"
    
    text = "📁 <b>GESTOR DE BANNER SSH</b>\n\n<b>Actual:</b>\n" + current
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("📝 Editar / Crear", callback_data="banner_edit"),
        types.InlineKeyboardButton("🗑️ Eliminar", callback_data="banner_remove"),
        types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_admins")
    )
    try:
        bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    except Exception as e:
        # Si falla el edit_message por alguna razón, enviamos un mensaje de error seguro
        bot.send_message(chat_id, "❌ <b>Error al mostrar el Banner:</b> Contenido incompatible con la interfaz de Telegram.", parse_mode='HTML')
        main_menu(chat_id, msg_id)

def process_banner_save(message):
    delete_user_msg(message)
    content = message.text
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'configurar_banner', content], capture_output=True, text=True)
    if "BANNER_UPDATED" in res.stdout:
        bot.send_message(message.chat.id, "✅ <b>Banner SSH actualizado con éxito.</b>", parse_mode='HTML')
    else:
        bot.send_message(message.chat.id, "❌ <b>Error al actualizar banner.</b>", parse_mode='HTML')
    show_banner_menu(message.chat.id, USER_STEPS.get(message.chat.id))

# --- ZIVPN BOT LOGIC ---
def run_zivpn_install(chat_id, msg_id):
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'instalar_zivpn'], capture_output=True, text=True)
    if "ZIVPN_SUCCESS" in res.stdout:
        bot.edit_message_text("✅ <b>Zivpn UDP Instalado</b>\nPuerto 5667 activo y redirección 6000-19999 lista.", chat_id, msg_id, parse_mode='HTML')
    else:
        bot.edit_message_text("❌ <b>Error al instalar Zivpn.</b>", chat_id, msg_id, parse_mode='HTML')
    time.sleep(3)
    main_menu(chat_id, msg_id)

def run_zivpn_removal(chat_id, msg_id):
    subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_zivpn'])
    data = load_data(); data['zivpn_users'] = {}; save_data(data)
    bot.edit_message_text("✅ <b>Zivpn Eliminado Correctamente.</b>", chat_id, msg_id, parse_mode='HTML')
    time.sleep(3)
    main_menu(chat_id, msg_id)

def process_zivpn_pass(message):
    delete_user_msg(message)
    pwd = message.text.strip()
    chat_id = message.chat.id
    is_sa = (chat_id == SUPER_ADMIN)
    is_adm = is_admin(chat_id)
    
    # Sistema de permisos: Super Admin puede elegir, Admin 7 días, Público 3 días
    if is_sa:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="menu_crear"))
        bot.edit_message_text(f"🔑 Pass: <code>{pwd}</code>\n{ICON_TIME} <b>¿Cuántos días de vigencia?</b>", chat_id, USER_STEPS.get(chat_id), parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(message, lambda m: finalize_zivpn(m, pwd))
    else:
        # Admin: 7 días, Público: 3 días
        days = 7 if is_adm else 3
        finalize_zivpn(message, pwd, days)

def finalize_ssh(message, user, days=None):
    delete_user_msg(message)
    try:
        if days is None:
            try: days = int(message.text)
            except ValueError: 
                bot.send_message(message.chat.id, "❌ <b>Error:</b> Los días deben ser un número.", parse_mode='HTML')
                main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
                return
        
        # Feedback visual de proceso
        status_msg = bot.send_message(message.chat.id, "⏳ <b>Creando Usuario SSH...</b>", parse_mode='HTML')
        
        # Limpieza de expirados antes de crear
        cleanup_expired()
    
        pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'crear_user', user, pwd, str(days)]
        
        # Ejecutar y capturar TODO (stdout + stderr)
        res = subprocess.run(cmd, capture_output=True, text=True)
        
        # Borrar mensaje de estado
        try: bot.delete_message(message.chat.id, status_msg.message_id)
        except: pass
        
        if "SUCCESS" in res.stdout:
            ip = get_public_ip()
            data = load_data()
            extra = data.get('extra_info', '')
            domain = data.get('cloudflare_domain', '')
            # Extraer fecha de res.stdout
            try: dt = res.stdout.strip().split('|')[2]
            except: dt = "Indefinida"
            
            msg = ICON_CHECK + " <b>BOT TELEGRAM DEPWISE V6.5</b>\n--------------------------------------\n"
            msg += ICON_PIN + " <b>HOST IP:</b> <code>" + ip + "</code> \n"
            if domain:
                msg += "🌐 <b>DOMINIO:</b> <code>" + domain + "</code> \n"
            if extra: msg += safe_format(extra) + "\n"
            msg += "<b>USER:</b> <code>" + user + "</code> \n<b>PASS:</b> <code>" + pwd + "</code> \n"
            
            # Datos SlowDNS si existen
            sdns = data.get('slowdns', {})
            if sdns.get('key'):
                msg += "\n🚀 <b>SLOWDNS CONFIG:</b>\n"
                msg += "<b>Dominio:</b> <code>" + sdns.get('ns','') + "</code>\n"
                msg += "<b>Key:</b> <code>" + sdns.get('key','') + "</code>\n"
                
            # Datos ProxyDT / Websock
            if hasattr(data, 'get') and data.get('proxydt'): # Safety check
                pdt = data.get('proxydt', {})
                ports = pdt.get('ports', {})
                if ports:
                    msg += "\n🌐 <b>WEBSOCK:</b> " + ", ".join([f"<code>{p}</code>" for p in ports.keys()]) + "\n"
            
            # Info Nuevos Protocolos
            if data.get('dropbear'): msg += ICON_BEAR + " <b>Dropbear:</b> <code>" + str(data.get('dropbear')) + "</code>\n"
            if data.get('badvpn'): msg += ICON_PHONE + " <b>BadVPN:</b> <code>7300</code> (Soporte Juegos/Llamadas)\n"
    
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
            error_detail = res.stdout.strip() + "\n" + res.stderr.strip()
            if not error_detail.strip(): error_detail = "Error desconocido (Exit Code: " + str(res.returncode) + ")"
            
            if "Ya existe" in error_detail:
                error_msg = ICON_X + " <b>ESE USUARIO YA ESTÁ EN USO</b>"
            else:
                safe_detail = html_lib.escape(error_detail[-300:]) # Ultimos 300 chars
                error_msg = ICON_X + " <b>FALLO AL CREAR:</b>\n<pre>" + safe_detail + "</pre>"
                
            try:
                bot.edit_message_text(error_msg, message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML')
            except:
                bot.send_message(message.chat.id, error_msg, parse_mode='HTML')
            time.sleep(4)
            main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
            
    except Exception as e:
        import traceback
        trace = traceback.format_exc()
        bot.send_message(message.chat.id, f"❌ <b>Error Interno del Bot:</b>\n<pre>{html_lib.escape(str(e))}</pre>", parse_mode='HTML')
        print(trace) # Imprimir al log del sistema para debug
        time.sleep(3)
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def cleanup_expired():
    data = load_data()
    now = datetime.now().strftime("%Y-%m-%d")
    to_del = []
    
    # Zivpn cleanup
    for pwd, exp in data.get('zivpn_users', {}).items():
        if exp < now:
            subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'gestionar_zivpn_pass', 'del', pwd])
            to_del.append(pwd)
    
    if to_del:
        for p in to_del: del data['zivpn_users'][p]
        save_data(data)

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

    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

# --- ASYNC INSTALLERS CON LOGS ---

def update_log_view(chat_id, msg_id, log_file, callback_name):
    content = "Iniciando..."
    if os.path.exists(log_file):
        # Leer ultimas 10 lineas para no saturar
        try: content = subprocess.check_output(['tail', '-n', '10', log_file]).decode('utf-8', errors='ignore')
        except: content = "Leyendo log..."
    
    safe_content = html_lib.escape(content)
    text = f"📜 <b>LOG INSTALACIÓN:</b>\n<pre>{safe_content}</pre>"
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("🔄 Actualizar", callback_data=callback_name))
    try: bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    except: pass

# Limpiando definicion cortada de badvpn

def install_badvpn_thread(chat_id, msg_id):
    log_file = "/tmp/badvpn_install.log"
    with open(log_file, 'w') as f: f.write("Iniciando instalacion BadVPN...\n")
    
    # Redirigir stdout y stderr al log
    cmd = f"bash {os.path.join(PROJECT_DIR, 'ssh_manager.sh')} instalar_badvpn >> {log_file} 2>&1"
    os.system(cmd)
    
    if os.system("systemctl is-active badvpn > /dev/null") == 0:
        d = load_data(); d['badvpn'] = True; save_data(d)
        # Editamos el mensaje de progreso para mostrar exito
        try: bot.edit_message_text("✅ <b>BadVPN Instalado Correctamente!</b>", chat_id, msg_id, parse_mode='HTML')
        except: bot.send_message(chat_id, "✅ <b>BadVPN Instalado Correctamente!</b>", parse_mode='HTML')
    else:
        # Editamos para mostrar error
        try: bot.edit_message_text("❌ <b>Error al instalar BadVPN.</b> Revisa el log.", chat_id, msg_id, parse_mode='HTML')
        except: bot.send_message(chat_id, "❌ <b>Error al instalar BadVPN.</b> Revisa el log.", parse_mode='HTML')
    
    time.sleep(3)
    # Volvemos al menu principal usando el mismo ID para mantener limpieza
    main_menu(chat_id, msg_id)

def run_dropbear(message):
    delete_user_msg(message)
    port = message.text.strip()
    msg = bot.send_message(message.chat.id, "⏳ Instalando Dropbear...", parse_mode='HTML')
    
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'instalar_dropbear', port], capture_output=True, text=True)
    
    if "DROPBEAR_SUCCESS" in res.stdout:
        d = load_data(); d['dropbear'] = port; save_data(d)
        bot.edit_message_text(f"✅ <b>Dropbear instalado en puerto {port}</b>", message.chat.id, msg.message_id, parse_mode='HTML')
    else: 
        bot.edit_message_text("❌ <b>Error al instalar Dropbear</b>", message.chat.id, msg.message_id, parse_mode='HTML')
    
    time.sleep(3)
    try: bot.delete_message(message.chat.id, msg.message_id)
    except: pass
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

if __name__ == "__main__":
    while True:
        try: bot.infinity_polling(timeout=50)
        except Exception: time.sleep(10)
EOF

# Inyectar Variables Dinámicas de forma segura
# Usamos @ como delimitador ya que es poco probable que esté en el TOKEN o RUTA
sed -i "s@CONF_TOKEN@$BOT_TOKEN@g" depwise_bot.py
sed -i "s@CONF_ADMIN@$ADMIN_ID@g" depwise_bot.py
sed -i "s@CONF_DIR@$PROJECT_DIR@g" depwise_bot.py

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
echo -e "       INSTALACION V6.5 COMPLETADA 💎"
echo -e "=================================================="
echo -e "IP Estatica y Markdown activados con exito.${NC}"
