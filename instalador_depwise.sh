#!/bin/bash
set -euo pipefail

# =========================================================
# INSTALADOR UNIVERSAL V6.7: BOT TELEGRAM DEPWISE SSH 💎
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
echo -e "       CONFIGURACION BOT DEPWISE V6.7"
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
chmod 600 "$ENV_FILE"

log_info "Instalando dependencias (Core + Build Tools)..."
log_info "Instalando dependencias (Core + Build Tools)..."
apt update && apt install -y python3 python3-pip curl python3-requests file net-tools lsof cmake make gcc g++ git jq
pip3 install pytelegrambotapi --break-system-packages --upgrade 2>/dev/null || pip3 install pytelegrambotapi --upgrade
# Cargar modulo owner para iptables
modprobe xt_owner 2>/dev/null || true

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
    local LIMIT_CONN=$4
    local LIMIT_GB=$5
    
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
        # APLICAR LIMITES
        # 1. Max Logins (limits.conf)
        if [ ! -z "$LIMIT_CONN" ]; then
            echo "$USER hard maxlogins $LIMIT_CONN" >> /etc/security/limits.conf
        fi
        
        # 2. Quota GB (iptables owner match)
        if [ ! -z "$LIMIT_GB" ]; then
            # Regla para contar trafico de salida (Descarga del cliente)
            # Primero borramos si existe basura
            iptables -D OUTPUT -m owner --uid-owner "$USER" -j ACCEPT 2>/dev/null || true
            iptables -I OUTPUT -m owner --uid-owner "$USER" -j ACCEPT
            
            # Guardamos el limite en un archivo para referencia futura
            mkdir -p /etc/ssh_limits
            echo "$LIMIT_GB" > "/etc/ssh_limits/$USER.limit"
        fi
        
        echo "SUCCESS: $USER|$PASS|$EXP_DATE"
    else
        echo "ERROR: Fallo desconocido al verificar usuario creado"
    fi
    
    # Reactivar strict mode
    set -e
}
eliminar_user() {
    local USER=$1
    if id "$USER" &>/dev/null; then 
        userdel -f -r "$USER"
        # Limpiar Limites
        sed -i "/^$USER hard maxlogins/d" /etc/security/limits.conf
        iptables -D OUTPUT -m owner --uid-owner "$USER" -j ACCEPT 2>/dev/null || true
        rm -f "/etc/ssh_limits/$USER.limit"
        echo "SUCCESS"
    else 
        echo "ERROR"
    fi
}
check_consumo() {
    # Evitar crash por set -e
    set +e
    local USER=$1
    
    # Obtener UID numerico
    # Obtener UID numerico
    # FIX: Renombrar variable local UID -> USER_ID (UID es readonly en Bash)
    local USER_ID=$(id -u "$USER" 2>/dev/null)
    if [ -z "$USER_ID" ]; then echo "0|Infinito"; set -e; return; fi
    
    # ESTRATEGIA: Bash Puro con RegEx "Fin de Linea" (Fail-Safe)
    # Tu captura muestra: "... owner UID match 1002"
    # El UID esta AL FINAL. Los paquetes (colision) estan AL PRINCIPIO.
    # Buscamos: palabra "owner" ...cualquier cosa... y luego UID o USER al final.
    # Regex: owner.* (UID|USER) [espacios opcionales] final
    
    local BYTES=$(iptables -nvx -L OUTPUT | grep -E "owner.*\b($USER_ID|$USER)\s*$" | awk '{print $2}' | head -n 1 || true)
    
    # Si falla o vacio es 0
    if [[ -z "$BYTES" || ! "$BYTES" =~ ^[0-9]+$ ]]; then 
        BYTES="0"
    fi
    
    # INTENTO 2: Fallback a iptables-save si el anterior fallo (0)
    if [ "$BYTES" == "0" ]; then
         local RAW=$(iptables-save -c | grep -E "owner.*$USER_ID\b" || true)
         if [[ "$RAW" == *":"* ]]; then
             # Format [pkts:bytes]
             BYTES=$(echo "$RAW" | awk -F':' '{print $2}' | awk -F']' '{print $1}' | head -n 1)
         fi
    fi
    
    # Convertir a GB
    if [ -z "$BYTES" ]; then BYTES="0"; fi
    local GB=$(awk "BEGIN {printf \"%.6f\", $BYTES/1024/1024/1024}")
    
    # Leer Limite
    local LIMIT="Infinito"
    if [ -f "/etc/ssh_limits/$USER.limit" ]; then
        LIMIT=$(cat "/etc/ssh_limits/$USER.limit")
    fi
    
    # Debug flag si sigue siendo 0 y hay proceso
    local DEBUG=""
    if [ "$BYTES" == "0" ] && ps -u "$USER" &>/dev/null; then
         DEBUG=" (Proc: Active)"
    fi
    
    echo "$GB|$LIMIT$DEBUG"
    set -e
}
reset_consumo() {
    local USER=$1
    iptables -Z OUTPUT
    # Nota: iptables -Z resetea TODO o Spec. Si usamos -L con usuario no resetea solo ese counter facilmente
    # Workaround: Recrear regla
    iptables -D OUTPUT -m owner --uid-owner "$USER" -j ACCEPT 2>/dev/null
    iptables -I OUTPUT -m owner --uid-owner "$USER" -j ACCEPT
    iptables -I OUTPUT -m owner --uid-owner "$USER" -j ACCEPT
    echo "RESET_OK"
}

sync_iptables() {
    # Asegurar que todos los usuarios con limite definido tengan su regla iptables
    # Esto corrige reglas perdidas por reinicio o usuarios creados antes del parche
    
    mkdir -p /etc/ssh_limits
    for f in /etc/ssh_limits/*.limit; do
        if [ ! -f "$f" ]; then continue; fi
        
        local USER=$(basename "$f" .limit)
        local UID=$(id -u "$USER" 2>/dev/null)
        
        if [ -z "$UID" ]; then
            # Usuario ya no existe en sistema, borrar limite
            rm -f "$f"
            continue
        fi
        
        # Verificar si existe regla con grep flexible
        if ! iptables -S OUTPUT | grep -qE "owner (UID match|--uid-owner) $UID"; then
            # No existe, agregar
            iptables -I OUTPUT -m owner --uid-owner "$USER" -j ACCEPT
        fi
    done
}

check_and_kill_excess() {
    # Iterar sobre usuarios que tienen limite en limits.conf
    # Formato limits.conf: usuario hard maxlogins N
    if [ ! -f /etc/security/limits.conf ]; then return; fi
    
    grep "hard maxlogins" /etc/security/limits.conf | while read line; do
        # Limpiar linea
        if [[ "$line" == \#* ]]; then continue; fi
        
        USER=$(echo "$line" | awk '{print $1}')
        LIMIT=$(echo "$line" | awk '{print $4}')
        
        if [ -z "$USER" ] || [ -z "$LIMIT" ]; then continue; fi
        
        # Contar procesos SSHD y Dropbear del usuario
        # Usamos pgrep -u usuario y filtramos por nombre exacto o CMD
        # Dropbear suele correr como root pero forkear como usuario? No siempre.
        # Mejor usar ps aux.
        
        # PIDs de este usuario que sean sshd o dropbear
        PIDS=$(ps -u "$USER" -o pid,comm | grep -E "sshd|dropbear" | awk '{print $1}' | sort -n || true)
        
        # Contar lineas
        COUNT=$(echo "$PIDS" | wc -w)
        
        if [ "$COUNT" -gt "$LIMIT" ]; then
            # Calcular cuantos sobran
            EXCESS=$((COUNT - LIMIT))
            
            # Matar los mas nuevos (PIDs mas altos, que estan al final por sort -n)
            # tac invierte, head coge los primeros
            
            TO_KILL=$(echo "$PIDS" | tr ' ' '\n' | tac | head -n "$EXCESS")
            
            for pid in $TO_KILL; do
                kill -9 "$pid"
            done
            # echo "Killed $EXCESS proc for $USER" # Silencioso para cron/loop
        fi
    done
}
listar_users() {
    echo "USERS_LIST:"
    cut -d: -f1,7 /etc/passwd | grep "/bin/bash" | cut -d: -f1 | while read user; do
        exp=$(LC_ALL=C chage -l "$user" | grep "Account expires" | cut -d: -f2)
        if [[ "$exp" != *"never"* ]]; then echo "- $user (Vence:$exp)"; fi
    done
}
contar_conexiones() {
    echo "ONLINE_LIST:"
    ps aux | grep sshd | grep -v root | grep -v grep | awk '{print $1}' | sort | uniq -c | while read count user; do
        echo "- $user: $count conectado(s)"
    done
}

modificar_password() {
    local USER=$1
    local PASS=$2
    if [ -z "$USER" ] || [ -z "$PASS" ]; then echo "ERROR: Args missing"; return 1; fi
    
    echo "$USER:$PASS" | chpasswd
    if [ $? -eq 0 ]; then echo "PASS_UPDATED"; else echo "ERROR"; fi
}

renovar_user() {
   local USER=$1
   local DAYS=$2
   if [ -z "$USER" ] || [ -z "$DAYS" ]; then echo "ERROR: Args missing"; return 1; fi
   
   local EXP_DATE=$(date -d "+$DAYS days" +%Y-%m-%d)
   usermod -e "$EXP_DATE" "$USER"
   local RET=$?
   
   # FIX: Desbloquear cuenta y resetear consumo al renovar
   # Importante para usuarios bloqueados por limite de datos
   passwd -u "$USER" 2>/dev/null
   iptables -D OUTPUT -m owner --uid-owner "$USER" -j ACCEPT 2>/dev/null || true
   iptables -I OUTPUT -m owner --uid-owner "$USER" -j ACCEPT
   
   if [ $RET -eq 0 ]; then echo "USER_RENEWED|$EXP_DATE"; else echo "ERROR"; fi
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
    
    # Lista de Miras (Mirrors) - ACTUALIZADO CON ENLACES PROVISTOS POR USUARIO (COMMIT: 928bb1af...)
    declare -a MIRRORS=(
        "https://raw.githubusercontent.com/Depwisescript/PROXY-DT/928bb1af4211b874361bc65c210189a5922ccaa8/DT%201.2.3/x86/proxy"
        "https://raw.githubusercontent.com/Depwisescript/PROXY-DT/928bb1af4211b874361bc65c210189a5922ccaa8/DT%201.2.3/proxydt"
    )

    # Si es ARM, usar el binario arm64 específico del commit provisto
    if [[ "$ARCH" == "aarch64" || "$ARCH" == "arm"* ]]; then
        MIRRORS=("https://raw.githubusercontent.com/Depwisescript/PROXY-DT/928bb1af4211b874361bc65c210189a5922ccaa8/DT%201.2.3/arm64/proxy" "${MIRRORS[@]}")
    fi

    # Check existing binary (DESACTIVADO PARA FORZAR ACTUALIZACIÓN)
    # if [ -f "/usr/bin/proxydt" ] && [ -x "/usr/bin/proxydt" ]; then
    #     echo "Binario detectado. Saltando descarga..." >> /tmp/proxydt_install.log
    #     echo "PROXYDT_SUCCESS|Existente"
    #     rm -f /tmp/proxydt_install.log /tmp/libssl1.1.deb
    #     return 0
    # fi

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

    # Verificar si el puerto ya está en uso (lsof + ss para redundancia)
    if lsof -n -P -i :$PORT -sTCP:LISTEN -t >/dev/null || ss -lptn "sport = :$PORT" | grep -q ":$PORT"; then
        echo "ERROR: El puerto $PORT ya está ocupado."
        return 1
    fi

    echo "[Unit]" > "$SERVICE_FILE"
    echo "Description=ProxyDT (Cracked) on port $PORT" >> "$SERVICE_FILE"
    echo "After=network.target" >> "$SERVICE_FILE"
    echo "[Service]" >> "$SERVICE_FILE"
    echo "Type=simple" >> "$SERVICE_FILE"
    # Kill cualquier proceso en el puerto antes de iniciar para evitar conflictos fantasma
    echo "ExecStartPre=/bin/sh -c 'fuser -k -n tcp $PORT || true'" >> "$SERVICE_FILE"
    # Intentar bind a todas las interfaces usando :$PORT (Go standard)
    echo "ExecStart=/usr/bin/proxydt --port $PORT --response SSHTFREE" >> "$SERVICE_FILE"
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
    
    if [ -f "/usr/local/bin/zivpn" ] && [ -x "/usr/local/bin/zivpn" ]; then
         echo "Binario Zivpn detectado. Saltando descarga." >> /tmp/zivpn_install.log
    else
         curl -L -s -f -o /usr/local/bin/zivpn "$BIN_URL"
         chmod +x /usr/local/bin/zivpn
    fi
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
    rm -f /tmp/zivpn_install.log
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

verificar_zivpn_user() {
    local PASS=$1
    # Buscamos en el log de zivpn las ultimas 50 lineas
    # Buscamos algo que indique actividad. Como zivpn no loguea claro "connect",
    # buscamos la IP asociada o errores de auth si fuera el caso.
    # NOTA: Sin acceso al formato exacto de logs de zivpn binario, asumimos busqueda simple.
    
    # Intento 1: Buscar ocurrencia literal del pass (Raro que salga en logs por seguridad)
    # Intento 2: Buscar sesiones activas con 'ss' como backup
    
    # Metodo Hibrido:
    # Si hay conexion activa en SS, es lo mas seguro.
    # Pero no podemos saber cual pass es cual.
    
    # Plan B (Logs): journalctl
    if [ -z "$PASS" ]; then echo "ERROR: Pass vacio"; return 1; fi
    
    # Buscamos ultimas lineas donde aparezca algo relevante
    local LOGS=$(journalctl -u zivpn -n 100 --no-pager | grep -i "server" | tail -n 5)
    
    # Como el binario es cerrado, retornaremos las ultimas lineas de actividad general del servidor
    # para que el admin deduzca.
    
    echo "ACTIVITY_REPORT"
    echo "$LOGS"
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
    # Definir variables de color y rutas
    local C_BOLD='\033[1m'
    local C_PURPLE='\033[0;35m'
    local C_RESET='\033[0m'
    local C_YELLOW='\033[0;33m'
    local C_GREEN='\033[0;32m'
    local C_RED='\033[0;31m'
    local BADVPN_BUILD_DIR="/tmp/badvpn_build"
    local BADVPN_SERVICE_FILE="/etc/systemd/system/badvpn.service"

    export TERM=xterm
    echo -e "${C_BOLD}${C_PURPLE}--- 🚀 Installing badvpn (udpgw) ---${C_RESET}"
    
    # Detener servicio previo si existe para asegurar instalacion limpia
    if [ -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ Cleaning previous installation...${C_RESET}"
        systemctl stop badvpn.service 2>/dev/null || true
        systemctl disable badvpn.service 2>/dev/null || true
        rm -f "$BADVPN_SERVICE_FILE"
    fi
    
    # Firewall (Simulado)
    if command -v iptables &> /dev/null; then
        iptables -I INPUT -p udp --dport 7300 -j ACCEPT 2>/dev/null || true
    fi

    echo -e "\n${C_GREEN}🔄 Updating package lists...${C_RESET}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    echo -e "\n${C_GREEN}📦 Installing all required packages...${C_RESET}"
    apt-get install -y cmake g++ make screen git build-essential libssl-dev libnspr4-dev libnss3-dev pkg-config
    
    if [ -f "/usr/bin/badvpn-udpgw" ]; then
        echo -e "${C_GREEN}✅ Binario badvpn detectado. Saltando compilacion.${C_RESET}"
    else
        echo -e "\n${C_GREEN}📥 Cloning badvpn from github...${C_RESET}"
        rm -rf "$BADVPN_BUILD_DIR"
        git clone https://github.com/ambrop72/badvpn.git "$BADVPN_BUILD_DIR"
        
        cd "$BADVPN_BUILD_DIR" || { echo -e "${C_RED}❌ Failed to change directory to build folder.${C_RESET}"; return; }
        echo -e "\n${C_GREEN}⚙️ Running CMake...${C_RESET}"
        cmake . || { echo -e "${C_RED}❌ CMake configuration failed.${C_RESET}"; rm -rf "$BADVPN_BUILD_DIR"; return; }
        echo -e "\n${C_GREEN}🛠️ Compiling source...${C_RESET}"
        make || { echo -e "${C_RED}❌ Compilation (make) failed.${C_RESET}"; rm -rf "$BADVPN_BUILD_DIR"; return; }
        
        local badvpn_binary
        badvpn_binary=$(find "$BADVPN_BUILD_DIR" -name "badvpn-udpgw" -type f | head -n 1)
        if [[ -z "$badvpn_binary" || ! -f "$badvpn_binary" ]]; then
            echo -e "${C_RED}❌ ERROR: Could not find the compiled 'badvpn-udpgw' binary after compilation.${C_RESET}"
            rm -rf "$BADVPN_BUILD_DIR"
            return
        fi
        echo -e "${C_GREEN}ℹ️ Found binary at: $badvpn_binary${C_RESET}"
        
        # Mover a binario del sistema para persistencia
        cp "$badvpn_binary" /usr/bin/badvpn-udpgw
        chmod +x /usr/bin/badvpn-udpgw
    fi
    
    echo -e "\n${C_GREEN}📝 Creating systemd service file...${C_RESET}"
    cat > "$BADVPN_SERVICE_FILE" <<-EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 1000 --max-connections-for-client 8
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    echo -e "\n${C_GREEN}▶️ Enabling and starting badvpn service...${C_RESET}"
    systemctl daemon-reload
    systemctl enable badvpn.service
    systemctl start badvpn.service
    sleep 2
    if systemctl is-active --quiet badvpn; then
        echo -e "\n${C_GREEN}✅ SUCCESS: badvpn (udpgw) is installed and active on port 7300.${C_RESET}"
    else
        echo -e "\n${C_RED}❌ ERROR: badvpn service failed to start.${C_RESET}"
        echo -e "${C_YELLOW}ℹ️ Displaying last 15 lines of the service log for diagnostics:${C_RESET}"
        journalctl -u badvpn.service -n 15 --no-pager
    fi
    
    # Limpieza
    rm -rf "$BADVPN_BUILD_DIR"
}

eliminar_badvpn() {
    local C_BOLD='\033[1m'
    local C_PURPLE='\033[0;35m'
    local C_RESET='\033[0m'
    local C_YELLOW='\033[0;33m'
    local C_GREEN='\033[0;32m'
    local BADVPN_SERVICE_FILE="/etc/systemd/system/badvpn.service"

    echo -e "\n${C_BOLD}${C_PURPLE}--- 🗑️ Uninstalling badvpn (udpgw) ---${C_RESET}"
    if [ ! -f "$BADVPN_SERVICE_FILE" ]; then
        echo -e "${C_YELLOW}ℹ️ badvpn is not installed, skipping.${C_RESET}"
        return
    fi
    echo -e "${C_GREEN}🛑 Stopping and disabling badvpn service...${C_RESET}"
    systemctl stop badvpn.service >/dev/null 2>&1
    systemctl disable badvpn.service >/dev/null 2>&1
    echo -e "${C_GREEN}🗑️ Removing systemd service file...${C_RESET}"
    rm -f "$BADVPN_SERVICE_FILE"
    rm -f /usr/bin/badvpn-udpgw
    systemctl daemon-reload
    echo -e "${C_GREEN}✅ badvpn has been uninstalled successfully.${C_RESET}"
}
ENDFUNC

# --- BLOQUE STUNNEL REMOVIDO POR SOLICITUD ---


# --- BLOQUE DROPBEAR ---
cat << 'ENDFUNC' >> ssh_manager.sh
instalar_dropbear() {
    local PORT=$1
    if [ -z "$PORT" ]; then echo "ERROR: Falta puerto"; return 1; fi
    
    # Instalar Paquete
    apt-get update -y > /dev/null 2>&1
    apt-get install dropbear -y > /dev/null 2>&1
    
    # Validar puerto
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null; then 
        echo "ERROR: Puerto $PORT ocupado"
        return 1
    fi

    # Asegurar directorio y keys
    mkdir -p /etc/dropbear
    if [ ! -f /etc/dropbear/dropbear_rsa_host_key ]; then
        dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
    fi
    if [ ! -f /etc/dropbear/dropbear_ecdsa_host_key ]; then
        dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
    fi

    # Detener servicio default que instala apt
    systemctl stop dropbear >/dev/null 2>&1 || true
    systemctl disable dropbear >/dev/null 2>&1 || true
    
    # Crear servicio custom (evita conflicto con actualizaciones)
    local SVC_FILE="/etc/systemd/system/dropbear_custom.service"
    
    cat <<EOF > "$SVC_FILE"
[Unit]
Description=Dropbear Custom SSH
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/dropbear -F -p $PORT -K 60 -r /etc/dropbear/dropbear_rsa_host_key -r /etc/dropbear/dropbear_ecdsa_host_key
KillMode=process
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable dropbear_custom
    systemctl restart dropbear_custom
    
    sleep 2
    if systemctl is-active dropbear_custom > /dev/null 2>&1; then 
        echo "DROPBEAR_SUCCESS|$PORT"
    else 
        echo "ERROR: Fallo arranque servicio. Logs:"
        journalctl -u dropbear_custom -n 10 --no-pager
    fi
}

eliminar_dropbear() {
    systemctl stop dropbear > /dev/null 2>&1
    apt-get purge dropbear -y > /dev/null 2>&1
    rm -f /etc/dropbear
    echo "DROPBEAR_REMOVED"
}
ENDFUNC

# --- BLOQUE FALCON PROXY ---
cat << 'ENDFUNC' >> ssh_manager.sh
instalar_falcon_proxy() {
    local PORT=$1
    if [ -z "$PORT" ]; then echo "ERROR: Falta puerto"; return 1; fi

    local ARCH=$(uname -m)
    local BIN_NAME=""
    if [[ "$ARCH" == "x86_64" ]]; then BIN_NAME="falconproxy"; 
    elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then BIN_NAME="falconproxyarm";
    else echo "ERROR: Arquitectura no soportada"; return 1; fi
    
    # Intentar obtener la URL de descarga via API GitHub
    local API_URL="https://api.github.com/repos/firewallfalcons/FirewallFalcon-Manager/releases/latest"
    local DOWN_URL=""
    local VER=""
    
    if command -v jq &> /dev/null; then
        local JSON=$(curl -s "$API_URL")
        VER=$(echo "$JSON" | jq -r .tag_name)
        DOWN_URL=$(echo "$JSON" | jq -r ".assets[] | select(.name == \"$BIN_NAME\") | .browser_download_url")
    fi
    
    # Fallback si falla jq o api rate limit
    if [ -z "$DOWN_URL" ] || [ "$DOWN_URL" == "null" ]; then
        echo "ERROR: No se pudo obtener la ultima version desde GitHub."
        return 1
    fi
    
    echo "Instalando Falcon Proxy ($VER) en puerto $PORT..." > /tmp/falcon_install.log
    
    # Check existing binary
    if [ -f "/usr/local/bin/falconproxy" ]; then
        echo "Binario detectado. Reemplazando..." >> /tmp/falcon_install.log
    fi

    wget -q -O /usr/local/bin/falconproxy "$DOWN_URL"
    if [ $? -ne 0 ]; then echo "ERROR: Fallo descarga del binario"; rm -f /tmp/falcon_install.log; return 1; fi
    chmod +x /usr/local/bin/falconproxy
    
    # Config File
    echo "PORTS=\"$PORT\"" > /etc/falconproxy.conf
    echo "INSTALLED_VERSION=\"$VER\"" >> /etc/falconproxy.conf
    
    # Servicio Systemd
    cat <<EOF > /etc/systemd/system/falconproxy.service
[Unit]
Description=Falcon Proxy ($VER)
After=network.target

[Service]
User=root
Type=simple
ExecStart=/usr/local/bin/falconproxy -p $PORT
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable falconproxy
    systemctl restart falconproxy
    
    sleep 2
    if systemctl is-active --quiet falconproxy; then
        echo "FALCON_SUCCESS|$VER|$PORT"
    else
        echo "ERROR: El servicio no arranco. Ver logs."
    fi
    rm -f /tmp/falcon_install.log
}

eliminar_falcon_proxy() {
    systemctl stop falconproxy >/dev/null 2>&1
    systemctl disable falconproxy >/dev/null 2>&1
    rm -f /etc/systemd/system/falconproxy.service
    rm -f /usr/local/bin/falconproxy
    rm -f /etc/falconproxy.conf
    systemctl daemon-reload
    echo "FALCON_REMOVED"
}
ENDFUNC

# --- SSL TUNNEL (HAPROXY) ---
cat << 'ENDFUNC' >> ssh_manager.sh

check_and_free_ports() {
    local PORT=$1
    if lsof -n -P -i :$PORT -sTCP:LISTEN -t >/dev/null; then
        fuser -k -n tcp $PORT || true
        sleep 1
    fi
}

check_and_open_firewall_port() {
    local PORT=$1
    if ! iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null; then
        iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
        netfilter-persistent save 2>/dev/null || true
    fi
}

instalar_ssl_tunnel() {
    local PORT=$1
    local SSL_CERT_FILE="/etc/haproxy/haproxy.pem"
    local HAPROXY_CONFIG="/etc/haproxy/haproxy.cfg"

    if ! command -v haproxy &> /dev/null; then
        apt-get update && apt-get install -y haproxy || { echo "ERROR: Falló al instalar HAProxy."; return 1; }
    fi

    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo "ERROR: Puerto inválido."
        return 1
    fi
    
    check_and_free_ports "$PORT"
    check_and_open_firewall_port "$PORT"

    # Certificado Generico
    if [ ! -f "$SSL_CERT_FILE" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
            -keyout "$SSL_CERT_FILE" -out "$SSL_CERT_FILE" \
            -subj "/CN=ssl-tunnel" \
            >/dev/null 2>&1
    fi

    # Config
    cat > "$HAPROXY_CONFIG" <<-EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000
frontend ssh_ssl_in
    bind *:$PORT ssl crt $SSL_CERT_FILE
    mode tcp
    default_backend ssh_backend
backend ssh_backend
    mode tcp
    server ssh_server 127.0.0.1:22
EOF

    systemctl daemon-reload
    systemctl restart haproxy
    sleep 2
    if systemctl is-active --quiet haproxy; then
        echo "SSL_TUNNEL_SUCCESS|$PORT"
    else
        echo "ERROR: HAProxy no arrancó. Ver 'systemctl status haproxy'."
    fi
}

eliminar_ssl_tunnel() {
    systemctl stop haproxy >/dev/null 2>&1
    # Restaurar config default limpia
    cat > "/etc/haproxy/haproxy.cfg" <<-EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
defaults
    log     global
EOF
    rm -f "/etc/haproxy/haproxy.pem"
    echo "SSL_TUNNEL_REMOVED"
}
ENDFUNC

# --- MONITOR DE RECURSOS ---

# --- OPTIMIZACIONES ---
cat << 'ENDFUNC' >> ssh_manager.sh

optimizar_servidor() {
    # Verificar kernel 4.9+
    kernel_version=$(uname -r | cut -d- -f1)
    major_version=$(echo $kernel_version | cut -d. -f1)
    minor_version=$(echo $kernel_version | cut -d. -f2)

    if [ "$major_version" -lt 4 ] || ([ "$major_version" -eq 4 ] && [ "$minor_version" -lt 9 ]); then
        echo "ERROR_KERNEL_OLD"
        return 1
    fi

    echo "Respaldo sysctl.conf..."
    cp /etc/sysctl.conf /etc/sysctl.conf.bak

    # Limpiar configuraciones previas de BBR
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
    sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    
    echo "Aplicando BBR y Optimizaciones..."
    cat <<EOF >> /etc/sysctl.conf
fs.file-max = 1000000
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
EOF

    sysctl -p
    echo "OPTIMIZED_BBR_ON"
}

desactivar_optimizacion() {
    echo "Restaurando sysctl.conf..."
    # Si existe backup, restaurar
    if [ -f /etc/sysctl.conf.bak ]; then
        mv /etc/sysctl.conf.bak /etc/sysctl.conf
    else
        # Si no, limpiar manual
        sed -i '/net.core.default_qdisc=fq/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf
        sed -i '/fs.file-max = 1000000/d' /etc/sysctl.conf
        sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
        sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    fi
    sysctl -p
    echo "OPTIMIZED_BBR_OFF"
}
ENDFUNC

# --- MONITOR DE RECURSOS ---
cat << 'ENDFUNC' >> ssh_manager.sh

obtener_recursos() {
    # CPU: Usamos vmstat para mayor compatibilidad o top fallback
    local CPU=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')
    if [ -z "$CPU" ]; then CPU="0"; fi
    
    # RAM
    local RAM_U=$(free -m | awk '/Mem:/ {print $3}')
    local RAM_T=$(free -m | awk '/Mem:/ {print $2}')
    
    # DISK
    local DISK_U=$(df -h / | awk 'NR==2 {print $3}')
    local DISK_T=$(df -h / | awk 'NR==2 {print $2}')
    local DISK_P=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    
    # UPTIME
    local UPT=$(uptime -p | sed 's/up //')
    
    echo "$CPU|$RAM_U|$RAM_T|$DISK_U|$DISK_T|$DISK_P|$UPT"
}
ENDFUNC

# --- CASE PRINCIPAL ---
cat << 'ENDFUNC' >> ssh_manager.sh
case "$1" in
    crear_user) crear_user "$2" "$3" "$4" "$5" "$6" ;;
    eliminar_user) eliminar_user "$2" ;;
    listar_users) listar_users ;;
    check_consumo) check_consumo "$2" ;;
    reset_consumo) reset_consumo "$2" ;;
    sync_iptables) sync_iptables ;;
    check_and_kill_excess) check_and_kill_excess ;;
    contar_conexiones) contar_conexiones ;;
    modificar_password) modificar_password "$2" "$3" ;;
    renovar_user) renovar_user "$2" "$3" ;;
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
    verificar_zivpn_user) verificar_zivpn_user "$2" ;;
    monitor_zivpn) monitor_zivpn ;;
    eliminar_zivpn) eliminar_zivpn ;;
    instalar_badvpn) instalar_badvpn ;;
    eliminar_badvpn) eliminar_badvpn ;;
    instalar_dropbear) instalar_dropbear "$2" ;;
    eliminar_dropbear) eliminar_dropbear ;;
    instalar_falcon_proxy) instalar_falcon_proxy "$2" ;;
    eliminar_falcon_proxy) eliminar_falcon_proxy ;;
    instalar_ssl_tunnel) instalar_ssl_tunnel "$2" ;;
    eliminar_ssl_tunnel) eliminar_ssl_tunnel ;;
    optimizar_servidor) optimizar_servidor ;;
    desactivar_optimizacion) desactivar_optimizacion ;;
    obtener_recursos) obtener_recursos ;;
esac
ENDFUNC
chmod +x ssh_manager.sh


# ---------------------------------------------------------
# 2. Bot de Python V6.7 (PRO CUSTOM)
# ---------------------------------------------------------
log_info "Creando bot V6.7 (Static IP + Zivpn Support)..."
cat << 'EOF' > depwise_bot.py
# -*- coding: utf-8 -*-
import telebot
from telebot import types
import subprocess
import json
import zipfile
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
        if 'cloudfront_domain' not in data: data['cloudfront_domain'] = ""
        # Nuevos protocolos
        if 'badvpn' not in data: data['badvpn'] = False
        if 'dropbear' not in data: data['dropbear'] = 0
        if 'ssh_time_users' not in data: data['ssh_time_users'] = {}
        
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
            "cloudflare_domain": "",
            "cloudfront_domain": ""
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
TEMP_SSH_CREATION = {}

def is_admin(chat_id):
    if chat_id == SUPER_ADMIN: return True
    return str(chat_id) in load_data().get('admins', {})

def delete_user_msg(message):
    try: bot.delete_message(message.chat.id, message.message_id)
    except: pass

def delete_later(chat_id, message_id, delay=5):
    def _run():
        time.sleep(delay)
        try: bot.delete_message(chat_id, message_id)
        except: pass
    threading.Thread(target=_run).start()

def render_progress_bar(percent, length=10):
    percent = float(percent)
    fill = int(length * percent / 100)
    
    # Emojis futuristas segun nivel
    if percent < 50: status = "🟢"
    elif percent < 80: status = "🟡"
    else: status = "🔴"
    
    bar = "■" * fill + "□" * (length - fill)
    return f"[{bar}] {status}"

def main_menu(chat_id, message_id=None):
    data = load_data()
    is_sa = (chat_id == SUPER_ADMIN)
    is_adm = is_admin(chat_id)
    
    if not data.get('public_access', True) and not is_adm:
        text = "⛔ <b>ACCESO DENEGADO</b>\n\n"
        text += "Este Bot es privado y exclusivo para miembros autorizados.\n\n"
        text += "🚀 <b>¿QUIERES ACCESO O TENER TU PROPIO BOT?</b>\n"
        text += "Ofrecemos las mejores herramientas VPN y Scripts del mercado.\n\n"
        text += "✅ Soporte 24/7\n✅ Actualizaciones Constantes\n✅ Calidad Garantizada\n\n"
        text += "👤 <b>Ventas / Admin:</b> @Dan3651\n"
        text += "📢 <b>Canal Oficial:</b> @Depwise2\n\n"
        text += "<i>Contacta ahora para autorización.</i>"
        
        if message_id:
            try: bot.edit_message_text(text, chat_id, message_id, parse_mode='HTML')
            except: bot.send_message(chat_id, text, parse_mode='HTML')
        else:
            bot.send_message(chat_id, text, parse_mode='HTML')
        return

    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton(ICON_USER + " Crear SSH", callback_data="menu_crear"),
        types.InlineKeyboardButton(ICON_INFO + " Info Servidor", callback_data="menu_info")
    )
    # Boton Mis Datos para todos
    markup.add(types.InlineKeyboardButton("📊 Mis Consumos", callback_data="my_stats"))
    
    # Solo Admins y Super Admin pueden editar/eliminar
    if is_adm or is_sa:
        markup.add(
            types.InlineKeyboardButton("✏️ Editar SSH", callback_data="menu_editar"),
            types.InlineKeyboardButton(ICON_DEL + " Eliminar SSH", callback_data="menu_eliminar")
        )
    else:
         markup.add(types.InlineKeyboardButton(ICON_DEL + " Eliminar SSH", callback_data="menu_eliminar"))
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
    
    # --- MONITOR DE RECURSOS (FUTURISTA) ---
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'obtener_recursos'], capture_output=True, text=True)
    try:
        # CPU|RAM_U|RAM_T|DISK_U|DISK_T|DISK_P|UPT
        metrics = res.stdout.strip().split('|')
        cpu_p = metrics[0]
        ram_u, ram_t = metrics[1], metrics[2]
        disk_u, disk_t, disk_p = metrics[3], metrics[4], metrics[5]
        upt = metrics[6]
        
        # Calcular porcentaje RAM
        ram_p = int(int(ram_u) * 100 / int(ram_t)) if int(ram_t) > 0 else 0
        
        text = ICON_GEM + " <b>BOT TELEGRAM DEPWISE V6.7</b>\n"
        text += "<i>Panel de Control Avanzado</i>\n\n"
        
        text += f"🧠 <b>CPU:</b> {render_progress_bar(cpu_p)} <code>{cpu_p}%</code>\n"
        text += f"💾 <b>RAM:</b> {render_progress_bar(ram_p)} <code>{ram_u}MB / {ram_t}MB</code>\n"
        text += f"💽 <b>DSK:</b> {render_progress_bar(disk_p)} <code>{disk_u} / {disk_t}</code>\n"
        text += f"⏱️ <b>UPT:</b> <code>{upt}</code>\n"
        text += "----------------------------------------\n"
        
    except:
        text = ICON_GEM + " <b>BOT TELEGRAM DEPWISE V6.7</b>\n"
        text += "<i>Cargando recursos...</i>\n\n"

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
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_USER + " Eliminar SSH", callback_data="del_ssh_menu"))
        markup.add(types.InlineKeyboardButton("🛰️ Eliminar ZIVPN", callback_data="del_zivpn_menu"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_DEL + " <b>¿Qué deseas eliminar?</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "del_ssh_menu":
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
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_eliminar"))
        bot.edit_message_text(ICON_USER + " <b>ELIMINAR SSH:</b>\n\n<b>Usuarios:</b>\n" + users + "\n\nEscribe nombre:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_delete)

    elif call.data == "del_zivpn_menu":
        if not is_admin(chat_id) and chat_id != SUPER_ADMIN:
             bot.answer_callback_query(call.id, "⛔ Acceso denegado.", show_alert=True)
             return
             
        data = load_data()
        zivpn_users = data.get('zivpn_users', {})
        zivpn_owners = data.get('zivpn_owners', {})
        
        # Filtrar usuarios ZIVPN
        my_zivpn = []
        if chat_id == SUPER_ADMIN:
            my_zivpn = list(zivpn_users.keys())
        else:
            my_zivpn = [pwd for pwd in zivpn_users if zivpn_owners.get(pwd) == str(chat_id)]
            
        list_str = "\n".join(["- " + p for p in my_zivpn]) if my_zivpn else "Vacio"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_eliminar"))
        bot.edit_message_text("🛰️ <b>ELIMINAR ZIVPN:</b>\n\n<b>Passwords:</b>\n" + list_str + "\n\nEscribe el password a borrar:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_delete_zivpn_input)

    # --- MENU EDITAR ---
    elif call.data == "menu_editar":
        if not is_admin(chat_id) and chat_id != SUPER_ADMIN:
             bot.answer_callback_query(call.id, "⛔ Acceso denegado: Solo Admins.", show_alert=True)
             return
        is_sa = (chat_id == SUPER_ADMIN)
        data = load_data()
        user_list = []
        
        if is_sa:
            # Super Admin ve todos
            res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'listar_users'], capture_output=True, text=True)
            raw = res.stdout.replace("USERS_LIST:", "").strip()
            if raw and raw != "Vacio":
                for line in raw.split('\n'):
                     # line format: "- username (Vence:XXXX)"
                     try: user_list.append(line.split(' ')[1])
                     except: pass
        else:
             # Filtrar solo los del usuario actual
            owners = data.get('ssh_owners', {})
            user_list = [u for u, owner in owners.items() if str(owner) == str(chat_id)]
        
        markup = types.InlineKeyboardMarkup(row_width=2)
        if not user_list:
             markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
             bot.edit_message_text("❌ No tienes usuarios para editar.", chat_id, msg_id, reply_markup=markup)
             return

        for u in user_list:
            markup.add(types.InlineKeyboardButton(f"👤 {u}", callback_data=f"edit_sel_{u}"))
        
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text("✏️ <b>EDITAR USUARIO SSH:</b>\nSelecciona uno:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data.startswith("edit_sel_"):
        user = call.data.replace("edit_sel_", "")
        TEMP_SSH_CREATION[chat_id] = {'user': user} # Reusamos dict temporal
        
        markup = types.InlineKeyboardMarkup()
        markup.add(
            types.InlineKeyboardButton("🔑 Cambiar Contraseña", callback_data=f"edit_pass_{user}"),
            types.InlineKeyboardButton("📅 Renovar Días", callback_data=f"edit_renew_{user}")
        )
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_editar"))
        bot.edit_message_text(f"⚙️ <b>Editando:</b> <code>{user}</code>\n¿Qué deseas hacer?", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    
    elif call.data.startswith("edit_pass_"):
        user = call.data.replace("edit_pass_", "")
        # Preguntar modo password
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("🎲 Automática", callback_data=f"ep_auto_{user}"),
                   types.InlineKeyboardButton("✍️ Manual", callback_data=f"ep_man_{user}"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data=f"edit_sel_{user}"))
        bot.edit_message_text(f"🔑 <b>Cambio de Password para {user}:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data.startswith("ep_auto_"):
        user = call.data.replace("ep_auto_", "")
        new_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
        perform_edit_pass(chat_id, user, new_pass)
        
    elif call.data.startswith("ep_man_"):
        user = call.data.replace("ep_man_", "")
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data=f"edit_sel_{user}"))
        bot.edit_message_text(f"✍️ <b>Escribe el nuevo Password para {user}:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, lambda m: process_edit_pass_manual(m, user))

    elif call.data.startswith("edit_renew_"):
        user = call.data.replace("edit_renew_", "")
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data=f"edit_sel_{user}"))
        bot.edit_message_text(f"📅 <b>Renovar {user}:</b>\n¿Cuántos días quieres sumar/asignar?", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, lambda m: process_edit_renew(m, user))

    elif call.data == "menu_info":
        ip = get_public_ip()
        data = load_data()
        extra = data.get('extra_info', '')
        domain = data.get('cloudflare_domain', '')
        cfront = data.get('cloudfront_domain', '')
        
        text = ICON_INFO + " <b>DATOS DEL SERVIDOR</b>\n\n"
        text += ICON_PIN + " <b>IP Fija:</b> <code>" + ip + "</code> \n"
        
        # Mostrar dominio Cloudflare si existe
        if domain:
            text += "🌐 <b>Dominio:</b> <code>" + domain + "</code> \n"
            
        # Mostrar dominio CloudFront si existe
        if cfront:
            text += "☁️ <b>CloudFront:</b> <code>" + cfront + "</code> \n"
        
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
        # Falcon Proxy Info
        if os.path.exists("/etc/falconproxy.conf"):
            try: 
                with open("/etc/falconproxy.conf") as f: 
                    fc = f.read(); 
                    if "PORTS" in fc: 
                        fp = fc.split('PORTS="')[1].split('"')[0]
                        text += "\n🦅 <b>Falcon Proxy:</b> <code>" + fp + "</code>"
            except: pass

        # SSL Tunnel Info
        if data.get('ssl_tunnel'): text += "\n🚀 <b>SSL Tunnel:</b> <code>" + str(data.get('ssl_tunnel')) + "</code>"

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
            types.InlineKeyboardButton("🚀 SlowDNS", callback_data="menu_slowdns"),
            types.InlineKeyboardButton("🛰️ ProxyDT-Go / Websock", callback_data="menu_proxydt"),
            types.InlineKeyboardButton("📡 UDP ZIVPN", callback_data="menu_zivpn"),
            types.InlineKeyboardButton(ICON_PHONE + " BadVPN (Llamadas)", callback_data="badvpn_menu"),
            types.InlineKeyboardButton(ICON_BEAR + " Dropbear (SSH Mini)", callback_data="dropbear_menu"),
            types.InlineKeyboardButton("🦅 Falcon Proxy (WS)", callback_data="falcon_menu"),
            types.InlineKeyboardButton("🚀 SSL Tunnel (HAProxy)", callback_data="ssl_tunnel_menu"),
            types.InlineKeyboardButton("⚡ Optimizar Servidor (BBR)", callback_data="dev_optimize_menu"),
            types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
        )
        bot.edit_message_text(ICON_GEAR + " <b>GESTIÓN DE PROTOCOLOS</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "ssl_tunnel_menu":
        d = load_data()
        port = d.get('ssl_tunnel')
        st = f"INSTALADO ({port})" if port else "NO INSTALADO"
        
        markup = types.InlineKeyboardMarkup()
        if not port:
            markup.add(types.InlineKeyboardButton("Instalar SSL Tunnel", callback_data="ask_ssl_tunnel"))
        else:
            markup.add(types.InlineKeyboardButton("Desinstalar SSL Tunnel", callback_data="del_ssl_tunnel"))
            
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        bot.edit_message_text(f"🚀 <b>SSL Tunnel (HAProxy)</b>\nEstado: {st}", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "dev_optimize_menu":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("⚡ Activar TCP BBR + Opti", callback_data="op_bbr_on"))
        markup.add(types.InlineKeyboardButton("🗑️ Quitar BBR (Default)", callback_data="op_bbr_off"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        
        msg = "⚡ <b>OPTIMIZADOR DE SERVIDOR</b>\n\n"
        msg += "Esto aplicará:\n"
        msg += "• TCP BBR (Google)\n"
        msg += "• Ajustes de Sysctl (Buffers)\n"
        msg += "• Menor Latencia\n\n"
        msg += "<i>Requiere Kernel 4.9+</i>"
        
        bot.edit_message_text(msg, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "op_bbr_on":
        bot.edit_message_text("⏳ <b>Optimizando Servidor...</b>\nPor favor espera.", chat_id, msg_id, parse_mode='HTML')
        
        def _run_opt():
            res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'optimizar_servidor'], capture_output=True, text=True)
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="dev_optimize_menu"))
            
            if "OPTIMIZED_BBR_ON" in res.stdout:
                bot.edit_message_text("✅ <b>SERVIDOR OPTIMIZADO</b>\n\nSe ha activado TCP BBR y ajustado el Sysctl.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            elif "ERROR_KERNEL_OLD" in res.stdout:
                bot.edit_message_text("❌ <b>Error: Kernel Muy Viejo</b>\nNecesitas Kernel 4.9+ para usar BBR.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            else:
                bot.edit_message_text(f"⚠️ <b>Resultado Inesperado:</b>\n{res.stdout[-100:]}", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        
        threading.Thread(target=_run_opt).start()

    elif call.data == "op_bbr_off":
        bot.edit_message_text("⏳ <b>Restaurando configuración original...</b>", chat_id, msg_id, parse_mode='HTML')
        
        def _run_deopt():
            subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'desactivar_optimizacion'])
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="dev_optimize_menu"))
            bot.edit_message_text("✅ <b>BBR DESACTIVADO</b>\n\nEl servidor ha vuelto a la configuración original (Cubic).", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            
        threading.Thread(target=_run_deopt).start()

    elif call.data == "ask_ssl_tunnel":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Cancelar", callback_data="ssl_tunnel_menu"))
        bot.edit_message_text("Introduce el <b>Puerto</b> para SSL Tunnel (ej: 444):", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, run_ssl_install)

    elif call.data == "del_ssl_tunnel":
        bot.answer_callback_query(call.id, "🗑️ Eliminando...")
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_ssl_tunnel'])
        d = load_data(); 
        if 'ssl_tunnel' in d: del d['ssl_tunnel']
        save_data(d)
        save_data(d)
        sent = bot.send_message(chat_id, "✅ SSL Tunnel eliminado.")
        delete_later(chat_id, sent.message_id)
        main_menu(chat_id, msg_id)
    elif call.data == "menu_slowdns" and chat_id == SUPER_ADMIN:
        d = load_data()
        is_inst = d.get('slowdns', {}).get('key')
        st = "INSTALADO" if is_inst else "NO INSTALADO"
        markup = types.InlineKeyboardMarkup()
        if not is_inst:
            markup.add(types.InlineKeyboardButton("Instalar SlowDNS", callback_data="install_slowdns"))
        else:
            markup.add(types.InlineKeyboardButton("Info SlowDNS", callback_data="menu_info"))
            markup.add(types.InlineKeyboardButton("Eliminar SlowDNS", callback_data="remove_slowdns"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        bot.edit_message_text(f"🚀 <b>Gestión SlowDNS</b>\nEstado: {st}", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "menu_zivpn" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Instalar ZIVPN", callback_data="zivpn_install"))
        markup.add(types.InlineKeyboardButton("🔍 Verificar Actividad", callback_data="zivpn_check_menu"))
        markup.add(types.InlineKeyboardButton("Eliminar ZIVPN", callback_data="zivpn_remove"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        bot.edit_message_text(f"📡 <b>Gestión ZIVPN</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data == "zivpn_check_menu" and chat_id == SUPER_ADMIN:
        data = load_data()
        zivpn = data.get('zivpn_users', {})
        if not zivpn:
            bot.answer_callback_query(call.id, "No hay passwords creados.")
            return

        markup = types.InlineKeyboardMarkup(row_width=2)
        keys = list(zivpn.keys())
        # Mostrar botones para los primeros 8 passwords para no saturar
        for pwd in keys[:8]:
            markup.add(types.InlineKeyboardButton(f"🔑 {pwd}", callback_data=f"chk_zi_{pwd}"))
            
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_zivpn"))
        bot.edit_message_text("🔍 <b>Selecciona Password a Verificar:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    elif call.data.startswith("chk_zi_") and chat_id == SUPER_ADMIN:
        pwd = call.data.replace("chk_zi_", "")
        bot.answer_callback_query(call.id, f"🔍 Revisando logs para {pwd}...")
        
        # Ejecutar chequeo
        res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'verificar_zivpn_user', pwd], capture_output=True, text=True)
        
        log_content = "Sin datos"
        if "ACTIVITY_REPORT" in res.stdout:
            log_content = res.stdout.replace("ACTIVITY_REPORT", "").strip()
        
        if not log_content: log_content = "Sin actividad reciente en logs."
        
        safe_log = html_lib.escape(log_content)
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="zivpn_check_menu"))
        
        msg = f"🔍 <b>REPORTE DE ACTIVIDAD ({pwd})</b>\n\n"
        msg += f"<i>Últimos eventos del servidor:</i>\n<pre>{safe_log}</pre>\n\n"
        msg += "⚠️ <i>Nota: ZIVPN encripta el tráfico, el log muestra actividad general del puerto 5667.</i>"
        
        bot.edit_message_text(msg, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
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
            sent = bot.send_message(chat_id, f"❌ <b>Error al abrir ProxyDT:</b>\n<code>{html_lib.escape(err_msg)}</code>", parse_mode='HTML')
            delete_later(chat_id, sent.message_id)
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
        USER_STEPS[chat_id] = sent.message_id
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
    elif call.data == "set_cloudfront" and chat_id == SUPER_ADMIN:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_admins"))
        bot.edit_message_text("☁️ <b>Configura tu Dominio CloudFront:</b>\n\nIntroduce el dominio (ej: d1234.cloudfront.net)\nO escribe 'borrar' para eliminarlo.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_cloudfront)
    elif call.data == "admin_del":
        data = load_data(); admins = data.get('admins', {})
        text = "ADMINS:\n"
        for aid, val in admins.items(): text += "- <code>" + aid + "</code> (" + val.get('alias','-') + ")\n"
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(text + "\nID a borrar:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_admin_del)

    elif call.data == "backup_data" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "📦 Creando Backup...")
        try:
            backup_path = os.path.join(PROJECT_DIR, 'backup_bot.zip')
            param_env = os.path.join(PROJECT_DIR, '.env')
            with zipfile.ZipFile(backup_path, 'w') as zipf:
                if os.path.exists(DATA_FILE): zipf.write(DATA_FILE, arcname='bot_data.json')
                if os.path.exists(param_env): zipf.write(param_env, arcname='.env')
            
            with open(backup_path, 'rb') as f:
                bot.send_document(chat_id, f, caption=f"📦 <b>BACKUP SYSTEM</b>\n\nFecha: {datetime.now().strftime('%Y-%m-%d %H:%M')}", parse_mode='HTML')
            os.remove(backup_path)
        except Exception as e:
            bot.send_message(chat_id, f"❌ Error: {str(e)}")

# --- FALCON PROXY HANDLERS ---
    elif call.data == "falcon_menu":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("Instalar Falcon Proxy", callback_data="ask_falcon"),
                   types.InlineKeyboardButton("Desinstalar", callback_data="del_falcon"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="menu_protocols"))
        bot.edit_message_text("🦅 <b>Falcon Proxy (Websockets/Socks)</b>\nGestor de Conexiones Premium.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    elif call.data == "ask_falcon":
        markup = types.InlineKeyboardMarkup(); markup.add(types.InlineKeyboardButton("Cancelar", callback_data="falcon_menu"))
        bot.edit_message_text("Introduce el <b>Puerto</b> para Falcon Proxy:", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, run_falcon_install)

    elif call.data == "del_falcon":
        bot.answer_callback_query(call.id, "🗑️ Eliminando...")
        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_falcon_proxy'])
        sent = bot.send_message(chat_id, "✅ Falcon Proxy eliminado.")
        delete_later(chat_id, sent.message_id)
        main_menu(chat_id, msg_id)

    elif call.data == "force_cleanup" and chat_id == SUPER_ADMIN:
        bot.answer_callback_query(call.id, "🧹 Analizando usuarios...")
        count = cleanup_expired(force_report=True, chat_report=chat_id)
        count = cleanup_expired(force_report=True, chat_report=chat_id)
        if count == 0: 
            sent = bot.send_message(chat_id, "✅ <b>Limpieza Completada:</b> No se encontraron usuarios vencidos.", parse_mode='HTML')
            delete_later(chat_id, sent.message_id)
    
    elif call.data.startswith("zd_"):
        pwd = call.data.replace("zd_", "")
        process_zivpn_days_ask(call.message, pwd)
    elif call.data.startswith("zh_"):
        pwd = call.data.replace("zh_", "")
        process_zivpn_hours_ask(call.message, pwd)
    elif call.data.startswith("zm_"):
        pwd = call.data.replace("zm_", "")
        process_zivpn_mins_ask(call.message, pwd)
    
    # --- SSH INFO MANUAL/AUTO CALLBACKS ---
    elif call.data == "ssh_pass_auto":
        data = TEMP_SSH_CREATION.get(chat_id)
        if data:
            pwd = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            # Si es Super Admin, preguntar limites. Si no, crear directo.
            if chat_id == SUPER_ADMIN:
                TEMP_SSH_CREATION[chat_id]['pwd'] = pwd
                ask_ssh_limits_menu(chat_id)
            else:
                perform_ssh_creation(chat_id, data['user'], pwd, data['days'])
        else: main_menu(chat_id, msg_id)

    elif call.data == "ssh_pass_manual":
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
        bot.edit_message_text(f"✍️ <b>Escribe la contraseña para el usuario:</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
        bot.register_next_step_handler(call.message, process_ssh_manual_pass)

    elif call.data == "back_main":
        bot.clear_step_handler_by_chat_id(chat_id=chat_id)
        main_menu(chat_id, msg_id)

    elif call.data == "my_stats":
        # Mostrar consumo
        data = load_data()
        owners = data.get('ssh_owners', {})
        
        # FIX: Super Admin ve TODO, Otros solo lo suyo
        if chat_id == SUPER_ADMIN:
             my_users = list(owners.keys())
             header = "📊 <b>CONSUMO GLOBAL (SUPER ADMIN):</b>\n\n"
        else:
             my_users = [u for u, o in owners.items() if str(o) == str(chat_id)]
             header = "📊 <b>TUS CONSUMOS DE DATOS:</b>\n\n"
        
        if not my_users:
            bot.answer_callback_query(call.id, "No tienes usuarios activos.")
            return
            
        my_users.sort()
        msg = header
        for u in my_users:
            res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'check_consumo', u], capture_output=True, text=True)
            # Output: GB|LIMIT
            try:
                parts = res.stdout.strip().split('|')
                used = parts[0]
                limit = parts[1]
                msg += f"👤 <b>{u}:</b> <code>{used} GB</code> / <code>{limit} GB</code>\n"
            except:
                msg += f"👤 <b>{u}:</b> Error al leer\n"
        
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(msg, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)

    # --- DURATION TYPE HANDLERS ---
    elif call.data in ["param_days", "param_mins", "param_hours"]:
        user = TEMP_SSH_CREATION.get(chat_id, {}).get('user')
        if not user: 
            main_menu(chat_id, msg_id)
            return

        if call.data == "param_days":
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
            bot.edit_message_text(ICON_TIME + " <b>¿Días de vigencia?</b>", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            bot.register_next_step_handler(call.message, lambda m: process_ssh_days(m, user))
        elif call.data == "param_hours":
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
            bot.edit_message_text(f"⏱️ <b>¿Cuántas HORAS?</b>\nUsuario: {user}", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            bot.register_next_step_handler(call.message, lambda m: process_ssh_hours(m, user))
        else:
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
            bot.edit_message_text(f"⏱️ <b>¿Cuántos MINUTOS?</b>\nUsuario: {user}", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            bot.register_next_step_handler(call.message, lambda m: process_ssh_minutes(m, user))

    # --- HANDLERS LIMITES SUPER ADMIN ---
    elif call.data.startswith("sl_"):
        data = TEMP_SSH_CREATION.get(chat_id)
        if not data: main_menu(chat_id, msg_id); return
        
        user = data['user']
        pwd = data['pwd']
        days = data['days']
        
        if call.data == "sl_unlimited":
            perform_ssh_creation(chat_id, user, pwd, days, "", "")
        elif call.data == "sl_admin":
            perform_ssh_creation(chat_id, user, pwd, days, "30", "50")
        elif call.data == "sl_public":
            perform_ssh_creation(chat_id, user, pwd, days, "1", "10")
        elif call.data == "sl_custom":
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
            bot.edit_message_text(f"🔌 <b>Max Conexiones:</b>\nEscribe el número (ej: 5) o '0' para ilimitado.", chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
            bot.register_next_step_handler(call.message, process_custom_limit_conn)

def process_custom_limit_conn(message):
    delete_user_msg(message)
    conn = message.text.strip()
    if conn == "0": conn = ""
    
    chat_id = message.chat.id
    TEMP_SSH_CREATION[chat_id]['limit_conn'] = conn
    
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
    bot.edit_message_text(f"💾 <b>Límite de Datos:</b>\nEscribe el valor con unidad.\nEjemplos: <code>50</code> (GB), <code>500 MB</code>, <code>100 M</code>\nO escribe '0' para ilimitado.", chat_id, USER_STEPS.get(chat_id), parse_mode='HTML', reply_markup=markup)
    bot.register_next_step_handler(message, process_custom_limit_gb)

def process_custom_limit_gb(message):
    delete_user_msg(message)
    raw_input = message.text.strip().upper()
    gb = ""
    
    if raw_input == "0": 
        gb = ""
    else:
        # Detectar MB
        if "M" in raw_input:
            try:
                # Extraer numeros
                val = "".join([c for c in raw_input if c.isdigit() or c == '.'])
                # Convertir MB a GB
                gb_val = float(val) / 1024
                # Formatear a 6 decimales
                gb = f"{gb_val:.6f}"
            except:
                bot.send_message(message.chat.id, "❌ Error de formato. Usa numeros.")
                main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
                return
        else:
            # Asumir GB
            val = "".join([c for c in raw_input if c.isdigit() or c == '.'])
            gb = val
    
    chat_id = message.chat.id
    data = TEMP_SSH_CREATION.get(chat_id)
    if data:
        conn = data.get('limit_conn', "")
        perform_ssh_creation(chat_id, data['user'], data['pwd'], data['days'], conn, gb)
    else:
        main_menu(chat_id, USER_STEPS.get(chat_id))

def show_pro_settings(chat_id, message_id):
    data = load_data()
    status = (ICON_UNLOCK + " Acceso Publico: ON") if data.get('public_access', True) else (ICON_LOCK + " Acceso Publico: OFF")
    domain_status = f"🌐 Dominio: {data.get('cloudflare_domain', 'No configurado')}"
    cf_status = f"☁️ CloudFront: {data.get('cloudfront_domain', 'No configurado')}"
    markup = types.InlineKeyboardMarkup(row_width=1)
    markup.add(
        types.InlineKeyboardButton(status, callback_data="toggle_public"),
        types.InlineKeyboardButton(ICON_PLUS + " Añadir Admin", callback_data="admin_add"),
        types.InlineKeyboardButton(ICON_DEL + " Eliminar Admin", callback_data="admin_del"),
        types.InlineKeyboardButton(ICON_WRITE + " Editar Info Extra", callback_data="set_edit_info"),
        types.InlineKeyboardButton(domain_status, callback_data="set_domain"),
        types.InlineKeyboardButton(cf_status, callback_data="set_cloudfront"),
        types.InlineKeyboardButton(ICON_MEGA + " Banner SSH (Nuevo)", callback_data="menu_banner"),
        types.InlineKeyboardButton("🛡️ Backup Data", callback_data="backup_data"),
        types.InlineKeyboardButton("🧹 Limpieza Vencidos", callback_data="force_cleanup"),
        types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main")
    )
    bot.edit_message_text(ICON_GEAR + " <b>AJUSTES AVANZADOS</b>\nBot v6.7 - Auto-Limpieza Activa", chat_id, message_id, reply_markup=markup, parse_mode='HTML')

def process_save_info(message):
    delete_user_msg(message)
    data = load_data(); data['extra_info'] = message.text; save_data(data)
    sent = bot.send_message(message.chat.id, "✅ Info extra guardada.")
    delete_later(message.chat.id, sent.message_id)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_domain(message):
    delete_user_msg(message)
    domain = message.text.strip().lower()
    data = load_data()
    msg = None
    if domain == 'borrar':
        data['cloudflare_domain'] = ""
        save_data(data)
        msg = bot.send_message(message.chat.id, "✅ <b>Dominio eliminado correctamente.</b>", parse_mode='HTML')
        delete_later(message.chat.id, msg.message_id)
    else:
        data['cloudflare_domain'] = domain
        save_data(data)
        msg = bot.send_message(message.chat.id, f"✅ <b>Dominio configurado:</b> <code>{domain}</code>", parse_mode='HTML')
        delete_later(message.chat.id, msg.message_id)
    
    show_pro_settings(message.chat.id, USER_STEPS.get(message.chat.id))
    time.sleep(3)
    try: bot.delete_message(message.chat.id, msg.message_id)
    except: pass

def process_cloudfront(message):
    delete_user_msg(message)
    domain = message.text.strip().lower()
    data = load_data()
    msg = None
    if domain == 'borrar':
        data['cloudfront_domain'] = ""
        save_data(data)
        msg = bot.send_message(message.chat.id, "✅ <b>CloudFront eliminado.</b>", parse_mode='HTML')
        delete_later(message.chat.id, msg.message_id)
    else:
        data['cloudfront_domain'] = domain
        save_data(data)
        msg = bot.send_message(message.chat.id, f"✅ <b>CloudFront configurado:</b> <code>{domain}</code>", parse_mode='HTML')
        delete_later(message.chat.id, msg.message_id)
    
    show_pro_settings(message.chat.id, USER_STEPS.get(message.chat.id))
    time.sleep(3)
    try: bot.delete_message(message.chat.id, msg.message_id)
    except: pass

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
    sent = bot.send_message(message.chat.id, f"✅ Admin {aid} agregado.")
    delete_later(message.chat.id, sent.message_id)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_admin_del(message):
    delete_user_msg(message)
    data = load_data(); aid = message.text.strip()
    if aid in data['admins']: 
        del data['admins'][aid]; save_data(data)
        sent = bot.send_message(message.chat.id, f"🗑️ Admin {aid} eliminado.")
        delete_later(message.chat.id, sent.message_id)
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_username(message):
    delete_user_msg(message)
    user = message.text.strip()
    chat_id = message.chat.id
    
    # 1. Verificar Nombre Valido
    if not user.isalnum():
        sent = bot.send_message(chat_id, "❌ <b>Nombre inválido:</b> Solo letras y números.", parse_mode='HTML')
        delete_later(chat_id, sent.message_id)
        main_menu(chat_id, USER_STEPS.get(chat_id))
        return

    # 2. Gestion de Dias (Admins y Super Admin)
    # Todos los admins ven el menu completo
    if is_admin(chat_id):
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("📅 Días", callback_data="param_days"),
                   types.InlineKeyboardButton("⏱️ Horas", callback_data="param_hours"),
                   types.InlineKeyboardButton("⏱️ Minutos", callback_data="param_mins"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
        bot.edit_message_text(ICON_TIME + " <b>¿Tipo de Duración?</b>", chat_id, USER_STEPS.get(chat_id), parse_mode='HTML', reply_markup=markup)
        
        # Guardamos usuario temporalmente
        TEMP_SSH_CREATION[chat_id] = {'user': user}
    else: 
        # Publico General (No Admins)
        # Limitado a 3 dias automaticos
        days = 3
        ask_ssh_pass_mode(chat_id, user, days)



def process_ssh_hours(message, user):
    delete_user_msg(message)
    try:
        hours = int(message.text.strip())
        if hours < 1: raise ValueError
        
        # Validacion Limite Admin (No Super)
        if message.chat.id != SUPER_ADMIN and hours > 168: # 7 dias * 24h
            sent = bot.send_message(message.chat.id, "❌ <b>Límite excedido:</b> Máximo 168 Horas (7 Días).", parse_mode='HTML')
            delete_later(message.chat.id, sent.message_id)
            main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
            return

        ask_ssh_pass_mode(message.chat.id, user, f"{hours}h")
    except:
        sent = bot.send_message(message.chat.id, "❌ Error: Numero invalido (Min 1).")
        delete_later(message.chat.id, sent.message_id)
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_ssh_minutes(message, user):
    delete_user_msg(message)
    try:
        mins = int(message.text.strip())
        if mins < 1: raise ValueError
        
        # Validacion Limite Admin (No Super)
        if message.chat.id != SUPER_ADMIN and mins > 10080: # 7 dias * 24h * 60m
            sent = bot.send_message(message.chat.id, "❌ <b>Límite excedido:</b> Máximo 10080 Minutos (7 Días).", parse_mode='HTML')
            delete_later(message.chat.id, sent.message_id)
            main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
            return

        ask_ssh_pass_mode(message.chat.id, user, f"{mins}m")
    except:
        sent = bot.send_message(message.chat.id, "❌ Error: Numero invalido (Min 1).")
        delete_later(message.chat.id, sent.message_id)
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def process_ssh_days(message, user):
    delete_user_msg(message)
    try:
        days = int(message.text.strip())
        
        # Validacion Limite Admin (No Super)
        if message.chat.id != SUPER_ADMIN and days > 7:
            sent = bot.send_message(message.chat.id, "❌ <b>Límite excedido:</b> Máximo 7 Días.", parse_mode='HTML')
            delete_later(message.chat.id, sent.message_id)
            main_menu(message.chat.id, USER_STEPS.get(message.chat.id))
            return

        ask_ssh_pass_mode(message.chat.id, user, days)
    except:
        sent = bot.send_message(message.chat.id, "❌ Error: Numero invalido.")
        delete_later(message.chat.id, sent.message_id)
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def ask_ssh_pass_mode(chat_id, user, days):
    TEMP_SSH_CREATION[chat_id] = {'user': user, 'days': days}
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton("🎲 Automática", callback_data="ssh_pass_auto"),
               types.InlineKeyboardButton("✍️ Manual", callback_data="ssh_pass_manual"))
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
    
    msg_id = USER_STEPS.get(chat_id)
    text = f"👤 <b>Usuario:</b> <code>{user}</code>\n📅 <b>Días:</b> {days}\n\n🔑 <b>¿Cómo defines la contraseña?</b>"
    
    try: bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    except: bot.send_message(chat_id, text, parse_mode='HTML', reply_markup=markup)

def process_ssh_manual_pass(message):
    delete_user_msg(message)
    pwd = message.text.strip()
    chat_id = message.chat.id
    data = TEMP_SSH_CREATION.get(chat_id)
    if data:
        if chat_id == SUPER_ADMIN:
            TEMP_SSH_CREATION[chat_id]['pwd'] = pwd
            ask_ssh_limits_menu(chat_id)
        else:
            perform_ssh_creation(chat_id, data['user'], pwd, data['days'])
    else:
        main_menu(chat_id, USER_STEPS.get(chat_id))

def ask_ssh_limits_menu(chat_id):
    msg_id = USER_STEPS.get(chat_id)
    markup = types.InlineKeyboardMarkup(row_width=2)
    markup.add(
        types.InlineKeyboardButton("♾️ Ilimitado", callback_data="sl_unlimited"),
        types.InlineKeyboardButton("💼 Admin (30/50GB)", callback_data="sl_admin"),
        types.InlineKeyboardButton("👤 Public (1/10GB)", callback_data="sl_public"),
        types.InlineKeyboardButton("⚙️ Personalizado", callback_data="sl_custom")
    )
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="back_main"))
    
    user = TEMP_SSH_CREATION[chat_id]['user']
    text = f"⚙️ <b>Límites para {user}:</b>\nSelecciona el perfil de restricciones:"
    
    try: bot.edit_message_text(text, chat_id, msg_id, parse_mode='HTML', reply_markup=markup)
    except: 
        sent = bot.send_message(chat_id, text, parse_mode='HTML', reply_markup=markup)
        USER_STEPS[chat_id] = sent.message_id

def run_ssl_install(message):
    delete_user_msg(message)
    port = message.text.strip()
    chat_id = message.chat.id
    msg_id = USER_STEPS.get(chat_id)
    
    # Mensaje de espera
    wait_msg = bot.send_message(chat_id, "⏳ <b>Instalando SSL Tunnel...</b>\nPor favor espera.", parse_mode='HTML')
    
    # Ejecutar script
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'instalar_ssl_tunnel', port], capture_output=True, text=True)
    
    # Borrar mensaje de espera
    try: bot.delete_message(chat_id, wait_msg.message_id)
    except: pass
    
    if "SSL_TUNNEL_SUCCESS" in res.stdout:
        # Guardar datos
        d = load_data()
        d['ssl_tunnel'] = port
        save_data(d)
        
        # Exito (Borrar a los 2s)
        final_msg = bot.send_message(chat_id, f"✅ <b>SSL Tunnel Instalado</b>\nPuerto: <code>{port}</code>", parse_mode='HTML')
        time.sleep(2)
        try: bot.delete_message(chat_id, final_msg.message_id)
        except: pass
        main_menu(chat_id, msg_id)
    else:
        # Error (Borrar a los 3s)
        err = res.stdout.strip() or "Error desconocido."
        safe_err = html_lib.escape(err)
        err_msg = bot.send_message(chat_id, f"❌ <b>Error:</b>\n<pre>{safe_err}</pre>", parse_mode='HTML')
        time.sleep(3)
        try: bot.delete_message(chat_id, err_msg.message_id)
        except: pass
        main_menu(chat_id, msg_id)

# --- SLOWDNS ---
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
        types.InlineKeyboardButton("🗑️ Eliminar ProxyDT", callback_data="proxydt_remove"),
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

        log_content = "Sin detalles."
        if os.path.exists("/tmp/proxydt_install.log"):
            try: log_content = subprocess.check_output(['tail', '-n', '5', '/tmp/proxydt_install.log']).decode('utf-8', errors='ignore')
            except: pass
        safe_log = html_lib.escape(log_content)
        bot.edit_message_text(f"❌ <b>Error al instalar ProxyDT-Go.</b>\n<pre>{safe_log}</pre>", chat_id, msg_id, parse_mode='HTML')
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

def process_delete_zivpn_input(message):
    delete_user_msg(message)
    pwd = message.text.strip()
    chat_id = message.chat.id
    
    data = load_data()
    if pwd not in data.get('zivpn_users', {}):
        sent = bot.send_message(chat_id, "❌ <b>Error:</b> Password no encontrado.", parse_mode='HTML')
        delete_later(chat_id, sent.message_id)
        main_menu(chat_id, USER_STEPS.get(chat_id))
        return

    # Verificar propiedad si no es Super Admin
    if chat_id != SUPER_ADMIN and str(data.get('zivpn_owners', {}).get(pwd)) != str(chat_id):
        sent = bot.send_message(chat_id, "⛔ <b>Error:</b> Ese password no es tuyo.", parse_mode='HTML')
        delete_later(chat_id, sent.message_id)
        main_menu(chat_id, USER_STEPS.get(chat_id))
        return

    # Ejecutar borrado
    subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'gestionar_zivpn_pass', 'del', pwd])
    
    # Limpiar DB
    del data['zivpn_users'][pwd]
    if pwd in data.get('zivpn_owners', {}): del data['zivpn_owners'][pwd]
    save_data(data)
    
    sent = bot.send_message(chat_id, f"✅ <b>ZIVPN Eliminado:</b> <code>{pwd}</code>", parse_mode='HTML')
    delete_later(chat_id, sent.message_id)
    main_menu(chat_id, USER_STEPS.get(chat_id))

def process_zivpn_pass(message):
    delete_user_msg(message)
    pwd = message.text.strip()
    chat_id = message.chat.id
    is_sa = (chat_id == SUPER_ADMIN)
    is_adm = is_admin(chat_id)
    
    # Sistema de permisos: Super Admin puede elegir, Admin 7 días, Público 3 días
    if is_sa:
        markup = types.InlineKeyboardMarkup()
        markup.add(types.InlineKeyboardButton("📅 Días", callback_data=f"zd_{pwd}"),
                   types.InlineKeyboardButton("⏱️ Horas", callback_data=f"zh_{pwd}"),
                   types.InlineKeyboardButton("⏱️ Minutos", callback_data=f"zm_{pwd}"))
        markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="menu_crear"))
        try:
            bot.edit_message_text(f"🔑 Pass: <code>{pwd}</code>\n{ICON_TIME} <b>¿Tipo de Duración?</b>", chat_id, USER_STEPS.get(chat_id), parse_mode='HTML', reply_markup=markup)
        except:
            # Si el mensaje anterior fue borrado, enviamos uno nuevo
            sent = bot.send_message(chat_id, f"🔑 Pass: <code>{pwd}</code>\n{ICON_TIME} <b>¿Tipo de Duración?</b>", parse_mode='HTML', reply_markup=markup)
            USER_STEPS[chat_id] = sent.message_id
    else:
        # Admin: 7 días, Público: 3 días
        days = 7 if is_adm else 3
        finalize_zivpn(message, pwd, days)

# --- ZIVPN DURATION HANDLERS ---
def process_zivpn_days_ask(message, pwd):
    # delete_user_msg(message) # Causaba que se borrara el menú antes de editarlo
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="menu_crear"))
    try:
        bot.edit_message_text(f"🔑 <b>ZIVPN ({pwd})</b>\nIntroduce los <b>Días</b>:", message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML', reply_markup=markup)
    except:
        sent = bot.send_message(message.chat.id, f"🔑 <b>ZIVPN ({pwd})</b>\nIntroduce los <b>Días</b>:", parse_mode='HTML', reply_markup=markup)
        USER_STEPS[message.chat.id] = sent.message_id
    bot.register_next_step_handler(message, lambda m: finalize_zivpn(m, pwd))

def process_zivpn_hours_ask(message, pwd):
    # delete_user_msg(message)
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="menu_crear"))
    try:
        bot.edit_message_text(f"🔑 <b>ZIVPN ({pwd})</b>\nIntroduce las <b>Horas</b>:", message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML', reply_markup=markup)
    except:
        sent = bot.send_message(message.chat.id, f"🔑 <b>ZIVPN ({pwd})</b>\nIntroduce las <b>Horas</b>:", parse_mode='HTML', reply_markup=markup)
        USER_STEPS[message.chat.id] = sent.message_id
    bot.register_next_step_handler(message, lambda m: finalize_zivpn(m, pwd, is_hours=True))

def process_zivpn_mins_ask(message, pwd):
    # delete_user_msg(message)
    markup = types.InlineKeyboardMarkup()
    markup.add(types.InlineKeyboardButton(ICON_BACK + " Cancelar", callback_data="menu_crear"))
    try:
        bot.edit_message_text(f"🔑 <b>ZIVPN ({pwd})</b>\nIntroduce los <b>Minutos</b>:", message.chat.id, USER_STEPS.get(message.chat.id), parse_mode='HTML', reply_markup=markup)
    except:
        sent = bot.send_message(message.chat.id, f"🔑 <b>ZIVPN ({pwd})</b>\nIntroduce los <b>Minutos</b>:", parse_mode='HTML', reply_markup=markup)
        USER_STEPS[message.chat.id] = sent.message_id
    bot.register_next_step_handler(message, lambda m: finalize_zivpn(m, pwd, is_minutes=True))

def finalize_zivpn(message, pwd, days=None, is_hours=False, is_minutes=False):
    delete_user_msg(message)
    try:
        chat_id = message.chat.id
        if days is None:
            try: 
                days = int(message.text)
                if days < 1: raise ValueError
            except ValueError:
                sent = bot.send_message(chat_id, "❌ Error: Numero invalido.")
                delete_later(chat_id, sent.message_id)
                main_menu(chat_id, USER_STEPS.get(chat_id))
                return

        date_show = f"{days} dias"
        if is_hours: date_show = f"{days} horas"
        if is_minutes: date_show = f"{days} minutos"

        msg_loading = f"⏳ <b>Registrando ZIVPN ({date_show})...</b>"
        status_msg = None
        try:
            # Intentar editar el mensaje anterior (el de "Introduce los minutos" o el menú)
            if USER_STEPS.get(chat_id):
                bot.edit_message_text(msg_loading, chat_id, USER_STEPS.get(chat_id), parse_mode='HTML')
                # Creamos un objeto dummy o usamos una clase simple para simular el objeto Message y guardar el ID
                # Esto es para que el bloque de exito posterior pueda usar status_msg.message_id
                class MockMsg: pass
                status_msg = MockMsg()
                status_msg.message_id = USER_STEPS.get(chat_id)
            else:
                status_msg = bot.send_message(chat_id, msg_loading, parse_mode='HTML')
        except:
            status_msg = bot.send_message(chat_id, msg_loading, parse_mode='HTML')
        
        # Llamada a bash (Para zivpn en bash, solo almacenamos password, la expiracion la maneja el bot)
        cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'gestionar_zivpn_pass', 'add', pwd]
        res = subprocess.run(cmd, capture_output=True, text=True)
        
        # try: bot.delete_message(chat_id, status_msg.message_id)
        # except: pass

        if "ZIVPN_PASS_UPDATED" in res.stdout:
            # Calcular fecha exacta
            now = datetime.now()
            if is_minutes:
                exp_date = (now + timedelta(minutes=days)).strftime("%Y-%m-%d %H:%M:%S")
            elif is_hours:
                exp_date = (now + timedelta(hours=days)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                exp_date = (now + timedelta(days=days)).strftime("%Y-%m-%d")
            
            # Guardar en base de datos bot
            data = load_data()
            if 'zivpn_users' not in data: data['zivpn_users'] = {}
            if 'zivpn_owners' not in data: data['zivpn_owners'] = {}
            
            data['zivpn_users'][pwd] = exp_date
            data['zivpn_owners'][pwd] = str(chat_id)
            save_data(data)
            
            # Construir mensaje de exito
            ip = get_public_ip()
            extra = data.get('extra_info', '')
            domain = data.get('cloudflare_domain', '')
            cfront = data.get('cloudfront_domain', '')
            
            msg = ICON_CHECK + " <b>CUENTA ZIVPN CREADA</b>\n"
            msg += "--------------------------------------\n"
            msg += ICON_PIN + " <b>IP:</b> <code>" + ip + "</code>\n"
            if domain: msg += "🌐 <b>DOMINIO:</b> <code>" + domain + "</code>\n"
            if cfront: msg += "☁️ <b>CLOUDFRONT:</b> <code>" + cfront + "</code>\n"
            if extra: msg += safe_format(extra) + "\n"
            
            msg += "\n🔐 <b>PASSWORD:</b> <code>" + pwd + "</code>\n"
            msg += "📡 <b>PUERTOS UDP:</b> <code>6000-19999</code>\n"
            msg += "⚠️ <b>PUERTO VPN:</b> <code>5667</code>\n"
            msg += "📅 <b>EXPIRA:</b> " + exp_date + f" ({date_show})\n"
            msg += "--------------------------------------\n"
            msg += ICON_MIC + " @Depwise2 | " + ICON_DEV + " @Dan3651"
            
            # Enviar mensaje final y auto-borrar
            if USER_STEPS.get(chat_id):
                # main_menu(chat_id, USER_STEPS.get(chat_id)) # Restaurar menu --> REMOVED
                
                markup = types.InlineKeyboardMarkup()
                markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
                
                try: 
                    # Intentar editar el mensaje de "Registrando..." (status_msg)
                    bot.edit_message_text(msg, chat_id, status_msg.message_id, parse_mode='HTML', reply_markup=markup)
                except:
                    # Si falla, enviar nuevo
                    sent = bot.send_message(chat_id, msg, parse_mode='HTML', reply_markup=markup)
                    
                # delete_later eliminado para que quede el mensaje con las credenciales
            else:
                markup = types.InlineKeyboardMarkup()
                markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver", callback_data="back_main"))
                sent = bot.send_message(chat_id, msg, parse_mode='HTML', reply_markup=markup)
                USER_STEPS[chat_id] = sent.message_id
                # delete_later eliminado para que quede el mensaje con las credenciales
                
        else:
            err = res.stdout + "\n" + res.stderr
            sent = bot.send_message(chat_id, f"❌ <b>Error al crear ZIVPN:</b>\n<pre>{html_lib.escape(err[-200:])}</pre>", parse_mode='HTML')
            delete_later(chat_id, sent.message_id)
            main_menu(chat_id, USER_STEPS.get(chat_id))

    except Exception as e:
        bot.send_message(message.chat.id, f"❌ <b>Error Critico:</b> {str(e)}")
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def perform_edit_pass(chat_id, user, new_pass):
    try:
        msg_id = USER_STEPS.get(chat_id)
        cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'modificar_password', user, new_pass]
        res = subprocess.run(cmd, capture_output=True, text=True)
        
        if "PASS_UPDATED" in res.stdout:
            bot.edit_message_text(f"✅ <b>Contraseña Actualizada</b>\n\nUsuario: <code>{user}</code>\nPass: <code>{new_pass}</code>", chat_id, msg_id, parse_mode='HTML')
        else:
            bot.edit_message_text("❌ Error al cambiar password.", chat_id, msg_id)
            
        time.sleep(3)
        main_menu(chat_id, msg_id)
    except: main_menu(chat_id, msg_id)

def process_edit_pass_manual(message, user):
    delete_user_msg(message)
    pwd = message.text.strip()
    perform_edit_pass(message.chat.id, user, pwd)

def process_edit_renew(message, user):
    delete_user_msg(message)
    try:
        days = int(message.text.strip())
        chat_id = message.chat.id
        msg_id = USER_STEPS.get(chat_id)
        
        cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'renovar_user', user, str(days)]
        
        # Validacion Límite 7 dias para Admins no-Super
        if chat_id != SUPER_ADMIN and days > 7:
            bot.send_message(chat_id, "❌ <b>Límite excedido:</b> Como Admin solo puedes renovar hasta 7 días.", parse_mode='HTML')
            main_menu(chat_id, msg_id)
            return

        res = subprocess.run(cmd, capture_output=True, text=True)
        
        if "USER_RENEWED" in res.stdout:
            exp_date = res.stdout.split('|')[1].strip()
            bot.edit_message_text(f"✅ <b>Usuario Renovado</b>\n\nUsuario: <code>{user}</code>\nNueva Vencimiento: {exp_date}", chat_id, msg_id, parse_mode='HTML')
        else:
            bot.edit_message_text("❌ Error al renovar usuario.", chat_id, msg_id)
            
        time.sleep(3)
        main_menu(chat_id, msg_id)
    except: 
        bot.send_message(message.chat.id, "❌ Error: Numero invalido.")
        main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

def perform_ssh_creation(chat_id, user, pwd, days, conn_limit=None, gb_limit=None):
    try:
        msg_id = USER_STEPS.get(chat_id)
        
        # Feedback visual de proceso
        try: bot.edit_message_text(f"⏳ <b>Creando Usuario SSH...</b>\n\nUser: {user}\nPass: {pwd}", chat_id, msg_id, parse_mode='HTML')
        except: pass
        
        # Limpieza de expirados antes de crear
        cleanup_expired()
    
        # Manejo de Minutos, Horas o Dias
        is_minutes = str(days).endswith("m")
        is_hours = str(days).endswith("h")
        final_days = days
        
        if is_minutes or is_hours:
            # Para el sistema linux, le damos 1 dia de vida minima para que no expire al instante
            # La limpieza exacta la hara el bot
            cmd_days = "1"
        else:
            cmd_days = str(days)

        # DEFINIR LIMITES (Logic update)
        # Si se pasan argumentos explicitos (Super Admin Custom), usarlos.
        # Si no, calcular segun rol.
        
        final_conn = ""
        final_gb = ""
        
        if conn_limit is not None and gb_limit is not None:
             final_conn = conn_limit
             final_gb = gb_limit
        else:
             if is_admin(chat_id):
                 final_conn = "30"
                 final_gb = "50"
             else:
                 final_conn = "1"
                 final_gb = "10"

        cmd = [os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'crear_user', user, pwd, cmd_days, final_conn, final_gb]
        
        # Ejecutar y capturar TODO (stdout + stderr)
        res = subprocess.run(cmd, capture_output=True, text=True)
        
        if "SUCCESS" in res.stdout:
            # Si es por minutos u horas, guardar timestamp exacto
            if is_minutes or is_hours:
                if is_minutes:
                    duration_val = int(str(days).replace("m", ""))
                    exp_dt_obj = datetime.now() + timedelta(minutes=duration_val)
                    disp_days = f"{duration_val} mins"
                else:
                    duration_val = int(str(days).replace("h", ""))
                    exp_dt_obj = datetime.now() + timedelta(hours=duration_val)
                    disp_days = f"{duration_val} horas"

                exp_str = exp_dt_obj.strftime("%Y-%m-%d %H:%M:%S")
                
                d = load_data()
                if 'ssh_time_users' not in d: d['ssh_time_users'] = {}
                d['ssh_time_users'][user] = exp_str
                save_data(d)
                
                dt = f"HOY {exp_dt_obj.strftime('%H:%M:%S')}"
            else:
                # Extraer fecha de res.stdout normal
                try: dt = res.stdout.strip().split('|')[2]
                except: dt = "Indefinida"
                disp_days = f"{days} dias"
            
            ip = get_public_ip()
            data = load_data()
            extra = data.get('extra_info', '')
            domain = data.get('cloudflare_domain', '')
            cfront = data.get('cloudfront_domain', '')
            
            msg = ICON_CHECK + " <b>BOT TELEGRAM DEPWISE V6.7</b>\n--------------------------------------\n"
            msg += ICON_PIN + " <b>HOST IP:</b> <code>" + ip + "</code> \n"
            if domain:
                msg += "🌐 <b>DOMINIO:</b> <code>" + domain + "</code> \n"
            if cfront:
                msg += "☁️ <b>CLOUDFRONT:</b> <code>" + cfront + "</code> \n"
            if extra: msg += safe_format(extra) + "\n"
            msg += "<b>USER:</b> <code>" + user + "</code> \n<b>PASS:</b> <code>" + pwd + "</code> \n"
            
            # INFO LIMITES
            msg += f"🔌 <b>Conexiones:</b> {final_conn if final_conn else 'Ilimitado'}\n"
            data_disp = final_gb + " GB" if final_gb else "Ilimitado"
            msg += f"💾 <b>Datos:</b> {data_disp}\n"
            
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
            if data.get('badvpn'): msg += ICON_PHONE + " <b>BadVPN:</b> <code>7300</code> (Soporte Juegos/Llamadas)\n"
            if data.get('dropbear'): msg += ICON_BEAR + " <b>Dropbear:</b> <code>" + str(data.get('dropbear')) + "</code>\n"
            if data.get('ssl_tunnel'): msg += "🚀 <b>SSL Tunnel:</b> <code>" + str(data.get('ssl_tunnel')) + "</code>\n"
            # Falcon Proxy Info
            if os.path.exists("/etc/falconproxy.conf"):
                try: 
                    with open("/etc/falconproxy.conf") as f: 
                        fc = f.read(); 
                        if "PORTS" in fc: 
                            fp = fc.split('PORTS="')[1].split('"')[0]
                            msg += "🦅 <b>Falcon Proxy:</b> <code>" + fp + "</code>\n"
                except: pass
    
            msg += "<b>VENCE:</b> " + dt + " (" + disp_days + ")\n--------------------------------------\n"
            msg += ICON_MIC + " @Depwise2 | " + ICON_DEV + " @Dan3651"
            
            # Registrar dueño
            data = load_data()
            data['ssh_owners'][user] = str(chat_id)
            save_data(data)
    
            if USER_STEPS.get(chat_id):
                # Restaurar menu principal en el mensaje original --> REMOVED (User request)
                # main_menu(chat_id, USER_STEPS.get(chat_id))
                
                # Enviar resultado EDITANDO el mensaje de "Cargando..." si es posible
                markup = types.InlineKeyboardMarkup()
                markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver al Menú", callback_data="back_main"))
                
                try:
                    # Intenta editar el mensaje de "Creando..."
                    msg_id_loading = USER_STEPS.get(chat_id)
                    bot.edit_message_text(msg, chat_id, msg_id_loading, parse_mode='HTML', reply_markup=markup)
                except:
                    # Si falla (muy viejo o borrado), envia uno nuevo
                    sent = bot.send_message(chat_id, msg, parse_mode='HTML', reply_markup=markup)
                    
                # delete_later(chat_id, sent.message_id, delay=10) # REMOVED: Credenciales deben persistir
            else:
                markup = types.InlineKeyboardMarkup()
                markup.add(types.InlineKeyboardButton(ICON_BACK + " Volver al Menú", callback_data="back_main"))
                sent = bot.send_message(chat_id, msg, parse_mode='HTML', reply_markup=markup)
                USER_STEPS[chat_id] = sent.message_id
                # delete_later(chat_id, sent.message_id, delay=10) # REMOVED: Credenciales deben persistir
        else:
            # Manejo de Error Detallado
            error_detail = res.stdout.strip() + "\n" + res.stderr.strip()
            if not error_detail.strip(): error_detail = "Error desconocido (Exit Code: " + str(res.returncode) + ")"
            
            if "Ya existe" in error_detail:
                error_msg = ICON_X + " <b>ESE USUARIO YA ESTÁ EN USO</b>"
            else:
                safe_detail = html_lib.escape(error_detail[-300:]) # Ultimos 300 chars
                error_msg = ICON_X + " <b>FALLO AL CREAR:</b>\n<pre>" + safe_detail + "</pre>"
                
            sent = bot.send_message(chat_id, error_msg, parse_mode='HTML')
            delete_later(chat_id, sent.message_id, delay=5)
            main_menu(chat_id, USER_STEPS.get(chat_id))
            
    except Exception as e:
        import traceback
        trace = traceback.format_exc()
        sent = bot.send_message(chat_id, f"❌ <b>Error Interno del Bot:</b>\n<pre>{html_lib.escape(str(e))}</pre>", parse_mode='HTML')
        delete_later(chat_id, sent.message_id)
        print(trace) # Imprimir al log del sistema para debug
        time.sleep(3)
        main_menu(chat_id, USER_STEPS.get(chat_id))

def cleanup_expired(force_report=False, chat_report=None):
    data = load_data()
    now_date = datetime.now()
    now_str = now_date.strftime("%Y-%m-%d")
    deleted_count = 0
    report_msg = "🧹 <b>REPORTE DE LIMPIEZA:</b>\n\n"
    
    # --- 1. ZIVPN CLEANUP (Soporta fechas YYYY-MM-DD y Datetime) ---
    to_del_zivpn = []
    for pwd, exp in data.get('zivpn_users', {}).items():
        try:
            # Detectar si es fecha corta o larga
            if len(exp) > 10:
                # Es datetime (Minutos/Horas)
                exp_dt = datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
                if datetime.now() > exp_dt:
                    is_expired = True
                else:
                    is_expired = False
            else:
                # Es fecha corta (Dias)
                if exp < now_str:
                    is_expired = True
                else:
                    is_expired = False
            
            if is_expired:
                subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'gestionar_zivpn_pass', 'del', pwd])
                to_del_zivpn.append(pwd)
                report_msg += f"• ZIVPN: <code>{pwd}</code> (Venció: {exp})\n"
                deleted_count += 1
        except: continue
    
    if to_del_zivpn:
        for p in to_del_zivpn: del data['zivpn_users'][p]
        save_data(data)

    # --- 1.1 SSH MINUTES CLEANUP ---
    to_del_mins = []
    ssh_mins = data.get('ssh_time_users', {})
    for user, exp_str in ssh_mins.items():
        try:
            # Format: YYYY-MM-DD HH:MM:SS
            exp_dt = datetime.strptime(exp_str, "%Y-%m-%d %H:%M:%S")
            if datetime.now() > exp_dt:
                subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_user', user])
                to_del_mins.append(user)
                report_msg += f"• SSH(Min): <code>{user}</code> (Venció: {exp_str})\n"
                deleted_count += 1
        except Exception as e:
            print(f"Error parse min user {user}: {e}")

    if to_del_mins:
        for u in to_del_mins: 
            del data['ssh_time_users'][u]
            if u in data['ssh_owners']: del data['ssh_owners'][u]
        save_data(data)

    # --- 2. SSH USERS CLEANUP ---
    owners = data.get('ssh_owners', {})
    if owners:
        # Check system users
        try:
            # Iterar copia de keys para evitar error runtime size change
            for user in list(owners.keys()):
                # Obtener expiracion real del sistema
                cmd = f"LC_ALL=C chage -l {user} | grep 'Account expires'"
                # Output format: "Account expires : Feb 05, 2026" or "Account expires : never"
                try: 
                    res = subprocess.check_output(cmd, shell=True).decode().strip()
                    date_part = res.split(':')[1].strip()
                    
                    if date_part.lower() == 'never': continue
                    
                    # Parsear fecha (Feb 05, 2026)
                    exp_dt = datetime.strptime(date_part, '%b %d, %Y')
                    
                    # Si fecha expiracion < hoy (ignorando hora, solo fecha)
                    if exp_dt.date() < now_date.date():
                        # Expirado!
                        subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'eliminar_user', user])
                        del data['ssh_owners'][user] # Borrar de BD
                        save_data(data) # Guardar iterativo por seguridad
                        report_msg += f"• SSH: <code>{user}</code> (Venció: {exp_dt.strftime('%Y-%m-%d')})\n"
                        deleted_count += 1
                        
                except Exception as ex:
                    print(f"Error checking {user}: {ex}")
                    pass
        except Exception as e:
            print(f"Error en SSH Cleanup: {e}")

    if deleted_count > 0 and force_report and chat_report:
        try: bot.send_message(chat_report, report_msg, parse_mode='HTML')
        except: pass
        
    return deleted_count

# Cache para evitar spam de alertas
ALERTS_CACHE = set()

def check_data_consumption():
    global ALERTS_CACHE
    data = load_data()
    owners = data.get('ssh_owners', {})
    for user in list(owners.keys()):
        try:
            res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'check_consumo', user], capture_output=True, text=True)
            # Output: GB|LIMIT
            parts = res.stdout.strip().split('|')
            used = float(parts[0])
            limit_str = parts[1]
            
            # Limpiar string de limite (por si trae debug info extra)
            # Ej: "10.0 (Proc: Active)" -> "10.0"
            if " " in limit_str:
                limit_str = limit_str.split(' ')[0]
            
            if limit_str == "Infinito": continue
            limit = float(limit_str)
            
            if used >= limit:
                # Solo bloquear/notificar si no se ha hecho ya
                if user not in ALERTS_CACHE:
                    # Bloquear usuario
                    subprocess.run(['passwd', '-l', user])
                    subprocess.run(['pkill', '-u', user])
                    # Avisar al dueño
                    owner_id = owners[user]
                    try:
                        bot.send_message(owner_id, f"⚠️ <b>ALERTA DE CONSUMO</b>\n\nEl usuario SSH <code>{user}</code> ha superado su límite de {limit} GB ({used} GB usados).\n\n⛔ <b>CUENTA BLOQUEADA (NO ELIMINADA)</b>\n💡 <i>Para desbloquear, usa la opción 'Renovar' en el menú.</i>", parse_mode='HTML')
                        ALERTS_CACHE.add(user)
                    except: pass
            else:
                # Si bajo del limite (recarga), quitar de cache
                if user in ALERTS_CACHE:
                    ALERTS_CACHE.remove(user)
        except: pass

# Hilo persistente de auto-limpieza
def auto_cleanup_loop():
    tick = 0
    while True:
        try:
            # 1. Monitor de Conexiones y DATOS (CADA 7 SEGUNDOS) - PRIORIDAD ALTA
            # Mata procesos sobrantes al instante y corta consumo rapido
            subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'check_and_kill_excess'])
            check_data_consumption()
            
            # 2. Limpieza de Expirados / Datos / Sync Iptables (CADA 60 SEGUNDOS APROX)
            # Ejecutamos cada 9 ticks (7 * 9 = 63 seg)
            if tick >= 9:
                cleanup_expired()
                # Sincronizar reglas iptables por si se borraron (reboot/flush)
                subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'sync_iptables'])
                tick = 0
            
            tick += 1
            time.sleep(7) 
        except:
            time.sleep(10) # Si falla, reintentar rapido

# Iniciar hilo al final del script principal


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


def run_falcon_install(message):
    delete_user_msg(message)
    port = message.text.strip()
    msg = bot.send_message(message.chat.id, "⏳ <b>Instalando Falcon Proxy...</b>\nDescargando ultima version...", parse_mode='HTML')
    
    res = subprocess.run([os.path.join(PROJECT_DIR, 'ssh_manager.sh'), 'instalar_falcon_proxy', port], capture_output=True, text=True)
    
    if "FALCON_SUCCESS" in res.stdout:
        parts = res.stdout.split('|')
        ver = parts[1]
        p_out = parts[2]
        bot.edit_message_text(f"✅ <b>Falcon Proxy Instalado</b>\n\nVersión: <code>{ver}</code>\nPuerto: <code>{p_out}</code>", message.chat.id, msg.message_id, parse_mode='HTML')
    else:
        err = res.stdout.strip() or "Error desconocido"
        bot.edit_message_text(f"❌ <b>Error al instalar:</b>\n{err}", message.chat.id, msg.message_id)
    
    time.sleep(2)
    try: bot.delete_message(message.chat.id, msg.message_id)
    except: pass
    main_menu(message.chat.id, USER_STEPS.get(message.chat.id))

if __name__ == "__main__":
    # Iniciar Auto-Limpieza en segundo plano
    threading.Thread(target=auto_cleanup_loop, daemon=True).start()
    
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
