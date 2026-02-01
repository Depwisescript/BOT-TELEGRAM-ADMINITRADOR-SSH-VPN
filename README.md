# 💎 Bot Telegram Depwise SSH - Versión 6.7 (PRO)

Una solución integral, estética y potente para la gestión de servidores SSH y VPN directamente desde Telegram. Diseñado para administradores que valoran el rendimiento y la facilidad de uso.

![Banner](https://img.shields.io/badge/Versión-6.7_PRO-blue?style=for-the-badge&logo=telegram) ![Python](https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python) ![Bash](https://img.shields.io/badge/Bash-Script-green?style=for-the-badge&logo=gnu-bash)

---

## 🚀 Novedades y Características (v6.7)

### 🦅 Nuevo: Falcon Proxy
- **Gestor Websocket/Socks**: Soporte nativo para Falcon Proxy.
- **Instalación Automática**: Descarga y configuración en un solo toque.
- **Gestión Visual**: Visualiza versión instalada y puertos activos.

### 🎨 Personalización y Estética
- **Banner SSH en Vivo**: Edita el banner de bienvenida de tu servidor SSH (texto o ASCII Art) directamente desde el bot.
- **Interfaz Copiable**: IPs, Puertos, Usuarios y Contraseñas formateados en `monospaced` para copiar con un clic.
- **Soporte Markdown**: Mensajes informativos con formato rico.

### ☁️ Integración Cloud (CDN)
- **Cloudflare & CloudFront**:
  - Configura y gestiona dominios CDN.
  - Visualización persistente en el panel de información.
  - Se adjuntan automáticamente a los detalles del usuario creado.

### 🛰️ Soporte Multi-Protocolo
| Protocolo | Estado | Características |
|:---:|:---:|:---|
| **SSH** | ✅ N/A | Gestión de usuarios, expiración automática y monitoreo. |
| **Dropbear** | ✅ Auto | SSH ligero alternativo. Generación automática de keys. |
| **G. ZIVPN** | ✅ UPD | Túnel UDP (Puerto 5667 -> 6000-19999). **Verificación de actividad en logs**. |
| **BadVPN** | ✅ UDPGW | Soporte para videollamadas y juegos (Puerto 7300). Compilación robusta. |
| **SlowDNS** | ✅ DNSTT | Instalación automática de binarios y claves servidor/cliente. |
| **ProxyDT** | ✅ Go | Versión *No-Token* (Cracked). WebSocket multi-puerto en caliente. |

---

## 🛡️ Panel de Administración

### 👤 Gestión de Usuarios
- **Crear/Eliminar/Renovar**: Control total de cuentas SSH y VPN.
- **Passwords**: Generación aleatoria o manual.
- **Auto-Limpieza**: El bot elimina automáticamente usuarios vencidos cada 6 horas.

### 🔧 Herramientas del Sistema
- **Monitor de Recursos**: Visualiza conexiones activas (SSH) y usuarios online.
- **Backup Data**: Crea y descarga una copia de seguridad (`.zip`) de tu base de datos y configuración.
- **Control de Acceso**:
  - **Modo Público/Privado**: Cierra el bot para uso exclusivo de administradores.
  - **Sistema de Revendedores**: Agrega sub-admins con límites de días (3 días público / 7 días admin).

---

## 🛠️ Instalación

Ejecuta el siguiente comando en tu terminal como usuario **root**:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Depwisescript/BOT-TELEGRAM-ADMINITRADOR-SSH-VPN/refs/heads/main/instalador_depwise.sh)
```

### Requisitos previos
- **SO**: Ubuntu 20.04+ (Recomendado) o Debian 10+.
- **Arquitectura**: AMD64 o ARM64.
- **Puertos**: Asegúrate de no tener conflictos en puertos estándar (80, 443, 22).

### Configuración Post-Instalación
El script solicitará interactivamente:
1.  **Token del Bot**: Crea uno en [@BotFather](https://t.me/BotFather).
2.  **ID de Admin**: Tu ID numérico (obtenlo en [@userinfobot](https://t.me/userinfobot)).

---

## 📸 Capturas / Comandos

- `/start` o `/menu`: Abre el panel principal.
- **Botones Inline**: Toda la navegación es a través de botones interactivos.

---

## 💎 Créditos

- **Desarrollador Principal**: [@Dan3651](https://t.me/Dan3651)
- **Canal Oficial**: [@Depwise2](https://t.me/Depwise2)

---
*Este software se distribuye con fines educativos y de administración de redes.*
