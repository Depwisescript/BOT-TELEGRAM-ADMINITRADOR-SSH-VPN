<div align="center">

# 💎 Bot Telegram Depwise SSH V6.7 (PRO)
### *La Solución Definitiva para Gestión de Redes Privadas*

[![Version](https://img.shields.io/badge/version-6.7%20PRO-blue.svg?style=for-the-badge)](https://github.com/Depwisescript)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Bash](https://img.shields.io/badge/bash-script-green.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Telegram](https://img.shields.io/badge/Telegram-Bot-2CA5E0.svg?style=for-the-badge&logo=telegram&logoColor=white)](https://core.telegram.org/bots)

</div>

---

## 🚀 ¿Qué es Depwise Bot?

Un potente **Asistente Virtual** para administradores de servidores VPS. Gestiona usuarios SSH, protocolos VPN y monitorea tu red directamente desde Telegram con una interfaz **moderna, rápida y elegante**.

> [!NOTE]
> Diseñado para Ubuntu 20.04+ y Debian 10+. Compatible con arquitecturas AMD64 y ARM64.

---

## ✨ Novedades V6.7: Potencia y Estilo

### � Protocolo SSL Tunnel (HAProxy) [NUEVO]
¡Llevamos la seguridad al siguiente nivel! 
- **Integración Nativa**: Instala/Desinstala HAProxy con un clic.
- **Puerto Custom**: Define tu puerto de escucha SSL (ej: 443, 8443).
- **Helper Inteligente**: Gestión automática de firewall y liberación de puertos.

### 📱 Experiencia de Usuario (UX) Renovada
- **🧹 Chat Limpio**: El bot mantiene tu chat impecable borrando automáticamente mensajes de carga (2s) y errores (3s).
- **📋 Copiado Rápido**: IPs, Puertos, Usuarios y Claves ahora usan formato `<code>` para copiar con un solo toque.
- **☁️ Dominios Cloud**: Soporte total visual para dominios **Cloudflare** y **CloudFront** en los reportes.

### 🛡️ Seguridad y Control Total [NUEVO]

El sistema ahora incluye un núcleo de seguridad avanzado:

1.  **"El Verdugo" (Monitor Activo)**:
    *   Detecta y **elimina** conexiones ilegales (ej: HTTP Custom/Injector) que intentan burlar el límite de dispositivos.
    *   Funciona en tiempo real (cada 7 segundos).

2.  **Límite de Datos (Quota)**:
    *   Define límites exactos (ej: `500 MB`, `10 GB`) para tus usuarios.
    *   **Bloqueo Automático**: Si un usuario excede su cuota, el bot bloquea la cuenta y cierra sus sesiones al instante.
    *   **Alerta de Consumo**: Recibe notificaciones en Telegram cuando un usuario cruza la línea roja.

3.  **Jerarquía de Poder**:
    *   **Usuarios Públicos**: Límite estricto (1 Disp / 10 GB).
    *   **Revendedores**: Límite ampliado (30 Disp / 50 GB).
    *   **Super Admin (Tú)**: **Control Total** (Límites personalizados o Ilimitado) y **Visión Global** de todos los consumos en "Mis Consumos".

---

## �️ Protocolos Soportados

| Protocolo | Estado | Descripción |
| :--- | :---: | :--- |
| **SSH Directo** | ✅ | Gestión completa + **Límites de Datos/Conexiones**. |
| **SSL Tunnel** | ✅ | **NUEVO.** Túnel seguro vía HAProxy. |
| **SlowDNS** | ✅ | DNSTT integrado con gestión de claves. |
| **ZIVPN (UDP)** | ✅ | Soporte para videollamadas y juegos online. |
| **ProxyDT-Go** | ✅ | Versión Cracked Multi-arquitectura con WebSocket. |
| **BadVPN** | ✅ | UDPGW 7300 compilado para alto rendimiento. |

---

## � Instalación en 1 Paso

Copia y pega este comando en tu terminal **root**:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Depwisescript/BOT-TELEGRAM-ADMINITRADOR-SSH-VPN/refs/heads/main/instalador_depwise.sh)
```

> [!IMPORTANT]
> El script instalará automáticamente todas las dependencias (Python, Pip, TMux, etc.) y te guiará paso a paso.

---

## 📸 Previas del Bot

<div align="center">
  <img src="./bot_v6.7.jpg" alt="Depwise Bot V6.7 Interface" width="600">
  <br>
  <i>Interfaz del Bot V6.7 (Captura Real)</i>
</div>

---

## ⚙️ Configuración Post-Instalación

1.  **Token del Bot**: Crea un bot en [@BotFather](https://t.me/BotFather) y obtén el API TOKEN.
2.  **ID Admin**: Consigue tu ID numérico en [@userinfobot](https://t.me/userinfobot).
3.  **Disfruta**: El bot se iniciará automáticamente y quedará residente en memoria.

---

<div align="center">

**Desarrollado con ❤️ por @Dan3651**
*Únete a la comunidad: @Depwise2*

</div>
