# 💎 Bot Telegram Depwise SSH - Versión 6.6 (FIXED)

Este es un bot de gestión SSH y VPN para Telegram de alto rendimiento, diseñado para administradores que buscan una solución integral, estética y profesional.

## 🚀 Novedades de la Versión 6.6

### 🛠️ Reparación Integral de ProxyDT
- **Instalación Robusta**: Sistema de múltiples espejos (mirrors) que garantiza la descarga del binario incluso si el repositorio principal falla.
- **Soporte Multi-Arquitectura**: Detección automática de **AMD64** y **ARM64** para instalar el binario correcto según tu VPS.
- **Auto-Fix de Dependencias**: Solución automática para el error `libssl.so.1.1 not found` en sistemas modernos (Ubuntu 22.04+), instalando las librerías necesarias sin intervención manual.
- **Socket Bind Fix**: Corrección de banderas de arranque para evitar el error "Failed to bind socket".

### 🛰️ Gestión Avanzada de ZIVPN (UDP)
- **Multi-Cuenta**: Soporte para múltiples passwords activos simultáneamente en un solo puerto.
- **Sistema de Permisos por Rol**: 
  - 👤 **Usuarios**: Creación de passwords por 3 días.
  - 👮 **Admins**: Creación de passwords por 7 días.
  - 👑 **Super Admin**: Sin límites (personalizable).
- **Tracking de Propiedad**: Cada password está vinculado a su creador, permitiendo un control total sobre las ventas y accesos.

### 🌐 Integración con Cloudflare
- **Dominio Personalizado**: Configura un dominio Cloudflare que apunte a tu VPS desde el menú "Ajustes Pro".
- **Visibilidad Total**: El dominio se muestra automáticamente en el menú "Info Servidor" y se incluye en los mensajes de entrega al crear usuarios SSH o passwords ZIVPN.

### 📊 Monitor Online Pro (Filtrado)
- **Privacidad para Admins**: Los administradores secundarios ahora solo pueden ver los usuarios SSH y los passwords ZIVPN que ellos mismos han creado.
- **Vista Global (Super Admin)**: El Super Admin mantiene acceso a la lista completa con información detallada de los dueños de cada cuenta.

### 🖥️ UX VIP y Mejoras Estéticas
- **Todo Copiable**: IPs, Dominios, Puertos, Usuarios y Contraseñas ahora usan etiquetas `<code>` de Telegram para copiar con un solo toque.
- **Info Extendida**: El menú de información ahora incluye rangos de puertos UDP para ZIVPN y estado del dominio.

## 🛡️ Características Core

- **Navegación de un Solo Mensaje**: Olvídate del spam; el bot edita un único mensaje para todas las funciones.
- **Limpieza Automática**: El bot elimina los comandos del usuario para mantener el chat impecable.
- **Instalador de SlowDNS**: Detección automática de arquitectura y red de espejos (mirrors) para instalaciones sin fallos.
- **Gestión de ProxyDT-Go (WebSocket)**: Abre y cierra puertos WebSocket con un solo clic.

## 🛠️ Instalación en tu VPS

Para instalar o actualizar a la versión 6.5, ejecuta el siguiente comando como root:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Depwisescript/BOT-TELEGRAM-ADMINITRADOR-SSH-VPN/refs/heads/main/instalador_depwise.sh)
```

## 📋 Requisitos del Sistema
- **SO**: Ubuntu 20.04+ / Debian 10+.
- **Acceso**: Root obligatorio.
- **Herramientas**: `curl`, `python3`.
- **Bot**: Token de @BotFather e ID de @userinfobot.

## 💎 Créditos
- **Desarrollo Core**: @Dan3651
- **Comunidad**: @Depwise2

---
*Este proyecto está diseñado para fines de gestión de redes privadas y administración de servidores.*
