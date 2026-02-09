# 💎 Bot Telegram Depwise SSH - Versión 6.7 (PRO)

Este es un bot de gestión SSH y VPN para Telegram de alto rendimiento. Diseñado para administradores que buscan una solución integral, **estética** y robusta.

---

## 🚀 Novedades de la Versión 6.7

### ☁️ Integración Total con Dominios (Cloudflare + CloudFront)
- **Dominio Cloudflare:** Configura tu dominio principal para SSH/Websock.
- **Dominio CloudFront:** [NUEVO] Agrega tu dominio CloudFront para distribución de contenido o payload.
- **Auto-Limpieza**: Los mensajes de confirmación se eliminan automáticamente a los 3 segundos para mantener tu chat impecable.
- **Visibilidad**: Ambos dominios aparecen en "Info Servidor" y son **copiables** al crear usuarios.

### 🛰️ Gestión Avanzada de Protocolos
- **ZIVPN (UDP) Mejorado**:
  - **🔍 Verificación de Actividad**: Nueva función para revisar si una contraseña tiene uso reciente (lee logs del sistema).
  - **Submenú Dedicado**: Gestión de instalación y eliminación separada.
- **BadVPN / UDPGW 2.0**:
  - **Instalador Robusto**: Compilación desde fuente con detección de errores, re-instalación forzada y limpieza de servicios previos.
  - **Anti-Bloqueo**: Usa `cmake` y `make` con flags optimizados.
- **Dropbear Secure**:
  - Generación automática de llaves (`host keys`) y servicio custom para evitar conflictos.

### 📱 Experiencia de Usuario (UX)
- **Menús Reorganizados**: "Gestión de Protocolos" ahora es un hub limpio que redirige a submenús específicos (SlowDNS, ZIVPN, ProxyDT, SSL Tunnel).
- **Todo Copiable**: IPs, Puertos, Usuarios, Passwords y Dominios usan formato `<code>` de Telegram para copiar con un toque.
- **Chat Limpio**: Mensajes de carga, errores y confirmaciones se eliminan automáticamente (2s/3s) para mantener el historial limpio.

### 🔒 Protocolo SSL Tunnel (HAProxy) [NUEVO]
- **Integración Nativa**: Instalación y desinstalación directa desde el bot sin afectar otros servicios.
- **Puerto Personalizable**: Elige el puerto de escucha para tu túnel SSL.
- **Visualización**: El puerto activo se muestra en "Info Servidor" y al crear usuarios.
- **Helper Functions**: Gestión inteligente de puertos y firewall para evitar conflictos.

---

## 🛡️ Características Core

- **Navegación Fluida**: El bot edita un único mensaje para todas las funciones (evita el spam).
- **ProxyDT-Go (Cracked)**:
  - Soporte Multi-Arquitectura (AMD64/ARM64).
  - Instalación automática con múltiples espejos (mirrors).
  - Apertura/Cierre de puertos WebSocket en caliente.
- **SlowDNS Manager**: Instalación automática de DNSTT con claves y servicio systemd.
- **Monitor de Usuarios**:
  - **Admin**: Ve sus propios usuarios.
  - **Super Admin**: Ve todos los usuarios y dueños.

---

## 🛠️ Instalación Rápida

Ejecuta este comando en tu terminal (como root):

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Depwisescript/BOT-TELEGRAM-ADMINITRADOR-SSH-VPN/refs/heads/main/instalador_depwise.sh)
```

**Requisitos:**
- Ubuntu 20.04+ / Debian 10+
- Python 3 instalado (el script lo instala si falta).

---

## ⚙️ Configuración Inicial
Al instalar, el script te pedirá:
1.  **Token del Bot**: Consíguelo en @BotFather.
2.  **ID de Admin**: Tu ID numérico de Telegram (usa @userinfobot).

---

## 💎 Créditos
- **Desarrollo Core**: @Dan3651
- **Comunidad**: @Depwise2

*Este proyecto es para administración de redes privadas.*
