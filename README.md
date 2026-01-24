# 💎 Bot Telegram Depwise SSH - Versión 6.1 (PRO CUSTOM)

Este es un bot de gestión SSH para Telegram altamente optimizado y automatizado, diseñado para administradores que buscan velocidad, estabilidad y una experiencia de usuario premium.

## 🚀 Características Principales (V6.1)

### 🖥️ Navegación de un Solo Mensaje (UX VIP)
- **Mensaje Dinámico**: Olvídate del spam del bot. Toda la navegación entre menús (Ajustes, Info, Protocolos) ocurre editando un único mensaje principal.
- **Limpieza de Chat**: El bot elimina automáticamente los mensajes enviados por el usuario para mantener el chat limpio y profesional.
- **Navegación Fluida**: Botones de "Volver" integrados en cada acción para una gestión sin interrupciones.

### 🌐 Instalador Maestro de SlowDNS (Zero-Link)
- **Detección de Arquitectura**: El bot identifica automáticamente si tu VPS es `amd64`, `arm64`, `arm` o `386` y descarga el binario verificado exacto.
- **Red de Espejos (Mirrors)**: Sistema inteligente que prueba múltiples fuentes de descarga oficiales si una falla, evitando errores de enlaces caídos.
- **Logs en Tiempo Real**: Botón 🔄 **Actualizar Estado** para ver el progreso real (descarga, llaves, red) mientras el bot trabaja en segundo plano.
- **Ejecución Asíncrona (Multihilo)**: La instalación no bloquea el bot; puedes seguir usando otras funciones mientras se configura el servidor.

### 🛡️ Seguridad y Robustez
- **Control de Acceso Público**: El Super Admin puede activar o desactivar el acceso al bot para usuarios generales mediante un interruptor en "Ajustes Pro".
- **Escape de HTML**: Protección total contra errores de parseo de Telegram. Cualquier salida del sistema se muestra de forma segura como texto plano.
- **Gestión de Dueños**: Los administradores secundarios solo pueden ver y eliminar los usuarios SSH que ellos mismos crearon.

### 📈 Monitoreo Avanzado
- **Monitor Online (Super Admin)**: Visualiza en tiempo real qué usuarios están conectados y cuántas sesiones tienen activas.
- **Info Servidor Pro**: Datos técnicos detallados que incluyen IP fija, límites de puertos y la configuración completa de SlowDNS (NS y Public Key) en formato copiable.
- **Confirmación Integrada**: Al crear un usuario SSH, el bot entrega en un solo mensaje: usuario, contraseña, fecha de vencimiento y los datos de conexión SlowDNS.

## 🛠️ Instalación en tu VPS

Para instalar o actualizar a la versión 6.1, ejecuta el siguiente comando en tu terminal como root:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Depwisescript/BOT-TELEGRAM-ADMINITRADOR-SSH-VPN/refs/heads/main/instalador_depwise.sh)
```

## 📋 Requisitos del Sistema
- Sistema Operativo: Ubuntu 20.04+ o Debian 10+.
- Acceso Root.
- Token de Bot de Telegram (obtenido en @BotFather).

## 💎 Créditos
- **Desarrollo Core**: @Dan3651
- **Comunidad**: @Depwise2

---
*Este proyecto está diseñado para fines educativos y de gestión de redes privadas.*

