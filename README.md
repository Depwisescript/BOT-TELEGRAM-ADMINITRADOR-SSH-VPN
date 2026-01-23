# 💎 BOT TELEGRAM DEPWISE SSH (V3.4 PRO)

¡Bienvenido al gestor de usuarios SSH más avanzado para Telegram! Este bot permite automatizar la creación, eliminación y gestión de cuentas SSH con límites de tiempo, todo desde una interfaz intuitiva de Telegram con botones profesionales.

## 🚀 Características Principales

-   **🌐 Acceso Público**: Permite que cualquier usuario cree cuentas SSH de **3 días** automáticamente.
-   **👥 Jerarquía de Admins**:
    -   **Público**: 3 días fijos.
    -   **Admins**: 7 días fijos (Agregados por el Super Admin).
    -   **Super Admin**: Duración personalizada e ilimitada.
-   **📱 Interfaz de Botones**: Menús interactivos fáciles de usar, sin comandos complejos.
-   **📢 Mensajes Globales (Broadcast)**: El Super Admin puede enviar anuncios a todos los usuarios que hayan usado el bot.
-   **⚡ Click-to-Copy**: IP, Usuario y Contraseña formateados para copiar con un toque.
-   **📝 Editor Dinámico**: Personaliza la información del servidor (dominios, puertos, notas) con soporte para Markdown.
-   **🛠️ Autodestrucción**: Las cuentas caducan automáticamente a nivel de sistema operativo.
-   **🔒 Seguridad Universal**: Codificación UTF-8 compatible con cualquier VPS (Ubuntu, Debian, etc.).

## 📋 Requisitos

-   Un servidor Linux (VPS) con acceso Root (Recomendado Ubuntu/Debian).
-   **Python 3.x** instalado.
-   Uun **Bot Token** (Obtenido de [@BotFather](https://t.me/BotFather)).
-   Tu **Chat ID** de Telegram (Obtenido de [@userinfobot](https://t.me/userinfobot)).

## 🛠️ Instalación en 1 Minuto

Sube el archivo `instalador_depwise.sh` a tu servidor y ejecuta los siguientes comandos:

```bash
# Dar permisos de ejecución
chmod +x instalador_depwise.sh

# Iniciar instalación
sudo ./instalador_depwise.sh
```

El script te pedirá el **TOKEN** y tu **CHAT ID** para configurar todo automáticamente.

## 🤖 Comandos del Bot

-   `/start` o `/menu`: Abre el panel de control principal.
-   **👤 Crear SSH**: Crea una cuenta con los límites de tu rango.
-   **🗑️ Eliminar SSH**: Muestra una lista de usuarios y permite borrar uno.
-   **📡 Info Servidor**: Muestra la IP y la información extra configurada.
-   **⚙️ Ajustes Pro** (Solo Super Admin):
    -   Añadir/Quitar Admins con alias.
    -   Editar la información dinámica del servidor.
-   **📢 Mensaje Global** (Solo Super Admin): Envía una notificación a toda la base de datos de usuarios.

## 💡 Tips de Edición
Al editar la **Info Extra**, puedes usar comillas invertidas para que el texto sea seleccionable en Telegram:
> Ejemplo: `Conectar a: \`dominio.com\` Puerto: \`8080\``

---
**Desarrollado por:** [@Dan36511](https://t.me/Dan3651)
**Canal de Soporte:** [@Depwise2](https://t.me/Depwise2)
