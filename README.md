# 🍷 Santa Cena App v2 · Gestión, Captación e Informes

Aplicación web móvil para la captación, distribución y reportes del Servicio de Santa Cena.

---

## 📱 Características Principales
1. **Acceso Móvil Multiplataforma (iOS / Android / Desktop):**
   - Autenticación por correo y contraseña con **Supabase Auth**.
   - Perfil de **Captadora** (registra hermanos por zona y culto).
   - Perfil de **Administrador único** (definido en `ADMIN_EMAILS` para ver métricas completas, editar registros y reset).
2. **Registro y Asignación con WhatsApp Inmediato:**
   - Selección de Culto (`☀️ 11:00 hrs` / `🌙 18:30 hrs`).
   - Envío automático de mensaje WhatsApp con fila, mesón y mapa interactivo.
3. **Edición Rápida y Corrección de Errores:**
   - Si se ingresó mal el teléfono o nombre, se edita con 1 click y se actualiza la agenda de contactos.
   - Botón directo para reenviar el WhatsApp al número corregido.
4. **Dashboard e Informes Ejecutivos:**
   - Tarjetas de Captación y % Zonas Centrales (5, 7, 9).
   - Gráfico de barras comparativo Z1 a Z14 (11:00 vs 18:30).
   - Ranking horizontal de captadoras por culto.
   - Plano interactivo del templo y tabla detalle.
   - Botón de impresión limpia de informe en PDF.
5. **Control de "No Cenaron" y Conteo General:**
   - Conciliación de Asistencia vs Conteo y registro de personas que no alcanzaron a cenar con sus motivos.

---

## 🛠️ Variables de Entorno Requeridas
Configúralas en Vercel o Render:

| Variable | Descripción |
|---|---|
| `SUPABASE_URL` | URL de tu proyecto en Supabase (ej: `https://xyz.supabase.co`) |
| `SUPABASE_KEY` | `anon` public key de Supabase |
| `ADMIN_EMAILS` | Correo del administrador único (ej: `admin@iglesia.cl`) |
| `ASSIGNATION_LINK_SECRET` | Texto aleatorio para firmar enlaces seguros (opcional) |

---

## 🚀 Despliegue Paso a Paso (Recomendado: Vercel)

### Opción 1: Despliegue en Vercel (Recomendado - 100% Gratis y Rápido)
1. Sube este proyecto a un nuevo repositorio en GitHub (ej: `santa-cena-v2`).
2. Entra a [vercel.com](https://vercel.com) e inicia sesión con tu GitHub.
3. Haz clic en **Add New Project** e importa el repositorio `santa-cena-v2`.
4. En **Environment Variables**, agrega `SUPABASE_URL`, `SUPABASE_KEY` y `ADMIN_EMAILS`.
5. Haz clic en **Deploy**. ¡Listo en 30 segundos con enlace HTTPS disponible para iOS y Android!

### Opción 2: Despliegue en Render (Nuevo Servicio)
1. En tu panel de Render, haz clic en **New +** -> **Web Service**.
2. Conecta el nuevo repositorio de GitHub.
3. En **Build Command**: `pip install -r requirements.txt`.
4. En **Start Command**: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`.
5. Agrega las variables de entorno en **Environment**.
6. (Opcional para que no se duerma): Agrega la URL `/health` a UptimeRobot.
