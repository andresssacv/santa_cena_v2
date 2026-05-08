from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from itsdangerous import URLSafeSerializer, BadSignature
import urllib.parse
import os
import unicodedata
import time
import threading

app = Flask(__name__)
CORS(app)

# ======================
# ENVIRONMENT VARIABLES
# ======================
SUPABASE_URL = (os.getenv("SUPABASE_URL") or "").strip()
SUPABASE_KEY = (os.getenv("SUPABASE_KEY") or "").strip()
ADMIN_EMAILS = [e.strip().lower() for e in os.getenv("ADMIN_EMAILS", "").split(",") if e.strip()]

missing_vars = [name for name, value in {
    "SUPABASE_URL": SUPABASE_URL,
    "SUPABASE_KEY": SUPABASE_KEY,
}.items() if not value]

SUPABASE_ENABLED = not missing_vars

supabase = None
supabase_init_error = None

TOKEN_CACHE = {}
TOKEN_CACHE_TTL_SECONDS = 300

# Cache de contactos en memoria (se recarga cada 10 min)
CONTACTS_CACHE = []
CONTACTS_CACHE_LAST_UPDATE = 0
CONTACTS_CACHE_TTL = 600  # 10 minutos
contacts_cache_lock = threading.Lock()

token_secret = os.getenv("ASSIGNATION_LINK_SECRET") or (SUPABASE_KEY if SUPABASE_KEY else "dev-secret")
token_serializer = URLSafeSerializer(token_secret)


def build_supabase_client(url, key):
    from supabase import create_client as supabase_create_client
    return supabase_create_client(url, key)


def get_config_error_message():
    if supabase_init_error:
        return (
            "Configuración inválida de Supabase: no se pudo inicializar el cliente. "
            f"Detalle: {supabase_init_error}"
        )
    return (
        "Configuración incompleta: faltan variables de entorno requeridas "
        + ", ".join(missing_vars) + "."
    )


def require_supabase():
    global supabase, supabase_init_error, SUPABASE_ENABLED
    if not SUPABASE_ENABLED:
        return jsonify({"status": "error", "message": get_config_error_message()}), 503
    if supabase is None:
        try:
            supabase = build_supabase_client(SUPABASE_URL, SUPABASE_KEY)
            supabase_init_error = None
        except Exception as e:
            supabase_init_error = str(e)
            SUPABASE_ENABLED = False
            if "SUPABASE_INIT_FAILED" not in missing_vars:
                missing_vars.append("SUPABASE_INIT_FAILED")
            return jsonify({"status": "error", "message": get_config_error_message()}), 503
    return None


def get_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.split(" ", 1)[1].strip()


def get_current_user():
    supabase_error = require_supabase()
    if supabase_error:
        return None, supabase_error[0], supabase_error[1]

    token = get_bearer_token()
    if not token:
        return None, jsonify({"status": "error", "message": "No autorizado (token requerido)"}), 401

    now = time.time()
    cached = TOKEN_CACHE.get(token)
    if cached and cached.get("exp", 0) > now:
        return cached.get("user"), None, None

    try:
        user_resp = supabase.auth.get_user(token)
        user = user_resp.user
        if not user:
            TOKEN_CACHE.pop(token, None)
            return None, jsonify({"status": "error", "message": "Token inválido"}), 401

        if len(TOKEN_CACHE) > 1000:
            TOKEN_CACHE.clear()
        TOKEN_CACHE[token] = {"user": user, "exp": now + TOKEN_CACHE_TTL_SECONDS}
        return user, None, None
    except Exception:
        TOKEN_CACHE.pop(token, None)
        return None, jsonify({"status": "error", "message": "Token inválido"}), 401


def require_admin(user):
    email = (user.email or "").lower()
    return email in ADMIN_EMAILS


def normalize_text(value):
    text = str(value or "").strip().lower()
    text = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn")


def obtener_mesa_label(sector):
    try:
        sector_id = int(sector)
    except (TypeError, ValueError):
        return "No definida"

    meson_norte = {1, 2, 5}
    meson_sur = {7, 9, 11, 12}
    meson_entrada = {3, 4, 6, 8, 10, 13, 14}

    if sector_id in meson_norte:
        return "Mesón Norte"
    if sector_id in meson_sur:
        return "Mesón Sur"
    if sector_id in meson_entrada:
        return "Mesón Entrada"
    return "No definida"


# ======================
# CONTACTS CACHE (NUEVO)
# ======================
def get_contacts_cache():
    """
    Retorna la lista de contactos desde caché en memoria.
    Si el caché expiró, lo recarga desde Supabase.
    """
    global CONTACTS_CACHE, CONTACTS_CACHE_LAST_UPDATE
    now = time.time()
    with contacts_cache_lock:
        if now - CONTACTS_CACHE_LAST_UPDATE > CONTACTS_CACHE_TTL or not CONTACTS_CACHE:
            try:
                # Traemos TODOS los contactos de una vez (máx 10.000)
                res = supabase.table("contactos").select("nombre, telefono, nombre_norm").limit(10000).execute()
                CONTACTS_CACHE = res.data or []
                CONTACTS_CACHE_LAST_UPDATE = now
            except Exception:
                pass  # Si falla, usamos caché anterior si existe
    return CONTACTS_CACHE


def invalidate_contacts_cache():
    global CONTACTS_CACHE_LAST_UPDATE
    with contacts_cache_lock:
        CONTACTS_CACHE_LAST_UPDATE = 0


# ======================
# AUTH ROUTES
# ======================
@app.route('/auth/login', methods=['POST'])
def auth_login():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    data = request.get_json(silent=True) or {}
    email    = (data.get('email') or '').strip()
    password = (data.get('password') or '').strip()

    if not email or not password:
        return jsonify({"status": "error", "message": "Email y contraseña requeridos"}), 400

    try:
        res = supabase.auth.sign_in_with_password({"email": email, "password": password})
        session = res.session
        user    = res.user
        if not session or not user:
            return jsonify({"status": "error", "message": "Credenciales incorrectas"}), 401

        return jsonify({
            "status":        "success",
            "access_token":  session.access_token,
            "refresh_token": session.refresh_token,
            "user": {
                "id":    str(user.id),
                "email": user.email,
            }
        })
    except Exception as e:
        msg = str(e).lower()
        if "invalid" in msg or "credentials" in msg or "email" in msg:
            return jsonify({"status": "error", "message": "Email o contraseña incorrectos"}), 401
        return jsonify({"status": "error", "message": "Error al iniciar sesión. Intenta nuevamente."}), 500


# ======================
# FRONTEND ROUTES
# ======================
@app.route('/')
def index():
    return render_template('login.html')


@app.route('/mapa')
def mapa():
    return render_template('index.html')


@app.route('/admin')
def admin():
    return render_template('admin.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/health')
def health():
    return jsonify({
        "status": "ok" if SUPABASE_ENABLED else "degraded",
        "supabase_configured": SUPABASE_ENABLED,
        "missing_vars": missing_vars,
        "supabase_init_error": supabase_init_error,
        "contacts_cached": len(CONTACTS_CACHE),
    }), 200


@app.route('/ver_asignacion/<token>')
def ver_asignacion(token):
    try:
        payload = token_serializer.loads(token)
    except BadSignature:
        return "Link inválido o expirado", 400

    fila = str(payload.get("fila", "")).strip()
    if not fila:
        return "Asignación inválida", 400

    return render_template('ver_asignacion.html', fila_asignada=fila)


# ======================
# CONTACTS FUNCTIONS
# ======================
def guardar_telefono(nombre, telefono):
    supabase.table("contactos").insert({
        "nombre": nombre.strip(),
        "nombre_norm": normalize_text(nombre),
        "telefono": str(telefono).strip()
    }).execute()
    invalidate_contacts_cache()


# ======================
# BÚSQUEDA CON CACHÉ (MEJORADA)
# ======================
@app.route('/contactos/sugerencias')
def contactos_sugerencias():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    q = (request.args.get('q') or '').strip()
    if len(q) < 2:
        return jsonify({"rows": []})

    qn = normalize_text(q)

    # Buscar desde caché local (instantáneo, sin ir a Supabase)
    contacts = get_contacts_cache()

    rows = []
    seen = set()
    for c in contacts:
        nombre = str(c.get("nombre") or "").strip()
        telefono = str(c.get("telefono") or "").strip()
        nombre_norm = str(c.get("nombre_norm") or normalize_text(nombre))

        if not nombre:
            continue

        # Búsqueda tolerante: buscar el query normalizado dentro del nombre normalizado
        if qn not in nombre_norm:
            continue

        key = (nombre.lower(), telefono)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"nombre": nombre, "telefono": telefono})

    rows.sort(key=lambda x: normalize_text(x.get("nombre", "")))
    return jsonify({"rows": rows[:10]})


# Endpoint para precargar contactos en el cliente (NUEVO)
@app.route('/contactos/todos')
def contactos_todos():
    """
    Retorna TODOS los contactos para caché del navegador.
    Solo se llama una vez al cargar la app.
    """
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    contacts = get_contacts_cache()
    # Retornar solo nombre y teléfono (sin datos sensibles extra)
    rows = [{"nombre": c.get("nombre", ""), "telefono": c.get("telefono", ""), "nombre_norm": c.get("nombre_norm", "")} for c in contacts if c.get("nombre")]
    return jsonify({"rows": rows, "total": len(rows)})


# ======================
# MAIN REGISTER ENDPOINT
# ======================
@app.route('/enviar_asignacion', methods=['POST'])
def enviar_asignacion():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    try:
        user, err, code = get_current_user()
        if err:
            return err, code

        data = request.get_json(silent=True) or {}
        nombre = data.get('nombre')
        fila = str(data.get('fila'))
        sector = data.get('sector')
        telefono_enviado = data.get('telefono')

        if not nombre or not fila or not sector:
            return jsonify({"status": "error", "message": "Faltan datos requeridos"}), 400

        nombre_buscado = nombre.strip()
        nombre_norm = normalize_text(nombre_buscado)

        # Buscar desde caché en memoria primero
        contacts = get_contacts_cache()
        candidatos = [
            c for c in contacts
            if normalize_text(c.get("nombre", "")) == nombre_norm
        ]

        # Si no hay en caché, buscar en Supabase directamente
        if not candidatos:
            contacto = (
                supabase.table("contactos")
                .select("nombre, telefono")
                .ilike("nombre", f"%{nombre_buscado}%")
                .limit(50)
                .execute()
            )
            candidatos_raw = contacto.data or []
            candidatos = [
                c for c in candidatos_raw
                if normalize_text(c.get("nombre", "")) == nombre_norm
            ]

        telefono_destino = None
        telefono_enviado = str(telefono_enviado).strip() if telefono_enviado else ""

        if len(candidatos) > 1:
            telefonos_candidatos = sorted(set(str(c.get("telefono", "")).strip() for c in candidatos if c.get("telefono")))
            if not telefono_enviado:
                return jsonify({
                    "status": "choose_phone",
                    "message": "Se encontraron varias personas con ese nombre. Seleccione el teléfono correcto.",
                    "options": telefonos_candidatos
                })
            if telefono_enviado not in telefonos_candidatos:
                return jsonify({
                    "status": "error",
                    "message": "El teléfono seleccionado no coincide con las opciones encontradas para ese nombre."
                }), 400
            telefono_destino = telefono_enviado

        elif len(candidatos) == 1:
            telefono_destino = str(candidatos[0].get("telefono", "")).strip()

        if not telefono_destino:
            if not telefono_enviado:
                return jsonify({
                    "status": "need_phone",
                    "message": "Hermano no encontrado. Ingrese teléfono."
                })
            telefono_destino = telefono_enviado
            supabase.table("contactos").insert({
                "nombre": nombre.strip(),
                "nombre_norm": normalize_text(nombre.strip()),
                "telefono": telefono_destino
            }).execute()
            invalidate_contacts_cache()

        # Validar nombre repetido
        nombre_existente = (
            supabase.table("registros_santa_cena")
            .select("id, fila")
            .ilike("nombre", nombre.strip())
            .execute()
        )
        if nombre_existente.data:
            fila_actual = nombre_existente.data[0].get("fila")
            return jsonify({
                "status": "error",
                "message": f"Este hermano ya está registrado en la fila {fila_actual}"
            }), 400

        # Validar fila repetida
        fila_existente = supabase.table("registros_santa_cena") \
            .select("id") \
            .eq("fila", fila) \
            .execute()
        if fila_existente.data:
            return jsonify({"status": "error", "message": "Fila ya ocupada"}), 400

        # Guardar registro
        supabase.table("registros_santa_cena").insert({
            "nombre": nombre.strip(),
            "fila": fila,
            "sector": sector,
            "registrador_id": user.id,
            "registrador_email": user.email
        }).execute()

        # Generar link WhatsApp
        mesa_label = obtener_mesa_label(sector)
        token = token_serializer.dumps({"fila": fila})
        link_visualizacion = f"{request.host_url.rstrip('/')}/ver_asignacion/{token}"

        mensaje = (
            f"✅ *Registro Santa Cena 2026*\n\n"
            f"Hola hermano(a) *{nombre}*,\n"
            f"Su lugar asignado es:\n"
            f"📍 *Sector {sector}*\n"
            f"🧭 *{mesa_label}*\n"
            f"🪑 *Fila {fila}*\n\n"
            f"🔎 Ver mapa interactivo:\n"
            f"Pincha aquí 👉 {link_visualizacion}"
        )

        url_wa = f"https://wa.me/{telefono_destino}?text={urllib.parse.quote(mensaje)}"
        return jsonify({"status": "success", "url_whatsapp": url_wa})

    except Exception as e:
        app.logger.exception('Error en /enviar_asignacion')
        return jsonify({"status": "error", "message": str(e) or 'Error interno al registrar'}), 500


# ======================
# ADMIN API
# ======================
@app.route('/mis_registros')
def mis_registros():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    res = supabase.table("registros_santa_cena") \
        .select("*") \
        .eq("registrador_id", user.id) \
        .order("created_at", desc=True) \
        .execute()
    return jsonify(res.data)


@app.route('/registros/listar')
def registros_listar():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    is_admin = require_admin(user)
    query = supabase.table("registros_santa_cena").select("*").order("created_at", desc=True)
    if not is_admin:
        query = query.eq("registrador_id", user.id)
    res = query.execute()
    return jsonify({"rows": res.data or [], "is_admin": is_admin})


@app.route('/admin/listar')
def admin_listar():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso solo administrador"}), 403
    res = supabase.table("registros_santa_cena") \
        .select("*") \
        .order("created_at", desc=True) \
        .execute()
    return jsonify(res.data)


@app.route('/admin/borrar', methods=['POST'])
def admin_borrar():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso solo administrador"}), 403
    data = request.get_json(silent=True) or {}
    registro_id = data.get("id")
    if not registro_id:
        return jsonify({"status": "error", "message": "ID requerido"}), 400
    supabase.table("registros_santa_cena") \
        .delete() \
        .eq("id", registro_id) \
        .execute()
    return jsonify({"status": "ok"})


@app.route('/registros/borrar', methods=['POST'])
def registros_borrar():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    data = request.get_json(silent=True) or {}
    registro_id = data.get("id")
    if not registro_id:
        return jsonify({"status": "error", "message": "ID requerido"}), 400
    existing = (
        supabase.table("registros_santa_cena")
        .select("id")
        .eq("id", registro_id)
        .eq("registrador_id", user.id)
        .limit(1)
        .execute()
    )
    if not existing.data:
        return jsonify({"status": "error", "message": "Registro no encontrado o sin permiso"}), 404
    supabase.table("registros_santa_cena") \
        .delete() \
        .eq("id", registro_id) \
        .eq("registrador_id", user.id) \
        .execute()
    return jsonify({"status": "ok"})


@app.route('/admin/reset', methods=['POST'])
def admin_reset():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso solo administrador"}), 403
    supabase.table("registros_santa_cena") \
        .delete() \
        .neq("id", 0) \
        .execute()
    return jsonify({"status": "ok"})


@app.route('/admin/export')
def admin_export():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error
    user, err, code = get_current_user()
    if err:
        return err, code
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso solo administrador"}), 403
    res = supabase.table("registros_santa_cena").select("*").execute()
    try:
        import pandas as pd
    except Exception:
        return jsonify({"status": "error", "message": "Pandas no disponible en el servidor"}), 503
    df = pd.DataFrame(res.data)
    path = "export.csv"
    df.to_csv(path, index=False)
    return send_file(path, as_attachment=True)


# ======================
# INICIALIZACIÓN ANTICIPADA (NUEVO)
# Precarga Supabase al arrancar en vez de en la primera request
# ======================
def init_on_startup():
    global supabase
    if SUPABASE_ENABLED and supabase is None:
        try:
            supabase = build_supabase_client(SUPABASE_URL, SUPABASE_KEY)
            app.logger.info("✅ Supabase inicializado al arrancar.")
            get_contacts_cache()
            app.logger.info(f"✅ Caché de contactos cargado: {len(CONTACTS_CACHE)} contactos.")
        except Exception as e:
            app.logger.error(f"❌ Error al inicializar Supabase: {e}")

    # Keep-alive para evitar cold start en Render plan gratuito
    try:
        from keep_alive import start_keep_alive
        start_keep_alive(interval_minutes=10)
    except Exception as e:
        app.logger.warning(f"⚠️ Keep-alive no iniciado: {e}")


# ======================
# RUN FOR RENDER
# ======================
if __name__ == '__main__':
    init_on_startup()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
else:
    # Para gunicorn (Render en producción)
    init_on_startup()
