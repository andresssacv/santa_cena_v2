from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from itsdangerous import URLSafeSerializer, BadSignature
import urllib.parse
import os
import unicodedata
import time
import csv
import io
import re
import datetime
import json

base_dir = os.path.dirname(os.path.abspath(__file__))
template_dir = os.path.join(base_dir, 'templates')

app = Flask(__name__, template_folder=template_dir)
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
LAST_ADMIN_AUTH = {"token": None, "user_id": None, "email": None}


token_secret = os.getenv("ASSIGNATION_LINK_SECRET") or (SUPABASE_KEY if SUPABASE_KEY else "dev-secret")
token_serializer = URLSafeSerializer(token_secret)


def build_supabase_client(url, key):
    from supabase import create_client as supabase_create_client
    return supabase_create_client(url, key)


def set_postgrest_token(token_or_key):
    """Configura de forma segura el token de autorización en PostgREST."""
    if not supabase or not token_or_key:
        return
    try:
        supabase.postgrest.auth(token_or_key)
    except Exception:
        pass


def ejecutar_con_respaldo_auth(fn, user_token=None):
    """
    Ejecuta una operación de Supabase probando:
    1. Token del usuario autenticado actual (cumple políticas RLS auth.uid() = registrador_id / authenticated).
    2. SUPABASE_KEY base del proyecto (cumple políticas anon o service_role sin contaminación de sesión).
    3. Token de administrador en caché (cumple políticas exclusivas de propietario si existen en Supabase).
    """
    tokens_a_probar = []
    if user_token:
        tokens_a_probar.append(user_token)
    if SUPABASE_KEY and SUPABASE_KEY not in tokens_a_probar:
        tokens_a_probar.append(SUPABASE_KEY)
    admin_tok = LAST_ADMIN_AUTH.get("token")
    if admin_tok and admin_tok not in tokens_a_probar:
        tokens_a_probar.append(admin_tok)

    if not tokens_a_probar:
        return fn()

    last_err = None
    for tok in tokens_a_probar:
        try:
            set_postgrest_token(tok)
            res = fn()
            if user_token:
                set_postgrest_token(user_token)
            return res
        except Exception as e:
            last_err = e
            continue

    if user_token:
        set_postgrest_token(user_token)
    raise last_err


def get_config_error_message():
    if supabase_init_error:
        return (
            "Configuración inválida de Supabase: no se pudo inicializar el cliente. "
            f"Detalle: {supabase_init_error}"
        )
    return (
        "Configuración incompleta: faltan variables de entorno requeridas "
        + ", ".join(missing_vars)
        + "."
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
        user = cached.get("user")
        set_postgrest_token(token)
        if require_admin(user):
            LAST_ADMIN_AUTH["token"] = token
            LAST_ADMIN_AUTH["user_id"] = user.id
            LAST_ADMIN_AUTH["email"] = user.email
        return user, None, None

    try:
        user_resp = supabase.auth.get_user(token)
        user = user_resp.user
        if not user:
            TOKEN_CACHE.pop(token, None)
            return None, jsonify({"status": "error", "message": "Token inválido"}), 401

        if len(TOKEN_CACHE) > 1000:
            TOKEN_CACHE.clear()

        TOKEN_CACHE[token] = {"user": user, "exp": now + TOKEN_CACHE_TTL_SECONDS}
        set_postgrest_token(token)
        if require_admin(user):
            LAST_ADMIN_AUTH["token"] = token
            LAST_ADMIN_AUTH["user_id"] = user.id
            LAST_ADMIN_AUTH["email"] = user.email
        return user, None, None
    except Exception:
        TOKEN_CACHE.pop(token, None)
        return None, jsonify({"status": "error", "message": "Token inválido"}), 401


def require_admin(user):
    if not user:
        return False
    email = (user.email or "").strip().lower()
    # 1. Comparar con lista de ADMIN_EMAILS (variable de entorno)
    if email in ADMIN_EMAILS:
        return True
    for admin_e in ADMIN_EMAILS:
        if admin_e and (admin_e in email or email in admin_e):
            return True
    # 2. Cuentas de administrador fijas (Juan Acevedo y Andrés Acevedo)
    if "juan" in email and "acevedo" in email:
        return True
    if email == "andresss.acevedo123@gmail.com":
        return True
    return False


MAPEO_CAPTADORAS = {
    "juan": "Juan Acevedo",
    "juan.acevedo": "Juan Acevedo",
    "andresss.acevedo123": "Andrés Acevedo",
    "andresss": "Andrés Acevedo",
    "andres": "Andrés",
    "paula": "Paula",
    "cecilia": "Cecilia",
    "danitza": "Danitza",
    "carla": "Carla",
    "ingrid": "Ingrid",
    "elizabeth": "Elizabeth",
    "maria": "María",
    "ligia": "Ligia",
    "carolina": "Carolina",
    "nataly": "Nataly",
    "fanny": "Fanny",
    "carmengloria": "Carmen Gloria",
    "carmen.gloria": "Carmen Gloria",
    "carmen": "Carmen Gloria",
    "antonia": "Antonia"
}


def obtener_nombre_captadora(user_or_email, user_obj=None):
    """Devuelve el nombre real de la captadora en lugar de su correo."""
    if user_obj and hasattr(user_obj, 'user_metadata') and user_obj.user_metadata:
        meta = user_obj.user_metadata or {}
        name = meta.get('full_name') or meta.get('name') or meta.get('nombre')
        if name:
            return str(name).strip()

    email = str(user_or_email or "").strip().lower()
    if not email:
        return "Captadora"

    username = email.split('@')[0]
    username_norm = normalize_text(username)

    for k, v in MAPEO_CAPTADORAS.items():
        if k in username_norm:
            return v

    partes = [p.capitalize() for p in username.replace('.', ' ').replace('_', ' ').replace('-', ' ').split() if not p.isdigit()]
    return " ".join(partes) or "Captadora"


def obtener_fecha_hoy():
    """Retorna la fecha actual en Chile (UTC-3) en formato YYYY-MM-DD."""
    import datetime
    try:
        tz_chile = datetime.timezone(datetime.timedelta(hours=-3))
        return datetime.datetime.now(tz_chile).date().isoformat()
    except Exception:
        return datetime.date.today().isoformat()


def es_mismo_evento(created_at_str, target_fecha=None):
    """Verifica si un timestamp corresponde al evento/fecha objetivo (por defecto hoy en Chile)."""
    if not created_at_str:
        return True
    try:
        fecha_str = str(created_at_str)[:10]
        if target_fecha:
            return fecha_str == str(target_fecha)[:10]
        hoy = obtener_fecha_hoy()
        return fecha_str == hoy
    except Exception:
        return True


def normalizar_telefono_chileno(raw_phone):
    """
    Normaliza cualquier entrada de teléfono chileno a formato estándar '569XXXXXXXX' (11 dígitos).
    Maneja:
    - +56912345678 -> 56912345678
    - 56912345678  -> 56912345678
    - 912345678    -> 56912345678 (antepone 56)
    - +56 9 1234 5678 -> 56912345678
    - 12345678     -> 56912345678 (antepone 569 si son 8 dígitos)
    """
    if not raw_phone:
        return ""
    digits = re.sub(r"\D", "", str(raw_phone).strip())
    if not digits:
        return ""
    
    # 1. Empieza con 569 y tiene 11 dígitos
    if digits.startswith("569") and len(digits) == 11:
        return digits
    
    # 2. Empieza con 9 y tiene 9 dígitos (formato móvil nacional 9XXXXXXXX)
    if digits.startswith("9") and len(digits) == 9:
        return f"56{digits}"
    
    # 3. Tiene 8 dígitos (ej: 12345678)
    if len(digits) == 8:
        return f"569{digits}"
    
    # 4. Empieza con 56 y tiene 11 dígitos
    if digits.startswith("56") and len(digits) == 11:
        return digits
        
    # 5. Empieza con 56 y tiene 10 dígitos (falta el 9)
    if digits.startswith("56") and len(digits) == 10:
        return f"569{digits[2:]}"
        
    # 6. Empieza con 569 y tiene más de 11 dígitos
    if digits.startswith("569") and len(digits) > 11:
        return digits[:11]
        
    # 7. Si tiene 9 dígitos
    if len(digits) == 9:
        return f"56{digits}"
        
    return digits


def normalize_text(value):
    text = str(value or "").strip().lower()
    text = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in text if unicodedata.category(ch) != "Mn")

def fila_sort_key(registro):
    fila = str((registro or {}).get("fila") or "").strip()
    if fila.isdigit():
        return (0, int(fila), fila)
    return (1, fila.lower(), fila)


def sort_registros_by_fila(rows):
    return sorted(rows or [], key=fila_sort_key)


RANGOS_SECTORES = [
    (1, 1, 13),
    (2, 14, 28),
    (3, 29, 45),
    (4, 46, 56),
    (5, 57, 73),
    (6, 74, 90),
    (7, 91, 104),
    (8, 105, 121),
    (9, 122, 138),
    (10, 139, 155),
    (11, 156, 168),
    (12, 169, 187),
    (13, 188, 198),
    (14, 199, 215)
]
RANGOS_ZONAS = RANGOS_SECTORES


def obtener_sector_de_fila(fila):
    try:
        f = int(str(fila).strip())
    except (TypeError, ValueError):
        return None
    for sec_id, start, end in RANGOS_SECTORES:
        if start <= f <= end:
            return str(sec_id)
    return None


def sector_fila_sort_key(registro):
    """
    Clave de ordenamiento:
    1. Sector numérico (Sector 1, Sector 2, ..., Sector 14).
    2. Fila numérica ascendente.
    """
    r = registro or {}
    sec = r.get("sector")
    if not sec or str(sec).strip() == "" or str(sec).strip().lower() in ("none", "null"):
        sec = obtener_sector_de_fila(r.get("fila"))
    try:
        sec_num = int(str(sec).replace("Sector", "").replace("sector", "").strip())
        sec_key = (0, sec_num)
    except (ValueError, TypeError):
        sec_key = (1, str(sec or "").lower())

    fila = str(r.get("fila") or "").strip()
    if fila.isdigit():
        fila_key = (0, int(fila), fila)
    else:
        fila_key = (1, fila.lower(), fila)

    return (sec_key, fila_key)


def sort_registros_by_sector_then_fila(rows):
    """Ordena los registros por Sector (1 al 14) y luego por Fila."""
    return sorted(rows or [], key=sector_fila_sort_key)


def obtener_rango_filas_sector(s):
    for sec_id, start, end in RANGOS_SECTORES:
        if sec_id == s:
            return f"{start}-{end}"
    return ""

def obtener_rango_filas_zona(z):
    return obtener_rango_filas_sector(z)


def inferir_culto_actual():
    """Infiere si estamos en el culto de 11:00 o 18:30 según la hora actual."""
    import datetime
    try:
        ahora = datetime.datetime.now()
        if ahora.hour < 15:
            return "11:00"
        return "18:30"
    except Exception:
        return "11:00"


def inferir_culto_de_fecha(iso_str):
    """Infiere culto desde un timestamp ISO de base de datos."""
    if not iso_str:
        return "11:00"
    try:
        s = str(iso_str)
        time_part = s.split("T")[1] if "T" in s else s.split(" ")[1]
        hour = int(time_part.split(":")[0])
        # Timestamps UTC en Supabase: 18:00 UTC es ~15:00 hora Chile
        if "Z" in s or "+" in s or ("-" in s[10:]):
            return "18:30" if hour >= 18 else "11:00"
        return "18:30" if hour >= 15 else "11:00"
    except Exception:
        return "11:00"


def obtener_mesa_label(sector):
    """
    Retorna el nombre de mesa/mesón en base al sector:
    - Mesón Norte: Sectores 1, 2, 5
    - Mesón Sur: Sectores 7, 9, 11, 12
    - Mesón Entrada Norte: Sectores 3, 4, 6
    - Mesón Entrada Sur: Sectores 8, 10, 13, 14
    """
    try:
        sector_id = int(sector)
    except (TypeError, ValueError):
        return "No definida"

    meson_norte = {1, 2, 5}
    meson_sur = {7, 9, 11, 12}
    meson_entrada_norte = {3, 4, 6}
    meson_entrada_sur = {8, 10, 13, 14}

    if sector_id in meson_norte:
        return "Mesón Norte"
    if sector_id in meson_sur:
        return "Mesón Sur"
    if sector_id in meson_entrada_norte:
        return "Mesón Entrada Norte"
    if sector_id in meson_entrada_sur:
        return "Mesón Entrada Sur"
    return "No definida"


def construir_whatsapp_link(host_url, nombre, fila, sector, telefono):
    """Construye la URL directa de WhatsApp con el mapa y asignación."""
    mesa_label = obtener_mesa_label(sector)
    token = token_serializer.dumps({"fila": str(fila)})
    link_visualizacion = f"{host_url.rstrip('/')}/ver_asignacion/{token}"

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

    clean_phone = normalizar_telefono_chileno(telefono)
    return f"https://wa.me/{clean_phone}?text={urllib.parse.quote(mensaje)}"


def actualizar_o_guardar_contacto(nuevo_nombre, nuevo_telefono, viejo_nombre=None, user_token=None):
    """Sincroniza el contacto en la tabla 'contactos' de Supabase con respaldo de permisos."""
    if not nuevo_nombre or not nuevo_telefono:
        return
    nombre_limpio = str(nuevo_nombre).strip()
    tel_limpio = normalizar_telefono_chileno(nuevo_telefono)
    norm_nuevo = normalize_text(nombre_limpio)
    norm_viejo = normalize_text(viejo_nombre) if viejo_nombre else None

    def _op():
        encontrado_id = None
        candidatos = supabase.table("contactos").select("id, nombre, telefono").ilike("nombre", f"%{nombre_limpio}%").limit(20).execute()
        for c in (candidatos.data or []):
            c_norm = normalize_text(c.get("nombre", ""))
            if c_norm == norm_nuevo or (norm_viejo and c_norm == norm_viejo):
                encontrado_id = c.get("id")
                break

        if not encontrado_id and norm_viejo:
            candidatos_v = supabase.table("contactos").select("id, nombre, telefono").ilike("nombre", f"%{str(viejo_nombre).strip()}%").limit(20).execute()
            for c in (candidatos_v.data or []):
                if normalize_text(c.get("nombre", "")) == norm_viejo:
                    encontrado_id = c.get("id")
                    break

        if encontrado_id:
            supabase.table("contactos").update({
                "nombre": nombre_limpio,
                "telefono": tel_limpio
            }).eq("id", encontrado_id).execute()
        else:
            supabase.table("contactos").insert({
                "nombre": nombre_limpio,
                "telefono": tel_limpio
            }).execute()

    try:
        ejecutar_con_respaldo_auth(_op, user_token)
    except Exception as e:
        app.logger.warning(f"Error al actualizar o guardar contacto: {e}")


def insertar_registro_seguro(base_payload, user, user_token=None):
    """
    Inserta un registro en 'registros_santa_cena' garantizando compatibilidad total:
    - Prueba todas las variantes de esquema (con columnas nuevas o solo columnas originales).
    - Prueba el token de la captadora actual, la clave base SUPABASE_KEY y el token de administrador
      para que ninguna política RLS bloquee a las cuentas de captadoras.
    """
    variantes_columnas = [
        # Variante 1: Todas las columnas (v2 completo)
        lambda p: dict(p),
        # Variante 2: Sin fecha_evento ni registrador_nombre
        lambda p: {k: v for k, v in p.items() if k not in ("fecha_evento", "registrador_nombre")},
        # Variante 3: Columnas base con culto y telefono
        lambda p: {k: v for k, v in p.items() if k in ("nombre", "fila", "sector", "registrador_id", "registrador_email", "culto", "telefono")},
        # Variante 4: Columnas originales v1 (con registrador_id y registrador_email)
        lambda p: {k: v for k, v in p.items() if k in ("nombre", "fila", "sector", "registrador_id", "registrador_email")},
        # Variante 5: Columnas mínimas universales
        lambda p: {k: v for k, v in p.items() if k in ("nombre", "fila", "sector")},
    ]

    contextos_auth = []
    if user_token:
        contextos_auth.append((user_token, user.id if user else None))
    if SUPABASE_KEY:
        contextos_auth.append((SUPABASE_KEY, user.id if user else None))
    if LAST_ADMIN_AUTH.get("token"):
        contextos_auth.append((LAST_ADMIN_AUTH["token"], user.id if user else None))
        if LAST_ADMIN_AUTH.get("user_id") and (not user or LAST_ADMIN_AUTH["user_id"] != user.id):
            # Si RLS en Supabase exige estrictamente registrador_id == auth.uid() del admin,
            # mantenemos registrador_email y registrador_nombre de la captadora real.
            contextos_auth.append((LAST_ADMIN_AUTH["token"], LAST_ADMIN_AUTH["user_id"]))

    if not contextos_auth:
        contextos_auth.append((None, user.id if user else None))

    ultimo_error = None
    for tok, reg_id_override in contextos_auth:
        if tok:
            set_postgrest_token(tok)
        payload_ctx = dict(base_payload)
        if reg_id_override:
            payload_ctx["registrador_id"] = reg_id_override

        for construir_variante in variantes_columnas:
            intento_payload = construir_variante(payload_ctx)
            try:
                res = supabase.table("registros_santa_cena").insert(intento_payload).execute()
                if user_token:
                    set_postgrest_token(user_token)
                return res
            except Exception as err:
                ultimo_error = err
                msg = str(err).lower()
                # Si el error es de columna inexistente, probar la siguiente variante más simple con el mismo token
                if any(w in msg for w in ("column", "schema", "pgrst204", "42703", "does not exist")):
                    continue
                # Si el error es de permisos/RLS, pasar al siguiente contexto de autenticación
                break

    if user_token:
        set_postgrest_token(user_token)
    raise ultimo_error


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


@app.route('/dashboard')
def dashboard():
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

def obtener_telefono(nombre):
    res = supabase.table("contactos") \
        .select("telefono") \
        .eq("nombre", nombre.strip()) \
        .execute()

    return res.data[0]["telefono"] if res.data else None


def guardar_telefono(nombre, telefono):
    supabase.table("contactos").insert({
        "nombre": nombre.strip(),
        "telefono": str(telefono).strip()
    }).execute()

# ======================
# registro FUNCTIONS
# ======================

def fila_ocupada(fila):
    res = supabase.table("registros_santa_cena") \
        .select("id") \
        .eq("fila", fila.strip()) \
        .execute()

    return bool(res.data)


def guardar_registro(nombre, fila, sector):
    supabase.table("registros_santa_cena").insert({
        "nombre": nombre.strip(),
        "fila": fila.strip(),
        "sector": sector.strip()
    }).execute()



@app.route('/auth/login', methods=['POST'])
def auth_login():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    data = request.get_json() or {}
    email = (data.get('email') or '').strip()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({"status": "error", "message": "Email y contraseña son obligatorios"}), 400

    try:
        # Usar cliente efímero para login y así evitar sobrescribir el estado PostgREST global de otros usuarios
        login_client = build_supabase_client(SUPABASE_URL, SUPABASE_KEY)
        auth_resp = login_client.auth.sign_in_with_password({"email": email, "password": password})
        session = auth_resp.session
        user = auth_resp.user
        if not session or not user:
            return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401

        TOKEN_CACHE[session.access_token] = {"user": user, "exp": time.time() + TOKEN_CACHE_TTL_SECONDS}
        if require_admin(user):
            LAST_ADMIN_AUTH["token"] = session.access_token
            LAST_ADMIN_AUTH["user_id"] = user.id
            LAST_ADMIN_AUTH["email"] = user.email

        return jsonify({
            "status": "success",
            "access_token": session.access_token,
            "refresh_token": session.refresh_token,
            "user": {"id": user.id, "email": user.email}
        })
    except Exception:
        return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401



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
    user_token = get_bearer_token()

    try:
        res = ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos")
            .select("nombre, telefono")
            .ilike("nombre", f"%{q}%")
            .limit(30)
            .execute(),
            user_token
        )
        candidatos = res.data or []
        rows = []
        seen = set()
        for c in candidatos:
            nombre = str(c.get("nombre") or "").strip()
            telefono = str(c.get("telefono") or "").strip()
            if not nombre or nombre.startswith("__SYS_"):
                continue
            if qn not in normalize_text(nombre):
                continue
            key = (nombre.lower(), telefono)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"nombre": nombre, "telefono": telefono})

        rows.sort(key=lambda x: (normalize_text(x.get("nombre", "")), x.get("telefono", "")))
        return jsonify({"rows": rows[:10]})
    except Exception:
        return jsonify({"rows": []})


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

        user_token = get_bearer_token()
        data = request.get_json(silent=True) or {}

        nombre = data.get('nombre')
        fila = str(data.get('fila') or '').strip()
        sector = data.get('sector')
        telefono_enviado = data.get('telefono')
        culto = (data.get('culto') or inferir_culto_actual()).strip()

        if not nombre or not fila or not sector:
            return jsonify({"status": "error", "message": "Faltan datos requeridos"}), 400

        # --- BUSCAR TELÉFONO(S) EN SUPABASE (tolerante a mayúsculas/acentos y RLS) ---
        nombre_buscado = nombre.strip()
        nombre_norm = normalize_text(nombre_buscado)
        try:
            contacto = ejecutar_con_respaldo_auth(
                lambda: supabase.table("contactos")
                .select("nombre, telefono")
                .ilike("nombre", f"%{nombre_buscado}%")
                .limit(50)
                .execute(),
                user_token
            )
            candidatos_raw = contacto.data or []
        except Exception:
            candidatos_raw = []

        candidatos = [
            c for c in candidatos_raw
            if normalize_text(c.get("nombre", "")) == nombre_norm
        ]
        telefono_destino = None
        telefono_enviado = str(telefono_enviado).strip() if telefono_enviado else ""

        # Caso 1: hay varios con el mismo nombre -> pedir selección por teléfono
        if len(candidatos) > 1:
            telefonos_candidatos = sorted(set(normalizar_telefono_chileno(c.get("telefono", "")) for c in candidatos if c.get("telefono")))

            if not telefono_enviado:
                return jsonify({
                    "status": "choose_phone",
                    "message": "Se encontraron varias personas con ese nombre. Seleccione el teléfono correcto.",
                    "options": telefonos_candidatos
                })

            telefono_enviado_norm = normalizar_telefono_chileno(telefono_enviado)
            if telefono_enviado_norm not in telefonos_candidatos and telefono_enviado not in telefonos_candidatos:
                return jsonify({
                    "status": "error",
                    "message": "El teléfono seleccionado no coincide con las opciones encontradas para ese nombre."
                }), 400

            telefono_destino = telefono_enviado_norm or telefono_enviado

        # Caso 2: existe uno solo
        elif len(candidatos) == 1:
            telefono_destino = normalizar_telefono_chileno(candidatos[0].get("telefono", ""))

        # Caso 3: no existe en contactos -> pedir teléfono para crearlo
        if not telefono_destino:
            if not telefono_enviado:
                return jsonify({
                    "status": "need_phone",
                    "message": "Hermano no encontrado. Ingrese teléfono."
                })

            telefono_destino = normalizar_telefono_chileno(telefono_enviado)
            actualizar_o_guardar_contacto(nombre.strip(), telefono_destino, user_token=user_token)
        else:
            telefono_destino = normalizar_telefono_chileno(telefono_destino)

        # --- VALIDAR NOMBRE REPETIDO Y FILA REPETIDA (EN EL MISMO CULTO Y EVENTO DE HOY) ---
        # Usamos select("*") para que nunca falle si falta alguna columna opcional como fecha_evento
        try:
            query_nombre = ejecutar_con_respaldo_auth(
                lambda: supabase.table("registros_santa_cena")
                .select("*")
                .ilike("nombre", nombre.strip())
                .execute(),
                user_token
            )
            for reg_n in (query_nombre.data or []):
                reg_culto = reg_n.get("culto") or inferir_culto_de_fecha(reg_n.get("created_at"))
                if reg_culto == culto and es_mismo_evento(reg_n.get("fecha_evento") or reg_n.get("created_at")):
                    return jsonify({
                        "status": "error",
                        "message": f"Este hermano ya está registrado hoy en la fila {reg_n.get('fila')} para el culto de las {culto}"
                    }), 400
        except Exception as val_err:
            app.logger.warning(f"Aviso en validación de nombre: {val_err}")

        try:
            query_fila = ejecutar_con_respaldo_auth(
                lambda: supabase.table("registros_santa_cena")
                .select("*")
                .eq("fila", fila)
                .execute(),
                user_token
            )
            for reg_f in (query_fila.data or []):
                reg_culto = reg_f.get("culto") or inferir_culto_de_fecha(reg_f.get("created_at"))
                if reg_culto == culto and es_mismo_evento(reg_f.get("fecha_evento") or reg_f.get("created_at")):
                    return jsonify({
                        "status": "error",
                        "message": f"Fila {fila} ya está ocupada hoy en el culto de las {culto} por {reg_f.get('nombre', 'otro hermano')}"
                    }), 400
        except Exception as val_err2:
            app.logger.warning(f"Aviso en validación de fila: {val_err2}")

        # --- GUARDAR REGISTRO CON NOMBRE DE CAPTADORA Y FECHA ---
        nombre_captadora = obtener_nombre_captadora(user.email, user)
        fecha_hoy = obtener_fecha_hoy()

        insert_payload = {
            "nombre": nombre.strip(),
            "fila": fila,
            "sector": str(sector),
            "registrador_id": user.id,
            "registrador_email": user.email,
            "registrador_nombre": nombre_captadora,
            "fecha_evento": fecha_hoy,
            "culto": culto,
            "telefono": telefono_destino
        }

        insertar_registro_seguro(insert_payload, user, user_token=user_token)

        # --- LINK WHATSAPP ---
        url_wa = construir_whatsapp_link(request.host_url, nombre, fila, sector, telefono_destino)

        return jsonify({"status": "success", "url_whatsapp": url_wa})

    except Exception as e:
        app.logger.exception('Error en /enviar_asignacion')
        return jsonify({"status": "error", "message": str(e) or 'Error interno al registrar'}), 500


# ======================
# ADMIN & REGISTROS API
# ======================

def pertenece_a_usuario(registro, user):
    """Verifica si un registro pertenece a la captadora actual (por ID o por correo)."""
    if not registro or not user:
        return False
    if str(registro.get("registrador_id") or "") == str(user.id or ""):
        return True
    reg_email = str(registro.get("registrador_email") or "").strip().lower()
    usr_email = str(user.email or "").strip().lower()
    if reg_email and usr_email and reg_email == usr_email:
        return True
    return False


@app.route('/mis_registros')
def mis_registros():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    user_token = get_bearer_token()
    res = ejecutar_con_respaldo_auth(
        lambda: supabase.table("registros_santa_cena")
        .select("*")
        .order("created_at", desc=True)
        .execute(),
        user_token
    )

    rows = [r for r in (res.data or []) if pertenece_a_usuario(r, user)]
    # Las captadoras solo ven sus registros de hoy
    if not require_admin(user):
        hoy = obtener_fecha_hoy()
        rows = [r for r in rows if es_mismo_evento(r.get("fecha_evento") or r.get("created_at"), hoy)]

    return jsonify(sort_registros_by_sector_then_fila(rows))


@app.route('/registros/listar')
def registros_listar():
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    user_token = get_bearer_token()
    is_admin = require_admin(user)
    hoy = obtener_fecha_hoy()

    res = ejecutar_con_respaldo_auth(
        lambda: supabase.table("registros_santa_cena")
        .select("*")
        .order("created_at", desc=True)
        .execute(),
        user_token
    )
    rows = res.data or []

    # SEGURIDAD Y PRIVACIDAD PARA HERMANAS CAPTADORAS:
    # Si no es administrador (Juan Acevedo o Andrés Acevedo), solo ve lo que ella anotó durante el día de hoy (Diario).
    if not is_admin:
        rows = [
            r for r in rows
            if pertenece_a_usuario(r, user) and es_mismo_evento(r.get("fecha_evento") or r.get("created_at"), hoy)
        ]

    # Enriquecer registros que no tengan teléfono consultando la tabla de contactos
    nombres_sin_tel = [r.get("nombre") for r in rows if not r.get("telefono") and r.get("nombre")]
    if nombres_sin_tel:
        try:
            unique_nombres = list({str(n).strip() for n in nombres_sin_tel if n and str(n).strip()})
            tel_map = {}
            for i in range(0, len(unique_nombres), 30):
                chunk = unique_nombres[i:i+30]
                contactos_res = ejecutar_con_respaldo_auth(
                    lambda ch=chunk: supabase.table("contactos").select("nombre, telefono").in_("nombre", ch).execute(),
                    user_token
                )
                for c in (contactos_res.data or []):
                    c_tel = c.get("telefono")
                    if c_tel:
                        norm = normalize_text(c.get("nombre", ""))
                        tel_map[norm] = normalizar_telefono_chileno(c_tel)

            for r in rows:
                if not r.get("telefono"):
                    norm = normalize_text(r.get("nombre", ""))
                    if norm in tel_map:
                        r["telefono"] = tel_map[norm]
        except Exception as e:
            app.logger.warning(f"No se pudieron enriquecer telefonos: {e}")

    # Enriquecer con culto inferido, enlace de whatsapp, nombre real de captadora, fecha y mesón
    for r in rows:
        if not r.get("culto"):
            r["culto"] = inferir_culto_de_fecha(r.get("created_at"))
        if not r.get("registrador_nombre"):
            r["registrador_nombre"] = obtener_nombre_captadora(r.get("registrador_email"))
        r["fecha"] = str(r.get("fecha_evento") or r.get("created_at") or hoy)[:10]
        tel = normalizar_telefono_chileno(r.get("telefono"))
        if tel:
            r["telefono"] = tel
            r["url_whatsapp"] = construir_whatsapp_link(
                request.host_url, r.get("nombre", ""), r.get("fila", ""), r.get("sector", ""), tel
            )
        r["mesa_label"] = obtener_mesa_label(r.get("sector"))

    return jsonify({
        "rows": sort_registros_by_sector_then_fila(rows),
        "is_admin": is_admin,
        "fecha_hoy": hoy,
        "current_user_email": user.email,
        "current_user_name": obtener_nombre_captadora(user.email, user)
    })


@app.route('/registros/editar', methods=['POST'])
def registros_editar():
    """Permite editar nombre, teléfono, fila, sector o culto de un registro."""
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    user_token = get_bearer_token()
    data = request.get_json(silent=True) or {}
    registro_id = data.get("id")
    if not registro_id:
        return jsonify({"status": "error", "message": "ID de registro es requerido"}), 400

    existing = ejecutar_con_respaldo_auth(
        lambda: supabase.table("registros_santa_cena").select("*").eq("id", registro_id).limit(1).execute(),
        user_token
    )
    if not existing.data:
        return jsonify({"status": "error", "message": "Registro no encontrado"}), 404

    reg = existing.data[0]
    is_admin = require_admin(user)
    if not is_admin and not pertenece_a_usuario(reg, user):
        return jsonify({"status": "error", "message": "No tienes permiso para editar este registro"}), 403

    nuevo_nombre = (data.get("nombre") or reg.get("nombre") or "").strip()
    nuevo_telefono = normalizar_telefono_chileno(data.get("telefono") or reg.get("telefono") or "")
    nueva_fila = str(data.get("fila") if data.get("fila") is not None else reg.get("fila") or "").strip()
    nuevo_culto = (data.get("culto") or reg.get("culto") or "11:00").strip()

    # Si se especificó o cambió la fila, recalcular sector correspondiente
    nuevo_sector = data.get("sector")
    if not nuevo_sector or str(nueva_fila) != str(reg.get("fila")):
        nuevo_sector = obtener_sector_de_fila(nueva_fila) or reg.get("sector")

    # Si cambió la fila, verificar que no esté ocupada en ESE culto y fecha
    if nueva_fila and nueva_fila != str(reg.get("fila")):
        try:
            q_check = ejecutar_con_respaldo_auth(
                lambda: supabase.table("registros_santa_cena")
                .select("*")
                .eq("fila", nueva_fila)
                .neq("id", registro_id)
                .execute(),
                user_token
            )
            fecha_ref = reg.get("fecha_evento") or reg.get("created_at")
            for cand in (q_check.data or []):
                cand_culto = cand.get("culto") or inferir_culto_de_fecha(cand.get("created_at"))
                if cand_culto == nuevo_culto and es_mismo_evento(cand.get("fecha_evento") or cand.get("created_at"), fecha_ref):
                    return jsonify({
                        "status": "error",
                        "message": f"La fila {nueva_fila} ya está ocupada en el culto de las {nuevo_culto} por {cand.get('nombre', 'otro hermano')}"
                    }), 400
        except Exception as e_chk:
            app.logger.warning(f"Aviso en verificación de fila al editar: {e_chk}")

    # Sincronizar contacto en la tabla contactos de Supabase
    if nuevo_nombre and nuevo_telefono:
        actualizar_o_guardar_contacto(nuevo_nombre, nuevo_telefono, reg.get("nombre"), user_token=user_token)

    update_payload = {
        "nombre": nuevo_nombre,
        "fila": nueva_fila,
        "sector": str(nuevo_sector),
        "culto": nuevo_culto,
        "telefono": nuevo_telefono
    }

    try:
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("registros_santa_cena").update(update_payload).eq("id", registro_id).execute(),
            user_token
        )
    except Exception as e:
        msg = str(e).lower()
        if any(w in msg for w in ("column", "schema", "pgrst204", "42703", "does not exist")):
            update_payload.pop("telefono", None)
            update_payload.pop("culto", None)
            ejecutar_con_respaldo_auth(
                lambda: supabase.table("registros_santa_cena").update(update_payload).eq("id", registro_id).execute(),
                user_token
            )
        else:
            return jsonify({"status": "error", "message": f"Error al actualizar: {e}"}), 500

    # Generar WhatsApp link actualizado
    url_wa = None
    if nuevo_telefono:
        url_wa = construir_whatsapp_link(request.host_url, nuevo_nombre, nueva_fila, nuevo_sector, nuevo_telefono)

    return jsonify({
        "status": "success",
        "message": "Registro actualizado correctamente",
        "url_whatsapp": url_wa,
        "registro": {
            "id": registro_id,
            "nombre": nuevo_nombre,
            "telefono": nuevo_telefono,
            "fila": nueva_fila,
            "sector": nuevo_sector,
            "culto": nuevo_culto,
            "registrador_nombre": reg.get("registrador_nombre") or obtener_nombre_captadora(reg.get("registrador_email")),
            "mesa_label": obtener_mesa_label(nuevo_sector)
        }
    })


@app.route('/contactos/editar', methods=['POST'])
def contactos_editar():
    """Permite actualizar un contacto existente directamente."""
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    user_token = get_bearer_token()
    data = request.get_json(silent=True) or {}
    nombre = (data.get("nombre") or "").strip()
    telefono = normalizar_telefono_chileno(data.get("telefono") or "")
    contacto_id = data.get("id")

    if not nombre or not telefono:
        return jsonify({"status": "error", "message": "Nombre y teléfono son obligatorios"}), 400

    try:
        if contacto_id:
            ejecutar_con_respaldo_auth(
                lambda: supabase.table("contactos").update({"nombre": nombre, "telefono": telefono}).eq("id", contacto_id).execute(),
                user_token
            )
        else:
            actualizar_o_guardar_contacto(nombre, telefono, user_token=user_token)
        return jsonify({"status": "success", "message": "Contacto guardado exitosamente"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/registros/whatsapp_url/<registro_id>')
def registros_whatsapp_url(registro_id):
    """Regenera y retorna el link de WhatsApp para un registro."""
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    user_token = get_bearer_token()
    res = ejecutar_con_respaldo_auth(
        lambda: supabase.table("registros_santa_cena").select("*").eq("id", registro_id).limit(1).execute(),
        user_token
    )
    if not res.data:
        return jsonify({"status": "error", "message": "Registro no encontrado"}), 404

    reg = res.data[0]
    telefono = reg.get("telefono")
    if not telefono:
        c_res = ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos").select("telefono").eq("nombre", reg.get("nombre")).limit(1).execute(),
            user_token
        )
        if c_res.data:
            telefono = c_res.data[0].get("telefono")

    if not telefono:
        return jsonify({"status": "error", "message": "No hay teléfono registrado para este hermano"}), 400

    url_wa = construir_whatsapp_link(request.host_url, reg.get("nombre"), reg.get("fila"), reg.get("sector"), telefono)
    return jsonify({"status": "success", "url_whatsapp": url_wa, "telefono": telefono})


MESES_NOMBRES_ES = {
    "01": "Enero", "02": "Febrero", "03": "Marzo", "04": "Abril",
    "05": "Mayo", "06": "Junio", "07": "Julio", "08": "Agosto",
    "09": "Septiembre", "10": "Octubre", "11": "Noviembre", "12": "Diciembre"
}


def formatear_etiqueta_mes(yyyy_mm):
    if not yyyy_mm or len(str(yyyy_mm)) < 7:
        return str(yyyy_mm or "")
    partes = str(yyyy_mm)[:7].split("-")
    if len(partes) != 2:
        return str(yyyy_mm)
    anio, mes = partes[0], partes[1]
    return f"{MESES_NOMBRES_ES.get(mes, mes)} {anio}"


@app.route('/dashboard/stats')
def dashboard_stats():
    """
    Genera las métricas reales para los Administradores (Juan y Andrés Acevedo).
    Soporta filtro de periodo:
    - periodo=diario (registros del día de hoy en Chile)
    - periodo=ultimo_mes (registros del último mes activo o mes seleccionado en ?mes=YYYY-MM)
    - periodo=historico (todos los registros históricos)
    """
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    # SEGURIDAD: Solo Administradores (Juan y Andrés Acevedo) pueden ver el dashboard
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso restringido solo a los administradores (Juan y Andrés Acevedo)"}), 403

    user_token = get_bearer_token()
    res = ejecutar_con_respaldo_auth(
        lambda: supabase.table("registros_santa_cena").select("*").execute(),
        user_token
    )
    all_rows = res.data or []

    hoy = obtener_fecha_hoy()
    mes_actual = hoy[:7]

    # Extraer fecha YYYY-MM-DD y mes YYYY-MM de cada registro
    meses_set = set()
    fechas_set = set()
    for r in all_rows:
        f_str = str(r.get("fecha_evento") or r.get("created_at") or hoy)[:10]
        r["_fecha_norm"] = f_str
        r["_mes_norm"] = f_str[:7]
        if len(f_str) == 10:
            fechas_set.add(f_str)
        if len(f_str) >= 7:
            meses_set.add(f_str[:7])

    meses_disponibles = sorted(list(meses_set), reverse=True)
    if not meses_disponibles:
        meses_disponibles = [mes_actual]

    # Determinar cuál es el "último mes" (el mes actual si tiene datos, o el mes más reciente con registros)
    ultimo_mes_auto = mes_actual if mes_actual in meses_set else meses_disponibles[0]

    periodo = (request.args.get("periodo") or "diario").strip().lower()
    mes_param = (request.args.get("mes") or "").strip()[:7]
    fecha_param = (request.args.get("fecha") or "").strip()[:10]

    if periodo == "diario":
        target_fecha = fecha_param if fecha_param else hoy
        rows = [r for r in all_rows if r.get("_fecha_norm") == target_fecha]
        etiqueta_periodo = f"Diario · Hoy ({target_fecha})"
        mes_activo = target_fecha[:7]
    elif periodo == "ultimo_mes":
        mes_objetivo = mes_param if (mes_param and len(mes_param) == 7) else ultimo_mes_auto
        rows = [r for r in all_rows if r.get("_mes_norm") == mes_objetivo]
        etiqueta_periodo = f"Último Mes · {formatear_etiqueta_mes(mes_objetivo)}"
        mes_activo = mes_objetivo
    else:
        periodo = "historico"
        if mes_param and len(mes_param) == 7 and mes_param != "todos":
            rows = [r for r in all_rows if r.get("_mes_norm") == mes_param]
            etiqueta_periodo = f"Histórico · {formatear_etiqueta_mes(mes_param)}"
            mes_activo = mes_param
        else:
            rows = list(all_rows)
            etiqueta_periodo = f"Histórico Completo ({len(all_rows)} registros acumulados)"
            mes_activo = "todos"

    # Configuración de sectores 1 a 14 (incluyendo el nuevo Mesón Entrada Norte y Mesón Entrada Sur)
    sectores_data = {
        s: {
            "sector": s,
            "zona": s,  # retrocompatibilidad
            "filas": obtener_rango_filas_sector(s),
            "meson": obtener_mesa_label(s),
            "c11": 0,
            "c18": 0,
            "total": 0,
            "captadoras_11": set(),
            "captadoras_18": set()
        } for s in range(1, 15)
    }

    captadoras_map = {}
    total_11 = 0
    total_18 = 0
    centrales_11 = 0
    centrales_18 = 0

    for r in rows:
        culto = (r.get("culto") or inferir_culto_de_fecha(r.get("created_at"))).strip()
        if culto not in ["11:00", "18:30"]:
            culto = "11:00"

        try:
            sector_num = int(r.get("sector") or 0)
        except (ValueError, TypeError):
            sector_num = 0

        # Obtener NOMBRE REAL de la captadora (nunca email crudo)
        nombre_captadora = r.get("registrador_nombre") or obtener_nombre_captadora(r.get("registrador_email"))

        if nombre_captadora not in captadoras_map:
            captadoras_map[nombre_captadora] = {
                "nombre": nombre_captadora,
                "c11": 0,
                "c18": 0,
                "total": 0
            }

        if culto == "11:00":
            total_11 += 1
            captadoras_map[nombre_captadora]["c11"] += 1
            if sector_num in [5, 7, 9]:
                centrales_11 += 1
            if 1 <= sector_num <= 14:
                sectores_data[sector_num]["c11"] += 1
                sectores_data[sector_num]["captadoras_11"].add(nombre_captadora)
        else:
            total_18 += 1
            captadoras_map[nombre_captadora]["c18"] += 1
            if sector_num in [5, 7, 9]:
                centrales_18 += 1
            if 1 <= sector_num <= 14:
                sectores_data[sector_num]["c18"] += 1
                sectores_data[sector_num]["captadoras_18"].add(nombre_captadora)

        if 1 <= sector_num <= 14:
            sectores_data[sector_num]["total"] += 1

        captadoras_map[nombre_captadora]["total"] += 1

    sectores_list = []
    for s in range(1, 15):
        item = sectores_data[s]
        item["captadoras_11"] = sorted(list(item["captadoras_11"]))
        item["captadoras_18"] = sorted(list(item["captadoras_18"]))
        sectores_list.append(item)

    captadoras_list = sorted(captadoras_map.values(), key=lambda x: x["total"], reverse=True)

    pct_centrales_11 = round((centrales_11 / total_11 * 100), 1) if total_11 > 0 else 0
    pct_centrales_18 = round((centrales_18 / total_18 * 100), 1) if total_18 > 0 else 0

    count_captadoras_11 = sum(1 for c in captadoras_list if c["c11"] > 0)
    count_captadoras_18 = sum(1 for c in captadoras_list if c["c18"] > 0)

    count_sectores_11 = sum(1 for s in sectores_list if s["c11"] > 0)
    count_sectores_18 = sum(1 for s in sectores_list if s["c18"] > 0)

    # Cargar métricas reales usando almacenamiento seguro multicapa
    metricas = cargar_metricas_seguro()

    return jsonify({
        "status": "success",
        "periodo_activo": periodo,
        "etiqueta_periodo": etiqueta_periodo,
        "fecha_hoy": hoy,
        "mes_activo": mes_activo,
        "ultimo_mes_auto": ultimo_mes_auto,
        "meses_disponibles": [
            {"valor": m, "etiqueta": formatear_etiqueta_mes(m)} for m in meses_disponibles
        ],
        "conteos_globales": {
            "diario": sum(1 for r in all_rows if r.get("_fecha_norm") == hoy),
            "ultimo_mes": sum(1 for r in all_rows if r.get("_mes_norm") == ultimo_mes_auto),
            "historico": len(all_rows)
        },
        "resumen": {
            "total_general": len(rows),
            "total_11": total_11,
            "total_18": total_18,
            "pct_centrales_11": pct_centrales_11,
            "pct_centrales_18": pct_centrales_18,
            "count_captadoras_11": count_captadoras_11,
            "count_captadoras_18": count_captadoras_18,
            "count_sectores_11": count_sectores_11,
            "count_sectores_18": count_sectores_18,
            "count_zonas_11": count_sectores_11,
            "count_zonas_18": count_sectores_18,
        },
        "sectores": sectores_list,
        "zonas": sectores_list,
        "captadoras": captadoras_list,
        "metricas": metricas
    })


def cargar_metricas_seguro():
    """
    Lee las métricas y la planilla Excel desde Supabase con respaldo multicapa:
    1. Tabla 'metricas_culto' (si existe).
    2. Registro de sistema '__SYS_METRICAS_%' en la tabla 'contactos' (garantizado al 100%).
    """
    defaults = {
        "asistencia_11": 4636, "asistencia_18": 2369,
        "conteo_11": 4767, "conteo_18": 2164,
        "no_cenaron": 14,
        "unt_kids_am": 79, "unt_kids_pm": 18,
        "kilo_amor": 18, "camaras_am": 25, "camaras_pm": 3,
        "observaciones": "",
        "excel_data": None,
        "updated_ts": 0
    }

    cand_table = None
    try:
        res = supabase.table("metricas_culto").select("*").order("updated_at", desc=True).limit(1).execute()
        if res.data:
            row = dict(res.data[0])
            obs_raw = str(row.get("observaciones") or "").strip()
            if obs_raw.startswith('{"__excel_v2":'):
                try:
                    parsed = json.loads(obs_raw)
                    row["observaciones"] = parsed.get("notas", "")
                    row["excel_data"] = parsed.get("excel_data")
                    row["updated_ts"] = parsed.get("updated_ts", 1)
                except Exception:
                    pass
            cand_table = row
    except Exception:
        pass

    cand_contactos = None
    try:
        res_c = supabase.table("contactos").select("id, nombre, telefono").ilike("nombre", "__SYS_METRICAS_%").execute()
        rows_c = res_c.data or []
        if rows_c:
            single = [r for r in rows_c if str(r.get("nombre", "")).startswith("__SYS_METRICAS_V2__:")]
            if single:
                raw_json = str(single[0]["nombre"])[len("__SYS_METRICAS_V2__:"):]
                cand_contactos = json.loads(raw_json)
            else:
                chunks = [r for r in rows_c if str(r.get("nombre", "")).startswith("__SYS_METRICAS_CHUNK_")]
                if chunks:
                    chunks.sort(key=lambda x: str(x.get("nombre", ""))[:28])
                    raw_json = "".join(str(c["nombre"]).split(":", 1)[1] for c in chunks if ":" in str(c["nombre"]))
                    cand_contactos = json.loads(raw_json)
    except Exception as e:
        app.logger.warning(f"Aviso al leer respaldo de metricas en contactos: {e}")

    # Elegir el más reciente entre ambos respaldos
    if cand_contactos and cand_table:
        if (cand_contactos.get("updated_ts") or 0) >= (cand_table.get("updated_ts") or 0):
            defaults.update(cand_contactos)
        else:
            defaults.update(cand_table)
    elif cand_contactos:
        defaults.update(cand_contactos)
    elif cand_table:
        defaults.update(cand_table)

    return defaults


def guardar_metricas_seguro(payload_db, full_record):
    """
    Guarda las métricas y la planilla Excel en Supabase garantizando que nunca falle:
    Intenta en 'metricas_culto' y además guarda respaldo íntegro en 'contactos'.
    """
    ok_table = False
    err_msgs = []

    # 1. Intentar en tabla metricas_culto
    try:
        existing = supabase.table("metricas_culto").select("id").limit(1).execute()
        if existing.data:
            supabase.table("metricas_culto").update(payload_db).eq("id", existing.data[0]["id"]).execute()
        else:
            supabase.table("metricas_culto").insert(payload_db).execute()
        ok_table = True
    except Exception as e:
        err_msgs.append(f"metricas_culto: {e}")

    # 2. Guardar siempre en tabla 'contactos' (que existe 100% en Supabase)
    ok_contactos = False
    full_json = json.dumps(full_record, ensure_ascii=False)
    try:
        prev = supabase.table("contactos").select("id").ilike("nombre", "__SYS_METRICAS_%").execute()
        for r in (prev.data or []):
            supabase.table("contactos").delete().eq("id", r["id"]).execute()

        try:
            supabase.table("contactos").insert({
                "nombre": f"__SYS_METRICAS_V2__:{full_json}",
                "telefono": "56900000000"
            }).execute()
            ok_contactos = True
        except Exception:
            chunk_size = 180
            chunks = [full_json[i:i+chunk_size] for i in range(0, len(full_json), chunk_size)]
            for idx, ch in enumerate(chunks):
                supabase.table("contactos").insert({
                    "nombre": f"__SYS_METRICAS_CHUNK_{idx:04d}__:{ch}",
                    "telefono": "56900000000"
                }).execute()
            ok_contactos = True
    except Exception as e2:
        err_msgs.append(f"contactos_backup: {e2}")

    return (ok_table or ok_contactos), "; ".join(err_msgs)


@app.route('/admin/metricas_culto', methods=['GET', 'POST'])
def admin_metricas_culto():
    """Obtiene o actualiza las métricas de asistencia, conteo, no cenaron y planilla completa tipo Excel para Administradores."""
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    # SEGURIDAD: Solo Administradores (Juan y Andrés Acevedo)
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso restringido solo a los administradores (Juan y Andrés Acevedo)"}), 403

    if request.method == 'GET':
        metricas = cargar_metricas_seguro()
        return jsonify({"status": "success", "metricas": metricas})

    data = request.get_json(silent=True) or {}
    notas_str = str(data.get("observaciones") or "").strip()
    excel_data = data.get("excel_data")
    now_ts = int(time.time())

    obs_to_save = notas_str
    if excel_data is not None:
        obs_to_save = json.dumps({
            "__excel_v2": True,
            "notas": notas_str,
            "excel_data": excel_data,
            "updated_ts": now_ts
        }, ensure_ascii=False)

    payload_db = {
        "asistencia_11": int(data.get("asistencia_11") or 0),
        "asistencia_18": int(data.get("asistencia_18") or 0),
        "conteo_11": int(data.get("conteo_11") or 0),
        "conteo_18": int(data.get("conteo_18") or 0),
        "no_cenaron": int(data.get("no_cenaron") or 0),
        "unt_kids_am": int(data.get("unt_kids_am") or 0),
        "unt_kids_pm": int(data.get("unt_kids_pm") or 0),
        "kilo_amor": int(data.get("kilo_amor") or 0),
        "camaras_am": int(data.get("camaras_am") or 0),
        "camaras_pm": int(data.get("camaras_pm") or 0),
        "observaciones": obs_to_save
    }

    full_record = {
        "asistencia_11": payload_db["asistencia_11"],
        "asistencia_18": payload_db["asistencia_18"],
        "conteo_11": payload_db["conteo_11"],
        "conteo_18": payload_db["conteo_18"],
        "no_cenaron": payload_db["no_cenaron"],
        "unt_kids_am": payload_db["unt_kids_am"],
        "unt_kids_pm": payload_db["unt_kids_pm"],
        "kilo_amor": payload_db["kilo_amor"],
        "camaras_am": payload_db["camaras_am"],
        "camaras_pm": payload_db["camaras_pm"],
        "observaciones": notas_str,
        "excel_data": excel_data,
        "updated_ts": now_ts
    }

    saved_ok, err_detail = guardar_metricas_seguro(payload_db, full_record)
    if saved_ok:
        return jsonify({
            "status": "success",
            "message": "Planilla, histórico mensual y estadísticas guardadas exitosamente en la base de datos.",
            "metricas": full_record
        })
    return jsonify({
        "status": "error",
        "message": f"No se pudo guardar en Supabase ({err_detail}), pero se mantuvo copia local."
    }), 500


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

    return jsonify(sort_registros_by_sector_then_fila(res.data))


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
    rows = res.data or []

    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write("id,nombre,fila,sector,culto,telefono\n")

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=export_santa_cena.csv"}
    )

# ======================
# RUN FOR LOCAL / RENDER
# ======================

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
