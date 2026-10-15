from flask import Flask, request, jsonify, render_template, Response
from flask_cors import CORS
from itsdangerous import URLSafeSerializer, BadSignature
import urllib.parse
import os
import unicodedata
import time
import csv
import io

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
    """Retorna la fecha actual en formato YYYY-MM-DD."""
    import datetime
    return datetime.date.today().isoformat()


def es_mismo_evento(created_at_str, target_fecha=None):
    """Verifica si un timestamp corresponde al evento/fecha objetivo (por defecto hoy)."""
    if not created_at_str:
        return True
    try:
        fecha_str = str(created_at_str)[:10]
        import datetime
        if target_fecha:
            return fecha_str == str(target_fecha)[:10]
        hoy = datetime.date.today().isoformat()
        return fecha_str == hoy
    except Exception:
        return True


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


RANGOS_ZONAS = [
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


def obtener_sector_de_fila(fila):
    try:
        f = int(str(fila).strip())
    except (TypeError, ValueError):
        return None
    for sec_id, start, end in RANGOS_ZONAS:
        if start <= f <= end:
            return str(sec_id)
    return None


def obtener_rango_filas_zona(z):
    for sec_id, start, end in RANGOS_ZONAS:
        if sec_id == z:
            return f"{start}-{end}"
    return ""


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
    """Retorna el nombre de mesa/mesón en base al sector."""
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

    clean_phone = "".join(ch for ch in str(telefono or "") if ch.isdigit() or ch == "+")
    return f"https://wa.me/{clean_phone}?text={urllib.parse.quote(mensaje)}"


def actualizar_o_guardar_contacto(nuevo_nombre, nuevo_telefono, viejo_nombre=None):
    """Sincroniza el contacto en la tabla 'contactos' de Supabase."""
    if not nuevo_nombre or not nuevo_telefono:
        return
    nombre_limpio = str(nuevo_nombre).strip()
    tel_limpio = str(nuevo_telefono).strip()
    norm_nuevo = normalize_text(nombre_limpio)
    norm_viejo = normalize_text(viejo_nombre) if viejo_nombre else None

    try:
        encontrado_id = None
        candidatos = supabase.table("contactos").select("id, nombre, telefono").limit(100).execute()
        for c in (candidatos.data or []):
            c_norm = normalize_text(c.get("nombre", ""))
            if c_norm == norm_nuevo or (norm_viejo and c_norm == norm_viejo):
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
    except Exception as e:
        app.logger.warning(f"Error al actualizar o guardar contacto: {e}")


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
        auth_resp = supabase.auth.sign_in_with_password({"email": email, "password": password})
        session = auth_resp.session
        user = auth_resp.user
        if not session or not user:
            return jsonify({"status": "error", "message": "Credenciales inválidas"}), 401

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

    try:
        res = (
            supabase.table("contactos")
            .select("nombre, telefono")
            .ilike("nombre", f"%{q}%")
            .limit(30)
            .execute()
        )
        candidatos = res.data or []
        rows = []
        seen = set()
        for c in candidatos:
            nombre = str(c.get("nombre") or "").strip()
            telefono = str(c.get("telefono") or "").strip()
            if not nombre:
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

        data = request.get_json(silent=True) or {}

        nombre = data.get('nombre')
        fila = str(data.get('fila'))
        sector = data.get('sector')
        telefono_enviado = data.get('telefono')
        culto = (data.get('culto') or inferir_culto_actual()).strip()

        if not nombre or not fila or not sector:
            return jsonify({"status": "error", "message": "Faltan datos requeridos"}), 400

        # --- BUSCAR TELÉFONO(S) EN SUPABASE (tolerante a mayúsculas/acentos) ---
        nombre_buscado = nombre.strip()
        nombre_norm = normalize_text(nombre_buscado)
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

        # Caso 1: hay varios con el mismo nombre -> pedir selección por teléfono
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

        # Caso 2: existe uno solo
        elif len(candidatos) == 1:
            telefono_destino = str(candidatos[0].get("telefono", "")).strip()

        # Caso 3: no existe en contactos -> pedir teléfono para crearlo
        if not telefono_destino:
            if not telefono_enviado:
                return jsonify({
                    "status": "need_phone",
                    "message": "Hermano no encontrado. Ingrese teléfono."
                })

            telefono_destino = telefono_enviado

            actualizar_o_guardar_contacto(nombre.strip(), telefono_destino)

        # --- VALIDAR NOMBRE REPETIDO (EN EL MISMO CULTO Y EVENTO) ---
        query_nombre = (
            supabase.table("registros_santa_cena")
            .select("id, fila, culto, created_at, fecha_evento")
            .ilike("nombre", nombre.strip())
            .execute()
        )

        for reg_n in (query_nombre.data or []):
            reg_culto = reg_n.get("culto") or inferir_culto_de_fecha(reg_n.get("created_at"))
            if reg_culto == culto and es_mismo_evento(reg_n.get("fecha_evento") or reg_n.get("created_at")):
                return jsonify({
                    "status": "error",
                    "message": f"Este hermano ya está registrado en la fila {reg_n.get('fila')} para el culto de las {culto}"
                }), 400

        # --- VALIDAR FILA REPETIDA (EN EL MISMO CULTO Y EVENTO) ---
        # Ahora Fila 14 puede ser usada a las 11:00 y a las 18:30 sin conflicto ni borrado de tabla
        query_fila = (
            supabase.table("registros_santa_cena")
            .select("id, nombre, culto, created_at, fecha_evento")
            .eq("fila", fila)
            .execute()
        )

        for reg_f in (query_fila.data or []):
            reg_culto = reg_f.get("culto") or inferir_culto_de_fecha(reg_f.get("created_at"))
            if reg_culto == culto and es_mismo_evento(reg_f.get("fecha_evento") or reg_f.get("created_at")):
                return jsonify({
                    "status": "error",
                    "message": f"Fila {fila} ya está ocupada en el culto de las {culto} por {reg_f.get('nombre', 'otro hermano')}"
                }), 400

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

        try:
            supabase.table("registros_santa_cena").insert(insert_payload).execute()
        except Exception as insert_err:
            msg = str(insert_err).lower()
            if "column" in msg or "schema" in msg:
                insert_payload.pop("telefono", None)
                insert_payload.pop("culto", None)
                insert_payload.pop("registrador_nombre", None)
                insert_payload.pop("fecha_evento", None)
                supabase.table("registros_santa_cena").insert(insert_payload).execute()
            else:
                raise insert_err

        # --- LINK WHATSAPP ---
        url_wa = construir_whatsapp_link(request.host_url, nombre, fila, sector, telefono_destino)

        return jsonify({"status": "success", "url_whatsapp": url_wa})

    except Exception as e:
        app.logger.exception('Error en /enviar_asignacion')
        return jsonify({"status": "error", "message": str(e) or 'Error interno al registrar'}), 500


# ======================
# ADMIN & REGISTROS API
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

    return jsonify(sort_registros_by_fila(res.data))


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
    rows = res.data or []

    # Enriquecer registros que no tengan teléfono consultando la tabla de contactos
    nombres_sin_tel = [r.get("nombre") for r in rows if not r.get("telefono") and r.get("nombre")]
    if nombres_sin_tel:
        try:
            contactos_res = supabase.table("contactos").select("nombre, telefono").limit(500).execute()
            tel_map = {
                normalize_text(c.get("nombre", "")): str(c.get("telefono", "")).strip()
                for c in (contactos_res.data or []) if c.get("telefono")
            }
            for r in rows:
                if not r.get("telefono"):
                    norm = normalize_text(r.get("nombre", ""))
                    if norm in tel_map:
                        r["telefono"] = tel_map[norm]
        except Exception as e:
            app.logger.warning(f"No se pudieron enriquecer telefonos: {e}")

    # Enriquecer con culto inferido, enlace de whatsapp, nombre real de captadora y fecha
    for r in rows:
        if not r.get("culto"):
            r["culto"] = inferir_culto_de_fecha(r.get("created_at"))
        if not r.get("registrador_nombre"):
            r["registrador_nombre"] = obtener_nombre_captadora(r.get("registrador_email"))
        r["fecha"] = str(r.get("fecha_evento") or r.get("created_at") or "")[:10]
        tel = r.get("telefono")
        if tel:
            r["url_whatsapp"] = construir_whatsapp_link(
                request.host_url, r.get("nombre", ""), r.get("fila", ""), r.get("sector", ""), tel
            )
        r["mesa_label"] = obtener_mesa_label(r.get("sector"))

    return jsonify({
        "rows": sort_registros_by_fila(rows),
        "is_admin": is_admin,
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

    data = request.get_json(silent=True) or {}
    registro_id = data.get("id")
    if not registro_id:
        return jsonify({"status": "error", "message": "ID de registro es requerido"}), 400

    existing = supabase.table("registros_santa_cena").select("*").eq("id", registro_id).limit(1).execute()
    if not existing.data:
        return jsonify({"status": "error", "message": "Registro no encontrado"}), 404

    reg = existing.data[0]
    is_admin = require_admin(user)
    if not is_admin and reg.get("registrador_id") != user.id:
        return jsonify({"status": "error", "message": "No tienes permiso para editar este registro"}), 403

    nuevo_nombre = (data.get("nombre") or reg.get("nombre") or "").strip()
    nuevo_telefono = (data.get("telefono") or reg.get("telefono") or "").strip()
    nueva_fila = str(data.get("fila") if data.get("fila") is not None else reg.get("fila") or "").strip()
    nuevo_culto = (data.get("culto") or reg.get("culto") or "11:00").strip()

    # Si se especificó o cambió la fila, recalcular sector correspondiente
    nuevo_sector = data.get("sector")
    if not nuevo_sector or str(nueva_fila) != str(reg.get("fila")):
        nuevo_sector = obtener_sector_de_fila(nueva_fila) or reg.get("sector")

    # Si cambió la fila, verificar que no esté ocupada en ESE culto y fecha
    if nueva_fila and nueva_fila != str(reg.get("fila")):
        q_check = (
            supabase.table("registros_santa_cena")
            .select("id, nombre, culto, fecha_evento, created_at")
            .eq("fila", nueva_fila)
            .neq("id", registro_id)
            .execute()
        )
        for cand in (q_check.data or []):
            cand_culto = cand.get("culto") or inferir_culto_de_fecha(cand.get("created_at"))
            if cand_culto == nuevo_culto and es_mismo_evento(cand.get("fecha_evento") or cand.get("created_at")):
                return jsonify({
                    "status": "error",
                    "message": f"La fila {nueva_fila} ya está ocupada en el culto de las {nuevo_culto} por {cand.get('nombre', 'otro hermano')}"
                }), 400

    # Sincronizar contacto en la tabla contactos de Supabase
    if nuevo_nombre and nuevo_telefono:
        actualizar_o_guardar_contacto(nuevo_nombre, nuevo_telefono, reg.get("nombre"))

    update_payload = {
        "nombre": nuevo_nombre,
        "fila": nueva_fila,
        "sector": str(nuevo_sector),
        "culto": nuevo_culto,
        "telefono": nuevo_telefono
    }

    try:
        supabase.table("registros_santa_cena").update(update_payload).eq("id", registro_id).execute()
    except Exception as e:
        msg = str(e).lower()
        if "column" in msg or "schema" in msg:
            update_payload.pop("telefono", None)
            update_payload.pop("culto", None)
            supabase.table("registros_santa_cena").update(update_payload).eq("id", registro_id).execute()
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

    data = request.get_json(silent=True) or {}
    nombre = (data.get("nombre") or "").strip()
    telefono = (data.get("telefono") or "").strip()
    contacto_id = data.get("id")

    if not nombre or not telefono:
        return jsonify({"status": "error", "message": "Nombre y teléfono son obligatorios"}), 400

    try:
        if contacto_id:
            supabase.table("contactos").update({"nombre": nombre, "telefono": telefono}).eq("id", contacto_id).execute()
        else:
            actualizar_o_guardar_contacto(nombre, telefono)
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

    res = supabase.table("registros_santa_cena").select("*").eq("id", registro_id).limit(1).execute()
    if not res.data:
        return jsonify({"status": "error", "message": "Registro no encontrado"}), 404

    reg = res.data[0]
    telefono = reg.get("telefono")
    if not telefono:
        c_res = supabase.table("contactos").select("telefono").eq("nombre", reg.get("nombre")).limit(1).execute()
        if c_res.data:
            telefono = c_res.data[0].get("telefono")

    if not telefono:
        return jsonify({"status": "error", "message": "No hay teléfono registrado para este hermano"}), 400

    url_wa = construir_whatsapp_link(request.host_url, reg.get("nombre"), reg.get("fila"), reg.get("sector"), telefono)
    return jsonify({"status": "success", "url_whatsapp": url_wa, "telefono": telefono})


@app.route('/dashboard/stats')
def dashboard_stats():
    """Genera las métricas reales para el Administrador (Juan Acevedo)."""
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    # SEGURIDAD: Solo Juan Acevedo / Administrador puede ver el dashboard
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso restringido solo al administrador (Juan Acevedo)"}), 403

    res = supabase.table("registros_santa_cena").select("*").execute()
    rows = res.data or []

    # Configuración de zonas 1 a 14
    zonas_data = {
        z: {
            "zona": z,
            "filas": obtener_rango_filas_zona(z),
            "c11": 0,
            "c18": 0,
            "total": 0,
            "captadoras_11": set(),
            "captadoras_18": set()
        } for z in range(1, 15)
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
                zonas_data[sector_num]["c11"] += 1
                zonas_data[sector_num]["captadoras_11"].add(nombre_captadora)
        else:
            total_18 += 1
            captadoras_map[nombre_captadora]["c18"] += 1
            if sector_num in [5, 7, 9]:
                centrales_18 += 1
            if 1 <= sector_num <= 14:
                zonas_data[sector_num]["c18"] += 1
                zonas_data[sector_num]["captadoras_18"].add(nombre_captadora)

        if 1 <= sector_num <= 14:
            zonas_data[sector_num]["total"] += 1

        captadoras_map[nombre_captadora]["total"] += 1

    zonas_list = []
    for z in range(1, 15):
        item = zonas_data[z]
        item["captadoras_11"] = sorted(list(item["captadoras_11"]))
        item["captadoras_18"] = sorted(list(item["captadoras_18"]))
        zonas_list.append(item)

    captadoras_list = sorted(captadoras_map.values(), key=lambda x: x["total"], reverse=True)

    pct_centrales_11 = round((centrales_11 / total_11 * 100), 1) if total_11 > 0 else 0
    pct_centrales_18 = round((centrales_18 / total_18 * 100), 1) if total_18 > 0 else 0

    count_captadoras_11 = sum(1 for c in captadoras_list if c["c11"] > 0)
    count_captadoras_18 = sum(1 for c in captadoras_list if c["c18"] > 0)

    count_zonas_11 = sum(1 for z in zonas_list if z["c11"] > 0)
    count_zonas_18 = sum(1 for z in zonas_list if z["c18"] > 0)

    # Cargar métricas reales (por defecto 0 si no se han guardado aún)
    metricas = {
        "asistencia_11": 0,
        "asistencia_18": 0,
        "conteo_11": 0,
        "conteo_18": 0,
        "no_cenaron": 0,
        "unt_kids_am": 0,
        "unt_kids_pm": 0,
        "kilo_amor": 0,
        "camaras_am": 0,
        "camaras_pm": 0,
        "observaciones": ""
    }
    try:
        m_res = supabase.table("metricas_culto").select("*").order("updated_at", desc=True).limit(1).execute()
        if m_res.data:
            metricas.update(m_res.data[0])
    except Exception:
        pass

    return jsonify({
        "status": "success",
        "resumen": {
            "total_general": len(rows),
            "total_11": total_11,
            "total_18": total_18,
            "pct_centrales_11": pct_centrales_11,
            "pct_centrales_18": pct_centrales_18,
            "count_captadoras_11": count_captadoras_11,
            "count_captadoras_18": count_captadoras_18,
            "count_zonas_11": count_zonas_11,
            "count_zonas_18": count_zonas_18,
        },
        "zonas": zonas_list,
        "captadoras": captadoras_list,
        "metricas": metricas
    })


@app.route('/admin/metricas_culto', methods=['GET', 'POST'])
def admin_metricas_culto():
    """Obtiene o actualiza las métricas de asistencia, conteo y no cenaron para el Administrador."""
    supabase_error = require_supabase()
    if supabase_error:
        return supabase_error

    user, err, code = get_current_user()
    if err:
        return err, code

    # SEGURIDAD: Solo Administrador (Juan Acevedo)
    if not require_admin(user):
        return jsonify({"status": "error", "message": "Acceso restringido solo al administrador (Juan Acevedo)"}), 403

    if request.method == 'GET':
        defaults = {
            "asistencia_11": 0, "asistencia_18": 0,
            "conteo_11": 0, "conteo_18": 0,
            "no_cenaron": 0,
            "unt_kids_am": 0, "unt_kids_pm": 0,
            "kilo_amor": 0, "camaras_am": 0, "camaras_pm": 0,
            "observaciones": ""
        }
        try:
            res = supabase.table("metricas_culto").select("*").order("updated_at", desc=True).limit(1).execute()
            if res.data:
                defaults.update(res.data[0])
        except Exception:
            pass
        return jsonify({"status": "success", "metricas": defaults})

    data = request.get_json(silent=True) or {}
    payload = {
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
        "observaciones": str(data.get("observaciones") or "").strip()
    }

    try:
        existing = supabase.table("metricas_culto").select("id").limit(1).execute()
        if existing.data:
            supabase.table("metricas_culto").update(payload).eq("id", existing.data[0]["id"]).execute()
        else:
            supabase.table("metricas_culto").insert(payload).execute()
        return jsonify({"status": "success", "message": "Métricas guardadas exitosamente"})
    except Exception as e:
        return jsonify({"status": "error", "message": f"Error al guardar métricas: {e}"}), 500


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

    return jsonify(sort_registros_by_fila(res.data))


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
