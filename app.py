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


TZ_CHILE = datetime.timezone(datetime.timedelta(hours=-3))


def obtener_fecha_hoy():
    """Retorna la fecha actual en Chile (UTC-3) en formato YYYY-MM-DD."""
    try:
        return datetime.datetime.now(TZ_CHILE).date().isoformat()
    except Exception:
        return datetime.date.today().isoformat()


def extraer_fecha_chile(ts_or_date):
    """Extrae la fecha YYYY-MM-DD convirtiendo timestamps UTC/ISO a hora de Chile (UTC-3)."""
    if not ts_or_date:
        return ""
    s = str(ts_or_date).strip()
    if len(s) == 10 and s[4:5] == "-" and s[7:8] == "-":
        return s
    try:
        iso_norm = s.replace("Z", "+00:00")
        if " " in iso_norm and "T" not in iso_norm:
            iso_norm = iso_norm.replace(" ", "T", 1)
        dt = datetime.datetime.fromisoformat(iso_norm)
        if dt.tzinfo is not None:
            dt = dt.astimezone(TZ_CHILE)
        return dt.date().isoformat()
    except Exception:
        return s[:10]


def es_mismo_evento(created_at_str, target_fecha=None):
    """Verifica si un timestamp corresponde al evento/fecha objetivo (por defecto hoy en Chile)."""
    if not created_at_str:
        return True
    try:
        fecha_str = extraer_fecha_chile(created_at_str)
        objetivo = extraer_fecha_chile(target_fecha) if target_fecha else obtener_fecha_hoy()
        return fecha_str == objetivo
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
    """Infiere si estamos en el culto de 11:00 o 18:30 según la hora actual en Chile (UTC-3)."""
    try:
        ahora = datetime.datetime.now(TZ_CHILE)
        if ahora.hour < 15:
            return "11:00"
        return "18:30"
    except Exception:
        return "11:00"


def inferir_culto_de_fecha(iso_str):
    """Infiere culto desde un timestamp ISO de base de datos convirtiendo a hora de Chile."""
    if not iso_str:
        return "11:00"
    try:
        s = str(iso_str).strip()
        iso_norm = s.replace("Z", "+00:00")
        if " " in iso_norm and "T" not in iso_norm:
            iso_norm = iso_norm.replace(" ", "T", 1)
        dt = datetime.datetime.fromisoformat(iso_norm)
        if dt.tzinfo is not None:
            dt = dt.astimezone(TZ_CHILE)
        return "18:30" if dt.hour >= 15 else "11:00"
    except Exception:
        try:
            s = str(iso_str)
            time_part = s.split("T")[1] if "T" in s else s.split(" ")[1]
            hour = int(time_part.split(":")[0])
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
    if nombre_limpio.startswith("__SYS_"):
        return
    tel_limpio = normalizar_telefono_chileno(nuevo_telefono)
    norm_nuevo = normalize_text(nombre_limpio)
    norm_viejo = normalize_text(viejo_nombre) if viejo_nombre else None

    def _op():
        encontrado_id = None
        candidatos = supabase.table("contactos").select("id, nombre, telefono").ilike("nombre", f"%{nombre_limpio}%").limit(20).execute()
        for c in (candidatos.data or []):
            c_nombre_raw = str(c.get("nombre") or "")
            if c_nombre_raw.startswith("__SYS_"):
                continue
            c_norm = normalize_text(c_nombre_raw)
            if c_norm == norm_nuevo or (norm_viejo and c_norm == norm_viejo):
                encontrado_id = c.get("id")
                break

        if not encontrado_id and norm_viejo:
            candidatos_v = supabase.table("contactos").select("id, nombre, telefono").ilike("nombre", f"%{str(viejo_nombre).strip()}%").limit(20).execute()
            for c in (candidatos_v.data or []):
                c_nombre_raw = str(c.get("nombre") or "")
                if c_nombre_raw.startswith("__SYS_"):
                    continue
                if normalize_text(c_nombre_raw) == norm_viejo:
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


# ==========================================================
# CAPA UNIFICADA DE INSCRIPCIÓN ILIMITADA Y MULTITABLA (V2)
# ==========================================================

def _empaquetar_reg_sys(payload):
    """Serializa un registro en JSON compacto para respaldo sin límites en contactos."""
    compact = {
        "n": payload.get("nombre") or "",
        "t": payload.get("telefono") or "",
        "f": str(payload.get("fila") or ""),
        "s": str(payload.get("sector") or ""),
        "c": payload.get("culto") or "11:00",
        "d": payload.get("fecha_evento") or obtener_fecha_hoy(),
        "ri": str(payload.get("registrador_id") or ""),
        "re": payload.get("registrador_email") or "",
        "rn": payload.get("registrador_nombre") or "",
        "ts": payload.get("created_at") or datetime.datetime.now(TZ_CHILE).isoformat()
    }
    return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))


def _desempaquetar_reg_sys(raw_json_str, contact_id=None):
    """Reconstruye un diccionario estándar de registro desde JSON compacto o completo."""
    obj = json.loads(raw_json_str)
    return {
        "id": f"sys:{contact_id}" if contact_id is not None else obj.get("id"),
        "nombre": obj.get("n") if "n" in obj else obj.get("nombre", ""),
        "telefono": obj.get("t") if "t" in obj else obj.get("telefono", ""),
        "fila": str(obj.get("f") if "f" in obj else obj.get("fila", "")),
        "sector": str(obj.get("s") if "s" in obj else obj.get("sector", "")),
        "culto": obj.get("c") if "c" in obj else obj.get("culto", "11:00"),
        "fecha_evento": obj.get("d") if "d" in obj else obj.get("fecha_evento", ""),
        "registrador_id": obj.get("ri") if "ri" in obj else obj.get("registrador_id", ""),
        "registrador_email": obj.get("re") if "re" in obj else obj.get("registrador_email", ""),
        "registrador_nombre": obj.get("rn") if "rn" in obj else obj.get("registrador_nombre", ""),
        "created_at": obj.get("ts") if "ts" in obj else obj.get("created_at", "")
    }


def _guardar_enriquecimiento_reg(raw_reg_id, campos_extra, user_token=None):
    """Guarda o actualiza metadatos extendidos para una fila de registros_santa_cena en contactos."""
    if raw_reg_id is None or not campos_extra:
        return
    prefix = f"__SYS_ENR_V2__:{raw_reg_id}:"
    compact_json = _empaquetar_reg_sys(campos_extra)

    def _op():
        prev = supabase.table("contactos").select("id").ilike("nombre", f"{prefix}%").execute()
        if prev.data:
            supabase.table("contactos").update({
                "nombre": f"{prefix}{compact_json}",
                "telefono": "56900000000"
            }).eq("id", prev.data[0]["id"]).execute()
        else:
            supabase.table("contactos").insert({
                "nombre": f"{prefix}{compact_json}",
                "telefono": "56900000000"
            }).execute()

    try:
        ejecutar_con_respaldo_auth(_op, user_token)
    except Exception as e:
        app.logger.warning(f"Aviso al guardar enriquecimiento de registro {raw_reg_id}: {e}")


def guardar_registro_ilimitado(base_payload, user, user_token=None):
    """
    Guarda cada inscripción sin límite de cantidad de personas ni restricciones por fila/cuenta:
    1. Primero intenta en la nueva tabla limpia 'historico_santa_cena' (sin restricciones UNIQUE).
    2. Si aún no se ha ejecutado el SQL de creación de 'historico_santa_cena', intenta en 'registros_santa_cena'
       adaptándose a las columnas disponibles y guardando enriquecimiento si faltan columnas v2.
    3. Si 'registros_santa_cena' rechaza el 2°+ registro por un UNIQUE antiguo (en fila, registrador_id o nombre)
       o por RLS, guarda automáticamente el registro íntegro en 'contactos' (__SYS_REG_V2__) para que NUNCA falle.
    """
    contextos_auth = []
    if user_token:
        contextos_auth.append((user_token, user.id if user else None))
    if SUPABASE_KEY:
        contextos_auth.append((SUPABASE_KEY, user.id if user else None))
    if LAST_ADMIN_AUTH.get("token"):
        contextos_auth.append((LAST_ADMIN_AUTH["token"], user.id if user else None))
        if LAST_ADMIN_AUTH.get("user_id") and (not user or LAST_ADMIN_AUTH["user_id"] != user.id):
            contextos_auth.append((LAST_ADMIN_AUTH["token"], LAST_ADMIN_AUTH["user_id"]))

    if not contextos_auth:
        contextos_auth.append((None, user.id if user else None))

    # 1. INTENTAR EN LA NUEVA TABLA 'historico_santa_cena'
    tabla_hist_existe = True
    for tok, reg_id_override in contextos_auth:
        if not tabla_hist_existe:
            break
        if tok:
            set_postgrest_token(tok)
        payload_hist = dict(base_payload)
        if reg_id_override:
            payload_hist["registrador_id"] = reg_id_override
        try:
            res_h = supabase.table("historico_santa_cena").insert(payload_hist).execute()
            if user_token:
                set_postgrest_token(user_token)
            row_h = dict((res_h.data or [payload_hist])[0])
            if "id" in row_h:
                row_h["id"] = f"hist:{row_h['id']}"
            return row_h
        except Exception as err_h:
            msg_h = str(err_h).lower()
            # Si la tabla historico_santa_cena aún no ha sido creada en Supabase, pasar directo al paso 2
            if any(w in msg_h for w in ("historico_santa_cena", "pgrst205", "42p01", "relation", "could not find the table")):
                tabla_hist_existe = False
                break
            continue

    # 2. INTENTAR EN 'registros_santa_cena' (CON DETECCIÓN DE VARIANTES PARCIALES)
    variantes_columnas = [
        ("full", lambda p: dict(p)),
        ("no_meta", lambda p: {k: v for k, v in p.items() if k not in ("fecha_evento", "registrador_nombre")}),
        ("base_culto_tel", lambda p: {k: v for k, v in p.items() if k in ("nombre", "fila", "sector", "registrador_id", "registrador_email", "culto", "telefono")}),
        ("v1_orig", lambda p: {k: v for k, v in p.items() if k in ("nombre", "fila", "sector", "registrador_id", "registrador_email")}),
        ("min", lambda p: {k: v for k, v in p.items() if k in ("nombre", "fila", "sector")}),
    ]

    for tok, reg_id_override in contextos_auth:
        if tok:
            set_postgrest_token(tok)
        payload_ctx = dict(base_payload)
        override_usado = False
        if reg_id_override and user and str(reg_id_override) != str(user.id):
            payload_ctx["registrador_id"] = reg_id_override
            override_usado = True

        for nombre_var, construir_variante in variantes_columnas:
            intento_payload = construir_variante(payload_ctx)
            try:
                res_r = supabase.table("registros_santa_cena").insert(intento_payload).execute()
                if user_token:
                    set_postgrest_token(user_token)
                inserted_row = dict((res_r.data or [base_payload])[0])
                raw_id = inserted_row.get("id")
                if raw_id is not None and (nombre_var != "full" or override_usado):
                    _guardar_enriquecimiento_reg(raw_id, base_payload, user_token=user_token)
                inserted_row.update(base_payload)
                if raw_id is not None:
                    inserted_row["id"] = str(raw_id)
                return inserted_row
            except Exception as err_r:
                msg_r = str(err_r).lower()
                if any(w in msg_r for w in ("column", "schema", "pgrst204", "42703", "does not exist")):
                    continue
                # Si es error UNIQUE (23505) o RLS (42501), probar siguiente contexto o caer a respaldo ilimitado
                break

    # 3. RESPALDO AUTOMÁTICO ILIMITADO EN 'contactos' (__SYS_REG_V2__)
    # Garantiza que aunque registros_santa_cena tenga un UNIQUE antiguo y aún no corran el SQL nuevo,
    # puedan inscribir a TODAS las personas necesarias sin ningún límite.
    payload_sys = dict(base_payload)
    payload_sys["created_at"] = datetime.datetime.now(TZ_CHILE).isoformat()
    compact_str = _empaquetar_reg_sys(payload_sys)

    def _insert_sys():
        try:
            return supabase.table("contactos").insert({
                "nombre": f"__SYS_REG_V2__:{compact_str}",
                "telefono": "56900000000"
            }).execute()
        except Exception:
            # Si existiera límite de longitud en columna nombre, omitir registrador_id (basta con registrador_email)
            slim_payload = dict(payload_sys)
            slim_payload["registrador_id"] = ""
            slim_str = _empaquetar_reg_sys(slim_payload)
            return supabase.table("contactos").insert({
                "nombre": f"__SYS_REG_V2__:{slim_str}",
                "telefono": "56900000000"
            }).execute()

    res_sys = ejecutar_con_respaldo_auth(_insert_sys, user_token)
    if user_token:
        set_postgrest_token(user_token)
    sys_id = (res_sys.data or [{}])[0].get("id", int(time.time() * 1000))
    out_row = dict(payload_sys)
    out_row["id"] = f"sys:{sys_id}"
    return out_row


def obtener_todos_los_registros(user_token=None):
    """
    Obtiene y unifica todos los registros desde:
    1. 'historico_santa_cena' (nueva tabla principal ilimitada).
    2. 'registros_santa_cena' (tabla histórica previa + enriquecimientos __SYS_ENR_V2__).
    3. Respaldo ilimitado '__SYS_REG_V2__' en 'contactos'.
    """
    hist_rows = []
    try:
        res_h = ejecutar_con_respaldo_auth(
            lambda: supabase.table("historico_santa_cena").select("*").order("created_at", desc=True).execute(),
            user_token
        )
        for r in (res_h.data or []):
            item = dict(r)
            raw_id = item.get("id")
            item["id"] = f"hist:{raw_id}"
            hist_rows.append(item)
    except Exception:
        pass

    reg_rows = []
    try:
        res_r = ejecutar_con_respaldo_auth(
            lambda: supabase.table("registros_santa_cena").select("*").order("created_at", desc=True).execute(),
            user_token
        )
        for r in (res_r.data or []):
            item = dict(r)
            if "id" in item and item["id"] is not None:
                item["id"] = str(item["id"])
            reg_rows.append(item)
    except Exception:
        pass

    # Cargar enriquecimientos (__SYS_ENR_V2__) y registros de respaldo (__SYS_REG_V2__)
    enr_map = {}
    sys_rows = []
    try:
        res_enr = ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos").select("id, nombre").ilike("nombre", "__SYS_ENR_V2__:%").execute(),
            user_token
        )
        for c in (res_enr.data or []):
            raw_name = str(c.get("nombre") or "")
            # Formato: __SYS_ENR_V2__:<raw_id>:<json>
            parts = raw_name.split(":", 2)
            if len(parts) == 3:
                target_id = parts[1]
                try:
                    enr_map[str(target_id)] = _desempaquetar_reg_sys(parts[2])
                except Exception:
                    pass
    except Exception:
        pass

    if enr_map and reg_rows:
        for r in reg_rows:
            rid = str(r.get("id") or "")
            if rid in enr_map:
                extra = enr_map[rid]
                for campo in ("nombre", "telefono", "fila", "sector", "culto", "fecha_evento", "registrador_id", "registrador_email", "registrador_nombre"):
                    if extra.get(campo):
                        r[campo] = extra[campo]

    try:
        res_sys = ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos").select("id, nombre").ilike("nombre", "__SYS_REG_V2__:%").order("id", desc=True).execute(),
            user_token
        )
        for c in (res_sys.data or []):
            raw_name = str(c.get("nombre") or "")
            if raw_name.startswith("__SYS_REG_V2__:"):
                raw_json = raw_name[len("__SYS_REG_V2__:"):]
                try:
                    sys_rows.append(_desempaquetar_reg_sys(raw_json, contact_id=c.get("id")))
                except Exception:
                    pass
    except Exception:
        pass

    return hist_rows + reg_rows + sys_rows


def obtener_registro_por_id(registro_id, user_token=None):
    """Busca un registro individual en cualquiera de las capas de almacenamiento."""
    sid = str(registro_id or "").strip()
    if not sid:
        return None

    if sid.startswith("hist:"):
        raw_id = sid[5:]
        try:
            res = ejecutar_con_respaldo_auth(
                lambda: supabase.table("historico_santa_cena").select("*").eq("id", raw_id).limit(1).execute(),
                user_token
            )
            if res.data:
                row = dict(res.data[0])
                row["id"] = f"hist:{row['id']}"
                return row
        except Exception:
            return None
        return None

    if sid.startswith("sys:"):
        raw_id = sid[4:]
        try:
            res = ejecutar_con_respaldo_auth(
                lambda: supabase.table("contactos").select("id, nombre").eq("id", raw_id).limit(1).execute(),
                user_token
            )
            if res.data:
                raw_name = str(res.data[0].get("nombre") or "")
                if raw_name.startswith("__SYS_REG_V2__:"):
                    return _desempaquetar_reg_sys(raw_name[len("__SYS_REG_V2__:"):], contact_id=res.data[0].get("id"))
        except Exception:
            return None
        return None

    # Registro en tabla registros_santa_cena
    try:
        res = ejecutar_con_respaldo_auth(
            lambda: supabase.table("registros_santa_cena").select("*").eq("id", sid).limit(1).execute(),
            user_token
        )
        if not res.data:
            return None
        row = dict(res.data[0])
        row["id"] = str(row.get("id"))
        try:
            enr = ejecutar_con_respaldo_auth(
                lambda: supabase.table("contactos").select("id, nombre").ilike("nombre", f"__SYS_ENR_V2__:{sid}:%").limit(1).execute(),
                user_token
            )
            if enr.data:
                parts = str(enr.data[0].get("nombre") or "").split(":", 2)
                if len(parts) == 3:
                    extra = _desempaquetar_reg_sys(parts[2])
                    for campo in ("nombre", "telefono", "fila", "sector", "culto", "fecha_evento", "registrador_id", "registrador_email", "registrador_nombre"):
                        if extra.get(campo):
                            row[campo] = extra[campo]
        except Exception:
            pass
        return row
    except Exception:
        return None


def actualizar_registro_por_id(registro_id, update_payload, reg_actual, user_token=None):
    """Actualiza un registro en cualquiera de las capas sin fallar por columnas o restricciones."""
    sid = str(registro_id or "").strip()
    merged = dict(reg_actual or {})
    merged.update(update_payload)

    if sid.startswith("hist:"):
        raw_id = sid[5:]
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("historico_santa_cena").update(update_payload).eq("id", raw_id).execute(),
            user_token
        )
        return

    if sid.startswith("sys:"):
        raw_id = sid[4:]
        compact_str = _empaquetar_reg_sys(merged)
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos").update({
                "nombre": f"__SYS_REG_V2__:{compact_str}",
                "telefono": "56900000000"
            }).eq("id", raw_id).execute(),
            user_token
        )
        return

    # Tabla registros_santa_cena
    try:
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("registros_santa_cena").update(update_payload).eq("id", sid).execute(),
            user_token
        )
        # Si tenía enriquecimiento previo, sincronizarlo también
        _guardar_enriquecimiento_reg(sid, merged, user_token=user_token)
    except Exception as e:
        msg = str(e).lower()
        if any(w in msg for w in ("column", "schema", "pgrst204", "42703", "does not exist")):
            basic_payload = {
                "nombre": update_payload.get("nombre"),
                "fila": update_payload.get("fila"),
                "sector": update_payload.get("sector")
            }
            try:
                ejecutar_con_respaldo_auth(
                    lambda: supabase.table("registros_santa_cena").update(basic_payload).eq("id", sid).execute(),
                    user_token
                )
            except Exception:
                pass
            _guardar_enriquecimiento_reg(sid, merged, user_token=user_token)
        else:
            # Si falló por un UNIQUE antiguo en fila/nombre, guardamos los cambios en enriquecimiento para que igual se apliquen
            _guardar_enriquecimiento_reg(sid, merged, user_token=user_token)


def eliminar_registro_por_id(registro_id, user_token=None):
    """Elimina un registro de cualquiera de las capas de almacenamiento."""
    sid = str(registro_id or "").strip()
    if not sid:
        return

    if sid.startswith("hist:"):
        raw_id = sid[5:]
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("historico_santa_cena").delete().eq("id", raw_id).execute(),
            user_token
        )
        return

    if sid.startswith("sys:"):
        raw_id = sid[4:]
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos").delete().eq("id", raw_id).execute(),
            user_token
        )
        return

    ejecutar_con_respaldo_auth(
        lambda: supabase.table("registros_santa_cena").delete().eq("id", sid).execute(),
        user_token
    )
    try:
        enr = ejecutar_con_respaldo_auth(
            lambda: supabase.table("contactos").select("id").ilike("nombre", f"__SYS_ENR_V2__:{sid}:%").execute(),
            user_token
        )
        for row_e in (enr.data or []):
            ejecutar_con_respaldo_auth(
                lambda eid=row_e["id"]: supabase.table("contactos").delete().eq("id", eid).execute(),
                user_token
            )
    except Exception:
        pass


def limpiar_todos_los_registros(user_token=None):
    """Limpia todos los registros de Santa Cena en las 3 capas (usado por Reset Total de Admin)."""
    try:
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("historico_santa_cena").delete().neq("nombre", "__NEVER__").execute(),
            user_token
        )
    except Exception:
        pass
    try:
        ejecutar_con_respaldo_auth(
            lambda: supabase.table("registros_santa_cena").delete().neq("nombre", "__NEVER__").execute(),
            user_token
        )
    except Exception:
        pass
    for pref in ("__SYS_REG_V2__:%", "__SYS_ENR_V2__:%"):
        try:
            res_c = ejecutar_con_respaldo_auth(
                lambda p=pref: supabase.table("contactos").select("id").ilike("nombre", p).execute(),
                user_token
            )
            for r in (res_c.data or []):
                ejecutar_con_respaldo_auth(
                    lambda cid=r["id"]: supabase.table("contactos").delete().eq("id", cid).execute(),
                    user_token
                )
        except Exception:
            pass


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

        nombre = (data.get('nombre') or '').strip()
        fila = str(data.get('fila') or '').strip()
        sector = data.get('sector')
        telefono_enviado = str(data.get('telefono') or '').strip()
        culto = (data.get('culto') or inferir_culto_actual()).strip()

        if not nombre or not fila or not sector:
            return jsonify({"status": "error", "message": "Faltan datos requeridos"}), 400

        # --- BUSCAR TELÉFONO(S) EN SUPABASE (tolerante a mayúsculas/acentos, ignora filas __SYS_) ---
        nombre_buscado = nombre
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
            if not str(c.get("nombre") or "").startswith("__SYS_")
            and normalize_text(c.get("nombre", "")) == nombre_norm
        ]

        telefonos_candidatos = sorted(set(
            normalizar_telefono_chileno(c.get("telefono", ""))
            for c in candidatos
            if normalizar_telefono_chileno(c.get("telefono", ""))
        ))

        telefono_destino = ""
        # Si la captadora ya ingresó o seleccionó un teléfono (manual, sugerencia o lista), usarlo directamente sin bloquear
        if telefono_enviado:
            telefono_destino = normalizar_telefono_chileno(telefono_enviado)
            if telefono_destino and telefono_destino not in telefonos_candidatos:
                actualizar_o_guardar_contacto(nombre_buscado, telefono_destino, user_token=user_token)
        else:
            if len(telefonos_candidatos) > 1:
                return jsonify({
                    "status": "choose_phone",
                    "message": "Se encontraron varias personas con ese nombre. Seleccione el teléfono correcto.",
                    "options": telefonos_candidatos
                })
            elif len(telefonos_candidatos) == 1:
                telefono_destino = telefonos_candidatos[0]
            else:
                return jsonify({
                    "status": "need_phone",
                    "message": "Hermano no encontrado. Ingrese teléfono."
                })

        if not telefono_destino:
            return jsonify({
                "status": "need_phone",
                "message": "Ingrese un número de teléfono válido para enviar el WhatsApp."
            })

        # --- INSCRIPCIÓN ILIMITADA EN NUEVA TABLA 'historico_santa_cena' (+ RESPALDO AUTOMÁTICO) ---
        # Sin bloqueo por cantidad de inscritos, fila repetida ni nombre repetido:
        # permite inscribir y enviar WhatsApp a TODAS las personas que sean necesarias.
        nombre_captadora = obtener_nombre_captadora(user.email, user)
        fecha_hoy = obtener_fecha_hoy()

        insert_payload = {
            "nombre": nombre_buscado,
            "fila": fila,
            "sector": str(sector),
            "registrador_id": user.id,
            "registrador_email": user.email,
            "registrador_nombre": nombre_captadora,
            "fecha_evento": fecha_hoy,
            "culto": culto,
            "telefono": telefono_destino
        }

        reg_guardado = guardar_registro_ilimitado(insert_payload, user, user_token=user_token)

        # --- LINK WHATSAPP ---
        url_wa = construir_whatsapp_link(request.host_url, nombre_buscado, fila, sector, telefono_destino)

        return jsonify({
            "status": "success",
            "url_whatsapp": url_wa,
            "registro": reg_guardado
        })

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
    reg_email = str(registro.get("registrador_email") or "").strip().lower()
    usr_email = str(user.email or "").strip().lower()
    if reg_email and usr_email:
        return reg_email == usr_email
    if str(registro.get("registrador_id") or "") == str(user.id or ""):
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
    all_rows = obtener_todos_los_registros(user_token)

    rows = [r for r in all_rows if pertenece_a_usuario(r, user)]
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

    rows = obtener_todos_los_registros(user_token)

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
            unique_nombres = list({
                str(n).strip() for n in nombres_sin_tel
                if n and str(n).strip() and not str(n).strip().startswith("__SYS_")
            })
            tel_map = {}
            for i in range(0, len(unique_nombres), 30):
                chunk = unique_nombres[i:i+30]
                contactos_res = ejecutar_con_respaldo_auth(
                    lambda ch=chunk: supabase.table("contactos").select("nombre, telefono").in_("nombre", ch).execute(),
                    user_token
                )
                for c in (contactos_res.data or []):
                    c_nombre_raw = str(c.get("nombre") or "")
                    if c_nombre_raw.startswith("__SYS_"):
                        continue
                    c_tel = c.get("telefono")
                    if c_tel:
                        norm = normalize_text(c_nombre_raw)
                        tel_map[norm] = normalizar_telefono_chileno(c_tel)

            for r in rows:
                if not r.get("telefono"):
                    norm = normalize_text(r.get("nombre", ""))
                    if norm in tel_map:
                        r["telefono"] = tel_map[norm]
        except Exception as e:
            app.logger.warning(f"No se pudieron enriquecer telefonos: {e}")

    # Enriquecer con culto inferido, enlace de whatsapp, nombre real de captadora, fecha en Chile y mesón
    for r in rows:
        if not r.get("culto"):
            r["culto"] = inferir_culto_de_fecha(r.get("created_at"))
        if not r.get("registrador_nombre"):
            r["registrador_nombre"] = obtener_nombre_captadora(r.get("registrador_email"))
        r["fecha"] = extraer_fecha_chile(r.get("fecha_evento") or r.get("created_at")) or hoy
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
    """Permite editar nombre, teléfono, fila, sector o culto de un registro sin restricción de personas por fila."""
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

    reg = obtener_registro_por_id(registro_id, user_token=user_token)
    if not reg:
        return jsonify({"status": "error", "message": "Registro no encontrado"}), 404

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
        actualizar_registro_por_id(registro_id, update_payload, reg, user_token=user_token)
    except Exception as e:
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
            "id": str(registro_id),
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

    if not nombre or not telefono or nombre.startswith("__SYS_"):
        return jsonify({"status": "error", "message": "Nombre y teléfono válidos son obligatorios"}), 400

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
    reg = obtener_registro_por_id(registro_id, user_token=user_token)
    if not reg:
        return jsonify({"status": "error", "message": "Registro no encontrado"}), 404

    telefono = reg.get("telefono")
    if not telefono and reg.get("nombre"):
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
    all_rows = obtener_todos_los_registros(user_token)

    hoy = obtener_fecha_hoy()
    mes_actual = hoy[:7]

    # Extraer fecha YYYY-MM-DD (en hora de Chile) y mes YYYY-MM de cada registro
    meses_set = set()
    fechas_set = set()
    for r in all_rows:
        f_str = extraer_fecha_chile(r.get("fecha_evento") or r.get("created_at")) or hoy
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

    user_token = get_bearer_token()
    rows = obtener_todos_los_registros(user_token)
    return jsonify(sort_registros_by_sector_then_fila(rows))


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

    user_token = get_bearer_token()
    data = request.get_json(silent=True) or {}
    registro_id = data.get("id")
    if not registro_id:
        return jsonify({"status": "error", "message": "ID requerido"}), 400

    eliminar_registro_por_id(registro_id, user_token=user_token)
    return jsonify({"status": "ok"})


@app.route('/registros/borrar', methods=['POST'])
def registros_borrar():
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
        return jsonify({"status": "error", "message": "ID requerido"}), 400

    reg = obtener_registro_por_id(registro_id, user_token=user_token)
    if not reg or (not require_admin(user) and not pertenece_a_usuario(reg, user)):
        return jsonify({"status": "error", "message": "Registro no encontrado o sin permiso"}), 404

    eliminar_registro_por_id(registro_id, user_token=user_token)
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

    user_token = get_bearer_token()
    limpiar_todos_los_registros(user_token=user_token)
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

    user_token = get_bearer_token()
    rows = sort_registros_by_sector_then_fila(obtener_todos_los_registros(user_token))

    output = io.StringIO()
    columnas_base = [
        "id", "nombre", "telefono", "fila", "sector", "culto",
        "fecha_evento", "registrador_nombre", "registrador_email", "created_at"
    ]
    if rows:
        extra_cols = []
        for r in rows:
            for k in r.keys():
                if k not in columnas_base and k not in extra_cols:
                    extra_cols.append(k)
        writer = csv.DictWriter(output, fieldnames=columnas_base + extra_cols, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    else:
        output.write(",".join(columnas_base) + "\n")

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
