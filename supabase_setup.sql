-- ====================================================================
-- CONFIGURACIÓN COMPLETA DE SUPABASE · SANTA CENA 2026 (HISTÓRICO ILIMITADO)
-- Copia y pega este script en el "SQL Editor" de tu proyecto en Supabase y dale a "Run"
-- ====================================================================

-- 1. CREAR NUEVA TABLA HISTÓRICA LIMPIA
-- Regla de negocio: 1 sola persona por cada fila DENTRO de la misma reunión (culto) y misma fecha,
-- permitiendo usar la misma fila en 11:00 y en 18:30 (para la misma u otra persona) y en distintas fechas,
-- y permitiendo a cada hermana inscribir a todas las personas que necesite en distintas filas.
CREATE TABLE IF NOT EXISTS public.historico_santa_cena (
    id BIGSERIAL PRIMARY KEY,
    nombre TEXT NOT NULL,
    telefono TEXT DEFAULT '',
    fila TEXT NOT NULL,
    sector TEXT NOT NULL,
    culto TEXT DEFAULT '11:00',
    fecha_evento DATE DEFAULT CURRENT_DATE,
    registrador_id TEXT,
    registrador_email TEXT,
    registrador_nombre TEXT,
    estado TEXT DEFAULT 'activo',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Índices de rendimiento y reglas exactas por reunión y fecha:
-- 1) Máximo 1 persona por cada fila en la misma reunión y fecha
-- 2) Una misma persona no puede inscribirse en 2 filas distintas en la misma reunión y fecha
DROP INDEX IF EXISTS public.idx_hist_sc_unico_fila_culto_fecha;
CREATE UNIQUE INDEX IF NOT EXISTS idx_hist_sc_unico_fila_culto_fecha
    ON public.historico_santa_cena(fecha_evento, culto, fila);

DROP INDEX IF EXISTS public.idx_hist_sc_unico_persona_culto_fecha;
CREATE UNIQUE INDEX IF NOT EXISTS idx_hist_sc_unico_persona_culto_fecha
    ON public.historico_santa_cena(fecha_evento, culto, lower(trim(nombre)));
CREATE INDEX IF NOT EXISTS idx_hist_sc_fecha ON public.historico_santa_cena(fecha_evento);
CREATE INDEX IF NOT EXISTS idx_hist_sc_culto ON public.historico_santa_cena(culto);
CREATE INDEX IF NOT EXISTS idx_hist_sc_sector ON public.historico_santa_cena(sector);
CREATE INDEX IF NOT EXISTS idx_hist_sc_registrador ON public.historico_santa_cena(registrador_email);

-- Desactivar bloqueos RLS en la nueva tabla histórica (el backend Flask valida roles y privacidad)
ALTER TABLE public.historico_santa_cena DISABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE public.historico_santa_cena TO anon, authenticated, service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated, service_role;

-- 2. ELIMINAR RESTRICCIONES E ÍNDICES "UNIQUE" GLOBALES ANTIGUOS EN 'registros_santa_cena'
-- (Elimina registros_santa_cena_row_key / registros_santa_cena_fila_key que bloqueaban repetir fila en otra reunión o fecha)
ALTER TABLE IF EXISTS public.registros_santa_cena DROP CONSTRAINT IF EXISTS registros_santa_cena_row_key;
ALTER TABLE IF EXISTS public.registros_santa_cena DROP CONSTRAINT IF EXISTS registros_santa_cena_fila_key;

DO $$
DECLARE
    r RECORD;
BEGIN
    -- Eliminar constraints UNIQUE antiguos
    FOR r IN (
        SELECT con.conname
        FROM pg_constraint con
        JOIN pg_class rel ON rel.oid = con.conrelid
        JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
        WHERE nsp.nspname = 'public'
          AND rel.relname = 'registros_santa_cena'
          AND con.contype = 'u'
    ) LOOP
        EXECUTE 'ALTER TABLE public.registros_santa_cena DROP CONSTRAINT IF EXISTS ' || quote_ident(r.conname);
    END LOOP;

    -- Eliminar índices UNIQUE sueltos (excepto la clave primaria)
    FOR r IN (
        SELECT idx_cls.relname AS index_name
        FROM pg_index i
        JOIN pg_class tbl_cls ON tbl_cls.oid = i.indrelid
        JOIN pg_class idx_cls ON idx_cls.oid = i.indexrelid
        JOIN pg_namespace nsp ON nsp.oid = tbl_cls.relnamespace
        WHERE nsp.nspname = 'public'
          AND tbl_cls.relname = 'registros_santa_cena'
          AND i.indisunique = true
          AND i.indisprimary = false
    ) LOOP
        EXECUTE 'DROP INDEX IF EXISTS public.' || quote_ident(r.index_name);
    END LOOP;
END $$;

-- Asegurar columnas en la tabla anterior por compatibilidad histórica
ALTER TABLE IF EXISTS public.registros_santa_cena ADD COLUMN IF NOT EXISTS telefono TEXT;
ALTER TABLE IF EXISTS public.registros_santa_cena ADD COLUMN IF NOT EXISTS culto TEXT DEFAULT '11:00';
ALTER TABLE IF EXISTS public.registros_santa_cena ADD COLUMN IF NOT EXISTS registrador_nombre TEXT;
ALTER TABLE IF EXISTS public.registros_santa_cena ADD COLUMN IF NOT EXISTS fecha_evento DATE DEFAULT CURRENT_DATE;
ALTER TABLE IF EXISTS public.registros_santa_cena ADD COLUMN IF NOT EXISTS estado TEXT DEFAULT 'activo';

ALTER TABLE IF EXISTS public.registros_santa_cena DISABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE public.registros_santa_cena TO anon, authenticated, service_role;

-- 3. ASEGURAR PERMISOS E ÍNDICES EN 'contactos'
CREATE INDEX IF NOT EXISTS idx_contactos_nombre ON public.contactos(nombre);
CREATE INDEX IF NOT EXISTS idx_contactos_telefono ON public.contactos(telefono);
GRANT ALL ON TABLE public.contactos TO anon, authenticated, service_role;

-- 4. TABLA DE MÉTRICAS Y PLANILLA MENSUAL DEL CULTO
CREATE TABLE IF NOT EXISTS public.metricas_culto (
    id BIGSERIAL PRIMARY KEY,
    fecha DATE DEFAULT CURRENT_DATE,
    asistencia_11 INT DEFAULT 0,
    asistencia_18 INT DEFAULT 0,
    conteo_11 INT DEFAULT 0,
    conteo_18 INT DEFAULT 0,
    no_cenaron INT DEFAULT 0,
    unt_kids_am INT DEFAULT 0,
    unt_kids_pm INT DEFAULT 0,
    kilo_amor INT DEFAULT 0,
    camaras_am INT DEFAULT 0,
    camaras_pm INT DEFAULT 0,
    observaciones TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE IF EXISTS public.metricas_culto DISABLE ROW LEVEL SECURITY;
GRANT ALL ON TABLE public.metricas_culto TO anon, authenticated, service_role;
