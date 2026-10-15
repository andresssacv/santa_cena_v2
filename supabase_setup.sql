-- ====================================================================
-- ACTUALIZACIÓN DE ESQUEMA PARA SUPABASE (SANTA CENA)
-- Copia y pega este script en el "SQL Editor" de tu proyecto en Supabase
-- ====================================================================

-- 1. Agregar columnas necesarias en 'registros_santa_cena' (si no existen)
ALTER TABLE IF EXISTS registros_santa_cena 
    ADD COLUMN IF NOT EXISTS telefono TEXT;

ALTER TABLE IF EXISTS registros_santa_cena 
    ADD COLUMN IF NOT EXISTS culto TEXT DEFAULT '11:00';

ALTER TABLE IF EXISTS registros_santa_cena 
    ADD COLUMN IF NOT EXISTS estado TEXT DEFAULT 'activo';

-- Índices para búsqueda rápida
CREATE INDEX IF NOT EXISTS idx_registros_culto ON registros_santa_cena(culto);
CREATE INDEX IF NOT EXISTS idx_registros_fila ON registros_santa_cena(fila);
CREATE INDEX IF NOT EXISTS idx_registros_nombre ON registros_santa_cena(nombre);

-- 2. Asegurar que la tabla 'contactos' tenga índices adecuados
CREATE INDEX IF NOT EXISTS idx_contactos_nombre ON contactos(nombre);
CREATE INDEX IF NOT EXISTS idx_contactos_telefono ON contactos(telefono);

-- 3. Tabla para guardar métricas generales del culto, asistencia, conteo y conciliación
CREATE TABLE IF NOT EXISTS metricas_culto (
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

-- Habilitar RLS o políticas si las usas (opcional)
-- ALTER TABLE metricas_culto ENABLE ROW LEVEL SECURITY;
