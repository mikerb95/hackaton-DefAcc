-- Esquema de Turso (PLAN, sección 10), alineado con radar/contratos.py.
-- Un cambio aquí se anuncia en .coordinacion/nucleo.md antes de hacerlo.
-- Convenciones: fechas en ISO 8601 como TEXT, booleanos como INTEGER 0/1,
-- listas y objetos como JSON en TEXT. NULL es "no se sabe", nunca cero.

CREATE TABLE IF NOT EXISTS inventario (
  id INTEGER PRIMARY KEY,
  equipo TEXT NOT NULL,
  programa TEXT NOT NULL,
  version TEXT,
  proveedor TEXT,
  sistema TEXT,
  fuente TEXT NOT NULL,          -- csv, excel, mcp, rmm
  cargado TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS programa_cpe (
  programa TEXT PRIMARY KEY,
  vendor TEXT,
  producto TEXT,
  confianza REAL,
  metodo TEXT,                   -- exacto, difuso, modelo, ninguno
  candidatos TEXT                -- JSON con los candidatos considerados
);

CREATE TABLE IF NOT EXISTS cpe_diccionario (
  vendor TEXT NOT NULL,
  producto TEXT NOT NULL,
  titulo TEXT,                   -- nombre legible, contra el que compara rapidfuzz
  PRIMARY KEY (vendor, producto)
);

CREATE TABLE IF NOT EXISTS cves (
  id TEXT PRIMARY KEY,
  publicada TEXT,
  modificada TEXT,
  estado TEXT,                   -- vulnStatus de NVD
  descripcion TEXT,
  cvss REAL,
  severidad TEXT,
  vector TEXT,
  version_cvss TEXT,
  cwes TEXT,                     -- JSON
  referencias TEXT,              -- JSON con url y etiquetas
  sin_productos INTEGER
);

CREATE TABLE IF NOT EXISTS cve_rangos (
  cve TEXT NOT NULL,
  cpe TEXT NOT NULL,             -- criterio completo de NVD
  vendor TEXT NOT NULL,
  producto TEXT NOT NULL,
  version TEXT,
  desde TEXT,
  desde_incluye INTEGER,
  hasta TEXT,
  hasta_incluye INTEGER
);
CREATE INDEX IF NOT EXISTS idx_rangos_producto ON cve_rangos (vendor, producto);
CREATE INDEX IF NOT EXISTS idx_rangos_cve ON cve_rangos (cve);

CREATE TABLE IF NOT EXISTS kev (
  cve TEXT PRIMARY KEY,
  fabricante TEXT,
  producto TEXT,
  accion TEXT,
  agregada TEXT,
  plazo TEXT,
  ransomware INTEGER
);

CREATE TABLE IF NOT EXISTS epss (
  cve TEXT PRIMARY KEY,
  epss REAL,
  percentil REAL,
  fecha TEXT
);

CREATE TABLE IF NOT EXISTS hallazgos (
  id TEXT PRIMARY KEY,           -- CVE|activo
  cve TEXT NOT NULL,
  activo TEXT NOT NULL,          -- producto@version
  producto TEXT NOT NULL,
  version_instalada TEXT,
  equipos TEXT,                  -- JSON
  prioridad TEXT NOT NULL,       -- inmediato, semanal, informativo, boletin
  por_que TEXT,                  -- JSON
  preciso INTEGER,
  rango TEXT,                    -- JSON con el Rango que emparejó
  kev INTEGER DEFAULT 0,
  ransomware INTEGER DEFAULT 0,
  epss REAL,                     -- NULL si EPSS no tiene la CVE
  cvss REAL,
  estado TEXT NOT NULL DEFAULT 'nuevo',  -- nuevo, en_curso, mitigado, descartado
  comentario TEXT,
  por TEXT,
  detectado TEXT,
  avisado INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_hallazgos_producto ON hallazgos (producto);

CREATE TABLE IF NOT EXISTS analisis (
  producto TEXT PRIMARY KEY,
  contenido TEXT,                -- JSON con la salida estructurada (contrato Analisis)
  verificado INTEGER,
  origen TEXT,                   -- agente o respaldo
  creado TEXT
);

CREATE TABLE IF NOT EXISTS cobertura (
  equipo TEXT,
  programa TEXT,
  version TEXT,
  motivo TEXT                    -- sin_version, no_comparable, sin_cpe
);

CREATE TABLE IF NOT EXISTS trabajos (
  id INTEGER PRIMARY KEY,
  tipo TEXT NOT NULL,            -- descargar, analizar
  estado TEXT NOT NULL DEFAULT 'pendiente',  -- pendiente, en_curso, hecho, fallido
  creado TEXT,
  terminado TEXT,
  detalle TEXT
);

CREATE TABLE IF NOT EXISTS ejecuciones (
  id INTEGER PRIMARY KEY,
  inicio TEXT,
  fin TEXT,
  tipo TEXT,
  fuentes TEXT,                  -- JSON: qué fuente respondió
  resumen TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS trazas (
  id INTEGER PRIMARY KEY,
  momento TEXT,
  herramienta TEXT,
  entrada TEXT,
  decision TEXT                  -- permitida, negada, limpiada
);
