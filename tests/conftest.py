"""Configuración común de pytest.

- Marcador `agente` (declarado en pyproject.toml): pruebas que llaman a Claude. No corren en CI;
  se piden con `pytest -m agente`.
- Aislamiento automático (`_aislar_bases`, en todas las pruebas): ninguna prueba toca la base
  compartida `datos_locales/radar.db`, Turso ni NVD con credenciales reales. `RADAR_SQLITE`
  apunta a un sqlite vacío en tmp_path y se quitan `TURSO_*` y `NVD_API_KEY` del entorno.
  `ANTHROPIC_API_KEY` se deja: la usan las pruebas marcadas `agente`.
- `base_temporal`: sqlite en tmp_path con el esquema, las CVE reales de radar/ejemplos.py
  (WinRAR, Chrome, Docker Desktop), KEV y EPSS. `base_con_hallazgos`: además, el cruce corrido.
  Sirven sin resources/ (CI y otro PC).
- `requiere_resources` y los fixtures del snapshot: `resources/` no está en el repositorio; si
  falta, la prueba se salta en vez de fallar.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
SNAPSHOT = RAIZ / "resources" / "nvd_snapshot"
RESPUESTA = RAIZ / "resources" / "semilla_respuesta.json"


VARIABLES_AISLADAS = (
    "TURSO_DATABASE_URL",
    "TURSO_AUTH_TOKEN",
    "TURSO_AUTH_TOKEN_LECTURA",
    "NVD_API_KEY",
    "NTFY_TOPICO",
    "NTFY_TOKEN",
    "NTFY_SERVIDOR",
)


@pytest.fixture(autouse=True)
def _aislar_bases(monkeypatch, tmp_path):
    """Cada prueba usa su propio sqlite vacío y nunca Turso ni la clave de NVD."""
    for nombre in VARIABLES_AISLADAS:
        monkeypatch.delenv(nombre, raising=False)
    monkeypatch.setenv("RADAR_SQLITE", str(tmp_path / "aislada.db"))


@pytest.fixture
def requiere_resources():
    """Salta la prueba si falta resources/ (material privado, fuera del repositorio)."""
    if not SNAPSHOT.exists() or not RESPUESTA.exists():
        pytest.skip("Falta resources/ (snapshot de NVD y respuesta conocida)")


@pytest.fixture
def base_temporal(tmp_path):
    """Conexión a un sqlite en tmp_path con esquema, CVE de ejemplo, KEV y EPSS."""
    from radar import bd, ejemplos

    c = bd.conectar(ruta_sqlite=tmp_path / "base_temporal.db")
    bd.crear_esquema(c)
    bd.guardar_cves(c, ejemplos.CVES)
    bd.guardar_kev(c, ejemplos.SENALES.kev)
    bd.guardar_epss(c, ejemplos.SENALES.epss)
    yield c
    c.close()


@pytest.fixture
def base_con_hallazgos(base_temporal):
    """`base_temporal` con inventario y cruce de ejemplos.py: 3 hallazgos (WinRAR y Chrome
    inmediatos con KEV, Docker Desktop semanal), cobertura y línea base aplicada."""
    from datetime import UTC, datetime

    from radar import bd, ejemplos
    from radar.config import Umbrales
    from radar.nucleo.corrida import correr

    bd.guardar_inventario(base_temporal, ejemplos.FILAS)
    correr(
        base_temporal,
        ejemplos.ACTIVOS,
        ejemplos.COBERTURA,
        umbrales=Umbrales(),
        ahora=datetime(2026, 11, 14, 10, 0, tzinfo=UTC),
    )
    return base_temporal


def archivo_de_par(par: str) -> Path:
    """Archivo del snapshot para un par 'vendor:producto'."""
    return SNAPSHOT / (par.replace(":", "__").replace("\\", "") + ".json")


@pytest.fixture(scope="session")
def respuesta_conocida() -> dict:
    if not RESPUESTA.exists():
        pytest.skip("Falta resources/semilla_respuesta.json (material privado, fuera del repo)")
    return json.loads(RESPUESTA.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def snapshot_kev() -> dict:
    ruta = SNAPSHOT / "kev.json"
    if not ruta.exists():
        pytest.skip("Falta resources/nvd_snapshot/kev.json")
    return json.loads(ruta.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def cves_por_par():
    """Carga perezosa del snapshot por par, con caché para toda la sesión."""
    from radar.fuentes.nvd import leer_snapshot

    if not SNAPSHOT.exists():
        pytest.skip("Falta resources/nvd_snapshot (material privado, fuera del repo)")
    cache: dict[str, list] = {}

    def cargar(par: str) -> list:
        if par not in cache:
            cache[par] = list(leer_snapshot([archivo_de_par(par)]).values())
        return cache[par]

    return cargar
