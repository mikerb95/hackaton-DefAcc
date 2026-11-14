"""Configuración común de pytest.

- Marcador `agente` (declarado en pyproject.toml): pruebas que llaman a Claude. No corren en CI;
  se piden con `pytest -m agente`.
- Fixtures del snapshot de NVD y la respuesta conocida. `resources/` no está en el repositorio:
  si falta, las pruebas que lo usan se saltan en vez de fallar.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
SNAPSHOT = RAIZ / "resources" / "nvd_snapshot"
RESPUESTA = RAIZ / "resources" / "semilla_respuesta.json"


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
