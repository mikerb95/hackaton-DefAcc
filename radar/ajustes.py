"""Ajustes que se cambian sin redesplegar: hoy, el modelo de Claude de cada uso.

Dos usos del modelo:

- `analista`: el agente que redacta análisis y comunicados (`radar/agente/analista.py`).
- `desempate`: la llamada corta del normalizador cuando dos CPE empatan
  (`radar/ingesta/normalizador.py`, solo con `RADAR_DESEMPATE_MODELO=1`).

De dónde sale el modelo, en este orden:

1. Lo elegido en la consola (sección Configuración del panel), guardado en la tabla `ajustes`.
2. La variable del uso: `RADAR_MODELO_ANALISTA` o `RADAR_MODELO_DESEMPATE`.
3. La variable común `RADAR_MODELO`.
4. `MODELO_POR_DEFECTO`.

La tabla vive aquí y no en `radar/esquema.sql` (mismo criterio que `radar/api/cuentas.py`): se
crea con `CREATE TABLE IF NOT EXISTS` la primera vez que se escribe. Si la base no responde o la
tabla no existe, se sigue con la variable de entorno: un ajuste ilegible nunca detiene al worker.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

Uso = Literal["analista", "desempate"]
USOS: tuple[Uso, ...] = ("analista", "desempate")

MODELO_POR_DEFECTO = "claude-opus-5-5"

# Los que ofrece la consola. Por variable de entorno se acepta cualquier ID con forma válida.
MODELOS_CONOCIDOS: dict[str, str] = {
    "claude-opus-5-5": "Claude Opus 5.5",
    "claude-sonnet-5-5": "Claude Sonnet 5.5",
    "claude-haiku-5-5": "Claude Haiku 5.5",
    "claude-fable-5-2": "Claude Fable 5.2",
}

VARIABLE_COMUN = "RADAR_MODELO"
VARIABLES: dict[Uso, str] = {
    "analista": "RADAR_MODELO_ANALISTA",
    "desempate": "RADAR_MODELO_DESEMPATE",
}

_FORMA = re.compile(r"^claude-[a-z0-9][a-z0-9.\-]{1,62}$")
CACHE_S = 30  # el worker pide el modelo por producto; así no consulta la base cada vez

ESQUEMA_AJUSTES = """
CREATE TABLE IF NOT EXISTS ajustes (
  clave TEXT PRIMARY KEY,
  valor TEXT NOT NULL,
  por TEXT,
  cambiado TEXT NOT NULL
);
"""


class AjusteInvalido(ValueError):
    """Valor de ajuste que no se acepta (se responde 422)."""


@dataclass(frozen=True)
class ModeloVigente:
    uso: Uso
    modelo: str
    origen: Literal["consola", "variable", "defecto"]
    variable: str | None = None  # la que lo dio, si origen == "variable"
    por: str | None = None
    cambiado: str | None = None

    def publico(self) -> dict[str, Any]:
        return {
            "uso": self.uso,
            "modelo": self.modelo,
            "nombre": MODELOS_CONOCIDOS.get(self.modelo, self.modelo),
            "origen": self.origen,
            "variable": self.variable,
            "por": self.por,
            "cambiado": self.cambiado,
            "del_entorno": modelo_de_entorno(self.uso)[0],
        }


def valido(modelo: str) -> bool:
    return bool(_FORMA.match(modelo))


def _clave(uso: Uso) -> str:
    return f"modelo.{uso}"


def modelo_de_entorno(uso: Uso) -> tuple[str, str | None]:
    """(modelo, variable que lo dio) sin mirar la base. Un valor mal formado se ignora."""
    for nombre in (VARIABLES[uso], VARIABLE_COMUN):
        valor = (os.environ.get(nombre) or "").strip()
        if not valor:
            continue
        if valido(valor):
            return valor, nombre
        print(
            f"[radar] {nombre}={valor!r} no parece un modelo de Claude; se ignora.",
            file=sys.stderr,
            flush=True,
        )
    return MODELO_POR_DEFECTO, None


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

_cache: dict[str, tuple[float, dict[str, dict[str, Any]]]] = {}


def _destino() -> str:
    return "|".join(
        os.environ.get(n, "") for n in ("TURSO_DATABASE_URL", "RADAR_SQLITE", "RADAR_DATOS")
    )


def _leer_guardados(conexion: Any = None) -> dict[str, dict[str, Any]]:
    """Ajustes guardados por clave. Vacío si la tabla no existe o la base no responde."""
    clave = _destino()
    if conexion is None:
        en_cache = _cache.get(clave)
        if en_cache and time.monotonic() - en_cache[0] < CACHE_S:
            return en_cache[1]
    propia = conexion is None
    try:
        if propia:
            from radar import bd

            conexion = bd.conectar(solo_lectura=True)
        cursor = conexion.execute("SELECT clave, valor, por, cambiado FROM ajustes")
        nombres = [d[0] for d in cursor.description]
        filas = {f[0]: dict(zip(nombres, f, strict=True)) for f in cursor.fetchall()}
    except Exception:  # noqa: BLE001 - tabla ausente o base caída: manda el entorno
        filas = {}
    finally:
        if propia and conexion is not None:
            with contextlib.suppress(Exception):
                conexion.close()
    _cache[clave] = (time.monotonic(), filas)
    return filas


def olvidar_cache() -> None:
    _cache.clear()


def modelo_vigente(uso: Uso, conexion: Any = None) -> ModeloVigente:
    guardado = _leer_guardados(conexion).get(_clave(uso))
    if guardado and valido(str(guardado["valor"])):
        return ModeloVigente(
            uso,
            guardado["valor"],
            "consola",
            por=guardado.get("por"),
            cambiado=guardado.get("cambiado"),
        )
    modelo, variable = modelo_de_entorno(uso)
    return ModeloVigente(uso, modelo, "variable" if variable else "defecto", variable)


def modelo(uso: Uso) -> str:
    """El ID de modelo que hay que usar ahora para `uso`."""
    return modelo_vigente(uso).modelo


def guardar_modelo(conexion: Any, uso: Uso, valor: str | None, por: str | None) -> None:
    """Fija el modelo de `uso` desde la consola. Con `valor` None se borra y vuelve a mandar
    la variable de entorno. Solo se aceptan los de `MODELOS_CONOCIDOS`."""
    if uso not in USOS:
        raise AjusteInvalido(f"Uso desconocido: {uso!r}.")
    conexion.executescript(ESQUEMA_AJUSTES)
    if valor is None:
        conexion.execute("DELETE FROM ajustes WHERE clave = ?", [_clave(uso)])
    else:
        if valor not in MODELOS_CONOCIDOS:
            raise AjusteInvalido(f"Modelo no disponible en la consola: {valor!r}.")
        conexion.execute(
            "INSERT INTO ajustes (clave, valor, por, cambiado) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor, por = excluded.por, "
            "cambiado = excluded.cambiado",
            [_clave(uso), valor, por, datetime.now(UTC).isoformat(timespec="seconds")],
        )
    conexion.commit()
    olvidar_cache()
