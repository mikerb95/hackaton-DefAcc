"""Acceso a datos del servidor MCP: lee de Turso por medio de radar/bd.py.

Mientras `radar/bd.py` no tenga una función de lectura, esa lectura sale de
`radar/ejemplos.py` y la respuesta lo dice (`"datos": "ejemplo"`), para que nadie tome
un ejemplo por un dato real. Con `RADAR_DATOS_EJEMPLO=1` se fuerzan los ejemplos (demo y
pruebas).

Si la función de bd existe y falla, el error sube: una base caída no se disfraza de
ejemplos ni de lista vacía (regla 2, fuente caída no es cero).
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

# Funciones pedidas a nucleo en .coordinacion/nucleo.md, con su respaldo de ejemplo.
LECTURAS: dict[str, str] = {
    "leer_hallazgos": "HALLAZGOS",  # -> list[Hallazgo]
    "leer_grupos": "GRUPOS",  # -> list[Grupo]
    "leer_cobertura": "COBERTURA",  # -> list[Cobertura]
    "leer_cves": "CVES",  # -> list[CVE]
    "leer_analisis": "ANALISIS",  # -> list[Analisis]
    "leer_ejecuciones": "EJECUCIONES",  # -> list[Ejecucion], la más reciente primero
}


def _forzar_ejemplos() -> bool:
    return os.environ.get("RADAR_DATOS_EJEMPLO", "").strip() in {"1", "true", "si", "sí"}


def _funcion_bd(nombre: str) -> Callable[[], list] | None:
    if _forzar_ejemplos():
        return None
    from radar import bd

    return getattr(bd, nombre, None)


def leer(nombre: str) -> tuple[list[Any], str]:
    """Devuelve (registros, origen) con origen "turso" o "ejemplo"."""
    if nombre not in LECTURAS:
        raise KeyError(nombre)
    funcion = _funcion_bd(nombre)
    if funcion is not None:
        return list(funcion()), "turso"
    from radar import ejemplos

    return list(getattr(ejemplos, LECTURAS[nombre])), "ejemplo"


def origen_combinado(*origenes: str) -> str:
    """Devuelve "turso" solo si todo vino de Turso; si algo es ejemplo, lo dice."""
    unicos = set(origenes)
    if unicos == {"turso"}:
        return "turso"
    if unicos == {"ejemplo"}:
        return "ejemplo"
    return "mixto (parte de ejemplo)"
