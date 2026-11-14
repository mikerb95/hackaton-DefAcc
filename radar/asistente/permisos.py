"""Qué herramientas y acciones recibe cada rol. El motor solo manda al modelo las del rol de
quien pregunta, y `validar` y `ejecutar` lo vuelven a comprobar en el servidor: quitar una
herramienta del prompt no es seguridad, el chequeo sí.

Los roles salen de las mismas reglas que protegen las rutas del panel: escrituras de
hallazgos y comunicados piden analista; equipos y usuarios piden admin.

Módulo puro.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from radar.asistente.escrituras import ESCRITURAS, Escritura
from radar.asistente.herramientas import HERRAMIENTAS, Herramienta


def herramientas_de(rol: str) -> list[Herramienta]:
    return [h for h in HERRAMIENTAS if rol in h.roles]


def escrituras_de(rol: str) -> list[Escritura]:
    return [e for e in ESCRITURAS if rol in e.roles]


def puede(rol: str, nombre: str) -> bool:
    return any(h.nombre == nombre for h in herramientas_de(rol)) or any(
        e.nombre == nombre for e in escrituras_de(rol)
    )


def validar(rol: str, nombre: str, entrada: Any) -> str | None:
    """Error para el modelo, o None si la llamada es válida y permitida."""
    if not puede(rol, nombre):
        return "Sin permiso para esa herramienta con tu rol."
    modelo = next((h.entrada for h in HERRAMIENTAS if h.nombre == nombre), None) or next(
        e.entrada for e in ESCRITURAS if e.nombre == nombre
    )
    try:
        modelo.model_validate(entrada or {})
    except ValidationError as error:
        detalle = "; ".join(
            f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in error.errors()[:3]
        )
        return f"Entrada no válida: {detalle}"
    return None


def definiciones(rol: str) -> list[dict[str, Any]]:
    """Herramientas en el formato de la API, en orden fijo (la caché depende del orden)."""
    salida = []
    for h in [*herramientas_de(rol), *escrituras_de(rol)]:
        esquema = h.entrada.model_json_schema()
        esquema.pop("title", None)
        salida.append({"name": h.nombre, "description": h.descripcion, "input_schema": esquema})
    if salida:
        salida[-1]["cache_control"] = {"type": "ephemeral"}
    return salida
