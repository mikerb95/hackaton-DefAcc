"""Termómetro de exposición por equipo (0 a 100, más alto es peor).

Sale solo de las acciones abiertas del equipo, contadas por prioridad, que ya calcula
`radar/equipos/vista.py`. No participa ningún modelo. La lectura queda atada a la peor
prioridad para que el color del termómetro diga lo mismo que la píldora del equipo:

- con alguna acción inmediata: 60 a 100 (alto, y crítico desde 85),
- si lo peor es semanal: 25 a 59 (medio),
- si solo hay informativas: 5 a 24 (bajo),
- sin acciones: 0.

Dentro de cada tramo suma cuántas acciones hay. Un equipo pendiente de aprobación o que
nunca reportó no marca 0: queda sin lectura, porque no se revisó (fuente caída no es cero).
"""

from __future__ import annotations

from typing import Any

# (desde, banda, etiqueta)
BANDAS: list[tuple[int, str, str]] = [
    (85, "critico", "Crítico"),
    (60, "alto", "Alto"),
    (25, "medio", "Medio"),
    (0, "bajo", "Bajo"),
]


def nivel(inmediato: int, semanal: int, informativo: int) -> int:
    """Lectura de 0 a 100 a partir de las acciones abiertas por prioridad."""
    if inmediato:
        return min(100, 60 + 10 * inmediato + 2 * semanal + informativo)
    if semanal:
        return min(59, 25 + 6 * semanal + informativo)
    if informativo:
        return min(24, 5 + 3 * informativo)
    return 0


def banda(lectura: int) -> tuple[str, str]:
    for desde, clave, etiqueta in BANDAS:
        if lectura >= desde:
            return clave, etiqueta
    return "bajo", "Bajo"


def termometro(fila: dict[str, Any]) -> dict[str, Any]:
    """Termómetro de una fila de `vista.lista` o del `equipo` de `vista.detalle`."""
    acciones = fila.get("acciones") or {}
    conteo = {p: int(acciones.get(p, 0)) for p in ("inmediato", "semanal", "informativo")}
    if fila.get("pendiente"):
        return {
            "medido": False,
            "nivel": None,
            "banda": None,
            "etiqueta": "Sin cruzar",
            "motivo": "Se mide cuando el equipo esté aprobado.",
            "acciones": conteo,
        }
    if not fila.get("ultimo_reporte"):
        return {
            "medido": False,
            "nivel": None,
            "banda": None,
            "etiqueta": "Sin reporte",
            "motivo": "El equipo todavía no ha enviado su inventario.",
            "acciones": conteo,
        }
    lectura = nivel(**conteo)
    clave, etiqueta = banda(lectura)
    return {
        "medido": True,
        "nivel": lectura,
        "banda": clave,
        "etiqueta": "Sin acciones" if lectura == 0 else etiqueta,
        "motivo": None,
        "acciones": conteo,
    }
