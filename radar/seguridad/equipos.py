"""Validación del nombre de equipo en la entrada (RFC 1123).

El nombre de equipo es el canal de inyección que sobrevive al normalizador: el nombre de
programa se pierde porque solo se eligen CPE reales, pero el equipo llega tal cual al
modelo y al comunicado de TI (inyección de segundo orden, docs/AMENAZAS.md).

Un nombre de equipo debe parecer un hostname: etiquetas de letras, dígitos y guion,
separadas por punto, de 1 a 63 caracteres, que no empiezan ni terminan en guion, y 253
caracteres en total. Si no lo es, la fila no se cruza: va a cobertura con el motivo
``equipo_invalido`` y el panel la muestra para revisión. Así el canal se cierra de forma
determinista, sin depender de que el modelo no obedezca.

Solo librería estándar. La usan ``radar/ingesta/archivos.py`` (frente plugin) y la suite de
inyección (``evals/escenarios.py``).
"""

from __future__ import annotations

import re

MOTIVO_EQUIPO_INVALIDO = "equipo_invalido"

LARGO_MAXIMO = 253
_ETIQUETA = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def nombre_equipo_valido(nombre: object) -> bool:
    """True si el nombre (sin espacios en los bordes) es un hostname según RFC 1123."""
    if not isinstance(nombre, str):
        return False
    texto = nombre.strip()
    texto = texto.removesuffix(".")
    if not texto or len(texto) > LARGO_MAXIMO:
        return False
    return all(_ETIQUETA.fullmatch(etiqueta) for etiqueta in texto.split("."))
