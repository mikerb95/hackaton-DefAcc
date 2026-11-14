"""Revisión de la respuesta del modelo antes de mostrarla.

1. Sin rayas largas ni medias como puntuación: el modelo las pone aunque el prompt lo
   prohíba, así que se quitan aquí también.
2. Ningún identificador de CVE que no haya salido de una herramienta en esta conversación.
   Es el equivalente de "el modelo no inventa cifras de dinero" de la receta: en el radar,
   lo que no se puede inventar es una CVE. Si aparece una, se avisa debajo de la respuesta.

Módulo puro.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Raya (U+2014) y semirraya (U+2013), armadas por código para no escribirlas en el fuente.
RAYAS = chr(0x2014) + chr(0x2013)
_RAYA_CON_ESPACIOS = re.compile(rf"\s+[{RAYAS}]\s+")
_RAYA = re.compile(rf"[{RAYAS}]")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def sin_rayas(texto: str) -> str:
    texto = _RAYA_CON_ESPACIOS.sub(", ", texto)
    return _RAYA.sub("-", texto)


def cves_no_vistas(texto: str, vistos: Iterable[str]) -> list[str]:
    fuente = " ".join(vistos).upper()
    faltan: list[str] = []
    for cve in _CVE.findall(texto):
        cve = cve.upper()
        if cve not in fuente and cve not in faltan:
            faltan.append(cve)
    return faltan


def revisar(texto: str, vistos: Iterable[str]) -> str:
    limpio = sin_rayas(texto)
    faltan = cves_no_vistas(limpio, list(vistos))
    if faltan:
        limpio += (
            "\n\nOjo: "
            + ", ".join(faltan)
            + " no salió de los datos del radar en esta conversación. Verifícala antes de usarla."
        )
    return limpio


def vistos_de(mensajes: list[dict]) -> list[str]:
    """Todo lo que devolvieron las herramientas en la conversación (fuente de la guardia)."""
    vistos: list[str] = []
    for m in mensajes:
        contenido = m.get("content")
        if m.get("role") != "user" or not isinstance(contenido, list):
            continue
        for b in contenido:
            if b.get("type") == "tool_result" and isinstance(b.get("content"), str):
                vistos.append(b["content"])
    return vistos
