"""Reconstruye el hilo para la pantalla desde el historial de la API (solo anexión).

Así no hay una segunda copia "para la pantalla" que se desalinee. Un turno empieza con cada
pregunta: un mensaje de usuario de texto, o el rechazo con indicación ("mejor en curso"),
que viaja como tool_result con el prefijo `PREFIJO_CAMBIOS`.

Módulo puro.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

PREFIJO_CAMBIOS = "La persona no aprobó la propuesta y pidió cambios: "
_INDICACION = re.compile(r'^"([\s\S]*)"\.')


def texto_rechazo(comentario: str | None) -> str:
    if comentario:
        return (
            f'{PREFIJO_CAMBIOS}"{comentario}". Ajusta la propuesta según su indicación y vuelve a '
            "proponer si corresponde."
        )
    return "La persona no aprobó la propuesta. No la repitas igual: pregúntale qué quiere cambiar."


@dataclass
class Turno:
    pregunta: str
    respuesta: str = ""
    pasos: list[str] = field(default_factory=list)

    def a_dict(self) -> dict[str, Any]:
        return asdict(self)


def _indicacion(bloques: list[dict[str, Any]]) -> str | None:
    for b in bloques:
        if b.get("type") != "tool_result" or not b.get("is_error"):
            continue
        contenido = b.get("content")
        if not isinstance(contenido, str) or not contenido.startswith(PREFIJO_CAMBIOS):
            continue
        resto = contenido[len(PREFIJO_CAMBIOS) :]
        m = _INDICACION.match(resto)
        return m.group(1) if m else resto
    return None


def turnos_de(mensajes: list[dict[str, Any]]) -> list[Turno]:
    turnos: list[Turno] = []
    actual: Turno | None = None
    for m in mensajes:
        contenido = m.get("content")
        if m.get("role") == "user":
            if isinstance(contenido, str):
                actual = Turno(contenido)
                turnos.append(actual)
            elif isinstance(contenido, list):
                texto = next(
                    (b.get("text") for b in contenido if b.get("type") == "text" and b.get("text")),
                    None,
                )
                tiene_resultado = any(b.get("type") == "tool_result" for b in contenido)
                cambio = _indicacion(contenido)
                if texto and not tiene_resultado:
                    actual = Turno(texto)
                    turnos.append(actual)
                elif cambio:
                    actual = Turno(cambio)
                    turnos.append(actual)
            continue
        if actual is None or not isinstance(contenido, list):
            continue
        for b in contenido:
            if b.get("type") == "text" and (b.get("text") or "").strip():
                t = b["text"].strip()
                actual.respuesta = f"{actual.respuesta}\n\n{t}" if actual.respuesta else t
            if b.get("type") == "tool_use" and b.get("name") and b["name"] not in actual.pasos:
                actual.pasos.append(b["name"])
    return turnos


def contar_turnos(mensajes: list[dict[str, Any]]) -> int:
    return len(turnos_de(mensajes))
