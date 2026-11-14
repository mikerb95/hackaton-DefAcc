"""Hook PostToolUse del plugin radar: limpia la salida de las herramientas del radar.

Lee de stdin la entrada del hook, toma ``tool_response`` (en herramientas MCP llega
como lista de bloques de contenido), limpia cada texto con ``limpieza.py`` (copia
exacta de ``radar/seguridad/limpieza.py``) y devuelve ``updatedToolOutput`` con la
misma forma, para que Claude vea solo el texto limpio y marcado como dato.

Nunca falla. En PostToolUse la herramienta ya corrió y un hook que falla deja pasar
el texto original aunque tenga ``"onFailure": "block"`` (verificado el 14 de noviembre
de 2026). Por eso cualquier error termina en una salida fija que retiene el texto, y el
script sale siempre con 0.

Escribe una línea de traza por llamada en ``${CLAUDE_PLUGIN_DATA}/traza.jsonl``, sin el
texto crudo: herramienta, largo, señales de instrucción y si se retuvo.

Solo librería estándar. Se lee entero antes de instalar el plugin: es corto a propósito.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

RETENIDO = (
    "Salida retenida por la guarda del radar: no se pudo limpiar. "
    "No se muestra el resultado de la herramienta."
)


def _salida(actualizado: object) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": actualizado,
            }
        },
        ensure_ascii=False,
    )


def _bloques_de(respuesta: object) -> tuple[list, bool]:
    """Bloques de contenido y si venían envueltos en {"content": [...]}."""
    if isinstance(respuesta, list):
        return respuesta, False
    if isinstance(respuesta, dict) and isinstance(respuesta.get("content"), list):
        return respuesta["content"], True
    if isinstance(respuesta, str):
        return [{"type": "text", "text": respuesta}], False
    return [{"type": "text", "text": json.dumps(respuesta, ensure_ascii=False, default=str)}], False


def _traza(registro: dict) -> None:
    carpeta = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not carpeta:
        return
    try:
        Path(carpeta).mkdir(parents=True, exist_ok=True)
        with open(Path(carpeta) / "traza.jsonl", "a", encoding="utf-8") as archivo:
            archivo.write(json.dumps(registro, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001, S110 - la traza nunca rompe la limpieza
        pass


def limpiar(entrada: dict) -> object:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import limpieza  # copia que viaja con el plugin

    bloques, envuelto = _bloques_de(entrada.get("tool_response"))
    limpio = limpieza.limpiar_resultado_herramienta({"content": bloques})
    texto_original = "".join(
        str(b.get("text", "")) for b in bloques if isinstance(b, dict) and b.get("type") == "text"
    )
    _traza(
        {
            "hora": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evento": "PostToolUse",
            "herramienta": entrada.get("tool_name"),
            "tool_use_id": entrada.get("tool_use_id"),
            "largo": len(texto_original),
            "sha256": hashlib.sha256(texto_original.encode("utf-8")).hexdigest(),
            "senales": limpieza.senales_de_instruccion(texto_original),
            "retenido": False,
        }
    )
    return limpio if envuelto else limpio["content"]


def principal() -> int:
    try:
        entrada = json.loads(sys.stdin.read())
        if not isinstance(entrada, dict):
            raise TypeError("la entrada del hook no es un objeto JSON")
        print(_salida(limpiar(entrada)))
    except Exception as error:  # noqa: BLE001 - ante cualquier error, retener
        _traza(
            {
                "hora": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "evento": "PostToolUse",
                "retenido": True,
                "error": type(error).__name__,
            }
        )
        print(_salida([{"type": "text", "text": RETENIDO}]))
    return 0


if __name__ == "__main__":
    sys.exit(principal())
