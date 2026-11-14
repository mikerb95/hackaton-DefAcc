"""Hook PreToolUse del plugin radar: una persona aprueba cada escritura.

Se engancha solo a ``cargar_inventario``, la única herramienta del radar que escribe.
Devuelve ``permissionDecision: "ask"`` con un resumen corto y limpio de lo que se va a
cargar, así Claude Code le pregunta a la persona aunque la herramienta esté aprobada.

Si algo falla, niega (``"deny"``): ante la duda, no se escribe. Sale siempre con 0 y
JSON válido; además ``hooks.json`` lleva ``"onFailure": "block"``, que en PreToolUse sí
bloquea la llamada.

Solo librería estándar.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path


def _decision(decision: str, motivo: str) -> str:
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": motivo,
            }
        },
        ensure_ascii=False,
    )


def _traza(registro: dict) -> None:
    carpeta = os.environ.get("CLAUDE_PLUGIN_DATA")
    if not carpeta:
        return
    try:
        Path(carpeta).mkdir(parents=True, exist_ok=True)
        with open(Path(carpeta) / "traza.jsonl", "a", encoding="utf-8") as archivo:
            archivo.write(json.dumps(registro, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001, S110 - la traza nunca rompe la guarda
        pass


def resumen(entrada_herramienta: object) -> str:
    """Una línea con lo que se va a cargar, sin pasar texto crudo del inventario."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import limpieza  # copia que viaja con el plugin

    if not isinstance(entrada_herramienta, dict):
        return "Carga de inventario con argumentos no reconocidos."
    partes = []
    for clave, valor in entrada_herramienta.items():
        if isinstance(valor, list):
            partes.append(f"{limpieza.limpiar_texto(clave, 40)}: {len(valor)} elementos")
        elif isinstance(valor, str) and len(valor) > 80:
            partes.append(f"{limpieza.limpiar_texto(clave, 40)}: texto de {len(valor)} caracteres")
        else:
            partes.append(
                f"{limpieza.limpiar_texto(clave, 40)}: {limpieza.limpiar_texto(valor, 80)}"
            )
    return "El radar quiere escribir en la base compartida (" + "; ".join(partes) + ")."


def principal() -> int:
    hora = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        entrada = json.loads(sys.stdin.read())
        if not isinstance(entrada, dict):
            raise TypeError("la entrada del hook no es un objeto JSON")
        motivo = resumen(entrada.get("tool_input"))
        _traza(
            {
                "hora": hora,
                "evento": "PreToolUse",
                "herramienta": entrada.get("tool_name"),
                "tool_use_id": entrada.get("tool_use_id"),
                "decision": "ask",
            }
        )
        print(_decision("ask", motivo + " Revisa y aprueba solo si tú pediste esta carga."))
    except Exception as error:  # noqa: BLE001 - ante cualquier error, negar
        _traza(
            {
                "hora": hora,
                "evento": "PreToolUse",
                "decision": "deny",
                "error": type(error).__name__,
            }
        )
        print(_decision("deny", "La guarda del radar no pudo revisar la escritura; se niega."))
    return 0


if __name__ == "__main__":
    sys.exit(principal())
