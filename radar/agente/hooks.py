"""Hooks del analista (Claude Agent SDK) y piezas del encierro (regla 7).

- ``PreToolUse`` (guarda previa): registra cada llamada y niega toda herramienta que no
  esté en la lista exacta de permitidas, y todo argumento con saltos, control o largo
  de más (un argumento así es texto del inventario que el modelo está repitiendo).
- ``PostToolUse`` (limpieza): reemplaza el resultado con ``updatedToolOutput`` limpio y
  marcado como dato, antes de que el modelo lo vea.

Los dos atrapan sus propios errores y responden lo seguro (negar, retener): un hook que
falla en ``PostToolUse`` deja pasar el resultado crudo aunque tenga
``on_failure="block"`` (verificado por el frente plugin el 14 de noviembre de 2026).
``on_failure="block"`` queda igual como segunda capa.

Uso desde el analista::

    traza = Traza()
    opciones = ClaudeAgentOptions(
        model=..., system_prompt=..., mcp_servers=..., output_format=...,
        allowed_tools=PERMITIDAS,
        **opciones_encierro(PERMITIDAS, traza),
    )
"""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import HookMatcher

from radar.seguridad.limpieza import (
    LONGITUD_MAXIMA,
    limpiar_estructura,
    limpiar_resultado_herramienta,
    senales_de_instruccion,
)

# Herramientas integradas que se retiran del contexto. allowed_tools solo aprueba; sin
# esta lista el agente conserva terminal y archivos (trampa 1 del plan).
HERRAMIENTAS_INTEGRADAS = (
    "Bash",
    "BashOutput",
    "KillShell",
    "Read",
    "Write",
    "Edit",
    "MultiEdit",
    "Glob",
    "Grep",
    "LS",
    "WebFetch",
    "WebSearch",
    "NotebookEdit",
    "Agent",
    "Task",
    "TodoWrite",
    "Skill",
    "SlashCommand",
    "ExitPlanMode",
)

# Herramienta interna con la que el CLI entrega ``output_format``: su entrada es el análisis
# final del agente, no una acción, y **no tiene efectos fuera del proceso**. Excepción mínima:
# - solo con el nombre exacto (nunca prefijo ni patrón: "StructuredOutputX" o
#   "mcp__radar__StructuredOutput" no la heredan);
# - se salta solo ``_argumento_sospechoso`` (el análisis es largo y lleva saltos de línea);
#   sigue pasando por la lista de permitidas y se registra en la traza, recortada;
# - su contenido igual pasa por ``decidir()``, que es la defensa real sobre la salida.
SALIDA_ESTRUCTURADA = "StructuredOutput"

RETENIDO = (
    "Resultado retenido por la guarda del radar: no se pudo limpiar. "
    "Continúa solo con los datos que ya tienes."
)


@dataclass(frozen=True)
class Evento:
    hora: float
    evento: str  # "PreToolUse" o "PostToolUse"
    herramienta: str
    decision: str  # "permitir", "negar", "limpiar", "retener"
    motivo: str = ""
    entrada: dict[str, Any] = field(default_factory=dict)
    senales: tuple[str, ...] = ()


@dataclass
class Traza:
    """Registro en memoria de cada llamada. La suite de inyección lo lee para contar
    intentos de herramientas no permitidas; el worker puede volcarlo a la base."""

    eventos: list[Evento] = field(default_factory=list)
    # Los anota el analista al terminar (ResultMessage.total_cost_usd y num_turns), para que
    # la suite mida el costo real por corrida. None si no hubo modelo.
    costo_usd: float | None = None
    turnos: int | None = None

    def registrar(self, evento: Evento) -> None:
        self.eventos.append(evento)

    def negadas(self) -> list[Evento]:
        return [e for e in self.eventos if e.decision == "negar"]

    def herramientas_intentadas(self) -> list[str]:
        return [e.herramienta for e in self.eventos if e.evento == "PreToolUse"]

    def como_dicts(self) -> list[dict[str, Any]]:
        return [
            {
                "hora": e.hora,
                "evento": e.evento,
                "herramienta": e.herramienta,
                "decision": e.decision,
                "motivo": e.motivo,
                "entrada": e.entrada,
                "senales": list(e.senales),
            }
            for e in self.eventos
        ]


def _negar(motivo: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": motivo,
        }
    }


# Formato exacto de los argumentos que son identificadores. Agregado tras la ronda 2
# (r2-06): un texto del ataque como argumento de una herramienta permitida pasaba.
FORMATOS_ARGUMENTO = {
    "cve": re.compile(r"^CVE-\d{4}-\d{4,}$"),
}


def _argumento_sospechoso(valor: Any, clave: str | None = None) -> str | None:
    """Motivo para negar un argumento, o None si es un identificador razonable."""
    if isinstance(valor, dict):
        for k, v in valor.items():
            if motivo := _argumento_sospechoso(v, k if isinstance(k, str) else None):
                return motivo
        return None
    if isinstance(valor, (list, tuple)):
        for v in valor:
            if motivo := _argumento_sospechoso(v, clave):
                return motivo
        return None
    if not isinstance(valor, str):
        return None
    formato = FORMATOS_ARGUMENTO.get((clave or "").lower())
    if formato is not None and not formato.fullmatch(valor):
        return f"el argumento '{clave}' no tiene el formato esperado"
    if len(valor) > LONGITUD_MAXIMA:
        return f"argumento de {len(valor)} caracteres (máximo {LONGITUD_MAXIMA})"
    if any(c in "\r\n" or unicodedata.category(c) in {"Cc", "Cf", "Zl", "Zp"} for c in valor):
        return "argumento con saltos de línea o caracteres de control"
    return None


def crear_guarda(permitidas: Iterable[str], traza: Traza):
    """Callback ``PreToolUse``: solo pasa lo que está en ``permitidas``, con argumentos limpios."""
    lista = frozenset(permitidas)

    async def guarda(input_data: dict[str, Any], tool_use_id: str | None, context: Any):
        nombre = "?"
        try:
            nombre = str(input_data.get("tool_name", "?"))
            entrada = input_data.get("tool_input") or {}
            entrada_limpia = limpiar_estructura(entrada)
            if nombre not in lista:
                motivo = f"Herramienta fuera de la lista del radar: {nombre}"
            elif nombre == SALIDA_ESTRUCTURADA:
                motivo = None
            else:
                motivo = _argumento_sospechoso(entrada)
            if motivo:
                traza.registrar(
                    Evento(time.time(), "PreToolUse", nombre, "negar", motivo, entrada_limpia)
                )
                return _negar(motivo)
            traza.registrar(
                Evento(time.time(), "PreToolUse", nombre, "permitir", "", entrada_limpia)
            )
            return {}
        except Exception as error:  # noqa: BLE001 - ante cualquier error, negar
            motivo = f"La guarda no pudo revisar la llamada ({type(error).__name__}); se niega"
            traza.registrar(Evento(time.time(), "PreToolUse", nombre, "negar", motivo))
            return _negar(motivo)

    return guarda


def _limpiar_respuesta(respuesta: Any) -> Any:
    """Limpia ``tool_response`` y la devuelve con la misma forma con que llegó."""
    if isinstance(respuesta, list):
        return limpiar_resultado_herramienta({"content": respuesta})["content"]
    return limpiar_resultado_herramienta(respuesta)


def _texto_crudo(respuesta: Any) -> str:
    bloques = respuesta.get("content") if isinstance(respuesta, dict) else respuesta
    if isinstance(bloques, list):
        return "".join(
            str(b.get("text", ""))
            for b in bloques
            if isinstance(b, dict) and b.get("type") == "text"
        )
    return str(respuesta)


def crear_limpieza(traza: Traza):
    """Callback ``PostToolUse``: reemplaza el resultado por su versión limpia."""

    async def limpiar_resultado(input_data: dict[str, Any], tool_use_id: str | None, context: Any):
        nombre = "?"
        try:
            nombre = str(input_data.get("tool_name", "?"))
            respuesta = input_data.get("tool_response")
            limpio = _limpiar_respuesta(respuesta)
            senales = tuple(senales_de_instruccion(_texto_crudo(respuesta)))
            traza.registrar(Evento(time.time(), "PostToolUse", nombre, "limpiar", senales=senales))
        except Exception as error:  # noqa: BLE001 - ante cualquier error, retener
            traza.registrar(
                Evento(time.time(), "PostToolUse", nombre, "retener", type(error).__name__)
            )
            limpio = {"content": [{"type": "text", "text": RETENIDO}]}
        return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": limpio}}

    return limpiar_resultado


def crear_hooks(permitidas: Iterable[str], traza: Traza) -> dict[str, list[HookMatcher]]:
    """Hooks para ``ClaudeAgentOptions(hooks=...)``. Sin matcher: cubren toda herramienta."""
    return {
        "PreToolUse": [HookMatcher(hooks=[crear_guarda(permitidas, traza)], on_failure="block")],
        "PostToolUse": [HookMatcher(hooks=[crear_limpieza(traza)], on_failure="block")],
    }


def opciones_encierro(permitidas: Iterable[str], traza: Traza) -> dict[str, Any]:
    """Las opciones del encierro (regla 7), para pasar con ``**`` a ``ClaudeAgentOptions``.

    ``allowed_tools`` no va aquí a propósito: lo pone el analista con la misma lista, y
    solo aprueba; lo que encierra es esto.
    """
    lista = list(permitidas)
    return {
        "permission_mode": "dontAsk",
        "disallowed_tools": list(HERRAMIENTAS_INTEGRADAS),
        "setting_sources": [],
        "env": {"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"},
        "hooks": crear_hooks(lista, traza),
    }
