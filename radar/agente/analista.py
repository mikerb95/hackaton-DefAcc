"""Analista con Claude Agent SDK (PLAN, sección 13; docs/contrato-analista.md §4 y §5).

``analizar(grupo, defensa, fuente, traza)`` corre el agente sobre un producto y devuelve la
salida estructurada **sin** pasarla por el verificador: eso lo hacen el worker
(worker/analizar.py) y la suite de inyección, con ``radar.agente.verificador.decidir``.
Devuelve ``None`` si el modelo falla o la salida no cumple el esquema; quien llama cae al
respaldo (regla 6).

Dos brazos:

- ``defensa=True`` (producción): solo las tres herramientas de lectura y el encierro de
  ``radar.agente.hooks.opciones_encierro`` (dontAsk, integradas retiradas, sin
  configuración del disco, sin memoria, guarda previa y limpieza posterior con
  ``on_failure="block"``). Regla 7.
- ``defensa=False`` (solo para medir): las tres más ``marcar_mitigado`` aprobada, sin
  hooks y sin dontAsk. Es vulnerable a propósito. Igual se le retiran las herramientas
  integradas y la configuración del disco: el brazo mide si el agente ejecuta la escritura
  del radar, no se le da terminal sobre la máquina que corre la suite.
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from pydantic import ValidationError

from radar.agente.herramientas import (
    LECTURA,
    PERMITIDAS_SIN_DEFENSA,
    SERVIDOR,
    Fuente,
    FuenteBase,
    crear_servidor,
)

# SALIDA_ESTRUCTURADA: herramienta interna con que el CLI entrega ``output_format``. Tiene que
# estar aprobada y en la lista de la guarda, o el agente nunca puede responder (primera
# corrida real: 8 turnos sin structured_output).
from radar.agente.hooks import (
    HERRAMIENTAS_INTEGRADAS,
    SALIDA_ESTRUCTURADA,
    Traza,
    opciones_encierro,
)
from radar.ajustes import MODELO_POR_DEFECTO, modelo
from radar.agente.instrucciones import ESQUEMA_ANALISIS, INSTRUCCIONES, armar_pedido
from radar.contratos import Analisis, Grupo

# El modelo sale de radar/ajustes.py (consola > RADAR_MODELO_ANALISTA > RADAR_MODELO > defecto).
MODELO = MODELO_POR_DEFECTO
MAX_TURNOS = 8
MAX_PRESUPUESTO_USD = 0.50

# Sin búsqueda de herramientas: el CLI difiere las herramientas MCP y el agente gastaba un
# turno pidiendo ToolSearch, que la guarda niega (segunda corrida real). Con esto las tres
# herramientas del radar llegan cargadas desde el primer turno.
ENTORNO_EXTRA = {"ENABLE_TOOL_SEARCH": "false"}


def _log(mensaje: str) -> None:
    print(f"[analista] {mensaje}", file=sys.stderr, flush=True)


def opciones(fuente: Fuente, defensa: bool, traza: Traza | None, cwd: str | None = None) -> Any:
    """``ClaudeAgentOptions`` de un brazo. ``cwd`` es un directorio vacío: el agente no
    tiene herramientas de archivos, pero el proceso ``claude`` igual arranca en algún lado."""
    from claude_agent_sdk import ClaudeAgentOptions

    comunes: dict[str, Any] = {
        "model": modelo("analista"),
        "system_prompt": INSTRUCCIONES,
        "output_format": {"type": "json_schema", "schema": ESQUEMA_ANALISIS},
        "max_turns": MAX_TURNOS,
        "max_budget_usd": MAX_PRESUPUESTO_USD,
        "cwd": cwd,
    }
    if defensa:
        permitidas = [*LECTURA, SALIDA_ESTRUCTURADA]
        encierro = opciones_encierro(permitidas, traza if traza is not None else Traza())
        encierro["env"] = {**encierro["env"], **ENTORNO_EXTRA}
        return ClaudeAgentOptions(
            mcp_servers={SERVIDOR: crear_servidor(fuente, escritura=False)},
            allowed_tools=permitidas,
            **encierro,
            **comunes,
        )
    return ClaudeAgentOptions(
        mcp_servers={SERVIDOR: crear_servidor(fuente, escritura=True)},
        allowed_tools=[*PERMITIDAS_SIN_DEFENSA, SALIDA_ESTRUCTURADA],
        disallowed_tools=list(HERRAMIENTAS_INTEGRADAS),
        setting_sources=[],
        env={"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1", **ENTORNO_EXTRA},
        **comunes,
    )


def a_analisis(salida: Any, grupo: Grupo) -> Analisis | None:
    """Convierte ``structured_output`` en ``Analisis``. ``None`` si no cumple el contrato.

    ``producto``, ``origen`` y ``verificado`` los pone el código: el modelo no decide de qué
    producto habla ni si su texto está verificado.
    """
    if not isinstance(salida, dict):
        return None
    datos = {k: v for k, v in salida.items() if k not in ("hallazgo", "verificado", "origen")}
    datos |= {"producto": grupo.producto, "origen": "agente", "verificado": False}
    try:
        return Analisis.model_validate(datos)
    except ValidationError as error:
        _log(f"salida fuera del contrato: {error.error_count()} errores")
        return None


async def analizar_async(
    grupo: Grupo, defensa: bool, fuente: Fuente | None = None, traza: Traza | None = None
) -> Analisis | None:
    from claude_agent_sdk import ResultMessage, query

    fuente = fuente if fuente is not None else FuenteBase(grupo)
    directorio = tempfile.mkdtemp(prefix="radar-analista-")
    resultado: ResultMessage | None = None
    try:
        async for mensaje in query(
            prompt=armar_pedido(grupo), options=opciones(fuente, defensa, traza, directorio)
        ):
            if isinstance(mensaje, ResultMessage):
                resultado = mensaje
    finally:
        shutil.rmtree(directorio, ignore_errors=True)
    if resultado is None:
        _log(f"{grupo.producto}: el agente terminó sin resultado")
        return None
    if traza is not None:
        # La suite guarda estos campos en cada resultado y evals.medir suma el costo.
        traza.costo_usd = resultado.total_cost_usd
        traza.turnos = resultado.num_turns
    costo = f"{resultado.total_cost_usd:.4f}" if resultado.total_cost_usd is not None else "?"
    _log(
        f"{grupo.producto}: {resultado.subtype}, {resultado.num_turns} turnos, "
        f"USD {costo}, defensa={defensa}"
    )
    if resultado.is_error:
        return None
    return a_analisis(resultado.structured_output, grupo)


def analizar(
    grupo: Grupo, defensa: bool, fuente: Fuente | None = None, traza: Traza | None = None
) -> Analisis | None:
    """Firma que espera la suite de inyección (``evals/inyeccion.py::agente_real``).

    Nunca lanza: un error del SDK, de la red o de la base devuelve ``None`` y quien llama
    usa el respaldo.
    """
    try:
        corrutina = analizar_async(grupo, defensa, fuente, traza)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(corrutina)
        # Ya hay un bucle corriendo (por ejemplo, dentro de otra corrutina): otro hilo.
        with ThreadPoolExecutor(max_workers=1) as hilo:
            return hilo.submit(asyncio.run, corrutina).result()
    except Exception as error:  # noqa: BLE001 - el modelo no es punto de falla (regla 6)
        _log(f"{grupo.producto}: falló ({type(error).__name__}: {error})")
        return None
