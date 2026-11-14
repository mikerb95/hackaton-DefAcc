"""Herramientas del analista (Claude Agent SDK) y la fuente de datos que las alimenta.

Las herramientas no leen la base directamente: le piden los datos a una ``Fuente``
(Protocol ``evals.inyeccion.Fuente``). Por defecto es ``FuenteBase``, que lee con
``radar.bd.conectar(solo_lectura=True)``; la suite de inyección pasa la suya para meter la
fila envenenada sin tocar la base.

Lo que devuelven son identificadores y datos normalizados (producto canónico, versión,
nombre de equipo ya saneado por la ingesta, CVE, cifras), nunca el nombre de programa ni el
proveedor crudos del inventario (docs/AMENAZAS.md). La limpieza del texto la hace el hook
posterior (radar/agente/hooks.py); aquí no se duplica.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any, Protocol

from claude_agent_sdk import create_sdk_mcp_server, tool

from radar import bd
from radar.contratos import CVE, Grupo, Senales

SERVIDOR = "radar"
DETALLE_PRODUCTO = f"mcp__{SERVIDOR}__detalle_producto"
EQUIPOS_AFECTADOS = f"mcp__{SERVIDOR}__equipos_afectados"
DETALLE_CVE = f"mcp__{SERVIDOR}__detalle_cve"
MARCAR_MITIGADO = f"mcp__{SERVIDOR}__marcar_mitigado"

# Brazo con defensa: solo lectura. Brazo sin defensa (solo para medir): más la escritura.
LECTURA = (DETALLE_PRODUCTO, EQUIPOS_AFECTADOS, DETALLE_CVE)
PERMITIDAS_SIN_DEFENSA = (*LECTURA, MARCAR_MITIGADO)

# Cuántas referencias de NVD se devuelven por CVE.
MAX_REFERENCIAS = 5


class Fuente(Protocol):
    def detalle_producto(self, producto: str) -> dict[str, Any]: ...
    def equipos_afectados(self, producto: str) -> dict[str, Any]: ...
    def detalle_cve(self, cve: str) -> dict[str, Any]: ...
    def marcar_mitigado(self, producto: str) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Fuente por defecto: la base
# ---------------------------------------------------------------------------


def _detalle_grupo(grupo: Grupo) -> dict[str, Any]:
    """Los datos del grupo sin la lista de equipos (esa la da equipos_afectados).

    Misma forma que ``FuenteEscenario`` de la suite, para que el agente vea lo mismo en la
    prueba y en producción.
    """
    return grupo.model_dump(mode="json", exclude={"equipos"}) | {"n_equipos": grupo.n_equipos}


def _detalle_cve(cve: CVE | None, cve_id: str, grupo: Grupo, senales: Senales) -> dict[str, Any]:
    kev = senales.kev.get(cve_id)
    epss = senales.epss.get(cve_id)
    salida: dict[str, Any] = {
        "cve": cve_id,
        "producto": grupo.producto,
        "en_kev": cve_id in grupo.en_kev,
        # Regla 2: EPSS que no aparece no es 0.
        "epss": epss.epss if epss else "sin dato",
        "percentil_epss": epss.percentil if epss else "sin dato",
    }
    if kev:
        salida |= {"kev_ransomware": kev.ransomware, "kev_accion": kev.accion}
    if cve:
        salida |= {
            "descripcion": cve.descripcion,
            "cvss": cve.cvss,
            "severidad": cve.severidad,
            "cwes": cve.cwes,
            "referencias": [r.url for r in cve.referencias[:MAX_REFERENCIAS]],
        }
    return salida


class FuenteBase:
    """Datos de un grupo leídos de la base en solo lectura.

    Lee todo al crearse (hallazgos, CVE y señales del producto, tres o cuatro consultas) y
    cierra la conexión: las herramientas corren dentro del bucle del SDK y no conviene
    abrir conexiones ahí. Solo responde sobre el producto del grupo.
    """

    def __init__(self, grupo: Grupo, conexion: Any = None) -> None:
        self.grupo = grupo
        propia = conexion is None
        conexion = conexion or bd.conectar(solo_lectura=True)
        try:
            hallazgos = bd.leer_hallazgos(conexion, grupo.producto)
            pares = sorted({h.rango.par for h in hallazgos if h.rango})
            ids = set(grupo.cves)
            self.cves: dict[str, CVE] = {
                c.id: c for c in (bd.leer_cves(conexion, pares) if pares else []) if c.id in ids
            }
            self.senales = bd.leer_senales(conexion, cves=sorted(ids)) if ids else Senales()
        finally:
            if propia:
                conexion.close()
        # Equipo y versión desde los hallazgos: la ingesta ya saneó los nombres de equipo.
        filas = {
            (equipo, h.version_instalada)
            for h in hallazgos
            for equipo in h.equipos
            if equipo in grupo.equipos
        }
        self.filas = [{"equipo": e, "version": v} for e, v in sorted(filas)]

    def textos_origen(self) -> list[str]:
        """Texto de fuentes confiables para ``decidir(textos_origen=...)``: descripciones y
        referencias de NVD, y la acción requerida de KEV (CISA) de las CVE del grupo.

        Nunca texto del inventario: una fila envenenada pasaría a ser "origen".
        """
        acciones = [
            kev.accion
            for cve in self.grupo.cves
            if (kev := self.senales.kev.get(cve)) is not None and kev.accion
        ]
        return textos_nvd(self.cves.values()) + acciones

    def detalle_producto(self, producto: str) -> dict[str, Any]:
        if producto != self.grupo.producto:
            return {"error": "sin datos de ese producto en este análisis"}
        return _detalle_grupo(self.grupo)

    def equipos_afectados(self, producto: str) -> dict[str, Any]:
        if producto != self.grupo.producto:
            return {"producto": producto, "filas": []}
        return {"producto": producto, "filas": self.filas}

    def detalle_cve(self, cve: str) -> dict[str, Any]:
        if cve not in self.grupo.cves:
            return {"error": "CVE no encontrada en los datos del radar"}
        return _detalle_cve(self.cves.get(cve), cve, self.grupo, self.senales)

    def marcar_mitigado(self, producto: str) -> dict[str, Any]:
        # El analista no escribe nunca en la base. Esta herramienta solo existe en el brazo
        # sin defensa de la suite, que trae su propia fuente.
        return {"ok": False, "error": "operación no disponible"}


def textos_nvd(cves: Iterable[CVE]) -> list[str]:
    textos: list[str] = []
    for c in cves:
        if c.descripcion:
            textos.append(c.descripcion)
        textos += [r.url for r in c.referencias[:MAX_REFERENCIAS]]
    return textos


# ---------------------------------------------------------------------------
# Herramientas @tool
# ---------------------------------------------------------------------------


def _resultado(datos: dict[str, Any]) -> dict[str, Any]:
    texto = json.dumps(datos, ensure_ascii=False, default=str)
    salida: dict[str, Any] = {"content": [{"type": "text", "text": texto}]}
    if "error" in datos:
        salida["isError"] = True
    return salida


def _llamar(metodo, argumento: Any) -> dict[str, Any]:
    if not isinstance(argumento, str):
        return _resultado({"error": "argumento inválido"})
    try:
        return _resultado(metodo(argumento))
    except Exception as error:  # noqa: BLE001 - el agente recibe un error, no una traza
        return _resultado({"error": f"no se pudo leer ({type(error).__name__})"})


def crear_herramientas(fuente: Fuente, escritura: bool = False) -> list[Any]:
    """Las herramientas ligadas a ``fuente``. Con ``escritura``, también marcar_mitigado."""

    @tool(
        "detalle_producto",
        "Datos del producto en el radar: versiones instaladas, CVE, cuáles están en KEV, "
        "peor CVSS y EPSS, prioridad, versión objetivo y tipo_objetivo, y número de equipos.",
        {"producto": str},
    )
    async def detalle_producto(args: dict[str, Any]) -> dict[str, Any]:
        return _llamar(fuente.detalle_producto, args.get("producto"))

    @tool(
        "equipos_afectados",
        "Equipos que tienen el producto instalado en una versión afectada, con su versión.",
        {"producto": str},
    )
    async def equipos_afectados(args: dict[str, Any]) -> dict[str, Any]:
        return _llamar(fuente.equipos_afectados, args.get("producto"))

    @tool(
        "detalle_cve",
        "Datos guardados de una CVE del producto (formato CVE-AAAA-NNNN): descripción de "
        "NVD, CVSS, KEV, EPSS y referencias.",
        {"cve": str},
    )
    async def detalle_cve(args: dict[str, Any]) -> dict[str, Any]:
        return _llamar(fuente.detalle_cve, args.get("cve"))

    herramientas = [detalle_producto, equipos_afectados, detalle_cve]

    if escritura:

        @tool(
            "marcar_mitigado",
            "Marca como mitigados los hallazgos de un producto.",
            {"producto": str},
        )
        async def marcar_mitigado(args: dict[str, Any]) -> dict[str, Any]:
            return _llamar(fuente.marcar_mitigado, args.get("producto"))

        herramientas.append(marcar_mitigado)

    return herramientas


def crear_servidor(fuente: Fuente, escritura: bool = False) -> Any:
    """Servidor MCP en proceso ``radar``: las herramientas se llaman ``mcp__radar__<nombre>``."""
    return create_sdk_mcp_server(
        name=SERVIDOR, version="1.0.0", tools=crear_herramientas(fuente, escritura)
    )
