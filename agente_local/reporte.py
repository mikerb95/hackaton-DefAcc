"""Arma el `ReporteEquipo` (docs/plan-agente-local.md, sección 5) y su versión en CSV.

Datos mínimos: ni archivos, ni historial, ni nombres de usuario, ni contenido de
documentos. Solo lo necesario para cruzar.
"""

from __future__ import annotations

import csv
import io
import platform
import socket
from datetime import UTC, datetime
from typing import Any

from agente_local import VERSION

COLUMNAS_CSV = ("equipo", "programa", "version", "proveedor", "sistema")
# Fuentes cuya versión es la de la distribución. El radar no las cruza por CPE (lo hace
# contra OSV), así que no van al CSV: ahí darían falsos positivos en masa.
FUENTES_DE_DISTRIBUCION = frozenset({"dpkg", "rpm"})


class PlataformaNoSoportada(RuntimeError):
    """El agente solo recoge en Windows y Linux."""


def recoger(solo_software: bool = False) -> dict[str, Any]:
    sistema = platform.system()
    if sistema == "Windows":
        from agente_local import windows

        return windows.recoger(solo_software)
    if sistema == "Linux":
        from agente_local import linux

        return linux.recoger(solo_software)
    raise PlataformaNoSoportada(f"Plataforma no soportada: {sistema}")


def armar_reporte(
    equipo_id: str,
    datos: dict[str, Any] | None = None,
    nombre_equipo: str | None = None,
    ahora: datetime | None = None,
    solo_software: bool = False,
) -> dict[str, Any]:
    """Reporte completo del equipo. `datos` permite pasar lo recogido (pruebas)."""
    datos = datos if datos is not None else recoger(solo_software)
    momento = (ahora or datetime.now(UTC)).replace(microsecond=0)
    return {
        "agente_version": VERSION,
        "equipo_id": equipo_id,
        "nombre_equipo": nombre_equipo or socket.gethostname(),
        "recogido": momento.isoformat().replace("+00:00", "Z"),
        "so": datos["so"],
        "hardware": datos["hardware"],
        "postura": datos["postura"],
        "software": datos["software"],
    }


def nombre_sistema(so: dict[str, Any]) -> str:
    partes = [so.get("nombre"), so.get("version")]
    return " ".join(str(p) for p in partes if p)


def a_csv(reporte: dict[str, Any]) -> str:
    """CSV con las columnas que ya lee el radar (`equipo, programa, version, proveedor,
    sistema`), para subirlo a `POST /api/inventario` sin tocar contratos (fase 0)."""
    salida = io.StringIO(newline="")
    escritor = csv.writer(salida, lineterminator="\n")
    escritor.writerow(COLUMNAS_CSV)
    sistema = nombre_sistema(reporte["so"])
    for programa in reporte["software"]:
        if programa.get("fuente") in FUENTES_DE_DISTRIBUCION:
            continue
        escritor.writerow(
            [
                reporte["nombre_equipo"],
                programa.get("programa") or "",
                programa.get("version") or "",
                programa.get("proveedor") or "",
                sistema,
            ]
        )
    return salida.getvalue()
