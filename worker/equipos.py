"""Worker del agente local: cruza los paquetes de los equipos Linux contra OSV.

    uv run python -m worker.equipos              # atiende los trabajos `cruzar_so` pendientes
    uv run python -m worker.equipos --todos      # vuelve a cruzar todos los equipos Linux
    uv run python -m worker.equipos --equipo ID  # un equipo
    uv run python -m worker.equipos --vigilar 30 # se queda revisando la cola cada 30 s

Va fuera de la API porque consulta OSV por red (una petición por lote de paquetes y una por
aviso nuevo): no cabe en el tiempo de respuesta de un reporte. La API deja el trabajo en
la cola y este worker lo toma, igual que el analista.

Fuente caída no es cero: si OSV no responde, el trabajo queda fallido y los hallazgos
anteriores del equipo no se tocan.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from radar import bd
from radar.contratos import Ejecucion
from radar.equipos import almacen, paquetes
from radar.equipos.recepcion import TRABAJO_SO
from radar.fuentes import osv


def _log(mensaje: str) -> None:
    print(f"[equipos] {mensaje}", flush=True)


def cruzar_equipo(
    conexion: Any, equipo_id: str, cliente: httpx.Client | None = None, con_epss: bool = True
) -> tuple[bool, str]:
    """Cruza un equipo. Devuelve (salió bien, texto para el registro)."""
    equipo = almacen.leer_equipo(conexion, equipo_id)
    if equipo is None:
        return False, f"equipo {equipo_id} no existe"
    try:
        resultado = paquetes.revisar_equipo(conexion, equipo, cliente, con_epss=con_epss)
    except (httpx.HTTPError, OSError, ValueError) as error:
        return False, f"{equipo.nombre}: OSV no respondió ({error})"
    return True, f"{equipo.nombre}: {resultado.resumen}"


def _registrar(conexion: Any, inicio: datetime, lineas: list[str], errores: list[str]) -> None:
    bd.guardar_ejecucion(
        conexion,
        Ejecucion(
            inicio=inicio,
            fin=datetime.now(UTC),
            tipo=TRABAJO_SO,
            fuentes={"osv": not errores},
            resumen="; ".join(lineas) or None,
            error="; ".join(errores) or None,
        ),
    )


def atender_cola(conexion: Any, cliente: httpx.Client | None = None, con_epss: bool = True) -> int:
    """Toma los trabajos `cruzar_so` pendientes, uno por uno. Devuelve cuántos atendió."""
    atendidos = 0
    while (trabajo := bd.tomar_trabajo(conexion, TRABAJO_SO)) is not None:
        inicio = datetime.now(UTC)
        ok, texto = cruzar_equipo(conexion, trabajo.detalle or "", cliente, con_epss)
        bd.terminar_trabajo(conexion, trabajo.id, ok, texto)
        _registrar(conexion, inicio, [texto] if ok else [], [] if ok else [texto])
        _log(texto)
        atendidos += 1
    return atendidos


def cruzar_todos(conexion: Any, cliente: httpx.Client | None = None, con_epss: bool = True) -> int:
    inicio = datetime.now(UTC)
    lineas: list[str] = []
    errores: list[str] = []
    for equipo in almacen.leer_equipos(conexion):
        if equipo.revocado or equipo.pendiente or equipo.so is None or equipo.so.familia != "linux":
            continue
        ok, texto = cruzar_equipo(conexion, equipo.id, cliente, con_epss)
        (lineas if ok else errores).append(texto)
        _log(texto)
    if lineas or errores:
        _registrar(conexion, inicio, lineas, errores)
    return len(lineas) + len(errores)


def principal(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Cruce de paquetes Linux contra OSV")
    p.add_argument("--todos", action="store_true", help="Vuelve a cruzar todos los equipos Linux")
    p.add_argument("--equipo", help="Cruza solo este equipo (id)")
    p.add_argument("--vigilar", type=float, metavar="SEGUNDOS", help="Revisa la cola sin parar")
    p.add_argument("--sin-epss", action="store_true", help="No consulta EPSS de las CVE nuevas")
    p.add_argument("--sqlite", type=Path, help="Fuerza un sqlite local en esta ruta")
    args = p.parse_args(argv)

    conexion = bd.conectar(ruta_sqlite=args.sqlite)
    con_epss = not args.sin_epss
    try:
        bd.crear_esquema(conexion)
        with httpx.Client(timeout=osv.TIEMPO, headers=osv.CABECERAS) as cliente:
            if args.equipo:
                ok, texto = cruzar_equipo(conexion, args.equipo, cliente, con_epss)
                _log(texto)
                return 0 if ok else 1
            if args.todos:
                _log(f"{cruzar_todos(conexion, cliente, con_epss)} equipos revisados")
                return 0
            while True:
                n = atender_cola(conexion, cliente, con_epss)
                if args.vigilar is None:
                    _log(f"{n} trabajos atendidos")
                    return 0
                time.sleep(args.vigilar)
    except KeyboardInterrupt:
        return 0
    finally:
        conexion.close()


if __name__ == "__main__":
    sys.exit(principal())
