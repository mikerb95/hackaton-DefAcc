"""Plan de descarga (PLAN, sección 7): KEV, CVE de cada par y EPSS, guardados en la base.

Uso:
    uv run python -m worker.descargar --desde-snapshot             # NVD y KEV del snapshot local
    uv run python -m worker.descargar --desde-snapshot --sin-epss  # sin red
    uv run python -m worker.descargar --en-linea                   # NVD, KEV y EPSS de la red
    uv run python -m worker.descargar --en-linea --incremental     # solo lo modificado en NVD
                                                                   # desde la última descarga
    uv run python -m worker.descargar --en-linea --pares rarlab:winrar google:chrome

`--desde-snapshot` no toca NVD: lee resources/nvd_snapshot (respaldo si la red falla).
`--en-linea` consulta NVD por par (`virtualMatchString`). Los pares salen de `--pares`, si no de
la tabla `programa_cpe` (lo que el normalizador asignó), y si está vacía, de los archivos del
snapshot. EPSS se baja siempre del día (no está congelado). Si una fuente falla, la ejecución lo
registra en `ejecuciones.fuentes` con False: fuente caída no es cero (regla 2).

Escribe en Turso si TURSO_DATABASE_URL y TURSO_AUTH_TOKEN están en `.env`; si no, en el sqlite
local (datos_locales/radar.db o RADAR_SQLITE).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from radar import bd, config
from radar.contratos import CVE, Ejecucion
from radar.fuentes import epss as fuente_epss
from radar.fuentes import kev as fuente_kev
from radar.fuentes.nvd import ClienteNvd, ErrorNvd, leer_snapshot, normalizar_par

SNAPSHOT = config.RAIZ / "resources" / "nvd_snapshot"
# Margen al pedir lo modificado desde la última descarga, por relojes y retrasos de NVD.
MARGEN_INCREMENTAL = timedelta(hours=2)


def _log(mensaje: str) -> None:
    print(f"[descargar] {mensaje}", flush=True)


def archivos_nvd(carpeta: Path) -> list[Path]:
    """Archivos de pares del snapshot (vendor__producto.json), sin kev.json ni scripts."""
    return sorted(carpeta.glob("*__*.json"))


def par_de_archivo(ruta: Path) -> str:
    with open(ruta, encoding="utf-8") as f:
        return json.load(f)["par"]


def solo_rangos_de(cves: dict[str, CVE], pares: Iterable[str]) -> dict[str, CVE]:
    """Deja solo los rangos de los pares pedidos. Una CVE de Chrome trae también Edge,
    Debian, Fedora... que el cruce nunca usa y que multiplican la tabla de rangos."""
    normalizados = {normalizar_par(p) for p in pares}
    salida = {}
    for cve_id, c in cves.items():
        propios = [r for r in c.rangos if normalizar_par(r.par) in normalizados]
        salida[cve_id] = (
            c if len(propios) == len(c.rangos) else c.model_copy(update={"rangos": propios})
        )
    return salida


class Registro:
    """Acumula fuentes, resumen y errores de una ejecución."""

    def __init__(self) -> None:
        self.inicio = datetime.now(UTC)
        self.fuentes: dict[str, bool] = {}
        self.resumen: list[str] = []
        self.errores: list[str] = []

    def ok(self, fuente: str, texto: str) -> None:
        self.fuentes[fuente] = True
        self.resumen.append(texto)
        _log(texto)

    def sin_bajar(self, fuente: str, motivo: str) -> None:
        """La fuente no se consultó a propósito. Queda en False: sin dato no es cero."""
        self.fuentes[fuente] = False
        texto = f"{fuente.upper()} sin bajar: {motivo}"
        self.resumen.append(texto)
        _log(texto)

    def fallo(self, fuente: str, error: Exception | str) -> None:
        self.fuentes[fuente] = False
        self.errores.append(f"{fuente.upper()}: {error}")
        _log(f"{fuente.upper()} falló: {error}")

    def cerrar(self, conexion: Any) -> Ejecucion:
        ejecucion = Ejecucion(
            inicio=self.inicio,
            fin=datetime.now(UTC),
            tipo="descargar",
            fuentes=self.fuentes,
            resumen="; ".join(self.resumen) or None,
            error="; ".join(self.errores) or None,
        )
        ejecucion.id = bd.guardar_ejecucion(conexion, ejecucion)
        return ejecucion


def paso_kev(conexion: Any, registro: Registro, datos: dict[str, Any] | None = None) -> None:
    """Guarda KEV desde `datos` o, si es None, lo baja de CISA."""
    t = time.monotonic()
    try:
        if datos is None:
            r = httpx.get(fuente_kev.URL_KEV, timeout=60, follow_redirects=True)
            r.raise_for_status()
            datos = r.json()
        n = bd.guardar_kev(conexion, fuente_kev.leer_catalogo(datos))
        registro.ok(
            "kev",
            f"KEV {datos.get('catalogVersion', '?')}: {n} entradas ({time.monotonic() - t:.1f}s)",
        )
    except (OSError, ValueError, KeyError, httpx.HTTPError) as e:
        registro.fallo("kev", e)


def paso_epss(conexion: Any, registro: Registro, con_epss: bool = True) -> None:
    """EPSS del día para todas las CVE guardadas (una sola descarga del CSV completo).

    Siempre deja `epss` en la ejecución: True si se bajó, False si falló o no se pidió. Así el
    resumen dice que la prioridad se calculó sin una de sus tres señales.
    """
    if not con_epss:
        registro.sin_bajar("epss", "se pidió --sin-epss; las prioridades no usan EPSS")
        return
    ids = [f[0] for f in conexion.execute("SELECT id FROM cves").fetchall()]
    if not ids:
        registro.sin_bajar("epss", "no hay CVE guardadas")
        return
    t = time.monotonic()
    try:
        senales = fuente_epss.descargar_completo(solo=ids)
        t_red = time.monotonic() - t
        n = bd.guardar_epss(conexion, senales)
        fecha = next(iter(senales.values())).fecha if senales else None
        registro.ok(
            "epss",
            f"EPSS {fecha}: {n} de {len(ids)} CVE (las demás sin dato, no cero) "
            f"(bajar {t_red:.1f}s, guardar {time.monotonic() - t - t_red:.1f}s)",
        )
    except (OSError, ValueError, httpx.HTTPError) as e:
        registro.fallo("epss", e)


def descargar_desde_snapshot(
    conexion: Any,
    carpeta: Path = SNAPSHOT,
    con_epss: bool = True,
    kev_en_linea: bool = False,
    pares: Iterable[str] | None = None,
) -> Ejecucion:
    """Carga NVD y KEV del snapshot local. Con `pares`, solo esos archivos."""
    registro = Registro()
    bd.crear_esquema(conexion)

    if kev_en_linea:
        paso_kev(conexion, registro)
    else:
        try:
            datos = json.loads((carpeta / "kev.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            registro.fallo("kev", e)
        else:
            paso_kev(conexion, registro, datos)

    try:
        archivos = archivos_nvd(carpeta)
        if pares is not None:
            pedidos = {normalizar_par(p) for p in pares}
            archivos = [a for a in archivos if normalizar_par(par_de_archivo(a)) in pedidos]
        if not archivos:
            raise FileNotFoundError(f"No hay archivos vendor__producto.json en {carpeta}")
        t = time.monotonic()
        cves = solo_rangos_de(leer_snapshot(archivos), [par_de_archivo(a) for a in archivos])
        t_leer = time.monotonic() - t
        n = bd.guardar_cves(conexion, cves.values())
        sin_productos = sum(1 for c in cves.values() if c.sin_productos)
        rangos = sum(len(c.rangos) for c in cves.values())
        registro.ok(
            "nvd",
            f"NVD (snapshot): {len(archivos)} pares, {n} CVE, {rangos} rangos, "
            f"{sin_productos} sin configurations "
            f"(leer {t_leer:.1f}s, guardar {time.monotonic() - t - t_leer:.1f}s)",
        )
    except (OSError, ValueError) as e:
        registro.fallo("nvd", e)

    paso_epss(conexion, registro, con_epss)
    return registro.cerrar(conexion)


def pares_a_consultar(conexion: Any) -> list[str]:
    """Pares que asignó el normalizador más los del sistema operativo de los equipos con
    agente local (Windows); si no hay ninguno, los del snapshot."""
    from radar.equipos import almacen
    from radar.equipos.so import pares_de_so

    asignados = sorted(
        set(bd.pares_asignados(conexion)) | set(pares_de_so(almacen.leer_equipos(conexion)))
    )
    if asignados:
        return asignados
    return sorted(par_de_archivo(a) for a in archivos_nvd(SNAPSHOT)) if SNAPSHOT.exists() else []


def ultima_descarga_buena(conexion: Any) -> datetime | None:
    """Inicio de la última descarga en la que NVD respondió."""
    for e in bd.leer_ejecuciones(conexion, 50):
        if e.tipo == "descargar" and e.fuentes.get("nvd"):
            return e.inicio
    return None


def descargar_en_linea(
    conexion: Any,
    pares: Iterable[str],
    desde: datetime | None = None,
    con_epss: bool = True,
    cliente: ClienteNvd | None = None,
) -> Ejecucion:
    """KEV, CVE de cada par desde NVD (todo, o lo modificado desde `desde`) y EPSS del día.

    Un par que falla no tumba a los demás: la fuente queda marcada como caída y el error dice
    cuál par faltó.
    """
    registro = Registro()
    bd.crear_esquema(conexion)
    paso_kev(conexion, registro)

    lista = list(pares)
    propio = cliente is None
    cliente = cliente or ClienteNvd()
    total, caidos = 0, []
    try:
        for par in lista:
            try:
                cves = solo_rangos_de(cliente.por_par(par, desde=desde), [par])
            except (ErrorNvd, ValueError) as e:
                caidos.append(f"{par} ({e})")
                _log(f"NVD falló en {par}: {e}")
                continue
            total += bd.guardar_cves(conexion, cves.values())
            _log(f"{par}: {len(cves)} CVE")
    finally:
        if propio:
            cliente.cerrar()
    modo = f"modificadas desde {desde.isoformat(timespec='minutes')}" if desde else "completo"
    texto = f"NVD en línea ({modo}): {len(lista) - len(caidos)} de {len(lista)} pares, {total} CVE"
    if caidos:
        registro.fallo("nvd", f"{texto}; sin respuesta: {', '.join(caidos)}")
    else:
        registro.ok("nvd", texto)

    paso_epss(conexion, registro, con_epss)
    return registro.cerrar(conexion)


def principal(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Descarga de fuentes del radar")
    modo = p.add_mutually_exclusive_group(required=True)
    modo.add_argument(
        "--desde-snapshot",
        nargs="?",
        const=str(SNAPSHOT),
        metavar="CARPETA",
        help="Lee NVD y KEV del snapshot local en vez de la red",
    )
    modo.add_argument("--en-linea", action="store_true", help="Consulta NVD, KEV y EPSS en la red")
    p.add_argument("--pares", nargs="+", metavar="VENDOR:PRODUCTO", help="Solo estos pares")
    p.add_argument(
        "--incremental",
        action="store_true",
        help="Con --en-linea: solo lo modificado en NVD desde la última descarga buena",
    )
    p.add_argument(
        "--dias", type=int, help="Con --en-linea: solo lo modificado en los últimos N días"
    )
    p.add_argument("--sin-epss", action="store_true", help="No baja EPSS")
    p.add_argument("--kev-en-linea", action="store_true", help="Con snapshot: KEV de CISA")
    p.add_argument("--sqlite", type=Path, help="Fuerza un sqlite local en esta ruta")
    args = p.parse_args(argv)

    conexion = bd.conectar(ruta_sqlite=args.sqlite)
    try:
        if args.desde_snapshot:
            ejecucion = descargar_desde_snapshot(
                conexion,
                Path(args.desde_snapshot),
                con_epss=not args.sin_epss,
                kev_en_linea=args.kev_en_linea,
                pares=args.pares,
            )
        else:
            bd.crear_esquema(conexion)
            desde = None
            if args.dias:
                desde = datetime.now(UTC) - timedelta(days=args.dias)
            elif args.incremental:
                ultima = ultima_descarga_buena(conexion)
                desde = ultima - MARGEN_INCREMENTAL if ultima else None
                if desde is None:
                    _log("No hay descarga previa: se baja todo")
            pares = args.pares or pares_a_consultar(conexion)
            if not pares:
                p.error("No hay pares que consultar: usa --pares o carga el normalizador")
            ejecucion = descargar_en_linea(conexion, pares, desde, con_epss=not args.sin_epss)
    finally:
        conexion.close()
    sin_dato = [f for f, ok in ejecucion.fuentes.items() if not ok]
    if sin_dato:
        _log(f"Fuentes sin dato en esta ejecución: {', '.join(sin_dato)}")
    return 1 if ejecucion.error else 0


if __name__ == "__main__":
    sys.exit(principal())
