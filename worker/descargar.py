"""Plan de descarga (PLAN, sección 7): KEV, CVE de cada par y EPSS, guardados en la base.

Uso:
    uv run python -m worker.descargar --desde-snapshot            # NVD y KEV del snapshot local
    uv run python -m worker.descargar --desde-snapshot --sin-epss # sin red
    uv run python -m worker.descargar --desde-snapshot --kev-en-linea

`--desde-snapshot` no toca NVD: lee resources/nvd_snapshot (respaldo si la red falla). EPSS sí se
baja del día, porque no está congelado. Si una fuente falla, la ejecución lo registra en
`ejecuciones.fuentes` con False: fuente caída no es cero (regla 2).

Escribe en Turso si TURSO_DATABASE_URL y TURSO_AUTH_TOKEN están en `.env`; si no, en el sqlite
local (datos_locales/radar.db o RADAR_SQLITE).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from radar import bd, config
from radar.contratos import Ejecucion
from radar.fuentes import epss as fuente_epss
from radar.fuentes import kev as fuente_kev
from radar.fuentes.nvd import leer_snapshot, normalizar_par

SNAPSHOT = config.RAIZ / "resources" / "nvd_snapshot"


def archivos_nvd(carpeta: Path) -> list[Path]:
    """Archivos de pares del snapshot (vendor__producto.json), sin kev.json ni scripts."""
    return sorted(p for p in carpeta.glob("*__*.json"))


def pares_del_snapshot(archivos: list[Path]) -> set[str]:
    """Pares descargados, leídos del campo 'par' de cada archivo (con escapes normalizados)."""
    pares = set()
    for ruta in archivos:
        with open(ruta, encoding="utf-8") as f:
            pares.add(normalizar_par(json.load(f)["par"]))
    return pares


def _log(mensaje: str) -> None:
    print(f"[descargar] {mensaje}", flush=True)


def descargar_desde_snapshot(
    conexion,
    carpeta: Path = SNAPSHOT,
    con_epss: bool = True,
    kev_en_linea: bool = False,
) -> Ejecucion:
    inicio = datetime.now(UTC)
    fuentes: dict[str, bool] = {}
    errores: list[str] = []
    resumen: list[str] = []
    bd.crear_esquema(conexion)

    # 1. KEV
    try:
        if kev_en_linea:
            r = httpx.get(fuente_kev.URL_KEV, timeout=60, follow_redirects=True)
            r.raise_for_status()
            datos_kev = r.json()
        else:
            datos_kev = json.loads((carpeta / "kev.json").read_text(encoding="utf-8"))
        n = bd.guardar_kev(conexion, fuente_kev.leer_catalogo(datos_kev))
        fuentes["kev"] = True
        resumen.append(f"KEV {datos_kev.get('catalogVersion', '?')}: {n} entradas")
        _log(resumen[-1])
    except (OSError, ValueError, httpx.HTTPError) as e:
        fuentes["kev"] = False
        errores.append(f"KEV: {e}")
        _log(f"KEV falló: {e}")

    # 2. CVE de cada par (snapshot, sin red)
    ids: list[str] = []
    try:
        archivos = archivos_nvd(carpeta)
        if not archivos:
            raise FileNotFoundError(f"No hay archivos vendor__producto.json en {carpeta}")
        t = time.monotonic()
        cves = leer_snapshot(archivos)
        # Solo se guardan los rangos de los pares descargados: una CVE de Chrome trae también
        # Edge, Debian, Fedora... que el cruce nunca usa y multiplican por 15 la tabla.
        pares = pares_del_snapshot(archivos)
        for cve_id, c in cves.items():
            propios = [r for r in c.rangos if normalizar_par(r.par) in pares]
            if len(propios) != len(c.rangos):
                cves[cve_id] = c.model_copy(update={"rangos": propios})
        n = bd.guardar_cves(conexion, cves.values())
        ids = list(cves)
        sin_productos = sum(1 for c in cves.values() if c.sin_productos)
        fuentes["nvd"] = True
        resumen.append(
            f"NVD (snapshot): {len(archivos)} pares, {n} CVE, {sin_productos} sin configurations"
        )
        _log(f"{resumen[-1]} ({time.monotonic() - t:.1f}s)")
    except (OSError, ValueError) as e:
        fuentes["nvd"] = False
        errores.append(f"NVD: {e}")
        _log(f"NVD falló: {e}")

    # 3. EPSS del día, solo de las CVE guardadas
    if con_epss and ids:
        try:
            senales = fuente_epss.descargar_completo(solo=ids)
            n = bd.guardar_epss(conexion, senales)
            fecha = next(iter(senales.values())).fecha if senales else None
            fuentes["epss"] = True
            resumen.append(f"EPSS {fecha}: {n} de {len(ids)} CVE (las demás sin dato, no cero)")
            _log(resumen[-1])
        except (OSError, ValueError, httpx.HTTPError) as e:
            fuentes["epss"] = False
            errores.append(f"EPSS: {e}")
            _log(f"EPSS falló: {e}")

    ejecucion = Ejecucion(
        inicio=inicio,
        fin=datetime.now(UTC),
        tipo="descargar",
        fuentes=fuentes,
        resumen="; ".join(resumen) or None,
        error="; ".join(errores) or None,
    )
    ejecucion.id = bd.guardar_ejecucion(conexion, ejecucion)
    return ejecucion


def principal(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Descarga de fuentes del radar")
    p.add_argument(
        "--desde-snapshot",
        nargs="?",
        const=str(SNAPSHOT),
        metavar="CARPETA",
        help="Lee NVD y KEV del snapshot local en vez de la red",
    )
    p.add_argument("--sin-epss", action="store_true", help="No baja EPSS")
    p.add_argument(
        "--kev-en-linea", action="store_true", help="Baja KEV de CISA en vez del snapshot"
    )
    p.add_argument("--sqlite", type=Path, help="Fuerza un sqlite local en esta ruta")
    args = p.parse_args(argv)

    if not args.desde_snapshot:
        p.error(
            "Por ahora solo existe --desde-snapshot (la descarga en línea de NVD viene después)"
        )

    conexion = bd.conectar(ruta_sqlite=args.sqlite)
    try:
        ejecucion = descargar_desde_snapshot(
            conexion,
            Path(args.desde_snapshot),
            con_epss=not args.sin_epss,
            kev_en_linea=args.kev_en_linea,
        )
    finally:
        conexion.close()
    caidas = [f for f, ok in ejecucion.fuentes.items() if not ok]
    if caidas:
        _log(f"Fuentes caídas: {', '.join(caidas)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(principal())
