"""Genera el inventario de prueba (CSV y Excel) y su respuesta conocida.

Uso, desde la raíz del repo:

    python -m datos_prueba.generar               # inventario limpio
    python -m datos_prueba.generar --inyeccion   # agrega las filas de casos_inyeccion.py

Semilla fija: dos corridas dan archivos idénticos. Las filas de inyección no las
escribe este frente: las pone `guarda` en datos_prueba/casos_inyeccion.py (tupla
`CASOS`, cada uno con `fila()` e `id`). Van en equipos propios (LAB-INY-NN).

Cada fila se valida contra radar.contratos.FilaInventario antes de escribirse.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import UTC, datetime
from pathlib import Path

from datos_prueba import respuesta, semilla

CARPETA_SALIDA = Path(__file__).resolve().parent / "generados"
COLUMNAS = ["equipo", "programa", "version", "proveedor", "sistema"]
CARGADO = datetime(2026, 11, 14, tzinfo=UTC)  # fijo: archivos reproducibles


def _repartir(rng: random.Random) -> list[tuple[dict, object]]:
    """Devuelve filas sin numerar, cada una con el caso que la originó."""
    pools = {
        "general": semilla.EQUIPOS,
        "desarrollo": semilla.EQUIPOS_DESARROLLO,
        "servidor": semilla.SERVIDORES,
    }
    filas: list[tuple[dict, object]] = []

    def fila(equipo, nombre, version, proveedor, origen):
        filas.append(
            (
                {
                    "equipo": equipo,
                    "programa": nombre,
                    "version": version,
                    "proveedor": proveedor,
                    "sistema": semilla.sistema_de(equipo),
                },
                origen,
            )
        )

    # Casos medidos: cada producto ocupa equipos distintos, una versión por equipo.
    por_producto: dict[str, list[semilla.Caso]] = {}
    for c in semilla.CASOS:
        por_producto.setdefault(c.producto, []).append(c)
    for producto in sorted(por_producto):
        casos = por_producto[producto]
        libres = [c for c in casos if not c.equipos_fijos]
        total = sum(c.equipos for c in libres)
        elegidos = rng.sample(pools[casos[0].grupo], total) if total else []
        i = 0
        for c in casos:
            if c.equipos_fijos:
                destino = list(c.equipos_fijos)
            else:
                destino = elegidos[i : i + c.equipos]
                i += c.equipos
            for eq in destino:
                fila(eq, c.nombre, c.version_campo, c.proveedor, c)

    # Cobertura.
    for c in semilla.COBERTURA:
        for eq in rng.sample(pools[c.grupo], c.equipos):
            fila(eq, c.nombre, c.version_campo, c.proveedor, c)

    # Relleno: entre 15 y 25 programas por equipo, servidores incluidos.
    lo, hi = semilla.RELLENO_POR_EQUIPO
    for eq in semilla.EQUIPOS + semilla.SERVIDORES:
        for nombre, proveedor, version in rng.sample(semilla.RELLENO, rng.randint(lo, hi)):
            fila(eq, nombre, version, proveedor, "relleno")
    return filas


def _filas_inyeccion() -> list[tuple[dict, object]]:
    try:
        from datos_prueba import casos_inyeccion  # lo escribe el frente guarda
    except ImportError as e:
        raise SystemExit(f"Falta datos_prueba/casos_inyeccion.py (frente guarda): {e}")
    out = []
    for caso in casos_inyeccion.CASOS:
        f = caso.fila()
        out.append(({k: f.get(k, "") for k in COLUMNAS}, {"tipo": "inyeccion", "caso": caso.id}))
    return out


def validar_contrato(filas: list[dict], fuente: str = "csv") -> None:
    """Falla si alguna fila no cabe en FilaInventario (vacíos pasan a None)."""
    from radar.contratos import FilaInventario

    for f in filas:
        datos = {k: (f[k] or None) for k in COLUMNAS}
        FilaInventario(**datos, fuente=fuente, cargado=CARGADO)


def generar(
    con_inyeccion: bool = False,
    semilla_aleatoria: int = semilla.SEMILLA_ALEATORIA,
    ruta_snapshot: Path = respuesta.RUTA_SNAPSHOT,
) -> tuple[list[dict], dict]:
    """Arma las filas del inventario y la respuesta conocida, sin escribir archivos."""
    rng = random.Random(semilla_aleatoria)
    filas = _repartir(rng)
    if con_inyeccion:
        filas += _filas_inyeccion()
    # Orden de exportación de un RMM: por equipo y nombre de programa.
    filas.sort(key=lambda fo: (fo[0]["equipo"], fo[0]["programa"].lower(), fo[0]["version"]))
    for n, (f, _) in enumerate(filas, start=1):
        f["fila"] = n
    resp = respuesta.construir(filas, ruta_snapshot)
    resp["semilla_aleatoria"] = semilla_aleatoria
    resp["con_inyeccion"] = con_inyeccion
    validar_contrato([f for f, _ in filas])
    return [f for f, _ in filas], resp


def escribir_csv(filas: list[dict], ruta: Path) -> None:
    with open(ruta, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNAS, extrasaction="ignore")
        w.writeheader()
        w.writerows(filas)


def _celda_excel(valor: str) -> str:
    """Excel no admite caracteres de control: se escriben como `_xHHHH_`, igual que hace
    Excel al guardar. Solo afecta al caso de inyección 7; el CSV conserva los bytes."""
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE

    return ILLEGAL_CHARACTERS_RE.sub(lambda m: f"_x{ord(m.group()):04X}_", valor)


def escribir_excel(filas: list[dict], ruta: Path) -> None:
    from openpyxl import Workbook  # import diferido: el CSV no lo necesita

    wb = Workbook()
    ws = wb.active
    ws.title = "Inventario"
    ws.append(COLUMNAS)
    for f in filas:
        ws.append([_celda_excel(f[c]) for c in COLUMNAS])
    # Fecha fija en los metadatos para que el archivo sea reproducible.
    fija = CARGADO.replace(tzinfo=None)
    wb.properties.created = fija
    wb.properties.modified = fija
    wb.save(ruta)
    _fijar_fechas_zip(ruta)


def _fijar_fechas_zip(ruta: Path) -> None:
    """Reescribe el .xlsx (un zip) con fecha fija en cada entrada: mismo inventario,
    mismos bytes."""
    import io
    import zipfile

    with zipfile.ZipFile(ruta) as z:
        entradas = [(i.filename, z.read(i)) for i in z.infolist()]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for nombre, datos in entradas:
            z.writestr(
                zipfile.ZipInfo(nombre, date_time=(2026, 11, 14, 0, 0, 0)),
                datos,
                compress_type=zipfile.ZIP_DEFLATED,
            )
    ruta.write_bytes(buf.getvalue())


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--inyeccion", action="store_true", help="incluye casos_inyeccion.py")
    p.add_argument("--salida", type=Path, default=CARPETA_SALIDA)
    p.add_argument("--sin-excel", action="store_true", help="solo CSV (sin openpyxl)")
    a = p.parse_args(argv)

    filas, resp = generar(con_inyeccion=a.inyeccion)
    a.salida.mkdir(parents=True, exist_ok=True)
    base = "inventario_inyeccion" if a.inyeccion else "inventario"
    escribir_csv(filas, a.salida / f"{base}.csv")
    if not a.sin_excel:
        escribir_excel(filas, a.salida / f"{base}.xlsx")
    (a.salida / f"{base}_respuesta.json").write_text(
        json.dumps(resp, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
    )
    t = resp["totales"]
    print(f"{t['filas']} filas en {t['equipos']} equipos -> {a.salida}/{base}.*")
    print(
        f"pares CVE-activo precisos: {t['pares_cve_activo_precisos']}, "
        f"KEV distintas: {t['kev_distintas']}, cobertura: {t['cobertura']}"
    )


if __name__ == "__main__":
    main()
