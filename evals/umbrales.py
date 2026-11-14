"""Barrido de umbrales para evals/reporte.md (PLAN, sección 16).

Cuántas alertas inmediatas salen según el umbral de EPSS y de CVSS: el costo de
atención contra el riesgo de callar. La cuenta la hace ``radar.nucleo.umbrales`` (no se
duplica aquí); este módulo solo la lee de la base y la pone en Markdown.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parents[1]
BASE_LOCAL = RAIZ / "datos_locales" / "radar.db"


def medir_umbrales(ruta: Path = BASE_LOCAL) -> dict[str, Any]:
    if not ruta.exists():
        return {"pendiente": "falta datos_locales/radar.db (correr la corrida completa)"}
    from radar import bd
    from radar.nucleo.umbrales import barrido_guardado

    resultado = barrido_guardado(bd.conectar(solo_lectura=True, ruta_sqlite=ruta))
    if not resultado.get("total"):
        return {"pendiente": "la base no tiene hallazgos guardados (correr la corrida completa)"}
    return resultado


def _umbral(valor: float, maximo: float) -> str:
    return "nunca" if valor >= maximo else f"{valor:g}"


def seccion_umbrales(r: dict[str, Any]) -> str:
    if "pendiente" in r:
        return f"## Barrido de umbrales\n\nPendiente: {r['pendiente']}.\n"
    rejilla_epss, rejilla_cvss = r["rejilla_epss"], r["rejilla_cvss"]
    celdas = {(c["epss"], c["cvss"]): c for c in r["celdas"]}
    encabezado = ["EPSS \\ CVSS"] + [_umbral(c, 10.0 + 1e-9) for c in rejilla_cvss]
    filas = []
    for e in rejilla_epss:
        fila = [_umbral(e, 1.0 + 1e-9)]
        for c in rejilla_cvss:
            celda = celdas.get((e, c))
            fila.append(f"{celda['productos']} / {celda['hallazgos']}" if celda else "")
        filas.append(fila)
    lineas = ["| " + " | ".join(encabezado) + " |", "|" + "---|" * len(encabezado)]
    lineas += ["| " + " | ".join(str(x) for x in f) + " |" for f in filas]
    actual, kev = r["actual"], r["solo_kev"]
    return (
        "## Barrido de umbrales\n\n"
        f"Sobre {r['total']} hallazgos precisos y abiertos de la base local "
        "(`radar.nucleo.umbrales.barrido_guardado`). Cada celda: comunicados (uno por "
        "producto) / hallazgos que salen como acción inmediata con ese par de umbrales. "
        '"nunca" significa que ese criterio no dispara solo.\n\n' + "\n".join(lineas) + "\n\n"
        f"- Piso por KEV (inmediato con cualquier umbral): {kev['productos']} comunicados, "
        f"{kev['hallazgos']} hallazgos, {kev['cves']} CVE, {kev['equipos']} equipos.\n"
        f"- Umbrales vigentes (EPSS {actual['epss']:g}, CVSS {actual['cvss']:g}): "
        f"{actual['productos']} comunicados, {actual['hallazgos']} hallazgos, "
        f"{actual['cves']} CVE, {actual['equipos']} equipos.\n"
        f"- Hallazgos sin dato de EPSS: {r.get('sin_epss', 0)} (sin dato no es 0).\n"
    )
