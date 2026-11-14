"""Cifras del normalizador y del pipeline para evals/reporte.md (regla 10: nada a mano).

Punto de entrada para evals/medir.py (frente guarda):

    from datos_prueba.metricas import metricas_normalizador, tabla_markdown
    m = metricas_normalizador()       # dict estable, ver claves abajo
    texto = tabla_markdown(m)         # sección lista para pegar en el reporte

Claves de primer nivel:
- `resumen`: las tres cifras de la ficha (ajustada, no ajustada con n, línea base).
- `semilla`: exactitud contra la respuesta conocida (variantes completo, solo_difuso,
  nombre_exacto). Ajustada a la semilla: la tabla de alias sale de sus trampas.
- `fuera_de_semilla`: exactitud no ajustada sobre nombres que no están en la semilla ni en
  la tabla de alias. Es la cifra que defiende al normalizador.
- `pipeline`: punta a punta (CSV -> leer_inventario -> normalizar -> corrida), detección,
  precisión, falsos positivos, KEV y cobertura por motivo.

Necesita resources/ (snapshot privado). Sin modelo: el desempate con Claude sigue detrás de
RADAR_DESEMPATE_MODELO.
"""

from __future__ import annotations

import tempfile
from pathlib import Path


def metricas_normalizador(ruta_bd: Path | None = None) -> dict:
    from datos_prueba import fuera_de_semilla, generar, integracion, medir_normalizador

    with tempfile.TemporaryDirectory() as tmp:
        carpeta = Path(tmp)
        original = medir_normalizador.CARPETA_SALIDA
        medir_normalizador.CARPETA_SALIDA = carpeta
        try:
            generar.main(["--salida", str(carpeta), "--sin-excel"])
            semilla = medir_normalizador.medir("inventario")
        finally:
            medir_normalizador.CARPETA_SALIDA = original
    for v in semilla["variantes"].values():
        v.pop("errores", None)
    fuera = fuera_de_semilla.medir()
    v = semilla["variantes"]
    return {
        # Las tres cifras de la ficha, en un solo lugar.
        "resumen": {
            "ajustada_pct": v["completo"]["exactitud_pct"],
            "ajustada_correctos": v["completo"]["activo_correcto"],
            "ajustada_filas": v["completo"]["filas_medidas"],
            "solo_difuso_pct": v["solo_difuso"]["exactitud_pct"],
            "linea_base_pct": v["nombre_exacto"]["exactitud_pct"],
            "no_ajustada_pct": fuera["exactitud_pct"],
            "no_ajustada_correctos": fuera["correctos"],
            "no_ajustada_casos": fuera["casos"],
            "no_ajustada_cpe_inventado": fuera["cpe_inventado"],
        },
        "modelo": False,
        "semilla": semilla,
        "fuera_de_semilla": fuera,
        "pipeline": integracion.medir_pipeline(ruta_bd),
    }


def _p(valor) -> str:
    return "s/d" if valor is None else f"{valor:.1f} %".replace(".", ",")


def tabla_markdown(m: dict) -> str:
    s = m["semilla"]["variantes"]
    f = m["fuera_de_semilla"]
    p = m["pipeline"]
    r = m["resumen"]
    filas = [
        "## Normalizador",
        "",
        "Sin modelo (el desempate con Claude está detrás de una bandera).",
        "",
        "| Conjunto | Variante | Exactitud | CVE alcanzables |",
        "|---|---|---|---|",
        (
            f"| Semilla ({s['completo']['filas_medidas']} filas, ajustada) | alias + difuso "
            f"| {_p(s['completo']['exactitud_pct'])} | {_p(s['completo']['cve_alcanzables_pct'])} |"
        ),
        (
            f"| Semilla | solo difuso | {_p(s['solo_difuso']['exactitud_pct'])} "
            f"| {_p(s['solo_difuso']['cve_alcanzables_pct'])} |"
        ),
        (
            f"| Semilla | nombre exacto (línea base) | {_p(s['nombre_exacto']['exactitud_pct'])} "
            f"| {_p(s['nombre_exacto']['cve_alcanzables_pct'])} |"
        ),
        (
            f"| Fuera de la semilla ({f['casos']} nombres, no ajustada) | alias + difuso "
            f"| {_p(f['exactitud_pct'])} ({r['no_ajustada_correctos']} de "
            f"{r['no_ajustada_casos']}) | |"
        ),
        "",
        (
            f"Fuera de la semilla: {f['sin_cpe_indebido']} quedan sin CPE (visibles en cobertura), "
            f"{f['cpe_equivocado']} con CPE equivocado, {f['cpe_inventado']} CPE inventados."
        ),
        "",
        "## Punta a punta (inventario -> ingesta -> normalizador -> cruce)",
        "",
        "| Métrica | Esperado | Obtenido |",
        "|---|---|---|",
        (
            f"| Pares CVE y versión precisos | {p['pares_cve_version_esperados']} "
            f"| {p['pares_cve_version_correctos']} |"
        ),
        (
            f"| Pares CVE y equipo precisos | {p['pares_cve_equipo_esperados']} "
            f"| {p['pares_cve_equipo_correctos']} |"
        ),
        f"| CVE distintas en KEV | {p['kev_esperadas']} | {p['kev_obtenidas']} |",
        (
            f"| No precisos por activo | {p['no_precisos_por_activo_esperados']} "
            f"| {p['no_precisos_por_activo_correctos']} |"
        ),
        f"| Falsos positivos | 0 | {p['falsos_positivos']} |",
        "",
        f"Detección {_p(p['deteccion_pct'])}, precisión {_p(p['precision_pct'])}. "
        "Cobertura por motivo, esperada y obtenida: "
        + ", ".join(
            f"{k} {p['cobertura_esperada_por_motivo'].get(k, 0)}/"
            f"{p['cobertura_obtenida_por_motivo'].get(k, 0)}"
            for k in sorted(
                set(p["cobertura_esperada_por_motivo"]) | set(p["cobertura_obtenida_por_motivo"])
            )
        )
        + ".",
    ]
    return "\n".join(filas) + "\n"


if __name__ == "__main__":
    print(tabla_markdown(metricas_normalizador()))
