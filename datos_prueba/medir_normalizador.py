"""Mide el normalizador contra la respuesta conocida del inventario de prueba.

    uv run python -m datos_prueba.medir_normalizador [--inyeccion]

Compara tres variantes sobre el mismo inventario (leído con radar.ingesta.archivos, como
lo vería la API):

- `completo`: tabla de alias + rapidfuzz (sin modelo, salvo RADAR_DESEMPATE_MODELO=1).
- `solo_difuso`: rapidfuzz sin la tabla de alias.
- `nombre_exacto`: línea base, el nombre tal cual contra los títulos del diccionario.

Escribe datos_prueba/generados/medicion_normalizador.json. Las cifras de la ficha salen de
ahí (regla 10), no a mano.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from datos_prueba.generar import CARPETA_SALIDA
from radar.contratos import FilaInventario
from radar.ingesta import normalizador as nz

MEDIDOS = ("vulnerable", "sano")


def _filas(base: str) -> list[FilaInventario]:
    from radar.ingesta.archivos import a_contrato, leer_inventario

    lectura = leer_inventario(CARPETA_SALIDA / f"{base}.csv")
    return [a_contrato(f) for f in lectura.filas]


def _linea_base(filas: list[FilaInventario], dic: nz.Diccionario) -> dict:
    """Nombre del programa tal cual, igual a un título del diccionario; versión del campo."""
    from rapidfuzz import utils

    por_texto: dict[str, list[str]] = {}
    for texto, i in zip(dic.textos, dic.indice, strict=True):
        por_texto.setdefault(texto, []).append(dic.claves[i])
    out = {}
    for f in filas:
        llave = (f.equipo, f.programa, f.version or "")
        version = (f.version or "").strip()
        if not version:
            out[llave] = ("cobertura:sin_version", (), None)
            continue
        if not nz._VERSION_COMPARABLE.match(version):
            out[llave] = ("cobertura:no_comparable", (), None)
            continue
        claves = por_texto.get(utils.default_process(f.programa), [])
        if not claves:
            out[llave] = ("cobertura:sin_cpe", (), None)
            continue
        par = min(set(claves), key=lambda k: (dic.pares[k].get("dep", 0), -dic.pares[k]["n"]))
        out[llave] = ("activo", (par,), version)
    return out


def _desde_normalizacion(r: nz.Normalizacion) -> dict:
    por_clave = {a.clave: a for a in r.activos}
    out = {}
    for llave, destino in r.por_fila.items():
        if destino.startswith("cobertura:"):
            out[llave] = (destino, (), None)
        else:
            a = por_clave[destino]
            out[llave] = ("activo", tuple(a.cpes), a.version)
    return out


def evaluar(resultado: dict, respuesta: dict) -> dict:
    """Cifras de una variante contra la respuesta conocida."""
    m = {
        "filas_medidas": 0,
        "cpe_correcto": 0,
        "version_correcta": 0,
        "activo_correcto": 0,
        "sin_cpe_indebido": 0,
        "cpe_equivocado": 0,
        "cve_fila_esperadas": 0,
        "cve_fila_alcanzables": 0,
        "cobertura_esperada": 0,
        "cobertura_motivo_correcto": 0,
        "cobertura_con_cpe": 0,
        "par_prohibido_asignado": 0,
        "relleno": 0,
        "relleno_con_cpe": 0,
        "inyeccion": 0,
        "inyeccion_con_cpe": 0,
    }
    errores: dict[str, dict] = {}
    for f in respuesta["filas"]:
        llave = (f["equipo"], f["programa"], f["version"] or "")
        tipo_r, pares_r, version_r = resultado.get(llave, ("ausente", (), None))
        if f["tipo"] in MEDIDOS:
            m["filas_medidas"] += 1
            esperados = tuple(sorted(f["pares"]))
            ok_cpe = tuple(sorted(pares_r)) == esperados
            ok_ver = version_r == f["version_comparable"]
            m["cpe_correcto"] += ok_cpe
            m["version_correcta"] += ok_ver
            m["activo_correcto"] += ok_cpe and ok_ver
            n_cves = len(f["cves"])
            m["cve_fila_esperadas"] += n_cves
            if ok_cpe and ok_ver:
                m["cve_fila_alcanzables"] += n_cves
            elif tipo_r == "activo":
                m["cpe_equivocado"] += not ok_cpe
            else:
                m["sin_cpe_indebido"] += 1
            if not (ok_cpe and ok_ver):
                e = errores.setdefault(
                    f"{f['programa']} | {f['version']}",
                    {
                        "esperado": [list(esperados), f["version_comparable"]],
                        "obtenido": [tipo_r, list(pares_r), version_r],
                        "filas": 0,
                    },
                )
                e["filas"] += 1
        elif f["tipo"] == "cobertura":
            m["cobertura_esperada"] += 1
            m["cobertura_motivo_correcto"] += tipo_r == f"cobertura:{f['motivo']}"
            m["cobertura_con_cpe"] += tipo_r == "activo"
            if f.get("par_prohibido") and f["par_prohibido"] in pares_r:
                m["par_prohibido_asignado"] += 1
            if tipo_r != f"cobertura:{f['motivo']}":
                e = errores.setdefault(
                    f"{f['programa']} | {f['version']}",
                    {
                        "esperado": [f"cobertura:{f['motivo']}"],
                        "obtenido": [tipo_r, list(pares_r), version_r],
                        "filas": 0,
                    },
                )
                e["filas"] += 1
        elif f["tipo"] == "relleno":
            m["relleno"] += 1
            m["relleno_con_cpe"] += tipo_r == "activo"
        elif f["tipo"] == "inyeccion":
            m["inyeccion"] += 1
            m["inyeccion_con_cpe"] += tipo_r == "activo"

    def pct(a: int, b: int) -> float | None:
        return round(100 * a / b, 1) if b else None

    m["exactitud_pct"] = pct(m["activo_correcto"], m["filas_medidas"])
    m["cve_alcanzables_pct"] = pct(m["cve_fila_alcanzables"], m["cve_fila_esperadas"])
    m["cobertura_correcta_pct"] = pct(m["cobertura_motivo_correcto"], m["cobertura_esperada"])
    m["errores"] = errores
    return m


def medir(base: str = "inventario") -> dict:
    respuesta = json.loads((CARPETA_SALIDA / f"{base}_respuesta.json").read_text(encoding="utf-8"))
    filas = _filas(base)
    dic = nz.diccionario_por_defecto()
    completo = nz.normalizar(filas, dic, usar_alias=True, usar_modelo=False)
    solo = nz.normalizar(filas, dic, usar_alias=False, usar_modelo=False)
    variantes = {
        "completo": evaluar(_desde_normalizacion(completo), respuesta),
        "solo_difuso": evaluar(_desde_normalizacion(solo), respuesta),
        "nombre_exacto": evaluar(_linea_base(filas, dic), respuesta),
    }
    empates = sorted({n for (n, _), d in completo.decisiones.items() if d.empate})
    return {
        "inventario": base,
        "snapshot": respuesta["snapshot"],
        "diccionario_pares": len(dic.claves),
        "modelo": False,
        "umbral": nz.PUNTAJE_MINIMO,
        "empates_resueltos_por_codigo": empates,
        "variantes": variantes,
    }


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--inyeccion", action="store_true")
    a = p.parse_args(argv)
    base = "inventario_inyeccion" if a.inyeccion else "inventario"
    r = medir(base)
    salida = CARPETA_SALIDA / f"medicion_normalizador{'_inyeccion' if a.inyeccion else ''}.json"
    Path(salida).write_text(json.dumps(r, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(
        f"{'variante':14} {'exactitud':>9} {'CVE alcanz.':>11} {'cobertura':>9} "
        f"{'relleno c/CPE':>13} {'prohibido':>9}"
    )
    for nombre, v in r["variantes"].items():
        print(
            f"{nombre:14} {v['exactitud_pct']!s:>8}% {v['cve_alcanzables_pct']!s:>10}% "
            f"{v['cobertura_correcta_pct']!s:>8}% {v['relleno_con_cpe']:>13} "
            f"{v['par_prohibido_asignado']:>9}"
        )
    print(f"empates resueltos por código: {r['empates_resueltos_por_codigo']}")
    print(f"-> {salida}")


if __name__ == "__main__":
    main()
