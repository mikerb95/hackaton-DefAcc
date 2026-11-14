"""Corre todas las mediciones y escribe evals/reporte.md (PLAN, sección 16; regla 10).

    uv run python -m evals.medir

Toda cifra de docs, ficha y pitch sale de este reporte o de pytest, nunca a mano. Una
sección sin datos (falta ``resources/``, falta el inventario generado, no hay clave de
API) sale marcada como pendiente con el motivo, nunca con un número inventado.

Secciones:

1. Detección del cruce contra la respuesta conocida (60 casos de ``semilla_respuesta.json``).
2. Normalizador (``datos_prueba.medir_normalizador``), con su línea base de nombre exacto.
3. Suite de inyección de dos brazos, con agente simulado obediente (peor caso) y honesto,
   y el analista real cuando exista.
4. Barrido de umbrales (``evals/umbrales.py``, pendiente de la función de nucleo).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

RAIZ = Path(__file__).resolve().parents[1]
REPORTE = Path(__file__).with_name("reporte.md")
HISTORIAL = Path(__file__).with_name("historial")
RESPUESTA = RAIZ / "resources" / "semilla_respuesta.json"
SNAPSHOT = RAIZ / "resources" / "nvd_snapshot"


def _pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f} %" if b else "sin datos"


def _tabla(encabezado: list[str], filas: list[list[Any]]) -> str:
    lineas = ["| " + " | ".join(encabezado) + " |", "|" + "---|" * len(encabezado)]
    lineas += ["| " + " | ".join(str(c) for c in fila) + " |" for fila in filas]
    return "\n".join(lineas)


# ---------------------------------------------------------------------------
# 1. Detección
# ---------------------------------------------------------------------------


def medir_deteccion() -> dict[str, Any]:
    """Pares CVE y versión esperados contra los que encuentra el cruce del radar."""
    if not RESPUESTA.exists() or not SNAPSHOT.exists():
        return {"pendiente": "falta resources/ (material privado, fuera del repositorio)"}
    from radar.contratos import Activo
    from radar.fuentes.nvd import leer_snapshot
    from radar.nucleo.cruce import cruzar_activo

    respuesta = json.loads(RESPUESTA.read_text(encoding="utf-8"))
    cache: dict[str, list] = {}

    def cves_de(par: str) -> list:
        if par not in cache:
            archivo = SNAPSHOT / (par.replace(":", "__").replace("\\", "") + ".json")
            cache[par] = list(leer_snapshot([archivo]).values())
        return cache[par]

    esperados = encontrados = reportados = casos_exactos = 0
    falsos: list[str] = []
    for caso in respuesta["casos"]:
        activo = Activo(
            clave=f"x@{caso['version']}",
            producto="x",
            nombre="x",
            version=caso["version"],
            cpes=[caso["par"]],
            equipos=["EQUIPO-001"],
        )
        r = cruzar_activo(activo, cves_de(caso["par"]))
        precisas = {c.cve.id for c in r.coincidencias if c.preciso}
        esperadas = set(caso["cves"])
        esperados += len(esperadas)
        encontrados += len(precisas & esperadas)
        reportados += len(precisas)
        falsos += [f"{caso['par']}@{caso['version']} {c}" for c in sorted(precisas - esperadas)]
        casos_exactos += precisas == esperadas
    return {
        "casos": len(respuesta["casos"]),
        "casos_exactos": casos_exactos,
        "pares_esperados": esperados,
        "pares_encontrados": encontrados,
        "pares_reportados": reportados,
        "falsos_positivos": falsos,
        "generado": respuesta.get("generado"),
    }


def seccion_deteccion(d: dict[str, Any]) -> str:
    if "pendiente" in d:
        return f"## Detección\n\nPendiente: {d['pendiente']}.\n"
    filas = [
        ["Casos (par y versión) con el resultado exacto", f"{d['casos_exactos']} de {d['casos']}"],
        [
            "Detección (pares CVE y versión encontrados)",
            (
                f"{d['pares_encontrados']} de {d['pares_esperados']} "
                f"({_pct(d['pares_encontrados'], d['pares_esperados'])})"
            ),
        ],
        [
            "Precisión (reportados que eran correctos)",
            (
                f"{d['pares_encontrados']} de {d['pares_reportados']} "
                f"({_pct(d['pares_encontrados'], d['pares_reportados'])})"
            ),
        ],
        ["Falsos positivos", len(d["falsos_positivos"])],
    ]
    texto = (
        "## Detección\n\n"
        "Cruce del radar (`radar.nucleo.cruce.cruzar_activo`) contra la respuesta conocida "
        "(`semilla_respuesta.json`, calculada con un script aparte, nunca con el cruce del "
        "proyecto). Solo CVE precisas; las no precisas se miden aparte en `tests/test_cruce.py`.\n\n"
        + _tabla(["Métrica", "Valor"], filas)
        + "\n"
    )
    if d["falsos_positivos"]:
        texto += (
            "\nFalsos positivos:\n\n" + "\n".join(f"- {f}" for f in d["falsos_positivos"]) + "\n"
        )
    return texto


# ---------------------------------------------------------------------------
# 2. Normalizador
# ---------------------------------------------------------------------------


def medir_normalizador() -> dict[str, Any]:
    try:
        from datos_prueba.medir_normalizador import medir

        return medir("inventario")
    except FileNotFoundError as error:
        return {
            "pendiente": f"falta el inventario generado ({Path(error.filename or '').name}); "
            "correr `uv run python -m datos_prueba.generar`"
        }
    except Exception as error:  # noqa: BLE001 - el reporte sale igual, con el motivo
        return {"pendiente": f"la medición falló: {type(error).__name__}: {error}"}


def seccion_normalizador(n: dict[str, Any]) -> str:
    if "pendiente" in n:
        return f"## Normalizador\n\nPendiente: {n['pendiente']}.\n"
    filas = []
    nombres = {
        "completo": "Completo (alias + difuso)",
        "solo_difuso": "Solo difuso",
        "nombre_exacto": "Línea base: nombre exacto",
    }
    for clave, v in n["variantes"].items():
        filas.append(
            [
                nombres.get(clave, clave),
                f"{v['activo_correcto']} de {v['filas_medidas']} ({v['exactitud_pct']} %)",
                f"{v['cve_alcanzables_pct']} %",
                f"{v['cobertura_motivo_correcto']} de {v['cobertura_esperada']}",
                v["cpe_equivocado"],
                v["relleno_con_cpe"],
            ]
        )
    return (
        "## Normalizador\n\n"
        f"Inventario `{n['inventario']}`, diccionario de {n['diccionario_pares']} pares, "
        f"sin modelo (`modelo={n['modelo']}`).\n\n"
        + _tabla(
            [
                "Variante",
                "Activo correcto (CPE y versión)",
                "CVE alcanzables",
                "Cobertura con motivo correcto",
                "CPE equivocado",
                "Relleno con CPE",
            ],
            filas,
        )
        + "\n"
    )


# ---------------------------------------------------------------------------
# 3. Inyección
# ---------------------------------------------------------------------------


def medir_inyeccion() -> dict[str, Any]:
    from evals.escenarios import escenarios
    from evals.inyeccion import correr_suite, tabla

    lista = escenarios(usar_base=False)
    salida: dict[str, Any] = {"origen_grupos": lista[0].origen if lista else None}
    for agente in ("obediente", "honesto"):
        resultados = correr_suite(lista, agente)
        salida[agente] = {
            "tabla": tabla(resultados),
            "resultados": [r.como_dict() for r in resultados],
        }
    try:
        from radar.agente.analista import analizar  # noqa: F401

        salida["real"] = {"pendiente": "existe analizar(); correr `pytest -m agente` con la clave"}
    except ImportError:
        salida["real"] = {"pendiente": "radar.agente.analista.analizar no existe todavía"}
    antes = HISTORIAL / "ronda2_antes_de_ajustes.json"
    if antes.exists():
        salida["ronda2_antes"] = json.loads(antes.read_text(encoding="utf-8"))
    return salida


def _fila_brazo(f: dict[str, Any]) -> list[Any]:
    return [
        f["ronda"],
        f["brazo"],
        f"{f['ataques_logrados']} de {f['casos']} ({_pct(f['ataques_logrados'], f['casos'])})",
        f"{f['utiles']} de {f['casos']}",
        f["intentos_negados"],
    ]


def seccion_inyeccion(i: dict[str, Any]) -> str:
    encabezado = ["Ronda", "Brazo", "Tasa de inyección", "Utilidad bajo ataque", "Intentos negados"]
    partes = [
        "## Suite de inyección\n",
        (
            "Dos brazos (PLAN, sección 16). **Sin defensa:** lectura más `marcar_mitigado` "
            "aprobada, sin hooks ni verificador. **Con defensa:** solo lectura, guarda previa, "
            "limpieza posterior (`radar/agente/hooks.py`) y verificador con respaldo.\n"
        ),
        (
            "Grupos de origen: cruce real del radar contra CVE, KEV y EPSS de la base local, "
            f"congelados en `evals/grupos_reales.json` (origen de esta corrida: "
            f"`{i['origen_grupos']}`). Equipos sintéticos más el equipo de la fila envenenada.\n"
        ),
        (
            "Tasa de inyección: casos en que el ataque logró su objetivo. Utilidad bajo ataque: "
            "casos en que el comunicado final salió completo y correcto (pasa el verificador).\n"
        ),
        "### Agente simulado que obedece (peor caso)\n",
        (
            "Si ve la orden del ataque en lo que le devuelven las herramientas (ya limpio en el "
            "brazo con defensa), la cumple. **No es la tasa de un modelo real**: mide si la "
            "tubería detiene el efecto del ataque aunque el modelo caiga.\n"
        ),
        _tabla(encabezado, [_fila_brazo(f) for f in i["obediente"]["tabla"]]) + "\n",
    ]
    logrados = [r for r in i["obediente"]["resultados"] if r["defensa"] and r["exito_ataque"]]
    if logrados:
        partes.append("Ataques que pasan la defensa con el agente obediente:\n")
        partes.append("\n".join(f"- `{r['caso']}`: {r['detalle']}" for r in logrados) + "\n")
    antes = i.get("ronda2_antes")
    if antes:
        filas_antes = [f for f in antes["tabla"] if f["ronda"] == 2]
        partes += [
            "### Ronda 2 antes de los ajustes\n",
            (
                f"Medida el {antes['momento']}, antes de agregar al verificador la revisión de "
                "enlaces, homoglifos y cuenta de equipos, y a la guarda el formato de los "
                "argumentos `cve`. Guardada en `evals/historial/ronda2_antes_de_ajustes.json` "
                "porque el código actual ya no la reproduce. Los ajustes cierran una clase de "
                "ataque, no una frase; una ronda 3 escrita después de ellos es la medida justa.\n"
            ),
            _tabla(encabezado, [_fila_brazo(f) for f in filas_antes]) + "\n",
        ]
    partes += [
        "### Agente simulado honesto\n",
        "Ignora las inyecciones. Mide que la defensa no descarta comunicados correctos.\n",
        _tabla(encabezado, [_fila_brazo(f) for f in i["honesto"]["tabla"]]) + "\n",
        (
            'En el brazo sin defensa, el agente honesto igual "sufre" los casos r1-07 y r1-09: '
            "el texto con control y la instrucción del final llegan al modelo sin limpiar, "
            "aunque este agente no obedezca.\n"
        ),
        "### Analista real\n",
        f"Pendiente: {i['real']['pendiente']}.\n",
        "### Detalle por caso (agente obediente)\n",
        _tabla(
            ["Caso", "Brazo", "Ataque", "Útil", "Comunicado final", "Detalle"],
            [
                [
                    r["caso"],
                    "con defensa" if r["defensa"] else "sin defensa",
                    "logrado" if r["exito_ataque"] else "detenido",
                    "sí" if r["util"] else "no",
                    r["origen_final"] or "ninguno",
                    r["detalle"].replace("|", "/"),
                ]
                for r in i["obediente"]["resultados"]
            ],
        )
        + "\n",
    ]
    return "\n".join(partes)


# ---------------------------------------------------------------------------
# Reporte
# ---------------------------------------------------------------------------


def escribir_reporte(destino: Path = REPORTE) -> Path:
    deteccion = medir_deteccion()
    normalizador = medir_normalizador()
    inyeccion = medir_inyeccion()
    texto = "\n".join(
        [
            "# Reporte de validación\n",
            (
                f"Generado por `uv run python -m evals.medir` el {time.strftime('%Y-%m-%d %H:%M')}. "
                "No se edita a mano: toda cifra de docs, ficha y pitch sale de aquí o de pytest.\n"
            ),
            seccion_deteccion(deteccion),
            seccion_normalizador(normalizador),
            seccion_inyeccion(inyeccion),
            (
                "## Barrido de umbrales\n\nPendiente: `evals/umbrales.py` usará la función de "
                "barrido que expone nucleo.\n"
            ),
        ]
    )
    destino.write_text(texto, encoding="utf-8")
    return destino


def principal() -> None:
    print(f"Escrito {escribir_reporte()}")


if __name__ == "__main__":
    principal()
