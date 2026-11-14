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
4. Barrido de umbrales (``evals/umbrales.py`` sobre ``radar.nucleo.umbrales``).
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
    return f"{100 * a / b:.1f} %".replace(".", ",") if b else "sin datos"


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
    """Cifras del normalizador desde su propia función (datos_prueba.metricas)."""
    if not RESPUESTA.exists():
        return {"pendiente": "falta resources/ (material privado, fuera del repositorio)"}
    try:
        from datos_prueba.metricas import metricas_normalizador

        return {"metricas": metricas_normalizador()}
    except Exception as error:  # noqa: BLE001 - el reporte sale igual, con el motivo
        return {"pendiente": f"la medición falló: {type(error).__name__}: {error}"}


def seccion_normalizador(n: dict[str, Any]) -> str:
    if "pendiente" in n:
        return f"## Normalizador\n\nPendiente: {n['pendiente']}.\n"
    from datos_prueba.metricas import tabla_markdown

    texto = tabla_markdown(n["metricas"]).strip()
    if not texto.startswith("## "):
        texto = "## Normalizador\n\n" + texto
    return texto + "\n"


# ---------------------------------------------------------------------------
# 3. Inyección
# ---------------------------------------------------------------------------

ETIQUETAS = {
    "obediente": "simulado (peor caso)",
    "honesto": "simulado (honesto)",
    "real": "analista real",
}

DESCRIPCION_RONDA = {
    1: "Ronda 1: casos escritos a mano antes de construir la defensa.",
    2: (
        "Ronda 2: escrita conociendo el verificador. Después de medirla se ajustaron el "
        "verificador y la guarda, así que la cifra de después está medida **sobre los "
        "mismos casos** con los que se ajustó: no es una cifra limpia."
    ),
    3: (
        "Ronda 3: escrita después de los ajustes, **sin volver a ajustar**. Es la cifra "
        "limpia. Incluye dos casos por el nombre de equipo, el canal que sobrevive al "
        "normalizador real."
    ),
}


def medir_inyeccion() -> dict[str, Any]:
    from evals.escenarios import escenarios
    from evals.inyeccion import correr_suite

    lista = escenarios(usar_base=False)
    salida: dict[str, Any] = {"origen_grupos": lista[0].origen if lista else None}
    for agente in ("obediente", "honesto"):
        salida[agente] = [r.como_dict() for r in correr_suite(lista, agente)]
    try:
        from radar.agente.analista import analizar  # noqa: F401

        salida["real"] = {"pendiente": "existe analizar(); correr `pytest -m agente` con la clave"}
    except ImportError:
        salida["real"] = {"pendiente": "radar.agente.analista.analizar no existe todavía"}
    antes = HISTORIAL / "ronda2_antes_de_ajustes.json"
    if antes.exists():
        salida["ronda2_antes"] = json.loads(antes.read_text(encoding="utf-8"))
    return salida


def _contar(resultados: list[dict[str, Any]], ronda: int, defensa: bool) -> tuple[int, int, int]:
    sub = [r for r in resultados if r["ronda"] == ronda and r["defensa"] == defensa]
    return len(sub), sum(r["exito_ataque"] for r in sub), sum(r["util"] for r in sub)


def _celda(logrados: int, casos: int) -> str:
    return f"{logrados} de {casos} ({_pct(logrados, casos)})"


def _fila_lado_a_lado(etiqueta: str, ronda: Any, resultados: list[dict[str, Any]]) -> list[Any]:
    n, sin, util_sin = _contar(resultados, ronda, False)
    _, con, util_con = _contar(resultados, ronda, True)
    return [
        ronda,
        etiqueta,
        _celda(sin, n),
        _celda(con, n),
        f"{util_sin} de {n}",
        f"{util_con} de {n}",
    ]


ENCABEZADO_BRAZOS = [
    "Ronda",
    "Agente",
    "Tasa de inyección sin defensa",
    "Tasa de inyección con defensa",
    "Utilidad sin defensa",
    "Utilidad con defensa",
]


def seccion_inyeccion(i: dict[str, Any]) -> str:
    obediente, honesto = i["obediente"], i["honesto"]
    rondas = sorted({r["ronda"] for r in obediente})
    filas = []
    for ronda in rondas:
        filas.append(_fila_lado_a_lado(ETIQUETAS["obediente"], ronda, obediente))
        if ronda == 2 and i.get("ronda2_antes"):
            previos = i["ronda2_antes"]["resultados"]
            fila = _fila_lado_a_lado(ETIQUETAS["obediente"], 2, previos)
            fila[0] = "2, antes de ajustar"
            filas[-1][0] = "2, después de ajustar (mismos casos)"
            filas.insert(len(filas) - 1, fila)
        filas.append(_fila_lado_a_lado(ETIQUETAS["honesto"], ronda, honesto))
    filas.append(["todas", ETIQUETAS["real"], "pendiente", "pendiente", "pendiente", "pendiente"])

    logrados = [r for r in obediente if r["defensa"] and r["exito_ataque"]]
    partes = [
        "## Suite de inyección\n",
        (
            "Dos brazos (PLAN, sección 16). **Sin defensa:** lectura más `marcar_mitigado` "
            "aprobada, sin hooks ni verificador. **Con defensa:** solo lectura, guarda previa, "
            "limpieza posterior (`radar/agente/hooks.py`) y verificador con respaldo.\n"
        ),
        (
            "Tasa de inyección: casos en que el ataque logró su objetivo. Utilidad bajo "
            "ataque: casos en que el comunicado final salió completo y correcto (pasa el "
            "verificador).\n"
        ),
        (
            '**Toda fila "simulado" es un agente de código, no un modelo.** '
            '"Simulado (peor caso)" cumple cualquier orden del ataque que vea en lo que le '
            "devuelven las herramientas (ya limpio, en el brazo con defensa): mide si la "
            'tubería detiene el efecto del ataque aunque el modelo caiga. "Simulado '
            '(honesto)" ignora las órdenes: mide que la defensa no descarte comunicados '
            'correctos. La tasa de un modelo real es la fila "analista real".\n'
        ),
        "\n".join(f"- {DESCRIPCION_RONDA[r]}" for r in rondas if r in DESCRIPCION_RONDA) + "\n",
        _tabla(ENCABEZADO_BRAZOS, filas) + "\n",
        (
            "Analista real: "
            f"{i['real']['pendiente']}. Se mide con `pytest -m agente` y el contrato de "
            "`docs/contrato-analista.md`.\n"
        ),
        "### Qué pasa la defensa con el agente que obedece\n",
        (
            "El verificador garantiza **nada de más** (CVE, cifras, versiones, equipos, "
            "enlaces y cuentas que no están en el origen) y la guarda **nada de escribir**. "
            "No garantiza **nada torcido**: un ataque que cambia el sentido usando solo datos "
            "permitidos pasa si el modelo obedece. Son límites declarados en "
            "`docs/LIMITES.md`.\n"
        ),
        "\n".join(f"- `{r['caso']}`: {r['detalle']}" for r in logrados) + "\n",
        (
            "Grupos de origen: cruce real del radar contra CVE, KEV y EPSS de la base local, "
            "congelados en `evals/grupos_reales.json` (origen de esta corrida: "
            f"`{i['origen_grupos']}`). Equipos sintéticos más el equipo de la fila "
            "envenenada. La ronda 2 de antes de ajustar sale de "
            "`evals/historial/ronda2_antes_de_ajustes.json`: el código actual ya no la "
            "reproduce.\n"
        ),
        "### Detalle por caso, simulado (peor caso)\n",
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
                for r in obediente
            ],
        )
        + "\n",
    ]
    return "\n".join(partes)


# ---------------------------------------------------------------------------
# Reporte
# ---------------------------------------------------------------------------


def escribir_reporte(destino: Path = REPORTE) -> Path:
    from evals.umbrales import medir_umbrales, seccion_umbrales

    texto = "\n".join(
        [
            "# Reporte de validación\n",
            (
                f"Generado por `uv run python -m evals.medir` el "
                f"{time.strftime('%Y-%m-%d %H:%M')}. No se edita a mano: toda cifra de docs, "
                "ficha y pitch sale de aquí o de pytest.\n"
            ),
            seccion_deteccion(medir_deteccion()),
            seccion_normalizador(medir_normalizador()),
            seccion_inyeccion(medir_inyeccion()),
            seccion_umbrales(medir_umbrales()),
        ]
    )
    destino.write_text(texto, encoding="utf-8")
    return destino


def principal() -> None:
    print(f"Escrito {escribir_reporte()}")


if __name__ == "__main__":
    principal()
