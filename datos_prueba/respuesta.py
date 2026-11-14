"""Respuesta conocida del inventario de prueba.

Sale de dos fuentes escritas a mano o calculadas aparte: la semilla
(datos_prueba/semilla.py) y el snapshot resources/semilla_respuesta.json, calculado
con un script auxiliar independiente. Nunca usa el cruce del proyecto: este módulo
tiene prohibido importar radar.nucleo, porque entonces la prueba se mediría contra sí
misma.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from datos_prueba.semilla import Caso, CasoCobertura

RAIZ = Path(__file__).resolve().parent.parent
RUTA_SNAPSHOT = RAIZ / "resources" / "semilla_respuesta.json"


@dataclass(frozen=True)
class Esperado:
    """Lo que el snapshot dice de un par en una versión."""

    cves: frozenset[str]
    kev: frozenset[str]
    no_precisas: frozenset[str]
    peor_cvss: float | None


def _clave_par(par: str) -> str:
    # El CPE de Notepad++ lleva \+\+ escapado; en el snapshot va sin escapar.
    return par.replace("\\", "")


def cargar_snapshot(ruta: Path = RUTA_SNAPSHOT) -> dict[tuple[str, str], Esperado]:
    datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
    return {
        (_clave_par(c["par"]), c["version"]): Esperado(
            cves=frozenset(c["cves"]),
            kev=frozenset(c["kev"]),
            no_precisas=frozenset(c["no_precisas"]),
            peor_cvss=c["peor_cvss"],
        )
        for c in datos["casos"]
    }


def esperado_de_caso(caso: Caso, snapshot: dict[tuple[str, str], Esperado]) -> dict:
    """Une lo esperado de todos los pares del caso (Docker Desktop tiene dos)."""
    cves: set[str] = set()
    kev: set[str] = set()
    no_precisas: set[str] = set()
    peores: list[float] = []
    por_par: dict[str, list[str]] = {}
    for par in caso.pares:
        clave = (_clave_par(par), caso.version_real)
        if clave not in snapshot:
            raise KeyError(f"El snapshot no trae {clave}: revisa la semilla")
        e = snapshot[clave]
        cves |= e.cves
        kev |= e.kev
        no_precisas |= e.no_precisas
        por_par[par] = sorted(e.cves)
        if e.peor_cvss is not None:
            peores.append(e.peor_cvss)
    return {
        "pares": list(caso.pares),  # con el escape de NVD, como en el contrato
        "version_comparable": caso.version_real,
        "cves": sorted(cves),
        "cves_por_par": por_par,
        "kev": sorted(kev),
        "no_precisas": sorted(no_precisas),
        "peor_cvss": max(peores) if peores else None,
    }


def respuesta_fila(fila: dict, origen, snapshot) -> dict:
    """Respuesta de una fila del inventario según el caso que la originó."""
    base = {k: fila.get(k) for k in ("fila", "equipo", "programa", "version", "proveedor")}
    if isinstance(origen, Caso):
        esp = esperado_de_caso(origen, snapshot)
        tipo = "vulnerable" if esp["cves"] else "sano"
        return {
            **base,
            "tipo": tipo,
            "producto": origen.canonico,
            "clave": origen.clave,
            "prueba": origen.prueba,
            **esp,
        }
    if isinstance(origen, CasoCobertura):
        return {
            **base,
            "tipo": "cobertura",
            "motivo": origen.motivo,
            "explicacion": origen.explicacion,
            "par_prohibido": origen.par_prohibido,
            "pares": [],
            "cves": [],
            "kev": [],
        }
    if origen == "relleno":
        return {**base, "tipo": "relleno", "medido": False, "cves": [], "kev": []}
    if isinstance(origen, dict) and origen.get("tipo") == "inyeccion":
        return {
            **base,
            "tipo": "inyeccion",
            "medido": False,
            "caso_inyeccion": origen.get("caso"),
            "cves": [],
            "kev": [],
        }
    raise ValueError(f"Origen desconocido para la fila {fila['fila']}: {origen!r}")


def construir(
    filas_con_origen: list[tuple[dict, object]], ruta_snapshot: Path = RUTA_SNAPSHOT
) -> dict:
    """Arma la respuesta completa: una entrada por fila y los totales esperados."""
    snapshot = cargar_snapshot(ruta_snapshot)
    filas = [respuesta_fila(f, o, snapshot) for f, o in filas_con_origen]
    medidas = [f for f in filas if f["tipo"] in ("vulnerable", "sano")]
    kev_distintas = sorted({c for f in medidas for c in f["kev"]})
    # Cada (par, versión) se cuenta una vez: es la cifra de SEMILLA.md (735), que no
    # multiplica por equipos.
    par_version = {
        (par, f["version_comparable"]): len(cves)
        for f in medidas
        for par, cves in f["cves_por_par"].items()
    }
    totales = {
        "filas": len(filas),
        "equipos": len({f["equipo"] for f in filas}),
        "pares_cve_version_precisos": sum(par_version.values()),
        "pares_cve_activo_precisos": sum(len(f["cves"]) for f in medidas),
        "pares_cve_activo_no_precisos": sum(len(f.get("no_precisas", [])) for f in medidas),
        "cve_distintas": len({c for f in medidas for c in f["cves"]}),
        "kev_distintas": len(kev_distintas),
        "kev": kev_distintas,
        "activos_vulnerables": sum(1 for f in filas if f["tipo"] == "vulnerable"),
        "activos_sanos": sum(1 for f in filas if f["tipo"] == "sano"),
        "cobertura": sum(1 for f in filas if f["tipo"] == "cobertura"),
        "cobertura_por_motivo": _contar(f["motivo"] for f in filas if f["tipo"] == "cobertura"),
        "relleno": sum(1 for f in filas if f["tipo"] == "relleno"),
        "inyeccion": sum(1 for f in filas if f["tipo"] == "inyeccion"),
        "equipos_con_kev": len({f["equipo"] for f in medidas if f["kev"]}),
    }
    datos = json.loads(Path(ruta_snapshot).read_text(encoding="utf-8"))
    return {
        "fuente": datos["fuente"],
        "snapshot": datos["generado"],
        "totales": totales,
        "filas": filas,
    }


def _contar(valores) -> dict[str, int]:
    out: dict[str, int] = {}
    for v in valores:
        out[v] = out.get(v, 0) + 1
    return dict(sorted(out.items()))
