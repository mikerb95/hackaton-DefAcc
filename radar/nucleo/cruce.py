"""Regla de afectación y versión objetivo (PLAN, sección 8). Código determinista.

Flujo: `cruzar_activo(activo, cves)` devuelve las coincidencias de un activo contra una lista
de CVE, o un motivo de cobertura si la versión instalada no se puede comparar. La
priorización y el armado del Hallazgo viven en prioridad.py.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from radar.contratos import CVE, Activo, Cobertura, Rango, TipoObjetivo
from radar.fuentes.nvd import normalizar_par
from radar.nucleo.versiones import Version, leer


class Afecta(Enum):
    SI = "si"
    NO = "no"
    TODAS = "todas"  # el rango no acota versión: hallazgo no preciso
    NO_COMPARABLE = "no_comparable"


def afecta(rango: Rango, instalada: str | Version | None) -> Afecta:
    """Aplica la regla de afectación de un rango a una versión instalada."""
    x = instalada if isinstance(instalada, Version) else leer(instalada)
    if x is None:
        return Afecta.NO_COMPARABLE

    # 1. CPE con versión fija: afecta si son iguales.
    if rango.version is not None:
        fija = leer(rango.version)
        if fija is None:
            return Afecta.NO_COMPARABLE
        return Afecta.SI if x == fija else Afecta.NO

    # 2. Sin versión ni límites: afecta a todas, no preciso.
    if rango.desde is None and rango.hasta is None:
        return Afecta.TODAS

    # 3. Límite inferior.
    if rango.desde is not None:
        d = leer(rango.desde)
        if d is None:
            return Afecta.NO_COMPARABLE
        if x < d or (x == d and not rango.desde_incluye):
            return Afecta.NO

    # 4. Límite superior.
    if rango.hasta is not None:
        h = leer(rango.hasta)
        if h is None:
            return Afecta.NO_COMPARABLE
        if x > h or (x == h and not rango.hasta_incluye):
            return Afecta.NO

    return Afecta.SI


def acotamiento(rango: Rango) -> int:
    """Qué tan acotado es un rango: versión fija 3, dos límites 2, un límite 1, nada 0."""
    if rango.version is not None:
        return 3
    return (rango.desde is not None) + (rango.hasta is not None)


@dataclass(frozen=True)
class Coincidencia:
    """Una CVE que afecta a un activo, con el rango que manda."""

    cve: CVE
    rango: Rango
    preciso: bool


@dataclass(frozen=True)
class ResultadoActivo:
    coincidencias: list[Coincidencia]
    cobertura: list[Cobertura]


def rangos_del_activo(cve: CVE, pares: set[str]) -> list[Rango]:
    """Rangos de la CVE cuyos pares coinciden con los del activo (escapes normalizados)."""
    return [r for r in cve.rangos if normalizar_par(r.par) in pares]


def evaluar_cve(cve: CVE, pares: set[str], instalada: Version) -> Coincidencia | None:
    """Coincidencia de una CVE con un activo, o None si no lo afecta.

    Un rango que afecta con precisión gana sobre uno que afecta "a todas". Si varios rangos
    precisos emparejan, manda el más acotado.
    """
    precisos: list[Rango] = []
    imprecisos: list[Rango] = []
    for rango in rangos_del_activo(cve, pares):
        resultado = afecta(rango, instalada)
        if resultado is Afecta.SI:
            precisos.append(rango)
        elif resultado is Afecta.TODAS:
            imprecisos.append(rango)
    if precisos:
        return Coincidencia(cve=cve, rango=max(precisos, key=acotamiento), preciso=True)
    if imprecisos:
        return Coincidencia(cve=cve, rango=imprecisos[0], preciso=False)
    return None


def cruzar_activo(activo: Activo, cves: Iterable[CVE]) -> ResultadoActivo:
    """Cruza un activo contra las CVE. Sin comparación no hay hallazgo (regla 1)."""
    if not activo.cpes:
        return ResultadoActivo([], _cobertura(activo, "sin_cpe"))
    if not activo.version or not activo.version.strip():
        return ResultadoActivo([], _cobertura(activo, "sin_version"))
    instalada = leer(activo.version)
    if instalada is None:
        return ResultadoActivo([], _cobertura(activo, "no_comparable"))

    pares = {normalizar_par(p) for p in activo.cpes}
    coincidencias = [c for c in (evaluar_cve(cve, pares, instalada) for cve in cves) if c]
    return ResultadoActivo(coincidencias, [])


def _cobertura(activo: Activo, motivo: str) -> list[Cobertura]:
    equipos = activo.equipos or [""]
    return [
        Cobertura(equipo=e, programa=activo.nombre, version=activo.version or None, motivo=motivo)
        for e in equipos
    ]


# ---------------------------------------------------------------------------
# Versión objetivo
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Objetivo:
    """Versión de arreglo. `tipo` dice cómo leer `version` (ver contratos.Grupo)."""

    version: str | None
    tipo: TipoObjetivo


NINGUNO = Objetivo(None, "ninguna")


def objetivo_de_rango(rango: Rango | None) -> Objetivo:
    """Versión de arreglo de una CVE según el rango que manda.

    - versionEndExcluding X: actualizar a X.
    - versionEndIncluding X: solo "posterior a X" (regla 5).
    - Versión fija X: "posterior a X" (no hay arreglo publicado en el rango).
    - Sin límite superior: no se promete nada.
    """
    if rango is None:
        return NINGUNO
    if rango.version is not None:
        return Objetivo(rango.version, "posterior_a") if leer(rango.version) else NINGUNO
    if rango.hasta is None or leer(rango.hasta) is None:
        return NINGUNO
    return Objetivo(rango.hasta, "posterior_a" if rango.hasta_incluye else "exacta")


def objetivo_de_producto(objetivos: Iterable[Objetivo]) -> Objetivo:
    """La mayor de las versiones de arreglo. Si alguna CVE no acota, no se promete ninguna.

    Si la mayor sale de un límite inclusivo (o empata con uno), el resultado es "posterior a".
    """
    lista = list(objetivos)
    if not lista or any(o.tipo == "ninguna" for o in lista):
        return NINGUNO
    mejor: Objetivo | None = None
    mejor_v: Version | None = None
    for o in lista:
        v = leer(o.version)
        if v is None:
            return NINGUNO
        if mejor_v is None or v > mejor_v:
            mejor, mejor_v = o, v
        elif v == mejor_v and o.tipo == "posterior_a":
            mejor = o
    return mejor or NINGUNO
