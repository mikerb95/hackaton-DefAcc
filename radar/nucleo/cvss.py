"""Puntaje base de CVSS 3.0 y 3.1 a partir del vector.

OSV publica el vector (`CVSS:3.1/AV:N/AC:L/...`) pero no el puntaje. Se calcula con la
fórmula de la especificación de FIRST. Otras versiones (2.0, 4.0) devuelven None: sin
puntaje no se inventa uno.
"""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_SIN_CAMBIO = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CON_CAMBIO = {"N": 0.85, "L": 0.68, "H": 0.5}


def _redondear_arriba(valor: float) -> float:
    """`Roundup` de la especificación 3.1: al décimo superior, sin errores de coma flotante."""
    entero = round(valor * 100_000)
    if entero % 10_000 == 0:
        return entero / 100_000
    return (math.floor(entero / 10_000) + 1) / 10


def puntaje_base(vector: str | None) -> float | None:
    """Puntaje base (0.0 a 10.0) de un vector CVSS 3.x, o None si no se puede calcular."""
    if not vector or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metricas: dict[str, str] = {}
    for parte in vector.split("/")[1:]:
        clave, separador, valor = parte.partition(":")
        if not separador:
            return None
        metricas[clave] = valor
    try:
        cambio = {"U": False, "C": True}[metricas["S"]]
        pr = (_PR_CON_CAMBIO if cambio else _PR_SIN_CAMBIO)[metricas["PR"]]
        explotabilidad = 8.22 * _AV[metricas["AV"]] * _AC[metricas["AC"]] * pr * _UI[metricas["UI"]]
        iss = 1 - (1 - _CIA[metricas["C"]]) * (1 - _CIA[metricas["I"]]) * (1 - _CIA[metricas["A"]])
    except KeyError:
        return None
    if cambio:
        impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impacto = 6.42 * iss
    if impacto <= 0:
        return 0.0
    total = impacto + explotabilidad
    if cambio:
        total *= 1.08
    return _redondear_arriba(min(total, 10))
