"""Comparación de versiones (PLAN, sección 8).

Reglas:
- Una versión es una tupla de hasta cuatro enteros, rellenada con ceros: `1.0` == `1.0.0`.
- Los sufijos de prelanzamiento cuentan: `1.2.3-beta` < `1.2.3-rc1` < `1.2.3`.
- Los metadatos de compilación tras `+` no cuentan para el orden (semver): `17.0.9+9` == `17.0.9`.
- Lo que no se puede leer devuelve None ("no comparable"). Nunca se adivina: `28.1.1, build
  4eba377`, `2.45.1.windows.1` o una versión de cinco componentes no se comparan. Limpiar
  esas formas es trabajo del normalizador.
"""

from __future__ import annotations

import re
from functools import lru_cache, total_ordering

MAX_COMPONENTES = 4

# Rango de cada etiqueta de prelanzamiento. La versión final queda por encima de todas.
_ETIQUETAS: dict[str, int] = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
    "cr": 4,
}
_FINAL = 9

_PATRON = re.compile(
    r"""
    ^v?
    (?P<numeros>\d+(?:\.\d+)*)
    (?:
        [-._]?
        (?P<etiqueta>dev|alpha|beta|preview|pre|rc|cr|a|b)
        [-._]?
        (?P<n_etiqueta>\d+)?
    )?
    (?:\+[0-9A-Za-z.\-]+)?
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)


@total_ordering
class Version:
    """Versión ya leída. Se construye con `leer()`, que devuelve None si no se puede leer."""

    __slots__ = ("etiqueta", "n_etiqueta", "numeros", "texto")

    def __init__(self, texto: str, numeros: tuple[int, ...], etiqueta: int, n_etiqueta: int):
        self.texto = texto
        self.numeros = numeros
        self.etiqueta = etiqueta
        self.n_etiqueta = n_etiqueta

    @property
    def _clave(self) -> tuple[tuple[int, ...], int, int]:
        return (self.numeros, self.etiqueta, self.n_etiqueta)

    @property
    def es_prelanzamiento(self) -> bool:
        return self.etiqueta != _FINAL

    def __eq__(self, otra: object) -> bool:
        if not isinstance(otra, Version):
            return NotImplemented
        return self._clave == otra._clave

    def __lt__(self, otra: Version) -> bool:
        return self._clave < otra._clave

    def __hash__(self) -> int:
        return hash(self._clave)

    def __repr__(self) -> str:
        return f"Version({self.texto!r})"

    def __str__(self) -> str:
        return self.texto


@lru_cache(maxsize=65_536)
def leer(texto: str | None) -> Version | None:
    """Lee una versión. Devuelve None si falta o no es comparable.

    Memorizada: el cruce lee las mismas versiones de rango una vez por activo (más de 100 000
    rangos por corrida). Las `Version` devueltas no se modifican.
    """
    if texto is None:
        return None
    limpio = texto.strip()
    m = _PATRON.match(limpio)
    if not m:
        return None
    partes = [int(x) for x in m.group("numeros").split(".")]
    if len(partes) > MAX_COMPONENTES:
        return None
    numeros = tuple(partes + [0] * (MAX_COMPONENTES - len(partes)))
    etiqueta = m.group("etiqueta")
    if etiqueta:
        rango = _ETIQUETAS[etiqueta.lower()]
        n = int(m.group("n_etiqueta") or 0)
    else:
        rango, n = _FINAL, 0
    return Version(limpio, numeros, rango, n)


def comparable(texto: str | None) -> bool:
    return leer(texto) is not None


def comparar(a: str | None, b: str | None) -> int | None:
    """-1, 0 o 1 como `a` frente a `b`. None si alguna de las dos no es comparable."""
    va, vb = leer(a), leer(b)
    if va is None or vb is None:
        return None
    return (va > vb) - (va < vb)


def mayor(versiones: list[str]) -> str | None:
    """La mayor de una lista de versiones comparables. None si la lista queda vacía.

    Las que no se pueden leer se descartan (no se adivina su lugar).
    """
    leidas = [v for v in (leer(x) for x in versiones) if v is not None]
    if not leidas:
        return None
    return max(leidas).texto
