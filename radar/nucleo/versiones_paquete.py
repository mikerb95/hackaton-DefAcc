"""Comparación de versiones de paquetes de distribución: dpkg (Debian, Ubuntu) y rpm.

No ordenan igual que una tupla de enteros (`radar/nucleo/versiones.py`): llevan época,
revisión de la distribución y reglas propias (`~` va antes que nada en dpkg).

- dpkg: `[época:]versión[-revisión]`, según la política de Debian (sección 5.6.12).
- rpm: `[época:]versión[-release]`, con el algoritmo `rpmvercmp`.

Solo librería estándar: no depende de `dpkg` ni de `rpm` instalados en el servidor.
Devuelven -1, 0 o 1, como `versiones.comparar`.
"""

from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Literal

Sistema = Literal["dpkg", "rpm"]


def _signo(n: int) -> int:
    return (n > 0) - (n < 0)


def _partir(version: str) -> tuple[int, str, str]:
    """(época, versión, revisión). Sin época es 0; sin revisión es cadena vacía."""
    texto = version.strip()
    epoca = 0
    if ":" in texto:
        cabeza, _, resto = texto.partition(":")
        if cabeza.isdigit():
            epoca, texto = int(cabeza), resto
    cuerpo, guion, revision = texto.rpartition("-")
    if not guion:
        return epoca, texto, ""
    return epoca, cuerpo, revision


# ---------------------------------------------------------------------------
# dpkg
# ---------------------------------------------------------------------------


def _orden_dpkg(caracter: str) -> int:
    # "~" ordena antes que el final de la cadena; las letras antes que el resto de signos.
    if caracter == "~":
        return -1
    if caracter.isalpha():
        return ord(caracter)
    return ord(caracter) + 256


def _comparar_parte_dpkg(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        # Tramo no numérico: carácter a carácter, con el final de cadena como 0.
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ca = _orden_dpkg(a[i]) if i < len(a) and not a[i].isdigit() else 0
            cb = _orden_dpkg(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ca != cb:
                return _signo(ca - cb)
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # Tramo numérico: como número, sin importar los ceros a la izquierda.
        inicio_a, inicio_b = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        na = int(a[inicio_a:i] or 0)
        nb = int(b[inicio_b:j] or 0)
        if na != nb:
            return _signo(na - nb)
    return 0


def comparar_dpkg(a: str, b: str) -> int:
    ea, va, ra = _partir(a)
    eb, vb, rb = _partir(b)
    if ea != eb:
        return _signo(ea - eb)
    return _comparar_parte_dpkg(va, vb) or _comparar_parte_dpkg(ra, rb)


# ---------------------------------------------------------------------------
# rpm
# ---------------------------------------------------------------------------

_TRAMO_RPM = re.compile(r"(~)|(\^)|(\d+)|([A-Za-z]+)")


def _tramos_rpm(texto: str) -> list[tuple[str, str]]:
    tramos = []
    for tilde, circunflejo, numero, letras in _TRAMO_RPM.findall(texto):
        if tilde:
            tramos.append(("~", ""))
        elif circunflejo:
            tramos.append(("^", ""))
        elif numero:
            tramos.append(("n", numero))
        else:
            tramos.append(("a", letras))
    return tramos


def _comparar_parte_rpm(a: str, b: str) -> int:
    ta, tb = _tramos_rpm(a), _tramos_rpm(b)
    for i in range(max(len(ta), len(tb))):
        xa = ta[i] if i < len(ta) else None
        xb = tb[i] if i < len(tb) else None
        # "~" ordena antes que todo, incluso que el final de la cadena.
        if (xa and xa[0] == "~") or (xb and xb[0] == "~"):
            if not (xa and xa[0] == "~"):
                return 1
            if not (xb and xb[0] == "~"):
                return -1
            continue
        # "^" ordena después del final de la cadena, pero antes que cualquier otro tramo.
        if (xa and xa[0] == "^") or (xb and xb[0] == "^"):
            if xa is None:
                return -1
            if xb is None:
                return 1
            if xa[0] != "^":
                return 1
            if xb[0] != "^":
                return -1
            continue
        if xa is None:
            return -1
        if xb is None:
            return 1
        if xa[0] != xb[0]:
            # Un tramo numérico siempre es más nuevo que uno de letras.
            return 1 if xa[0] == "n" else -1
        if xa[0] == "n":
            na, nb = int(xa[1]), int(xb[1])
            if na != nb:
                return _signo(na - nb)
        elif xa[1] != xb[1]:
            return 1 if xa[1] > xb[1] else -1
    return 0


def comparar_rpm(a: str, b: str) -> int:
    ea, va, ra = _partir(a)
    eb, vb, rb = _partir(b)
    if ea != eb:
        return _signo(ea - eb)
    resultado = _comparar_parte_rpm(va, vb)
    if resultado or not ra or not rb:
        # Sin release en alguno de los dos, solo se compara la versión.
        return resultado
    return _comparar_parte_rpm(ra, rb)


# ---------------------------------------------------------------------------
# Uso común
# ---------------------------------------------------------------------------


def comparar(a: str, b: str, sistema: Sistema) -> int:
    return comparar_dpkg(a, b) if sistema == "dpkg" else comparar_rpm(a, b)


def mayor(versiones: list[str], sistema: Sistema) -> str | None:
    """La mayor de una lista de versiones, o None si la lista está vacía."""
    limpias = [v for v in versiones if v and v.strip()]
    if not limpias:
        return None
    return max(limpias, key=cmp_to_key(lambda x, y: comparar(x, y, sistema)))
