"""Nombre de equipo en la entrada: validación (RFC 1123) y saneado.

El nombre de equipo era el canal de inyección que sobrevive al normalizador: el nombre de
programa se pierde porque solo se eligen CPE reales, pero el equipo llegaba tal cual al
modelo y al comunicado de TI (inyección de segundo orden, docs/AMENAZAS.md).

Un nombre de equipo debe parecer un hostname: etiquetas de letras, dígitos y guion,
separadas por punto, de 1 a 63 caracteres, que no empiezan ni terminan en guion, y 253
caracteres en total. Si no lo es, **el nombre se sanea en la ingesta y la fila se cruza
igual**: no va a cobertura, porque eso escondería el equipo de los hallazgos, que es lo que
busca la inyección.

El saneado es ``prefijo~fNNN``: el prefijo con caracteres de hostname, más ``~f`` y la
primera fila donde aparece ("EQUIPO-017 (ignora...)" en la fila 502 queda
"EQUIPO-017~f502"). No se deja "EQUIPO-017" a secas porque se fusionaría con el EQUIPO-017
real: quien envenena una fila podría atribuirle programas y hallazgos a otra máquina, y se
borraría la pista. "~" no es válido en un hostname, así que nunca choca con uno real, y el
número dice qué fila corregir.

Una sola implementación: la usan ``radar/ingesta/archivos.py`` (frente plugin) y la suite
de inyección (``evals/escenarios.py``). Solo librería estándar.
"""

from __future__ import annotations

import re

LARGO_MAXIMO = 253
LARGO_PREFIJO_SANEADO = 40
_ETIQUETA = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def nombre_equipo_valido(nombre: object) -> bool:
    """True si el nombre (sin espacios en los bordes) es un hostname según RFC 1123."""
    if not isinstance(nombre, str):
        return False
    texto = nombre.strip().removesuffix(".")
    if not texto or len(texto) > LARGO_MAXIMO:
        return False
    return all(_ETIQUETA.fullmatch(etiqueta) for etiqueta in texto.split("."))


def sanear_nombre_equipo(nombre: object, fila: int) -> str:
    """Nombre de equipo seguro. Si ya es válido, se devuelve sin espacios en los bordes.

    Si no, ``prefijo~f<fila>``: los caracteres de hostname (letras ASCII, dígitos, guion y
    punto) hasta el primero que no lo es, recortados a 40 y sin guion ni punto en los bordes
    ("equipo" si no queda nada), más ``~f`` y ``fila``, la primera fila del inventario donde
    aparece el nombre. La ingesta guarda el original para auditoría.
    """
    texto = nombre if isinstance(nombre, str) else ("" if nombre is None else str(nombre))
    if nombre_equipo_valido(texto):
        return texto.strip()
    prefijo = ""
    for caracter in texto.strip():
        if not (caracter.isascii() and (caracter.isalnum() or caracter in "-.")):
            break
        prefijo += caracter
    prefijo = prefijo[:LARGO_PREFIJO_SANEADO].strip("-.") or "equipo"
    return f"{prefijo}~f{fila}"
