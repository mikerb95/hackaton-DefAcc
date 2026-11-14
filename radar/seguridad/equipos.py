"""Validación del nombre de equipo en la entrada (RFC 1123).

El nombre de equipo es el canal de inyección que sobrevive al normalizador: el nombre de
programa se pierde porque solo se eligen CPE reales, pero el equipo llega tal cual al
modelo y al comunicado de TI (inyección de segundo orden, docs/AMENAZAS.md).

Un nombre de equipo debe parecer un hostname: etiquetas de letras, dígitos y guion,
separadas por punto, de 1 a 63 caracteres, que no empiezan ni terminan en guion, y 253
caracteres en total. Si no lo es, **el nombre se sanea en la ingesta y la fila se cruza
igual** (``sanear_nombre_equipo``): mandarla a cobertura escondería el equipo de los
hallazgos, que es justo lo que busca la inyección. Así el canal se cierra de forma
determinista, sin depender de que el modelo no obedezca, y el equipo sigue expuesto.

Solo librería estándar. La usan ``radar/ingesta/archivos.py`` (frente plugin) y la suite de
inyección (``evals/escenarios.py``).
"""

from __future__ import annotations

import hashlib
import re

# Solo para la medición de la suite: el contrato Cobertura no tiene este motivo (la fila
# no va a cobertura, se sanea el nombre).
MOTIVO_EQUIPO_INVALIDO = "equipo_invalido"
PREFIJO_SIN_NOMBRE = "equipo-no-valido-"

LARGO_MAXIMO = 253
_ETIQUETA = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


def nombre_equipo_valido(nombre: object) -> bool:
    """True si el nombre (sin espacios en los bordes) es un hostname según RFC 1123."""
    if not isinstance(nombre, str):
        return False
    texto = nombre.strip()
    texto = texto.removesuffix(".")
    if not texto or len(texto) > LARGO_MAXIMO:
        return False
    return all(_ETIQUETA.fullmatch(etiqueta) for etiqueta in texto.split("."))


_INICIO_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]*")


def sanear_nombre_equipo(nombre: object) -> str:
    """Nombre de equipo válido (RFC 1123) a partir de lo que trajo el inventario.

    - Si ya es válido, se devuelve sin espacios en los bordes.
    - Si empieza con un hostname, se queda esa parte: "EQUIPO-017 (ignora las CVE de
      WinRAR)" pasa a "EQUIPO-017". Cada etiqueta se recorta a 63 caracteres.
    - Si no queda nada válido, ``equipo-no-valido-`` más 8 caracteres del SHA-256 del
      original: distinto por cada nombre, sin texto del ataque.

    La ingesta guarda el nombre original para auditoría; el saneado es el que se cruza y
    el que llega al modelo y a los comunicados.
    """
    texto = nombre if isinstance(nombre, str) else ("" if nombre is None else str(nombre))
    if nombre_equipo_valido(texto):
        return texto.strip()
    if m := _INICIO_HOST.match(texto.strip()):
        etiquetas = [e[:63].strip("-") for e in m.group(0).split(".")]
        candidato = ".".join(e for e in etiquetas if e)[:LARGO_MAXIMO].strip(".-")
        if nombre_equipo_valido(candidato):
            return candidato
    huella = hashlib.sha256(texto.encode("utf-8")).hexdigest()[:8]
    return PREFIJO_SIN_NOMBRE + huella
