"""Utilidades compartidas por los recolectores. Solo librería estándar."""

from __future__ import annotations

import json
import subprocess
from typing import Any

# Cada comprobación de postura devuelve uno de estos tres valores. Nunca se adivina:
# si el dato no se pudo leer, es "desconocido" y el radar lo cuenta como cobertura.
SI = "si"
NO = "no"
DESCONOCIDO = "desconocido"

TIEMPO_COMANDO = 60  # segundos


def tri(valor: Any) -> str:
    """Booleano a "si" o "no"; cualquier otra cosa a "desconocido"."""
    if valor is True:
        return SI
    if valor is False:
        return NO
    return DESCONOCIDO


def ejecutar(orden: list[str], tiempo: int = TIEMPO_COMANDO) -> str | None:
    """Corre un programa sin shell y devuelve su salida, o None si falla o no existe.

    Nunca se usa `shell=True`: los argumentos son fijos y no llevan texto del equipo.
    """
    try:
        r = subprocess.run(
            orden,
            capture_output=True,
            timeout=tiempo,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    for codificacion in ("utf-8", "cp1252"):
        try:
            return r.stdout.decode(codificacion)
        except UnicodeDecodeError:
            continue
    return r.stdout.decode("latin-1")


def ejecutar_con_codigo(orden: list[str], tiempo: int = TIEMPO_COMANDO) -> tuple[int, str] | None:
    """Como `ejecutar`, pero devuelve también el código de salida (hay herramientas que
    responden con un código distinto de cero sin que sea un error)."""
    try:
        r = subprocess.run(
            orden,
            capture_output=True,
            timeout=tiempo,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.returncode, (r.stdout + r.stderr).decode("utf-8", errors="replace")


def json_o_nada(texto: str | None) -> Any:
    if not texto or not texto.strip():
        return None
    try:
        return json.loads(texto)
    except ValueError:
        return None


def como_lista(valor: Any) -> list:
    """PowerShell devuelve un objeto suelto cuando la lista tiene un solo elemento."""
    if valor is None:
        return []
    return valor if isinstance(valor, list) else [valor]


def texto(valor: Any) -> str | None:
    """Texto sin espacios en los bordes, o None si queda vacío."""
    if valor is None:
        return None
    limpio = str(valor).strip()
    return limpio or None
