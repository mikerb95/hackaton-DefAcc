"""Cuenta las palabras de docs/RESUMEN.md (sin el título de la página ni las marcas).

    uv run python docs/contar_palabras.py [archivo]

La entrega pide entre 150 y 250 palabras. Cuenta como palabra cada número ("83,3") y cada
secuencia de letras; los signos no cuentan.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

MINIMO, MAXIMO = 150, 250


def contar(texto: str) -> int:
    cuerpo = "\n".join(ln for ln in texto.splitlines() if not ln.startswith("# "))
    cuerpo = re.sub(r"\*\*([^*]+)\*\*", r"\1", cuerpo)
    return len(re.findall(r"[0-9]+(?:[.,][0-9]+)?|[^\W\d_]+(?:-[^\W\d_]+)*", cuerpo))


if __name__ == "__main__":
    ruta = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("RESUMEN.md")
    n = contar(ruta.read_text(encoding="utf-8"))
    print(f"{ruta.name}: {n} palabras (rango pedido {MINIMO} a {MAXIMO})")
    sys.exit(0 if MINIMO <= n <= MAXIMO else 1)
