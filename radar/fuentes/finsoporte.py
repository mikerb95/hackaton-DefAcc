"""Fechas de fin de soporte de sistemas operativos, de endoflife.date (gratis y sin clave).

El radar lee una copia guardada en `radar/datos/fin_soporte.json` (sin red en la API ni
en las pruebas). Para refrescarla:

    uv run python -m radar.fuentes.finsoporte

Comprobado el 14 de noviembre de 2026: `GET https://endoflife.date/api/{producto}.json`
responde una lista de ciclos con `cycle`, `eol` (fecha, o `false` si aún no tiene) y, en
Windows, `latest` con el build base (`10.0.22631`).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

URL = "https://endoflife.date/api/{producto}.json"
RUTA = Path(__file__).resolve().parent.parent / "datos" / "fin_soporte.json"
PRODUCTOS = (
    "windows",
    "windows-server",
    "ubuntu",
    "debian",
    "rhel",
    "rocky-linux",
    "almalinux",
    "centos",
)
TIEMPO = httpx.Timeout(30.0)
CABECERAS = {"User-Agent": "radar-vulnerabilidades/0.1"}


def reducir(ciclos: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deja de cada ciclo lo que usa el radar.

    `eol` en endoflife.date puede ser una fecha, `false` (aún con soporte, sin fecha de fin) o
    `true` (ya sin soporte, fecha desconocida). `true` se guarda como `vencido_sin_fecha`:
    nunca como "sin fecha", que se leería como un sistema con soporte.
    """
    salida = []
    for c in ciclos:
        fin = c.get("eol")
        salida.append(
            {
                "ciclo": str(c.get("cycle")),
                "fin": fin if isinstance(fin, str) else None,
                "vencido_sin_fecha": fin is True,
                "build": c.get("latest") if isinstance(c.get("latest"), str) else None,
                "lts": bool(c.get("lts")),
            }
        )
    return salida


def descargar(cliente: httpx.Client | None = None) -> dict[str, Any]:
    propio = cliente is None
    cliente = cliente or httpx.Client(timeout=TIEMPO, headers=CABECERAS, follow_redirects=True)
    productos: dict[str, list[dict[str, Any]]] = {}
    try:
        for producto in PRODUCTOS:
            r = cliente.get(URL.format(producto=producto))
            r.raise_for_status()
            productos[producto] = reducir(r.json())
    finally:
        if propio:
            cliente.close()
    return {
        "fuente": "https://endoflife.date",
        "capturado": datetime.now(UTC).date().isoformat(),
        "productos": productos,
    }


@lru_cache(maxsize=1)
def cargar(ruta: Path = RUTA) -> dict[str, Any]:
    """La copia guardada. Si falta, devuelve un catálogo vacío: sin dato no hay hallazgo."""
    try:
        return json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"fuente": None, "capturado": None, "productos": {}}


def ciclos(producto: str, catalogo: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    return (catalogo or cargar())["productos"].get(producto, [])


def fecha(ciclo: dict[str, Any]) -> date | None:
    return date.fromisoformat(ciclo["fin"]) if ciclo.get("fin") else None


def vencido_sin_fecha(ciclo: dict[str, Any]) -> bool:
    """El ciclo ya no tiene soporte aunque endoflife.date no publique la fecha (`eol: true`)."""
    return bool(ciclo.get("vencido_sin_fecha"))


def principal() -> int:
    datos = descargar()
    RUTA.write_text(json.dumps(datos, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    total = sum(len(c) for c in datos["productos"].values())
    print(f"[finsoporte] {total} ciclos de {len(datos['productos'])} productos en {RUTA}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(principal())
