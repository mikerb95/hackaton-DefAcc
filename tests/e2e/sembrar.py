"""Base de pruebas para Playwright: esquema, CVE de ejemplo, cruce y tres usuarios.

Uso: RADAR_SQLITE=/tmp/x.db uv run python tests/e2e/sembrar.py
Nunca toca Turso: exige RADAR_SQLITE y lo usa con ruta explícita.
"""

from __future__ import annotations

import os
import sys
from datetime import UTC, datetime
from pathlib import Path

CLAVE = "clave-de-prueba-e2e"


def main() -> int:
    ruta = Path(os.environ.get("RADAR_SQLITE", ""))
    if not ruta.name:
        print("Falta RADAR_SQLITE", file=sys.stderr)
        return 2
    os.environ.pop("TURSO_DATABASE_URL", None)
    ruta.unlink(missing_ok=True)

    from radar import bd, ejemplos
    from radar.api import cuentas
    from radar.config import Umbrales
    from radar.nucleo.corrida import correr

    c = bd.conectar(ruta_sqlite=ruta)
    bd.crear_esquema(c)
    bd.guardar_cves(c, ejemplos.CVES)
    bd.guardar_kev(c, ejemplos.SENALES.kev)
    bd.guardar_epss(c, ejemplos.SENALES.epss)
    bd.guardar_inventario(c, ejemplos.FILAS)
    correr(c, ejemplos.ACTIVOS, ejemplos.COBERTURA, umbrales=Umbrales(), ahora=datetime.now(UTC))
    c.close()

    c = cuentas.conectar()
    for usuario, rol in (("ana", "analista"), ("luis", "lector"), ("jefa", "admin")):
        cuentas.crear_usuario(c, usuario, usuario.title(), rol, CLAVE)
    c.close()
    print(f"Base de pruebas lista en {ruta}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
