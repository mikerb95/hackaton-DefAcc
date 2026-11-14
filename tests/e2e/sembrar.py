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
    sembrar_equipo()
    print(f"Base de pruebas lista en {ruta}")
    return 0


def sembrar_equipo() -> None:
    """Un equipo inscrito y PENDIENTE de aprobación, con su primer reporte guardado. Deja el
    enlace firmado de Mi equipo en ENLACE (lo usa Playwright tras aprobarlo)."""
    import secrets
    import uuid

    from fastapi.testclient import TestClient

    import app
    from agente_local.envio import nuevo_codigo
    from radar.api.agente import CABECERA_CREDENCIAL
    from radar.api.mi_equipo import firmar_enlace

    cliente = TestClient(app.app)
    equipo_id = str(uuid.uuid4())
    credencial = secrets.token_urlsafe(32)
    r = cliente.post(
        "/api/agente/inscribir",
        json={"equipo_id": equipo_id, "nombre_equipo": "PC-CONTA-03", "credencial": credencial, "codigo": nuevo_codigo()},
    )
    r.raise_for_status()
    reporte = {
        "agente_version": "0.1.0",
        "equipo_id": equipo_id,
        "nombre_equipo": "PC-CONTA-03",
        "recogido": "2026-11-14T15:00:00Z",
        "so": {"familia": "windows", "nombre": "Windows 11 Pro", "version": "23H2", "build": "10.0.22631.4317", "arquitectura": "x64"},
        "software": [{"programa": "WinRAR 5.61 (64-bit)", "version": "5.61", "proveedor": "win.rar GmbH", "fuente": "registro", "ambito": "maquina"}],
    }
    r = cliente.post("/api/agente/reporte", json=reporte, headers={CABECERA_CREDENCIAL: credencial})
    r.raise_for_status()
    ENLACE.write_text(firmar_enlace(equipo_id)[0], encoding="utf-8")


ENLACE = Path("/tmp/radar-e2e-enlace.txt")


if __name__ == "__main__":
    sys.exit(main())
