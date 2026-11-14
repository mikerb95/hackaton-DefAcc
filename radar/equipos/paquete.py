"""Paquete de instalación del agente local que se descarga desde el panel.

Es un .zip con el código del agente, los instaladores de Windows (`instalar.cmd`, doble
clic) y Linux (`instalar.sh`) y un `configuracion.txt` con la URL del radar. Así quien
instala no escribe comandos ni direcciones: descomprime y le da doble clic.

Los archivos se copian tal cual están en el repositorio: los `.cmd` necesitan CRLF, los
`.ps1` llevan BOM para que Windows PowerShell 5.1 lea bien las tildes, y el `.sh` va con LF
y permiso de ejecución.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

RAIZ_AGENTE = Path(__file__).resolve().parents[2] / "agente_local"
INSTALACION = RAIZ_AGENTE / "instalacion"
CARPETA = "radar-agente"
NOMBRE_ARCHIVO = "radar-agente.zip"

LEEME = """Agente local del radar de vulnerabilidades
==========================================

Windows: doble clic en instalar.cmd. Pide permiso de administrador, instala el agente y al
final muestra un código de activación (también queda copiado en el portapapeles).

Linux: sudo sh instalar.sh

Después escribe el código en el panel del radar, sección "Equipos con agente", botón
"Activar". Hasta entonces el equipo reporta pero su inventario no se cruza.

El agente solo recoge el inventario y lo envía al radar. No abre puertos ni recibe órdenes.
Para quitarlo: doble clic en desinstalar.cmd (Windows).
"""


def configuracion(url: str, token: str | None = None) -> str:
    lineas = ["# Lo armó el panel del radar al descargar este paquete.", f"url={url}"]
    if token:
        lineas.append(f"token={token}")
    return "\r\n".join(lineas) + "\r\n"


def armar(url: str, token: str | None = None) -> bytes:
    """El .zip listo para descargar, con la URL (y el token, si el radar lo exige)."""
    memoria = io.BytesIO()
    with zipfile.ZipFile(memoria, "w", zipfile.ZIP_DEFLATED) as zipeado:

        def agregar(nombre: str, datos: bytes, ejecutable: bool = False) -> None:
            info = zipfile.ZipInfo(f"{CARPETA}/{nombre}", date_time=(2026, 11, 14, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if ejecutable else 0o644) << 16
            zipeado.writestr(info, datos)

        for archivo in sorted(RAIZ_AGENTE.glob("*.py")):
            agregar(f"agente_local/{archivo.name}", archivo.read_bytes())
        for archivo in sorted(INSTALACION.iterdir()):
            if archivo.is_file():
                agregar(archivo.name, archivo.read_bytes(), archivo.suffix == ".sh")
        agregar("configuracion.txt", configuracion(url, token).encode("utf-8"))
        agregar("LEEME.txt", LEEME.replace("\n", "\r\n").encode("utf-8"))
    return memoria.getvalue()
