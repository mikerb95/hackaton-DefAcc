"""Paquetes .zip del agente local que el panel ofrece en "Agregar equipo".

Se arman desde `agente_local/` con un orden y fechas fijos, así el mismo código da el mismo
zip byte a byte (la prueba `tests/test_cuentas.py` lo compara con lo publicado). Solo entra
una lista cerrada de archivos: nunca `.env`, tokens, `resources/` ni `__pycache__`.

    uv run python -m radar.api.paquetes      # reescribe public/descargas/*.zip
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
AGENTE = RAIZ / "agente_local"
DESTINO = RAIZ / "public" / "descargas"
FECHA_FIJA = (2026, 11, 14, 0, 0, 0)

COMUNES = ("__init__.py", "__main__.py", "comun.py", "envio.py", "reporte.py")
POR_SISTEMA = {
    "windows": {
        "modulos": ("windows.py",),
        "instalacion": ("instalar.ps1", "desinstalar.ps1", "seguridad.ps1", "ejecutar.py"),
    },
    "linux": {
        "modulos": ("linux.py",),
        "instalacion": (
            "instalar.sh", "ejecutar.py", "radar-agente.service", "radar-agente.timer",
        ),
    },
}

LEEME = {
    "windows": """Agente local del radar para Windows

Requisitos: Python 3.10 o superior y una consola de PowerShell como administrador.

1. Descomprime este archivo.
2. En la carpeta descomprimida, corre el comando que muestra el panel en "Agregar equipo":

   powershell -ExecutionPolicy Bypass -File .\\agente_local\\instalacion\\instalar.ps1 -Url <url del radar> -Token <token>

Qué hace: copia el agente a Program Files, canjea el token por la credencial del equipo y
registra una tarea programada. No abre puertos ni recibe órdenes del servidor.
Para quitarlo: agente_local\\instalacion\\desinstalar.ps1 y "Retirar" en el panel.
""",
    "linux": """Agente local del radar para Linux

Requisitos: python3 y systemd. Se instala como root.

1. Descomprime este archivo.
2. En la carpeta descomprimida, corre el comando que muestra el panel en "Agregar equipo":

   sudo RADAR_AGENTE_TOKEN=<token> sh agente_local/instalacion/instalar.sh <url del radar>

Qué hace: copia el agente a /opt/radar-agente, canjea el token por la credencial del equipo
y activa un temporizador de systemd. No abre puertos ni recibe órdenes del servidor.
""",
}


def archivos(sistema: str) -> list[tuple[str, Path]]:
    """(ruta dentro del zip, archivo de origen), en orden fijo."""
    partes = POR_SISTEMA[sistema]
    lista = [(f"agente_local/{n}", AGENTE / n) for n in (*COMUNES, *partes["modulos"])]
    lista += [
        (f"agente_local/instalacion/{n}", AGENTE / "instalacion" / n)
        for n in partes["instalacion"]
    ]
    return sorted(lista)


def armar(sistema: str) -> bytes:
    salida = io.BytesIO()
    with zipfile.ZipFile(salida, "w", zipfile.ZIP_DEFLATED) as zip_:
        entradas = [("LEEME.txt", LEEME[sistema].encode())]
        entradas += [(nombre, origen.read_bytes()) for nombre, origen in archivos(sistema)]
        for nombre, contenido in entradas:
            info = zipfile.ZipInfo(nombre, FECHA_FIJA)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zip_.writestr(info, contenido)
    return salida.getvalue()


def nombre_zip(sistema: str) -> str:
    return f"radar-agente-{sistema}.zip"


def main() -> int:
    DESTINO.mkdir(parents=True, exist_ok=True)
    for sistema in POR_SISTEMA:
        ruta = DESTINO / nombre_zip(sistema)
        ruta.write_bytes(armar(sistema))
        print(f"{ruta.relative_to(RAIZ)}: {ruta.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
