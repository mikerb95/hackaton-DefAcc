"""Paquetes .zip del agente local que el panel ofrece en "Agregar equipo".

Se arman desde `agente_local/` con un orden y fechas fijos, así el mismo código da el mismo
zip byte a byte (la prueba `tests/test_cuentas.py` lo compara con lo publicado). Solo entra
una lista cerrada de archivos: nunca `.env`, `resources/` ni `__pycache__`.

Dos formas:
- `armar(sistema)`: el zip genérico de `public/descargas/`. El instalador pregunta la URL.
- `armar(sistema, url, token)`: el que entrega el asistente del panel, con `configuracion.txt`
  (URL del radar y el token recién creado). En Windows basta con doble clic en INSTALAR.cmd.

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

COMUNES = (
    "__init__.py",
    "__main__.py",
    "aviso.py",
    "comun.py",
    "ed25519.py",
    "envio.py",
    "orden_parcheo.py",
    "parcheo.py",
    "plan_parcheo.py",
    "reporte.py",
)
POR_SISTEMA = {
    "windows": {
        "modulos": ("windows.py", "parcheo_windows.py"),
        "instalacion": (
            "instalar.cmd",
            "instalar.ps1",
            "desinstalar.cmd",
            "desinstalar.ps1",
            "seguridad.ps1",
            "ejecutar.py",
        ),
    },
    "linux": {
        "modulos": ("linux.py", "parcheo_linux.py"),
        "instalacion": (
            "instalar.sh",
            "ejecutar.py",
            "radar-agente.service",
            "radar-agente.timer",
            "radar-agente-aviso.service",
            "radar-agente-aviso.timer",
            "radar-agente-parcheo.service",
            "radar-agente-parcheo.timer",
        ),
    },
}

LEEME = {
    "windows": """Agente local del radar para Windows

1. Descomprime este archivo.
2. Dale doble clic a INSTALAR.cmd y acepta el permiso de administrador.
   Si el equipo no tiene Python instalado para todos los usuarios, lo instala con winget.
3. Al terminar aparece una ventana con el código de activación (queda copiado en el
   portapapeles). Escríbelo en el panel del radar, en la ficha del equipo.

Si el paquete no trae configuracion.txt, el instalador pregunta la dirección del radar.

Parcheo aprobado (opcional): si el zip viene del panel con "Permitir parcheo", ya lo trae.
Si no, en una consola de administrador:
   powershell -ExecutionPolicy Bypass -File agente_local\\instalacion\\instalar.ps1 -ClaveAprobacion <clave-base64>
El agente solo aplica planes firmados con esa clave, revierte si algo falla y nunca reinicia.

El agente no abre puertos ni acepta comandos del servidor.
Para quitarlo: doble clic en agente_local\\instalacion\\desinstalar.cmd y "Retirar" en el panel.
""",
    "linux": """Agente local del radar para Linux

Requisitos: python3 y systemd. Se instala como root.

1. Descomprime este archivo.
2. En la carpeta descomprimida: sudo sh agente_local/instalacion/instalar.sh
   (lee la dirección del radar de configuracion.txt; si no está, pásala como argumento).
3. Escribe en el panel del radar el código de activación que muestra al terminar.

Parcheo aprobado (opcional): si el zip viene del panel con "Permitir parcheo", ya lo trae.
Si no, pasa la clave pública del aprobador al instalar:
   sudo RADAR_CLAVE_APROBACION=<clave-base64> sh agente_local/instalacion/instalar.sh
El agente solo aplica planes firmados con esa clave, revierte si algo falla y nunca reinicia.

Qué hace: copia el agente a /opt/radar-agente, inscribe el equipo y activa un temporizador
de systemd. No abre puertos ni acepta comandos del servidor.
""",
}

# Lanzador en la raíz del zip: el doble clic no tiene que buscar dentro de carpetas.
LANZADOR_WINDOWS = (
    "@echo off\r\n"
    "rem Instalador del agente local del radar. Uso: doble clic.\r\n"
    'call "%~dp0agente_local\\instalacion\\instalar.cmd"\r\n'
)


def configuracion(url: str, token: str | None = None, clave: str | None = None) -> str:
    """Lo que el instalador lee para no pedir nada: la URL del radar, el token si hay y, si se
    habilita el parcheo, la clave pública del aprobador (docs/plan-parcheo.md)."""
    lineas = ["# Lo armó el panel del radar al descargar este paquete.", f"url={url}"]
    if token:
        lineas.append(f"token={token}")
    if clave:
        lineas.append(f"clave_aprobacion={clave}")
    return "\r\n".join(lineas) + "\r\n"


def archivos(sistema: str) -> list[tuple[str, Path]]:
    """(ruta dentro del zip, archivo de origen), en orden fijo."""
    partes = POR_SISTEMA[sistema]
    lista = [(f"agente_local/{n}", AGENTE / n) for n in (*COMUNES, *partes["modulos"])]
    lista += [
        (f"agente_local/instalacion/{n}", AGENTE / "instalacion" / n) for n in partes["instalacion"]
    ]
    return sorted(lista)


def armar(
    sistema: str, url: str | None = None, token: str | None = None, clave: str | None = None
) -> bytes:
    """El zip del sistema. Con `url`, lleva además `configuracion.txt` para no preguntar nada.

    Los archivos van tal cual están: los `.cmd` en CRLF, los `.ps1` con BOM (tildes en
    Windows PowerShell 5.1) y el `.sh` con LF y permiso de ejecución.
    """
    salida = io.BytesIO()
    with zipfile.ZipFile(salida, "w", zipfile.ZIP_DEFLATED) as zip_:
        entradas = [("LEEME.txt", LEEME[sistema].replace("\n", "\r\n").encode())]
        if sistema == "windows":
            entradas.append(("INSTALAR.cmd", LANZADOR_WINDOWS.encode()))
        if url:
            entradas.append(("configuracion.txt", configuracion(url, token, clave).encode()))
        entradas += [(nombre, origen.read_bytes()) for nombre, origen in archivos(sistema)]
        for nombre, contenido in entradas:
            info = zipfile.ZipInfo(nombre, FECHA_FIJA)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if nombre.endswith(".sh") else 0o644) << 16
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
