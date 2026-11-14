"""Aviso a quien usa el equipo: qué tiene que actualizar y si debe reiniciar.

Dos mitades, porque corren con cuentas distintas:

1. `actualizar(estado)`: la llama `enviar` (SYSTEM o root) después de cada reporte. Pide
   `GET /api/agente/aviso` con la credencial del equipo y deja un resumen en
   `<datos>/aviso/aviso.json`, legible por cualquier usuario del equipo y escribible solo
   por administradores. Ese archivo no lleva la credencial.
2. `avisar(...)`: la corre la tarea de cada usuario (al entrar y cada dos horas). Lee ese
   archivo y, si hay algo para hoy o esta semana, o un reinicio pendiente, muestra una
   notificación del sistema con un botón que abre `/mi-equipo/` en el navegador.

La respuesta del servidor es texto no confiable: solo se copian campos conocidos, con tipo
y largo acotados, y el enlace se arma aquí con la URL guardada al inscribir y un token que
tiene que calzar con un patrón estricto. El servidor no puede hacer que el aviso abra otra
página ni ejecute nada. Solo librería estándar.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import subprocess
import time
import urllib.error
import urllib.request
import webbrowser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agente_local import VERSION
from agente_local.envio import (
    CABECERA_CREDENCIAL,
    TAMANO_MAXIMO_RESPUESTA,
    TIEMPO,
    ErrorEnvio,
    Estado,
    _SinRedireccion,
    carpeta_por_defecto,
    validar_url,
)

RUTA_AVISO = "/api/agente/aviso"
RUTA_PAGINA = "/mi-equipo/"
CARPETA_PUBLICA = "aviso"
ARCHIVO_AVISO = "aviso.json"
ARCHIVO_MEMORIA = "aviso-visto.json"
REPETIR_CADA = 8 * 3600  # segundos entre dos avisos iguales
_TOKEN = re.compile(
    r"^eq1\.[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\.\d{10}\.[A-Za-z0-9_-]{43}$"
)
_BANDAS = {"critico", "alto", "medio", "bajo"}
_ES_WINDOWS = platform.system() == "Windows"


# ---------------------------------------------------------------------------
# Lado del servicio (SYSTEM o root)
# ---------------------------------------------------------------------------


def pedir(estado: Estado, abrir: Any = None) -> dict[str, Any]:
    """`GET /api/agente/aviso` con la credencial. Devuelve el JSON crudo del servidor."""
    if not estado.inscrito:
        raise ErrorEnvio("El equipo no está inscrito.")
    peticion = urllib.request.Request(
        validar_url(estado.url) + RUTA_AVISO,
        method="GET",
        headers={
            "User-Agent": f"radar-agente/{VERSION}",
            CABECERA_CREDENCIAL: estado.credencial,
        },
    )
    abrir = abrir or urllib.request.build_opener(_SinRedireccion).open
    try:
        with abrir(peticion, timeout=TIEMPO) as respuesta:
            contenido = respuesta.read(TAMANO_MAXIMO_RESPUESTA)
    except urllib.error.HTTPError as error:
        raise ErrorEnvio(
            f"El radar respondió {error.code} al pedir el aviso.", error.code
        ) from error
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        raise ErrorEnvio(f"Sin conexión con el radar: {error}") from error
    try:
        datos = json.loads(contenido)
    except ValueError as error:
        raise ErrorEnvio("El radar devolvió un aviso ilegible.") from error
    if not isinstance(datos, dict):
        raise ErrorEnvio("El radar devolvió un aviso ilegible.")
    return datos


def _entero(valor: Any, tope: int = 10_000) -> int:
    if isinstance(valor, bool) or not isinstance(valor, int):
        return 0
    return min(max(valor, 0), tope)


def _texto(valor: Any, largo: int) -> str | None:
    if not isinstance(valor, str):
        return None
    limpio = "".join(c for c in valor if c.isprintable()).strip()
    return limpio[:largo] or None


def _fecha(valor: Any) -> str | None:
    texto = _texto(valor, 40)
    if texto is None:
        return None
    try:
        # Python 3.10 (mínimo del agente) no acepta "Z" en fromisoformat.
        return datetime.fromisoformat(texto.replace("Z", "+00:00")).isoformat()  # noqa: FURB162
    except ValueError:
        return None


def depurar(crudo: dict[str, Any], base: str) -> dict[str, Any]:
    """Solo los campos conocidos, con tipo y largo acotados, y el enlace armado aquí."""
    token = crudo.get("enlace")
    if not isinstance(token, str) or not _TOKEN.match(token):
        raise ErrorEnvio("El radar devolvió un enlace con forma desconocida.")
    acciones = crudo.get("acciones") if isinstance(crudo.get("acciones"), dict) else {}
    banda = crudo.get("banda")
    return {
        "version": 1,
        "equipo": _texto(crudo.get("equipo"), 80) or "este equipo",
        "medido": crudo.get("medido") is True,
        "nivel": _entero(crudo.get("nivel"), 100) if crudo.get("nivel") is not None else None,
        "banda": banda if banda in _BANDAS else None,
        "acciones": {p: _entero(acciones.get(p)) for p in ("inmediato", "semanal", "informativo")},
        "explotadas": _entero(crudo.get("explotadas")),
        "reinicio_pendiente": crudo.get("reinicio_pendiente") is True,
        "reinicio_desde": _fecha(crudo.get("reinicio_desde")),
        "parcheo_en_curso": crudo.get("parcheo_en_curso") is True,
        "enlace": f"{validar_url(base)}{RUTA_PAGINA}#t={token}",
        "vence": _fecha(crudo.get("vence")),
        "recibido": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def carpeta_publica(carpeta: Path) -> Path:
    return carpeta / CARPETA_PUBLICA


def _lectura_para_todos(ruta: Path, es_carpeta: bool) -> None:
    """Administradores y SYSTEM (o root) escriben; los demás usuarios solo leen."""
    if _ES_WINDOWS:
        herencia = "(OI)(CI)" if es_carpeta else ""
        try:
            subprocess.run(
                [
                    "icacls",
                    str(ruta),
                    "/inheritance:r",
                    "/grant:r",
                    f"*S-1-5-18:{herencia}F",
                    f"*S-1-5-32-544:{herencia}F",
                    f"*S-1-5-32-545:{herencia}RX",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        ruta.chmod(0o755 if es_carpeta else 0o644)
    except OSError:
        pass


def guardar(carpeta: Path, aviso: dict[str, Any]) -> Path:
    """Escribe el aviso de forma atómica en la carpeta pública y devuelve su ruta."""
    destino = carpeta_publica(carpeta)
    destino.mkdir(parents=True, exist_ok=True)
    _lectura_para_todos(destino, es_carpeta=True)
    ruta = destino / ARCHIVO_AVISO
    temporal = destino / f".{ARCHIVO_AVISO}.tmp"
    temporal.write_text(json.dumps(aviso, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporal, ruta)
    _lectura_para_todos(ruta, es_carpeta=False)
    return ruta


def actualizar(estado: Estado, abrir: Any = None) -> dict[str, Any]:
    """Pide el aviso al radar y lo deja listo para la tarea de cada usuario."""
    aviso = depurar(pedir(estado, abrir), estado.url)
    guardar(estado.carpeta, aviso)
    return aviso


# ---------------------------------------------------------------------------
# Lado de la persona
# ---------------------------------------------------------------------------


def _archivo_confiable(ruta: Path) -> bool:
    """En Linux, el aviso tiene que ser de root (o de quien corre) y no escribible por otros.
    En Windows lo garantiza la ACL que pone el servicio."""
    if _ES_WINDOWS:
        return True
    try:
        datos = ruta.stat()
    except OSError:
        return False
    return datos.st_uid in (0, os.getuid()) and not datos.st_mode & 0o022


def leer(carpeta: Path | None = None) -> dict[str, Any] | None:
    """El aviso guardado por el servicio, o None si no hay o no es de fiar."""
    ruta = carpeta_publica(carpeta or carpeta_por_defecto()) / ARCHIVO_AVISO
    if not ruta.is_file() or not _archivo_confiable(ruta):
        return None
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(datos, dict) or datos.get("version") != 1:
        return None
    enlace = datos.get("enlace")
    if not isinstance(enlace, str) or "#t=" not in enlace:
        return None
    base, _, token = enlace.partition(RUTA_PAGINA + "#t=")
    try:
        if not _TOKEN.match(token) or validar_url(base) != base:
            return None
    except ErrorEnvio:
        return None
    return datos


def ultimo_arranque() -> float | None:
    """Momento (segundos desde 1970) del último arranque del equipo, o None."""
    try:
        if _ES_WINDOWS:
            import ctypes

            ticks = ctypes.windll.kernel32.GetTickCount64  # type: ignore[attr-defined]
            ticks.restype = ctypes.c_ulonglong
            return time.time() - ticks() / 1000
        segundos = float(Path("/proc/uptime").read_text().split()[0])
        return time.time() - segundos
    except (OSError, ValueError, AttributeError, IndexError):
        return None


def reinicio_pendiente(aviso: dict[str, Any], arranque: float | None) -> bool:
    """Hay que reiniciar si el parcheo lo pidió y el equipo no arrancó después."""
    if not aviso.get("reinicio_pendiente"):
        return False
    desde = aviso.get("reinicio_desde")
    if not desde or arranque is None:
        return True
    try:
        momento = datetime.fromisoformat(desde).timestamp()
    except ValueError:
        return True
    return arranque < momento


def mensaje(aviso: dict[str, Any], arranque: float | None) -> tuple[str, str] | None:
    """Título y cuerpo de la notificación, o None si no hay nada que pedirle a la persona."""
    acciones = aviso.get("acciones") or {}
    hoy = acciones.get("inmediato", 0)
    semana = acciones.get("semanal", 0)
    reiniciar = reinicio_pendiente(aviso, arranque)
    if not (hoy or semana or reiniciar):
        return None
    partes = []
    if hoy:
        partes.append(f"{hoy} {'actualización' if hoy == 1 else 'actualizaciones'} para hoy")
    if semana:
        partes.append(f"{semana} para esta semana")
    cuerpo = ", ".join(partes)
    if cuerpo:
        cuerpo = cuerpo[0].upper() + cuerpo[1:] + "."
    if aviso.get("explotadas"):
        cuerpo += " Hay fallas que ya se están usando en ataques reales."
    if reiniciar:
        cuerpo = (cuerpo + " " if cuerpo else "") + "Reinicia el equipo para terminar de instalar."
    titulo = "Tu equipo necesita atención" if hoy or reiniciar else "Tu equipo tiene pendientes"
    return titulo, cuerpo.strip()


def carpeta_memoria() -> Path:
    if _ES_WINDOWS and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "RadarAgente"
    return Path.home() / ".radar-agente"


def _huella(titulo: str, cuerpo: str) -> str:
    return hashlib.sha256(f"{titulo}\n{cuerpo}".encode()).hexdigest()[:16]


def toca_avisar(huella: str, memoria: dict[str, Any], ahora: float) -> bool:
    """Un aviso distinto se muestra enseguida; el mismo, cada `REPETIR_CADA` segundos."""
    if memoria.get("huella") != huella:
        return True
    ultimo = memoria.get("momento")
    return not isinstance(ultimo, (int, float)) or ahora - ultimo >= REPETIR_CADA


def _leer_memoria(ruta: Path) -> dict[str, Any]:
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        return datos if isinstance(datos, dict) else {}
    except (OSError, ValueError):
        return {}


# -- notificación del sistema -------------------------------------------------

_TOAST = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$t = [Security.SecurityElement]::Escape($env:RADAR_AVISO_TITULO)
$c = [Security.SecurityElement]::Escape($env:RADAR_AVISO_CUERPO)
$u = [Security.SecurityElement]::Escape($env:RADAR_AVISO_ENLACE)
$xml = "<toast activationType='protocol' launch='$u' scenario='reminder'><visual><binding template='ToastGeneric'><text>$t</text><text>$c</text><text placement='attribution'>Radar de vulnerabilidades</text></binding></visual><actions><action content='Ver qué hacer' activationType='protocol' arguments='$u'/><action content='Más tarde' activationType='system' arguments='dismiss'/></actions></toast>"
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show(
    [Windows.UI.Notifications.ToastNotification]::new($doc))
"""


def _notificar_windows(titulo: str, cuerpo: str, enlace: str) -> bool:
    # Los textos van por variables de entorno y se escapan dentro de PowerShell: nunca se
    # pegan en el guion.
    codificado = base64.b64encode(_TOAST.encode("utf-16-le")).decode()
    entorno = {
        **os.environ,
        "RADAR_AVISO_TITULO": titulo,
        "RADAR_AVISO_CUERPO": cuerpo,
        "RADAR_AVISO_ENLACE": enlace,
    }
    try:
        r = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-EncodedCommand",
                codificado,
            ],
            env=entorno,
            capture_output=True,
            timeout=60,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def _notificar_linux(titulo: str, cuerpo: str, enlace: str) -> bool:
    base = ["notify-send", "--app-name=Radar", "--urgency=critical", "--icon=security-high"]
    try:
        # Con botón (libnotify 0.7.9 o superior): espera la respuesta y abre la página.
        r = subprocess.run(
            [*base, "--wait", "--action=abrir=Ver qué hacer", titulo, cuerpo],
            capture_output=True,
            timeout=600,
            check=False,
        )
        if r.returncode == 0:
            if r.stdout.decode(errors="replace").strip() == "abrir":
                abrir_pagina(enlace)
            return True
        r = subprocess.run([*base, titulo, cuerpo], capture_output=True, timeout=30, check=False)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        return True  # se mostró y nadie la tocó
    except (OSError, subprocess.SubprocessError):
        return False


def notificar(titulo: str, cuerpo: str, enlace: str) -> bool:
    if _ES_WINDOWS:
        return _notificar_windows(titulo, cuerpo, enlace)
    return _notificar_linux(titulo, cuerpo, enlace)


def abrir_pagina(enlace: str) -> bool:
    try:
        return webbrowser.open(enlace, new=2)
    except webbrowser.Error:
        return False


def avisar(
    carpeta: Path | None = None,
    forzar: bool = False,
    ahora: float | None = None,
    mostrar: Any = notificar,
) -> str:
    """Lo que corre la tarea de cada usuario. Devuelve qué pasó, en una línea."""
    aviso = leer(carpeta)
    if aviso is None:
        return "Todavía no hay aviso del radar para este equipo."
    texto = mensaje(aviso, ultimo_arranque())
    if texto is None:
        return "Sin pendientes urgentes en este equipo."
    titulo, cuerpo = texto
    ahora = ahora if ahora is not None else time.time()
    ruta_memoria = carpeta_memoria() / ARCHIVO_MEMORIA
    memoria = _leer_memoria(ruta_memoria)
    huella = _huella(titulo, cuerpo)
    if not forzar and not toca_avisar(huella, memoria, ahora):
        return "Aviso ya mostrado hace poco."
    if not mostrar(titulo, cuerpo, aviso["enlace"]):
        return f"No se pudo mostrar la notificación: {titulo}. {cuerpo}"
    try:
        ruta_memoria.parent.mkdir(parents=True, exist_ok=True)
        ruta_memoria.write_text(json.dumps({"huella": huella, "momento": ahora}), encoding="utf-8")
    except OSError:
        pass
    return f"Aviso mostrado: {titulo}. {cuerpo}"
