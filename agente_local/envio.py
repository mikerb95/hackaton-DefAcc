"""Inscripción, credencial y envío del reporte (docs/plan-agente-local.md, sección 6).

- Solo conexiones salientes por HTTPS. HTTP se acepta únicamente contra la propia máquina
  (pruebas en local).
- Al inscribirse, el agente genera su credencial y un código de activación. El código se
  muestra en pantalla y TI lo escribe en el panel para activar el equipo. El token de la
  organización es opcional y no se guarda.
- De la respuesta del servidor solo se lee el intervalo deseado. No hay canal de órdenes:
  cualquier otro campo se ignora.
- Sin red, el reporte queda guardado y se reintenta en la próxima corrida.
"""

from __future__ import annotations

import json
import os
import platform
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from agente_local import VERSION

RUTA_INSCRIBIR = "/api/agente/inscribir"
RUTA_REPORTE = "/api/agente/reporte"
RUTA_INVENTARIO = "/api/inventario"
CABECERA_CREDENCIAL = "X-Credencial-Equipo"
CABECERA_CLAVE = "X-Clave-Acceso"
TIEMPO = 60
TAMANO_MAXIMO_RESPUESTA = 64 * 1024
INTERVALO_MINIMO, INTERVALO_MAXIMO = 1, 168  # horas
ANFITRIONES_LOCALES = {"localhost", "127.0.0.1", "::1"}

ARCHIVO_ESTADO = "estado.json"
ARCHIVO_PENDIENTE = "pendiente.json"


class ErrorEnvio(RuntimeError):
    """El envío no se pudo hacer. El mensaje es apto para mostrar."""

    def __init__(self, mensaje: str, codigo: int | None = None):
        super().__init__(mensaje)
        self.codigo = codigo


# ---------------------------------------------------------------------------
# Carpeta y estado
# ---------------------------------------------------------------------------


def carpeta_por_defecto() -> Path:
    """Carpeta de datos del agente. `RADAR_AGENTE_DATOS` la cambia (pruebas, sin privilegios)."""
    forzada = os.environ.get("RADAR_AGENTE_DATOS")
    if forzada:
        return Path(forzada)
    if platform.system() == "Windows":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RadarAgente"
    return Path("/var/lib/radar-agente")


def _carpeta_usable(carpeta: Path) -> Path:
    """La carpeta pedida, o una en el perfil del usuario si no se puede escribir en ella."""
    try:
        carpeta.mkdir(parents=True, exist_ok=True)
        prueba = carpeta / ".escritura"
        prueba.write_text("", encoding="utf-8")
        prueba.unlink()
        return carpeta
    except OSError:
        propia = Path.home() / ".radar-agente"
        propia.mkdir(parents=True, exist_ok=True)
        return propia


_SID_PROPIO: list[str | None] = []


def _sid_propio() -> str | None:
    """SID de la cuenta que corre el agente en Windows (se consulta una sola vez)."""
    if not _SID_PROPIO:
        sid = None
        try:
            r = subprocess.run(
                ["whoami", "/user", "/fo", "csv", "/nh"],
                capture_output=True,
                timeout=30,
                check=False,
            )
            campos = r.stdout.decode("utf-8", errors="replace").strip().split(",")
            candidato = campos[-1].strip().strip('"')
            if r.returncode == 0 and candidato.startswith("S-1-"):
                sid = candidato
        except (OSError, subprocess.SubprocessError):
            pass
        _SID_PROPIO.append(sid)
    return _SID_PROPIO[0]


def proteger(ruta: Path) -> None:
    """Deja el archivo legible solo por quien corre el agente (SYSTEM o root en producción)."""
    if platform.system() == "Windows":
        # SID fijos para no depender del idioma: SYSTEM y Administradores. Se suma la cuenta
        # que corre el agente: en producción es SYSTEM, pero en una prueba manual es una
        # persona, y sin esto el agente se quitaría el acceso a su propio archivo. Si no se
        # puede saber quién corre, no se tocan los permisos.
        propio = _sid_propio()
        if propio is None:
            return
        try:
            subprocess.run(
                [
                    "icacls",
                    str(ruta),
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:F",
                    "*S-1-5-32-544:F",
                    f"*{propio}:F",
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
        return
    try:
        ruta.chmod(0o600)
    except OSError:
        pass


class Estado:
    """Identidad y credencial del equipo, guardadas en la carpeta del agente."""

    def __init__(self, carpeta: Path | None = None):
        self.carpeta = _carpeta_usable(carpeta or carpeta_por_defecto())
        self.ruta = self.carpeta / ARCHIVO_ESTADO
        self.datos: dict[str, Any] = {}
        if self.ruta.exists():
            try:
                self.datos = json.loads(self.ruta.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self.datos = {}
        if not isinstance(self.datos, dict):
            self.datos = {}

    @property
    def equipo_id(self) -> str:
        """Identificador estable del equipo: se genera una vez y se guarda."""
        if not self.datos.get("equipo_id"):
            self.datos["equipo_id"] = str(uuid.uuid4())
            self.guardar()
        return self.datos["equipo_id"]

    @property
    def credencial(self) -> str | None:
        return self.datos.get("credencial")

    @property
    def url(self) -> str | None:
        return self.datos.get("url")

    @property
    def inscrito(self) -> bool:
        return bool(self.credencial and self.url)

    def guardar(self) -> None:
        self.ruta.write_text(json.dumps(self.datos, indent=2), encoding="utf-8")
        proteger(self.ruta)

    def borrar(self) -> None:
        """Desinstalar borra la credencial y lo pendiente."""
        for nombre in (ARCHIVO_ESTADO, ARCHIVO_PENDIENTE):
            try:
                (self.carpeta / nombre).unlink()
            except OSError:
                pass
        self.datos = {}

    # -- reporte pendiente ---------------------------------------------------

    @property
    def ruta_pendiente(self) -> Path:
        return self.carpeta / ARCHIVO_PENDIENTE

    def guardar_pendiente(self, reporte: dict[str, Any]) -> None:
        self.ruta_pendiente.write_text(json.dumps(reporte), encoding="utf-8")
        proteger(self.ruta_pendiente)

    def quitar_pendiente(self) -> None:
        try:
            self.ruta_pendiente.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------


class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    """Una redirección llevaría la credencial a otro servidor: no se sigue."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def validar_url(url: str) -> str:
    """URL base del radar, sin barra final. Exige HTTPS salvo contra la propia máquina."""
    partes = urllib.parse.urlsplit(url.strip())
    if partes.scheme not in ("https", "http") or not partes.hostname:
        raise ErrorEnvio(f"URL no válida: {url!r}")
    if partes.scheme == "http" and partes.hostname not in ANFITRIONES_LOCALES:
        raise ErrorEnvio("El agente solo envía por HTTPS (HTTP solo contra localhost).")
    if partes.username or partes.password:
        raise ErrorEnvio("La URL no lleva usuario ni contraseña.")
    return urllib.parse.urlunsplit((partes.scheme, partes.netloc, partes.path.rstrip("/"), "", ""))


def _pedir(url: str, cuerpo: bytes, cabeceras: dict[str, str], abrir: Any = None) -> dict[str, Any]:
    peticion = urllib.request.Request(
        url,
        data=cuerpo,
        method="POST",
        headers={"User-Agent": f"radar-agente/{VERSION}", **cabeceras},
    )
    abrir = abrir or urllib.request.build_opener(_SinRedireccion).open
    try:
        with abrir(peticion, timeout=TIEMPO) as respuesta:
            contenido = respuesta.read(TAMANO_MAXIMO_RESPUESTA)
    except urllib.error.HTTPError as error:
        detalle = ""
        try:
            detalle = str(json.loads(error.read(TAMANO_MAXIMO_RESPUESTA)).get("detail", ""))
        except (ValueError, OSError, AttributeError):
            pass
        raise ErrorEnvio(
            f"El radar respondió {error.code}" + (f": {detalle[:200]}" if detalle else ""),
            error.code,
        ) from error
    except (urllib.error.URLError, OSError, TimeoutError) as error:
        raise ErrorEnvio(f"Sin conexión con el radar: {error}") from error
    try:
        datos = json.loads(contenido)
    except ValueError:
        return {}
    return datos if isinstance(datos, dict) else {}


def _json(url: str, datos: dict[str, Any], cabeceras: dict[str, str], abrir: Any) -> dict:
    cuerpo = json.dumps(datos, ensure_ascii=False).encode("utf-8")
    return _pedir(url, cuerpo, {"Content-Type": "application/json", **cabeceras}, abrir)


def intervalo_de(respuesta: dict[str, Any]) -> int | None:
    """Lo único que se lee de la respuesta: cada cuántas horas quiere reportes el radar."""
    valor = respuesta.get("intervalo_horas")
    if isinstance(valor, bool) or not isinstance(valor, int):
        return None
    return min(max(valor, INTERVALO_MINIMO), INTERVALO_MAXIMO)


# Sin letras ni cifras que se confundan al leerlas en voz alta (0/O, 1/I/L).
ALFABETO_CODIGO = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def nuevo_codigo() -> str:
    """Código de activación de 8 caracteres en dos grupos, por ejemplo `K7PQ-4MXR`."""
    letras = "".join(secrets.choice(ALFABETO_CODIGO) for _ in range(8))
    return f"{letras[:4]}-{letras[4:]}"


def inscribir(
    estado: Estado,
    url: str,
    nombre_equipo: str,
    token: str | None = None,
    abrir: Any = None,
) -> str:
    """Inscribe el equipo y devuelve su código de activación.

    El agente genera aquí su propia credencial y el código. La credencial no sale nunca de
    este equipo salvo hacia el radar (que guarda su huella); el código se muestra en
    pantalla para que TI lo escriba en el panel. Así solo se activa un equipo cuyo código
    alguien vio en su pantalla. El token de la organización es opcional: solo hace falta
    si el radar lo exige.
    """
    base = validar_url(url)
    credencial = secrets.token_urlsafe(32)
    codigo = nuevo_codigo()
    cuerpo = {
        "equipo_id": estado.equipo_id,
        "nombre_equipo": nombre_equipo,
        "agente_version": VERSION,
        "credencial": credencial,
        "codigo": codigo,
    }
    if token:
        cuerpo["token"] = token
    _json(base + RUTA_INSCRIBIR, cuerpo, {}, abrir)
    estado.datos.update(credencial=credencial, url=base, codigo=codigo)
    estado.guardar()
    return codigo


def enviar(estado: Estado, reporte: dict[str, Any], abrir: Any = None) -> int | None:
    """Envía el reporte. Si falla por red, lo deja pendiente. Devuelve el intervalo pedido."""
    if not estado.inscrito:
        raise ErrorEnvio("El equipo no está inscrito: corre primero `inscribir`.")
    try:
        respuesta = _json(
            validar_url(estado.url) + RUTA_REPORTE,
            reporte,
            {CABECERA_CREDENCIAL: estado.credencial},
            abrir,
        )
    except ErrorEnvio as error:
        # Un rechazo del servidor (4xx) no se reintenta con el mismo reporte.
        if error.codigo is None or error.codigo >= 500:
            estado.guardar_pendiente(reporte)
        else:
            estado.quitar_pendiente()
        raise
    estado.quitar_pendiente()
    intervalo = intervalo_de(respuesta)
    if intervalo is not None:
        estado.datos["intervalo_horas"] = intervalo
        estado.guardar()
    return intervalo


# ---------------------------------------------------------------------------
# Fase 0: subir el CSV a la ruta que ya existe
# ---------------------------------------------------------------------------


def subir_csv(url: str, clave: str | None, csv_texto: str, abrir: Any = None) -> dict[str, Any]:
    """Sube el inventario como archivo a `POST /api/inventario` (la carga del panel)."""
    frontera = uuid.uuid4().hex
    cuerpo = (
        (
            f"--{frontera}\r\n"
            'Content-Disposition: form-data; name="archivo"; filename="inventario.csv"\r\n'
            "Content-Type: text/csv\r\n\r\n"
        ).encode()
        + csv_texto.encode("utf-8")
        + f"\r\n--{frontera}--\r\n".encode()
    )
    cabeceras = {"Content-Type": f"multipart/form-data; boundary={frontera}"}
    if clave:
        cabeceras[CABECERA_CLAVE] = clave
    return _pedir(validar_url(url) + RUTA_INVENTARIO, cuerpo, cabeceras, abrir)
