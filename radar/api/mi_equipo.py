"""Lo que ve la persona que usa un equipo: qué tiene que actualizar y si debe reiniciar.

El panel es para TI. Quien usa el PC no tiene cuenta en el radar y no debería necesitarla
para saber que su equipo está expuesto. Por eso hay dos rutas, sin sesión:

- `GET /api/agente/aviso`: la llama el agente local con la credencial del equipo, después de
  cada reporte. Devuelve un resumen corto (cuántas acciones hay por urgencia, si quedó un
  reinicio pendiente) y un enlace firmado. El agente lo deja en un archivo que puede leer
  la persona y lo muestra como notificación del sistema.
- `GET /api/mi-equipo`: la llama la página `/mi-equipo/` con ese enlace en la cabecera
  `X-Enlace-Equipo`. Devuelve, en lenguaje simple, qué hacer en ese equipo y nada más.

El enlace es `eq1.<equipo_id>.<vence>.<firma>`: HMAC-SHA256 con un secreto del servidor
(`RADAR_SECRETO_ENLACES`, o uno derivado de `CLAVE_ACCESO`), vigente siete días. No da
acceso a nada más que la vista de ese equipo, se renueva con cada reporte y deja de servir
si el equipo se revoca o se retira. La página lo lee del fragmento (`#t=...`), que el
navegador no manda al servidor, para que no quede en los registros de acceso.

Todo sale de `radar/equipos/vista.py` y del historial de parcheo: no participa ningún modelo.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Header, HTTPException, status

from radar.api.agente import CABECERA_CREDENCIAL, _conexion, _exigir_base
from radar.api.termometro import termometro

CABECERA_ENLACE = "X-Enlace-Equipo"
PREFIJO = "eq1"
VIGENCIA = 7 * 24 * 3600  # segundos
RUTA_PAGINA = "/mi-equipo/"
_ENLACE = re.compile(
    r"^eq1\.([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})\.(\d{10})\.([A-Za-z0-9_-]{43})$"
)
_SECRETO_LOCAL = secrets.token_bytes(32)

router_aviso = APIRouter(prefix="/api/agente")
router_mi_equipo = APIRouter(prefix="/api")

# Prioridad del radar -> cuándo hacerlo, dicho para quien no es de TI.
CUANDO = {"inmediato": "hoy", "semanal": "esta_semana", "informativo": "cuando_puedas"}


# ---------------------------------------------------------------------------
# Enlace firmado
# ---------------------------------------------------------------------------


def _secreto() -> bytes:
    propio = os.environ.get("RADAR_SECRETO_ENLACES", "")
    if propio:
        return propio.encode()
    clave = os.environ.get("CLAVE_ACCESO", "")
    if clave:
        # Derivado y con etiqueta propia: el enlace nunca deja ver la clave ni sirve como ella.
        return hmac.new(clave.encode(), b"radar:enlace-equipo:v1", hashlib.sha256).digest()
    if os.environ.get("VERCEL"):
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "El radar no tiene secreto para los enlaces."
        )
    # En local sin clave: un secreto por proceso. Los enlaces caducan al reiniciar.
    return _SECRETO_LOCAL


def _firma(cuerpo: str) -> str:
    digesto = hmac.new(_secreto(), cuerpo.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digesto).rstrip(b"=").decode()


def firmar_enlace(equipo_id: str, ahora: float | None = None) -> tuple[str, int]:
    """Enlace de la vista del equipo y su vencimiento (segundos desde 1970)."""
    vence = int((ahora if ahora is not None else time.time()) + VIGENCIA)
    cuerpo = f"{PREFIJO}.{equipo_id.lower()}.{vence}"
    return f"{cuerpo}.{_firma(cuerpo)}", vence


def verificar_enlace(enlace: str | None, ahora: float | None = None) -> str | None:
    """El equipo del enlace, o None si está mal formado, mal firmado o vencido."""
    coincide = _ENLACE.match((enlace or "").strip())
    if not coincide:
        return None
    equipo_id, vence, firma = coincide.groups()
    if not hmac.compare_digest(firma, _firma(f"{PREFIJO}.{equipo_id}.{vence}")):
        return None
    if int(vence) < (ahora if ahora is not None else time.time()):
        return None
    return equipo_id


def _iso(segundos: float) -> str:
    return datetime.fromtimestamp(segundos, UTC).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Parcheo: reinicio pendiente y plan en curso
# ---------------------------------------------------------------------------


def _parcheo(conexion: Any, equipo_id: str) -> dict[str, Any]:
    """Lo que la persona debe saber del parcheo. Si las tablas no existen, nada."""
    try:
        from radar.equipos import parcheo_almacen, parcheo_reporte

        planes = parcheo_almacen.planes_de_equipo(conexion, equipo_id, limite=10)
        en_curso = parcheo_almacen.plan_activo(conexion, equipo_id)
    except Exception:  # noqa: BLE001 - el parcheo es opcional; su falla no tapa la vista
        return {"en_curso": False, "reinicio_pendiente": False, "reinicio_desde": None}
    ultimo = next((p for p in planes if p.get("recibido")), None)
    resumen = parcheo_reporte.resumen_plan(ultimo) if ultimo else None
    reinicio = bool(resumen and resumen["reinicio_pendiente"])
    return {
        "en_curso": bool(en_curso),
        "reinicio_pendiente": reinicio,
        # El agente compara esta fecha con el último arranque del PC: si arrancó después,
        # el reinicio ya se hizo y no vuelve a avisar.
        "reinicio_desde": resumen["recibido"] if reinicio else None,
        "ultimo": (
            {
                "estado": resumen["estado_general"],
                "recibido": resumen["recibido"],
                "conteo": resumen["conteo"],
            }
            if resumen
            else None
        ),
    }


# ---------------------------------------------------------------------------
# Vista simple
# ---------------------------------------------------------------------------


def _so_legible(so: dict[str, Any] | None) -> str | None:
    if not so:
        return None
    partes = [so.get("nombre"), so.get("version")]
    return " ".join(str(p) for p in partes if p) or None


def _tarea_producto(p: dict[str, Any]) -> dict[str, Any]:
    versiones = p.get("versiones") or []
    detalle = (
        f"Tienes la versión {', '.join(versiones)}." if versiones else "Tu versión tiene fallas."
    )
    return {
        "tipo": "actualizar",
        "titulo": f"Actualiza {p['producto']}",
        "cuando": CUANDO.get(p.get("prioridad") or "", "cuando_puedas"),
        "prioridad": p.get("prioridad"),
        "detalle": detalle,
        "explotada": bool(p.get("en_kev")),
        "ransomware": bool(p.get("ransomware")),
        "n_fallas": p.get("n_cves") or 0,
        "por_que": p.get("por_que") or [],
        "pasos": p.get("pasos") or "",
        "comandos": p.get("comandos") or [],
    }


def _tarea_equipo(h: dict[str, Any]) -> dict[str, Any]:
    return {
        "tipo": h.get("tipo") or "postura",
        "titulo": h.get("titulo") or "Ajuste de seguridad",
        "cuando": CUANDO.get(h.get("prioridad") or "", "cuando_puedas"),
        "prioridad": h.get("prioridad"),
        "detalle": None,
        "explotada": False,
        "ransomware": False,
        "n_fallas": 0,
        "por_que": h.get("por_que") or [],
        "pasos": h.get("pasos") or "",
        "comandos": h.get("comandos") or [],
    }


_ORDEN_CUANDO = {"hoy": 0, "esta_semana": 1, "cuando_puedas": 2}


def vista_simple(conexion: Any, equipo_id: str) -> dict[str, Any] | None:
    """Vista del equipo para quien lo usa, o None si no existe."""
    from radar.equipos import vista

    datos = vista.detalle(conexion, equipo_id)
    if datos is None:
        return None
    equipo = datos["equipo"]
    tareas = [_tarea_producto(p) for p in datos["productos"]]
    tareas += [_tarea_equipo(h) for h in datos["hallazgos_equipo"]]
    tareas.sort(key=lambda t: (_ORDEN_CUANDO[t["cuando"]], not t["explotada"], t["titulo"]))
    return {
        "equipo": {
            "nombre": equipo["nombre"],
            "so": _so_legible(equipo.get("so")),
            "ultimo_reporte": equipo.get("ultimo_reporte"),
            "pendiente": bool(equipo.get("pendiente")),
            "revocado": bool(equipo.get("revocado")),
        },
        "termometro": termometro(equipo),
        "tareas": tareas,
        "parcheo": _parcheo(conexion, equipo_id),
        "sin_revisar": datos["sin_revisar"],
    }


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------


@router_aviso.get("/aviso")
def aviso_del_agente(x_credencial_equipo: str | None = Header(default=None)) -> dict:
    """Resumen para la notificación del equipo y el enlace firmado a su vista."""
    from radar.api.parcheo import _equipo_autenticado

    _exigir_base()
    conexion = _conexion()
    try:
        equipo = _equipo_autenticado(conexion, x_credencial_equipo)
        datos = vista_simple(conexion, equipo.id)
    finally:
        conexion.close()
    if datos is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Equipo no encontrado.")
    enlace, vence = firmar_enlace(equipo.id)
    t = datos["termometro"]
    return {
        "equipo": datos["equipo"]["nombre"],
        "medido": t["medido"],
        "nivel": t["nivel"],
        "banda": t["banda"],
        "etiqueta": t["etiqueta"],
        "acciones": t["acciones"],
        "explotadas": sum(1 for x in datos["tareas"] if x["explotada"]),
        "reinicio_pendiente": datos["parcheo"]["reinicio_pendiente"],
        "reinicio_desde": datos["parcheo"]["reinicio_desde"],
        "parcheo_en_curso": datos["parcheo"]["en_curso"],
        "ruta": RUTA_PAGINA,
        "enlace": enlace,
        "vence": _iso(vence),
        "generado": _iso(time.time()),
    }


@router_mi_equipo.get("/mi-equipo")
def mi_equipo(x_enlace_equipo: str | None = Header(default=None)) -> dict:
    """La vista del equipo para quien lo usa. Solo con un enlace firmado vigente."""
    equipo_id = verificar_enlace(x_enlace_equipo)
    if equipo_id is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "El enlace no es válido o ya venció. Abre el aviso más reciente del agente.",
        )
    _exigir_base()
    conexion = _conexion()
    try:
        datos = vista_simple(conexion, equipo_id)
    finally:
        conexion.close()
    if datos is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Este equipo ya no está en el radar.")
    if datos["equipo"]["revocado"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Este equipo fue dado de baja en el radar.")
    coincide = _ENLACE.match(x_enlace_equipo.strip())
    datos["vence"] = _iso(int(coincide.group(2))) if coincide else None
    return datos
