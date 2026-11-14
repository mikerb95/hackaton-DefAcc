"""Rutas del agente local (docs/plan-agente-local.md, sección 6).

Dos grupos, con credenciales distintas:

- `/api/agente/*` lo llaman los equipos. No usa la clave compartida del panel: la
  inscripción pide un token de inscripción creado en el panel (con vencimiento y tope de
  usos, `radar/api/cuentas.py`) o el de la organización (`AGENTE_TOKEN_INSCRIPCION`), y cada reporte
  pide la credencial propia del equipo en `X-Credencial-Equipo`. Robar la credencial de un
  equipo solo sirve para enviar reportes de ese equipo, y se revoca sin tocar a los demás.
- `/api/equipos*` lo llama el panel, con la clave compartida, como el resto de la API.

El servidor nunca devuelve órdenes: la respuesta a un reporte es `202` con el intervalo
deseado y nada más. Tomar el servidor no da ejecución en los PC.
"""

from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from radar.api.acceso import exigir_clave, exigir_rol
from radar.api.datos import obtener_datos
from radar.equipos.contratos import TAMANO_MAXIMO_REPORTE

CABECERA_CREDENCIAL = "X-Credencial-Equipo"
INTERVALO_POR_DEFECTO = 12  # horas

router_agente = APIRouter(prefix="/api/agente")
router_equipos = APIRouter(prefix="/api", dependencies=[Depends(exigir_clave)])


def intervalo_horas() -> int:
    try:
        return min(max(int(os.environ.get("AGENTE_INTERVALO_HORAS", "")), 1), 168)
    except ValueError:
        return INTERVALO_POR_DEFECTO


def _exigir_base() -> None:
    if obtener_datos().origen != "base":
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "El radar no tiene base conectada."
        )


def _conexion(solo_lectura: bool = False):
    from radar import bd

    conexion = bd.conectar(solo_lectura=solo_lectura)
    if not solo_lectura:
        bd.crear_esquema(conexion)
    return conexion


# ---------------------------------------------------------------------------
# Lo que llama el agente
# ---------------------------------------------------------------------------


class Inscripcion(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    equipo_id: str = Field(pattern=r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
    nombre_equipo: str = Field(min_length=1, max_length=2000)
    agente_version: str | None = Field(default=None, max_length=40)


@router_agente.post("/inscribir")
def inscribir(cuerpo: Inscripcion) -> dict:
    """Canjea un token de inscripción por la credencial del equipo.

    Vale un token creado en el panel (vigente, sin revocar y con usos) o el de la
    organización en `AGENTE_TOKEN_INSCRIPCION`. Si la inscripción falla después de gastar un
    uso del token, el uso se devuelve."""
    from radar.api import cuentas
    from radar.equipos import almacen
    from radar.seguridad.equipos import sanear_nombre_equipo
    from radar.seguridad.limpieza import limpiar_texto

    _exigir_base()
    esperado = os.environ.get("AGENTE_TOKEN_INSCRIPCION", "")
    token_id = None
    if cuerpo.token.startswith(cuentas.PREFIJO_TOKEN):
        conexion_tokens = cuentas.conectar()
        try:
            token_id = cuentas.consumir_token(conexion_tokens, cuerpo.token)
        finally:
            conexion_tokens.close()
        if token_id is None:
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED,
                "Token de inscripción no válido, vencido, revocado o sin usos.",
            )
    elif not esperado and not _inscripcion_abierta():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "La inscripción está cerrada: crea un token en el panel o define "
            "AGENTE_TOKEN_INSCRIPCION.",
        )
    elif not esperado or not hmac.compare_digest(cuerpo.token.encode(), esperado.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token de inscripción no válido.")
    conexion = _conexion()
    try:
        credencial = almacen.inscribir(
            conexion,
            cuerpo.equipo_id.lower(),
            sanear_nombre_equipo(cuerpo.nombre_equipo, 0),
            limpiar_texto(cuerpo.agente_version, 40) or None,
        )
    except almacen.EquipoYaInscrito as error:
        if token_id is not None:
            cuentas.devolver_uso(conexion, token_id)
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Ese equipo ya está inscrito. Hay que retirarlo en el radar antes de repetir.",
        ) from error
    finally:
        conexion.close()
    return {"credencial": credencial, "intervalo_horas": intervalo_horas()}


@router_agente.post("/reporte", status_code=status.HTTP_202_ACCEPTED)
async def reporte(
    peticion: Request, x_credencial_equipo: str | None = Header(default=None)
) -> dict:
    """Recibe el reporte de un equipo. Responde 202 y el intervalo; nunca comandos."""
    from radar.equipos import almacen, recepcion

    _exigir_base()
    if not x_credencial_equipo:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Falta {CABECERA_CREDENCIAL}.")
    declarado = peticion.headers.get("content-length", "")
    if declarado.isdigit() and int(declarado) > TAMANO_MAXIMO_REPORTE:
        raise HTTPException(413, "Reporte muy grande.")

    conexion = _conexion()
    try:
        equipo = almacen.equipo_de_credencial(conexion, x_credencial_equipo)
        if equipo is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credencial no reconocida.")
        if equipo.revocado:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "El equipo fue revocado.")
        cuerpo = bytearray()
        async for bloque in peticion.stream():
            if len(cuerpo) + len(bloque) > TAMANO_MAXIMO_REPORTE:
                raise HTTPException(413, "Reporte muy grande.")
            cuerpo.extend(bloque)
        try:
            datos, recortes = recepcion.leer_reporte(cuerpo)
        except recepcion.ErrorReporte as error:
            raise HTTPException(error.codigo, str(error)) from error
        if datos.equipo_id.lower() != equipo.id:
            # La credencial de un equipo no sirve para reportar por otro.
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, "La credencial no corresponde a ese equipo."
            )
        recepcion.procesar(conexion, equipo, datos, recortes)
    finally:
        conexion.close()
    return {"recibido": True, "intervalo_horas": intervalo_horas()}


# ---------------------------------------------------------------------------
# Lo que llama el panel
# ---------------------------------------------------------------------------


def _inscripcion_abierta() -> bool:
    from radar.api import cuentas

    if os.environ.get("AGENTE_TOKEN_INSCRIPCION"):
        return True
    conexion = cuentas.conectar()
    try:
        return cuentas.hay_tokens_vigentes(conexion)
    finally:
        conexion.close()


@router_equipos.get("/equipos")
def equipos() -> dict:
    from radar.equipos import vista

    if obtener_datos().origen != "base":
        return {
            "disponible": False,
            "equipos": [],
            "motivo": "Los equipos con agente necesitan una base conectada.",
        }
    conexion = _conexion()
    try:
        lista = vista.lista(conexion)
    finally:
        conexion.close()
    return {
        "disponible": True,
        "total": len(lista),
        "inscripcion_abierta": _inscripcion_abierta(),
        "equipos": lista,
    }


@router_equipos.get("/equipos/{equipo_id}")
def equipo(equipo_id: str) -> dict:
    from radar.equipos import vista

    _exigir_base()
    conexion = _conexion()
    try:
        datos = vista.detalle(conexion, equipo_id)
    finally:
        conexion.close()
    if datos is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Equipo no encontrado.")
    return datos


ADMIN = [Depends(exigir_rol("admin"))]


@router_equipos.post("/equipos/{equipo_id}/revocar", dependencies=ADMIN)
def revocar(equipo_id: str) -> dict:
    """Deja de aceptar reportes de un equipo (credencial robada o equipo perdido)."""
    from radar.equipos import almacen

    _exigir_base()
    conexion = _conexion()
    try:
        hecho = almacen.revocar(conexion, equipo_id)
    finally:
        conexion.close()
    if not hecho:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Equipo no encontrado.")
    return {"revocado": True}


@router_equipos.delete("/equipos/{equipo_id}", dependencies=ADMIN)
def retirar(equipo_id: str) -> dict:
    """Borra el equipo y lo que reportó (desinstalación), y vuelve a cruzar."""
    from radar.equipos import almacen
    from radar.equipos.cruce import recruzar

    _exigir_base()
    conexion = _conexion()
    try:
        hecho = almacen.retirar(conexion, equipo_id)
        if hecho:
            recruzar(conexion)
    finally:
        conexion.close()
    if not hecho:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Equipo no encontrado.")
    return {"retirado": True}
