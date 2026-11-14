"""Rutas del agente local (docs/plan-agente-local.md, sección 6).

Dos grupos, con credenciales distintas:

- `/api/agente/*` lo llaman los equipos. No usa la clave compartida del panel: la
  inscripción pide el token de la organización (`AGENTE_TOKEN_INSCRIPCION`) y cada reporte
  pide la credencial propia del equipo en `X-Credencial-Equipo`. Robar la credencial de un
  equipo solo sirve para enviar reportes de ese equipo, y se revoca sin tocar a los demás.
- `/api/equipos*` lo llama el panel, con la clave compartida, como el resto de la API.

El servidor nunca devuelve órdenes: la respuesta a un reporte es `202` con el intervalo
deseado y nada más. Tomar el servidor no da ejecución en los PC.

Activación en la consola (como Acronis): al instalarse, el agente genera un código de
activación y lo muestra en la pantalla del equipo. El equipo queda pendiente: reporta y se
ve en el panel, pero su inventario no entra al cruce hasta que una persona escribe ese
código en el panel (`POST /api/equipos/activar`). Rechazar es retirarlo.
`AGENTE_APROBACION=automatica` quita ese paso.
"""

from __future__ import annotations

import hmac
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from radar.api.acceso import exigir_clave
from radar.api.datos import obtener_datos
from radar.equipos.contratos import TAMANO_MAXIMO_REPORTE

CABECERA_CREDENCIAL = "X-Credencial-Equipo"
INTERVALO_POR_DEFECTO = 12  # horas

router_agente = APIRouter(prefix="/api/agente")
router_equipos = APIRouter(prefix="/api", dependencies=[Depends(exigir_clave)])


MAX_PENDIENTES = 200


def aprobacion_automatica() -> bool:
    """`AGENTE_APROBACION=automatica` deja entrar a los equipos sin pasar por la consola.
    Por defecto es manual: cada equipo nuevo espera a que TI lo apruebe."""
    return os.environ.get("AGENTE_APROBACION", "").strip().lower() == "automatica"


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
    equipo_id: str = Field(pattern=r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
    nombre_equipo: str = Field(min_length=1, max_length=2000)
    agente_version: str | None = Field(default=None, max_length=40)
    # La credencial y el código los genera el agente. El radar guarda solo sus huellas.
    credencial: str = Field(min_length=32, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    codigo: str = Field(pattern=r"^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$")
    token: str | None = Field(default=None, max_length=200)


@router_agente.post("/inscribir")
def inscribir(cuerpo: Inscripcion) -> dict:
    """Inscribe un equipo con la credencial y el código de activación que generó el agente.

    El equipo queda pendiente hasta que TI escribe ese código en el panel. Si el radar
    define `AGENTE_TOKEN_INSCRIPCION`, además hace falta ese token (capa extra para un
    radar expuesto en internet); sin él la inscripción está abierta y el filtro es el código.
    """
    from radar.equipos import almacen
    from radar.seguridad.equipos import sanear_nombre_equipo
    from radar.seguridad.limpieza import limpiar_texto

    _exigir_base()
    esperado = os.environ.get("AGENTE_TOKEN_INSCRIPCION", "")
    if esperado and not hmac.compare_digest((cuerpo.token or "").encode(), esperado.encode()):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token de inscripción no válido.")
    automatica = aprobacion_automatica()
    conexion = _conexion()
    try:
        # Una inscripción que nadie activa en una semana se borra, y hay un tope de
        # pendientes: la inscripción abierta no puede llenar la base.
        almacen.borrar_pendientes_viejos(conexion)
        if not automatica and almacen.contar_pendientes(conexion) >= MAX_PENDIENTES:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Hay demasiados equipos esperando aprobación en la consola.",
            )
        almacen.inscribir(
            conexion,
            cuerpo.equipo_id.lower(),
            sanear_nombre_equipo(cuerpo.nombre_equipo, 0),
            limpiar_texto(cuerpo.agente_version, 40) or None,
            cuerpo.credencial,
            cuerpo.codigo,
            aprobar=automatica,
        )
    except almacen.EquipoYaInscrito as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Ese equipo ya está inscrito. Hay que retirarlo en el radar antes de repetir.",
        ) from error
    finally:
        conexion.close()
    return {"inscrito": True, "intervalo_horas": intervalo_horas()}


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
        recepcion.recibir(conexion, equipo, datos, recortes)
    finally:
        conexion.close()
    return {"recibido": True, "intervalo_horas": intervalo_horas()}


# ---------------------------------------------------------------------------
# Lo que llama el panel
# ---------------------------------------------------------------------------


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
        "token_exigido": bool(os.environ.get("AGENTE_TOKEN_INSCRIPCION")),
        "aprobacion": "automatica" if aprobacion_automatica() else "manual",
        "pendientes": sum(1 for e in lista if e["pendiente"] and not e["revocado"]),
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


def url_publica(peticion: Request) -> str:
    """URL del radar que va en el paquete: `RADAR_URL_PUBLICA` o la de la petición."""
    forzada = os.environ.get("RADAR_URL_PUBLICA", "").strip()
    return (forzada or str(peticion.base_url)).rstrip("/")


@router_equipos.get("/agente-instalador.zip")
def instalador(peticion: Request) -> Response:
    """Paquete de instalación del agente con la URL de este radar: se descomprime y se le da
    doble clic. Pide la clave del panel porque, si el radar exige token, el token va dentro."""
    from radar.equipos import paquete

    datos = paquete.armar(url_publica(peticion), os.environ.get("AGENTE_TOKEN_INSCRIPCION") or None)
    return Response(
        datos,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{paquete.NOMBRE_ARCHIVO}"'},
    )


class Activacion(BaseModel):
    codigo: str = Field(min_length=8, max_length=20)
    # La activación la hace una persona con nombre: sin "por" no se activa.
    por: str = Field(min_length=1, max_length=100, pattern=r"\S")


@router_equipos.post("/equipos/activar")
def activar(cuerpo: Activacion) -> dict:
    """TI activa un equipo con el código que el instalador mostró en su pantalla. Desde ese
    momento su inventario entra al cruce. Rechazar es retirarlo (DELETE)."""
    from radar.equipos import almacen, recepcion
    from radar.seguridad.limpieza import limpiar_texto

    _exigir_base()
    conexion = _conexion()
    try:
        equipo_id = almacen.equipo_de_codigo(conexion, cuerpo.codigo)
        if equipo_id is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "Ningún equipo pendiente tiene ese código. Revísalo en la pantalla del equipo.",
            )
        recibido = recepcion.aprobar(conexion, equipo_id, limpiar_texto(cuerpo.por, 100))
        equipo = almacen.leer_equipo(conexion, equipo_id)
    except recepcion.ErrorAprobacion as error:
        raise HTTPException(status.HTTP_409_CONFLICT, "El equipo ya no está pendiente.") from error
    finally:
        conexion.close()
    return {
        "activado": True,
        "equipo": {"id": equipo.id, "nombre": equipo.nombre},
        "cruzado": recibido is not None,
    }


@router_equipos.post("/equipos/{equipo_id}/revocar")
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


@router_equipos.delete("/equipos/{equipo_id}")
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
