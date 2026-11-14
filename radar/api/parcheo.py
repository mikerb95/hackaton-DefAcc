"""Rutas del parcheo desde el agente local (docs/plan-parcheo.md).

- `/api/agente/plan` y `/api/agente/parcheo/resultado` los llama el equipo con su credencial.
  El servidor entrega el plan tal como lo firmó el admin; no puede fabricar uno, porque la
  clave privada nunca llega aquí y el agente verifica con su propia clave fijada.
- `/api/equipos/{id}/parcheo*`, `/api/parcheo/*` los llama el panel. Ver es para cualquier
  sesión; armar, registrar o cancelar planes y registrar claves exige rol admin.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from radar.api.acceso import exigir_clave, exigir_rol, quien
from radar.api.agente import CABECERA_CREDENCIAL, _conexion, _exigir_base

router_agente_parcheo = APIRouter(prefix="/api/agente")
router_parcheo = APIRouter(prefix="/api", dependencies=[Depends(exigir_clave)])
ADMIN = [Depends(exigir_rol("admin"))]


def _equipo_autenticado(conexion, credencial: str | None):
    from radar.equipos import almacen

    if not credencial:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Falta {CABECERA_CREDENCIAL}.")
    equipo = almacen.equipo_de_credencial(conexion, credencial)
    if equipo is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Credencial no reconocida.")
    if equipo.revocado:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "El equipo fue revocado.")
    return equipo


def _quien_o_422(request: Request) -> str:
    from radar.seguridad.limpieza import limpiar_texto

    por = quien(request, None)
    if not por:
        raise HTTPException(422, "Planes y claves se aprueban con una sesión de usuario.")
    return limpiar_texto(por, 100)


# ---------------------------------------------------------------------------
# Lo que llama el agente
# ---------------------------------------------------------------------------


@router_agente_parcheo.get("/plan")
def plan_del_agente(
    x_credencial_equipo: str | None = Header(default=None),
) -> Response | dict:
    """El plan firmado pendiente del equipo, o 204 si no hay ninguno."""
    from radar.equipos import parcheo

    _exigir_base()
    conexion = _conexion()
    try:
        equipo = _equipo_autenticado(conexion, x_credencial_equipo)
        datos = parcheo.plan_para_agente(conexion, equipo)
    finally:
        conexion.close()
    if datos is None:
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return datos


@router_agente_parcheo.post("/parcheo/resultado", status_code=status.HTTP_202_ACCEPTED)
async def resultado_del_agente(
    peticion: Request, x_credencial_equipo: str | None = Header(default=None)
) -> dict:
    from radar.equipos import parcheo_reporte

    _exigir_base()
    declarado = peticion.headers.get("content-length", "")
    if declarado.isdigit() and int(declarado) > parcheo_reporte.TAMANO_MAXIMO_RESULTADO:
        raise HTTPException(413, "Resultado muy grande.")
    conexion = _conexion()
    try:
        equipo = _equipo_autenticado(conexion, x_credencial_equipo)
        cuerpo = bytearray()
        async for bloque in peticion.stream():
            if len(cuerpo) + len(bloque) > parcheo_reporte.TAMANO_MAXIMO_RESULTADO:
                raise HTTPException(413, "Resultado muy grande.")
            cuerpo.extend(bloque)
        try:
            return parcheo_reporte.recibir_resultado(conexion, equipo, bytes(cuerpo))
        except parcheo_reporte.ErrorResultado as error:
            raise HTTPException(error.codigo, str(error)) from error
    finally:
        conexion.close()


# ---------------------------------------------------------------------------
# Lo que llama el panel
# ---------------------------------------------------------------------------


@router_parcheo.get("/equipos/{equipo_id}/parcheo")
def parcheo_de_equipo(equipo_id: str) -> dict:
    from radar.equipos import parcheo, parcheo_reporte
    from radar.equipos import parcheo_almacen as tablas

    _exigir_base()
    conexion = _conexion()
    try:
        datos = parcheo.propuesta(conexion, equipo_id)
        if datos is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Equipo no encontrado.")
        planes = [parcheo_reporte.resumen_plan(p) for p in tablas.planes_de_equipo(conexion, equipo_id)]
        claves = [
            {"huella": c["huella"], "nombre": c["nombre"], "publica": c["publica"]}
            for c in tablas.claves_vigentes(conexion)
        ]
    finally:
        conexion.close()
    return {"propuesta": datos, "planes": planes, "claves": claves}


class PedidoBorrador(BaseModel):
    acciones: list[str] = Field(min_length=1, max_length=60)


@router_parcheo.post("/equipos/{equipo_id}/parcheo/borrador", dependencies=ADMIN)
def borrador(equipo_id: str, cuerpo: PedidoBorrador, request: Request) -> dict:
    """Plan canónico con las acciones elegidas. El navegador firma estos bytes exactos."""
    from radar.equipos import parcheo
    from radar.seguridad import plan_parcheo

    por = _quien_o_422(request)
    _exigir_base()
    conexion = _conexion()
    try:
        datos = parcheo.propuesta(conexion, equipo_id)
    finally:
        conexion.close()
    if datos is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Equipo no encontrado.")
    try:
        plan = parcheo.borrador(datos, cuerpo.acciones, por)
    except parcheo.ErrorPlan as error:
        raise HTTPException(error.codigo, str(error)) from error
    return {"plan": plan_parcheo.canonico(plan).decode("ascii")}


class PlanFirmado(BaseModel):
    plan: str = Field(min_length=2, max_length=200_000)
    firma: str = Field(min_length=80, max_length=100)


@router_parcheo.post("/equipos/{equipo_id}/parcheo", dependencies=ADMIN)
def registrar_plan(equipo_id: str, cuerpo: PlanFirmado, request: Request) -> dict:
    from radar.equipos import parcheo

    _quien_o_422(request)
    _exigir_base()
    conexion = _conexion()
    try:
        return parcheo.registrar(conexion, equipo_id, cuerpo.plan, cuerpo.firma)
    except parcheo.ErrorPlan as error:
        raise HTTPException(error.codigo, str(error)) from error
    finally:
        conexion.close()


@router_parcheo.post("/parcheo/{plan_id}/cancelar", dependencies=ADMIN)
def cancelar_plan(plan_id: str, request: Request) -> dict:
    """Deja de entregar el plan. Si el agente ya lo bajó, puede estar ejecutándolo."""
    from radar.equipos import parcheo_almacen as tablas

    por = _quien_o_422(request)
    _exigir_base()
    conexion = _conexion()
    try:
        plan = tablas.leer_plan(conexion, plan_id)
        hecho = tablas.cancelar(conexion, plan_id, por)
    finally:
        conexion.close()
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Plan no encontrado.")
    if not hecho:
        raise HTTPException(status.HTTP_409_CONFLICT, "El plan ya terminó o estaba cancelado.")
    return {"cancelado": True, "ya_entregado": bool(plan.get("entregas"))}


@router_parcheo.get("/parcheo/{plan_id}/informe")
def informe(plan_id: str) -> dict:
    from radar.equipos import parcheo_reporte

    _exigir_base()
    conexion = _conexion()
    try:
        datos = parcheo_reporte.informe(conexion, plan_id)
    finally:
        conexion.close()
    if datos is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Plan no encontrado.")
    return datos


# -- claves de aprobación ------------------------------------------------------


@router_parcheo.get("/parcheo/claves")
def claves() -> dict:
    from radar.equipos import parcheo_almacen as tablas

    _exigir_base()
    conexion = _conexion()
    try:
        return {"claves": tablas.listar_claves(conexion)}
    finally:
        conexion.close()


class NuevaClave(BaseModel):
    publica: str = Field(min_length=40, max_length=60)
    nombre: str = Field(min_length=1, max_length=80, pattern=r"\S")


@router_parcheo.post("/parcheo/claves", dependencies=ADMIN)
def registrar_clave(cuerpo: NuevaClave, request: Request) -> dict:
    """Registra la clave pública de un aprobador. La privada se queda en su navegador."""
    from radar.equipos import parcheo, parcheo_almacen as tablas
    from radar.seguridad.limpieza import limpiar_texto

    por = _quien_o_422(request)
    _exigir_base()
    try:
        publica = parcheo.leer_clave_publica(cuerpo.publica)
    except parcheo.ErrorPlan as error:
        raise HTTPException(error.codigo, str(error)) from error
    conexion = _conexion()
    try:
        huella = tablas.registrar_clave(conexion, publica, limpiar_texto(cuerpo.nombre, 80), por)
    except tablas.ClaveYaRegistrada as error:
        raise HTTPException(status.HTTP_409_CONFLICT, "Esa clave ya está registrada.") from error
    finally:
        conexion.close()
    return {"huella": huella}


@router_parcheo.post("/parcheo/claves/{huella}/revocar", dependencies=ADMIN)
def revocar_clave(huella: str) -> dict:
    from radar.equipos import parcheo_almacen as tablas

    _exigir_base()
    conexion = _conexion()
    try:
        hecho = tablas.revocar_clave(conexion, huella)
    finally:
        conexion.close()
    if not hecho:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Clave no encontrada o ya revocada.")
    return {"revocada": True}
