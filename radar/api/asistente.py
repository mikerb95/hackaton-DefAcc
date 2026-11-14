"""Rutas del asistente (docs/plan-asistente.md).

Panel (sesión o clave, `radar/api/acceso.py`); el rol sale de la sesión, nunca del cuerpo:

- `GET  /api/asistente/estado`: si la caja puede preguntar, el modelo y lo que queda hoy.
- `POST /api/asistente`: `{pregunta, id?}`. SSE. Sin `id` crea; con `id` sigue (con una
  propuesta abierta, la pregunta es "pedir cambios").
- `POST /api/asistente/decision`: `{id, aprobado}`. SSE. Solo `true` explícito aprueba.
- `GET  /api/asistente/recientes`: las del usuario; `?todas=1` el admin ve todas.
- `GET  /api/asistente/conversacion/{id}`: el hilo para pintarlo (admin: ajenas en solo lectura).
- `GET  /api/asistente/buscar?q=`: buscador del panel SIN IA (sirve aunque falte la clave).
- `GET/PUT /api/asistente/topes`, `GET /api/asistente/consumo`: solo admin.

/mi-equipo/ (enlace firmado, sin cuenta):

- `POST /api/mi-equipo/asistente`: `{pregunta}`. SSE. Solo consulta, solo ese equipo.

Si el navegador se va a mitad de la respuesta, la tarea sigue en su hilo y la conversación
termina guardada: cortarla dejaría a medias algo ya pagado.
"""

from __future__ import annotations

import json
import queue
import re
import threading
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StrictBool

from radar.api.acceso import Identidad, exigir_clave, exigir_rol
from radar.asistente import almacen, motor
from radar.asistente.contexto import Contexto
from radar.asistente.herramientas import secciones_para

router_asistente = APIRouter(prefix="/api/asistente", dependencies=[Depends(exigir_clave)])
router_asistente_equipo = APIRouter(prefix="/api/mi-equipo")
ADMIN = [Depends(exigir_rol("admin"))]

_ID = r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$"

ATAJOS = {
    "lector": [
        "¿Qué exige acción hoy?",
        "¿Qué CVE están en KEV?",
        "¿Qué quedó sin comparar y por qué?",
    ],
    "analista": [
        "¿Qué exige acción hoy?",
        "¿Qué hallazgos en KEV siguen nuevos?",
        "¿Qué productos hay que actualizar primero?",
        "¿Qué comunicados faltan por aprobar?",
    ],
    "admin": [
        "¿Qué exige acción hoy?",
        "¿Hay equipos esperando aprobación?",
        "¿Qué equipos están peor?",
        "¿Qué comunicados faltan por aprobar?",
    ],
}


def contexto(identidad: Identidad) -> Contexto:
    if identidad.via == "sesion" and identidad.id is not None:
        usuario_id = f"sesion:{identidad.id}"
    else:
        usuario_id = f"{identidad.via}:{identidad.usuario}"
    return Contexto(usuario_id, identidad.nombre, identidad.rol, identidad.via, identidad.id)


def transmitir(tarea: Callable[[Callable[[dict[str, Any]], None]], Any]) -> StreamingResponse:
    """SSE. La tarea corre en su propio hilo; si el navegador se va, termina igual."""
    cola: queue.Queue[dict[str, Any] | None] = queue.Queue()

    def correr() -> None:
        try:
            tarea(cola.put)
        except motor.Conflicto as conflicto:
            cola.put({"tipo": "error", "mensaje": str(conflicto), "nueva": conflicto.nueva})
        except Exception as error:  # noqa: BLE001
            motor._registrar(f"error en la tarea: {type(error).__name__}: {error}")
            cola.put({"tipo": "error", "mensaje": "El asistente tuvo un error inesperado."})
        finally:
            cola.put(None)

    threading.Thread(target=correr, daemon=True).start()

    def eventos():
        while (evento := cola.get()) is not None:
            yield f"data: {json.dumps(evento, ensure_ascii=False, default=str)}\n\n"

    return StreamingResponse(
        eventos(),
        media_type="text/event-stream; charset=utf-8",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def _antes_de_gastar(ctx: Contexto) -> None:
    """Clave presente (503) y presupuesto (429). Falla cerrado si no se puede leer el gasto."""
    if not motor.disponible():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "El asistente no tiene clave de API: por ahora la caja solo busca.",
        )
    try:
        restante = motor.presupuesto(ctx)
    except Exception as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "No se pudo comprobar el gasto de hoy; por seguridad el asistente no responde.",
        ) from error
    if restante <= 0:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Se alcanzó el tope de gasto de hoy. Mañana vuelve a estar disponible.",
        )


# ---------------------------------------------------------------------------
# Panel
# ---------------------------------------------------------------------------


@router_asistente.get("/estado")
def estado(identidad: Annotated[Identidad, Depends(exigir_clave)]) -> dict:
    ctx = contexto(identidad)
    disponible = motor.disponible()
    restante = None
    motivo = None if disponible else "sin_clave"
    if disponible:
        try:
            restante = round(motor.presupuesto(ctx), 4)
            if restante <= 0:
                motivo = "sin_presupuesto"
        except Exception:  # noqa: BLE001
            motivo = "sin_gasto"
    return {
        "disponible": disponible and motivo is None,
        "motivo": motivo,
        "modelo": motor.modelo() if disponible else None,
        "restante_usd": restante,
        "atajos": ATAJOS.get(ctx.rol, []),
        "puede_proponer": ctx.rol in ("analista", "admin"),
        "nombre": identidad.nombre,
    }


class Pregunta(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pregunta: str = Field(min_length=1, max_length=2000)
    id: str | None = Field(default=None, pattern=_ID)


@router_asistente.post("")
def preguntar(
    cuerpo: Pregunta, identidad: Annotated[Identidad, Depends(exigir_clave)]
) -> StreamingResponse:
    ctx = contexto(identidad)
    _antes_de_gastar(ctx)
    texto = cuerpo.pregunta.strip()
    if not texto:
        raise HTTPException(422, "La pregunta está vacía.")
    return transmitir(lambda emitir: motor.preguntar(ctx, texto, cuerpo.id, emitir))


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=_ID)
    aprobado: StrictBool


@router_asistente.post("/decision")
def decision(
    cuerpo: Decision, identidad: Annotated[Identidad, Depends(exigir_clave)]
) -> StreamingResponse:
    ctx = contexto(identidad)
    _antes_de_gastar(ctx)
    return transmitir(
        lambda emitir: motor.decidir_propuesta(ctx, cuerpo.id, cuerpo.aprobado is True, emitir)
    )


@router_asistente.get("/recientes")
def recientes(identidad: Annotated[Identidad, Depends(exigir_clave)], todas: bool = False) -> dict:
    ctx = contexto(identidad)
    if todas and not ctx.es_admin:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Solo el administrador ve las conversaciones de todos."
        )
    with motor.base() as c:
        filas = almacen.recientes(c, None if todas else ctx.usuario_id)
    return {"conversaciones": filas}


@router_asistente.get("/conversacion/{id_}")
def conversacion(id_: str, identidad: Annotated[Identidad, Depends(exigir_clave)]) -> dict:
    if not re.match(_ID, id_):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversación no encontrada.")
    datos = motor.ver(contexto(identidad), id_)
    if datos is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversación no encontrada.")
    return datos


@router_asistente.get("/buscar")
def buscar(
    identidad: Annotated[Identidad, Depends(exigir_clave)],
    q: Annotated[str, Query(min_length=1, max_length=100)],
) -> dict:
    """Buscador sin IA: secciones, productos, CVE y equipos. No gasta nada."""
    from radar.api.datos import obtener_datos

    t = q.casefold().strip()
    resultados: list[dict[str, str]] = [
        {"tipo": "Sección", "titulo": s["titulo"], "detalle": "", "enlace": s["enlace"]}
        for s in secciones_para(identidad.rol, q)
        if t in s["titulo"].casefold() or len(t) >= 3
    ][:3]
    if len(t) >= 2:
        datos = obtener_datos()
        for g in datos.productos():
            if t in g.producto.casefold():
                resultados.append(
                    {
                        "tipo": "Producto",
                        "titulo": g.producto,
                        "detalle": f"{g.prioridad or ''}, {len(g.equipos)} equipo(s)",
                        "enlace": "/panel/#hallazgos",
                    }
                )
        vistos: set[str] = set()
        for h in datos.hallazgos(texto=q):
            if h.cve in vistos or t not in h.cve.casefold():
                continue
            vistos.add(h.cve)
            resultados.append(
                {
                    "tipo": "CVE",
                    "titulo": h.cve,
                    "detalle": f"{h.producto} {h.version_instalada}",
                    "enlace": "/panel/#hallazgos",
                }
            )
        if datos.origen == "base":
            from radar.equipos import almacen as equipos

            with motor.base() as c:
                for e in equipos.leer_equipos(c):
                    if t in e.nombre.casefold():
                        resultados.append(
                            {
                                "tipo": "Equipo",
                                "titulo": e.nombre,
                                "detalle": "pendiente" if e.pendiente else "",
                                "enlace": "/panel/#equipos",
                            }
                        )
    return {"resultados": resultados[:12]}


@router_asistente.get("/topes", dependencies=ADMIN)
def leer_topes() -> dict:
    with motor.base() as c:
        t = almacen.topes(c)
        dia = almacen.dia_colombia()
        return {"topes": t, "gasto_hoy": round(almacen.gasto(c, dia), 4), "dia": dia}


class CambioTopes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dia: float | None = Field(default=None, ge=0, le=almacen.TOPE_MAXIMO)
    usuario: float | None = Field(default=None, ge=0, le=almacen.TOPE_MAXIMO)
    equipo: float | None = Field(default=None, ge=0, le=almacen.TOPE_MAXIMO)


@router_asistente.put("/topes", dependencies=ADMIN)
def cambiar_topes(
    cuerpo: CambioTopes, identidad: Annotated[Identidad, Depends(exigir_clave)]
) -> dict:
    with motor.base() as c:
        for nombre, valor in cuerpo.model_dump(exclude_none=True).items():
            almacen.guardar_tope(c, nombre, valor, identidad.nombre)
    return leer_topes()


@router_asistente.get("/consumo", dependencies=ADMIN)
def consumo(mes: Annotated[str | None, Query(pattern=r"^\d{4}-\d{2}$")] = None) -> dict:
    mes = mes or almacen.dia_colombia()[:7]
    with motor.base() as c:
        datos = almacen.reporte(c, mes)
        datos["auditoria"] = almacen.auditoria(c, 20)
    return datos


# ---------------------------------------------------------------------------
# /mi-equipo/
# ---------------------------------------------------------------------------


class PreguntaEquipo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pregunta: str = Field(min_length=1, max_length=500)


@router_asistente_equipo.post("/asistente")
def preguntar_equipo(
    cuerpo: PreguntaEquipo, x_enlace_equipo: str | None = Header(default=None)
) -> StreamingResponse:
    """Solo consulta y solo sobre el equipo del enlace. Sin historial: cada pregunta es nueva."""
    from radar.api.agente import _exigir_base
    from radar.api.mi_equipo import verificar_enlace
    from radar.equipos import almacen as equipos

    equipo_id = verificar_enlace(x_enlace_equipo)
    if equipo_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "El enlace no es válido o ya venció.")
    _exigir_base()
    with motor.base() as c:
        equipo = equipos.leer_equipo(c, equipo_id)
    if equipo is None or equipo.revocado:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Este equipo ya no está activo en el radar.")
    ctx = Contexto(f"equipo:{equipo_id}", "Persona del equipo", "equipo", "equipo", None, equipo_id)
    _antes_de_gastar(ctx)
    texto = cuerpo.pregunta.strip()
    return transmitir(lambda emitir: motor.preguntar(ctx, texto, None, emitir))
