"""Rutas de la API del panel (PLAN, sección 11).

Todas piden la clave compartida (`radar/api/acceso.py`). Los datos vienen de
`radar/api/datos.py`, que hoy lee `radar/ejemplos.py`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field

from radar.api.acceso import exigir_clave
from radar.api.datos import obtener_datos
from radar.contratos import EstadoHallazgo, Grupo, Prioridad
from radar.ingesta.archivos import ErrorLectura, leer_inventario

router = APIRouter(prefix="/api", dependencies=[Depends(exigir_clave)])


def texto_objetivo(grupo: Grupo) -> str:
    """Cómo se dice la versión objetivo. Con versionEndIncluding no se sabe la versión que
    arregla, solo que hay que pasar de ella (regla 5): nunca "actualizar a X"."""
    if grupo.tipo_objetivo == "exacta":
        return f"actualizar a {grupo.version_objetivo}"
    if grupo.tipo_objetivo == "posterior_a":
        return f"posterior a {grupo.version_objetivo}"
    return "sin versión objetivo conocida"


def _grupo_json(grupo: Grupo) -> dict:
    datos = grupo.model_dump()
    datos["n_equipos"] = grupo.n_equipos
    datos["n_cves"] = grupo.n_cves
    datos["objetivo_texto"] = texto_objetivo(grupo)
    return datos


@router.get("/resumen")
def resumen() -> dict:
    return obtener_datos().resumen()


@router.get("/hallazgos")
def hallazgos(
    prioridad: Prioridad | None = None,
    kev: bool | None = None,
    texto: Annotated[str | None, Query(max_length=100)] = None,
) -> dict:
    lista = obtener_datos().hallazgos(prioridad=prioridad, kev=kev, texto=texto)
    return {"total": len(lista), "hallazgos": [h.model_dump() for h in lista]}


@router.get("/productos")
def productos() -> dict:
    return {"productos": [_grupo_json(g) for g in obtener_datos().productos()]}


@router.get("/analisis/{producto}")
def analisis(producto: str) -> dict:
    datos = obtener_datos()
    grupo = datos.grupo(producto)
    if grupo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Producto sin hallazgos.")
    analisis = datos.analisis(producto)
    return {
        "grupo": _grupo_json(grupo),
        "analisis": analisis.model_dump() if analisis else None,
        "pendiente": analisis is None,
        "aprobacion": datos.aprobacion(producto),
    }


class CambioEstado(BaseModel):
    estado: EstadoHallazgo
    comentario: str | None = Field(default=None, max_length=500)
    por: str | None = Field(default=None, max_length=100)


@router.post("/hallazgos/{id_hallazgo:path}/estado")
def cambiar_estado(id_hallazgo: str, cambio: CambioEstado) -> dict:
    datos = obtener_datos()
    nuevo = datos.cambiar_estado(id_hallazgo, cambio.estado, cambio.comentario, cambio.por)
    if nuevo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Hallazgo no encontrado.")
    return {"hallazgo": nuevo.model_dump(), "persistente": datos.persistente}


class Aprobacion(BaseModel):
    por: str | None = Field(default=None, max_length=100)


@router.post("/comunicado/{producto}/aprobar")
def aprobar(producto: str, cuerpo: Aprobacion | None = None) -> dict:
    datos = obtener_datos()
    registro = datos.aprobar(producto, cuerpo.por if cuerpo else None)
    if registro is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No hay comunicado para ese producto.")
    return {"aprobacion": registro, "persistente": datos.persistente}


@router.post("/inventario")
async def cargar_inventario(archivo: Annotated[UploadFile, File()]) -> dict:
    contenido = await archivo.read()
    try:
        lectura = leer_inventario(contenido, archivo.filename)
    except ErrorLectura as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return {
        "lectura": lectura.resumen(),
        "descartadas": [{"fila": d.fila, "motivo": d.motivo} for d in lectura.descartadas[:50]],
        # El cruce y el trabajo de análisis llegan con radar/nucleo y radar/bd.py.
        "cruce": "pendiente",
    }


@router.post("/revisar", status_code=status.HTTP_202_ACCEPTED)
def revisar() -> dict:
    # Sin Turso no hay cola donde dejar el trabajo: se dice, no se finge.
    return {"encolado": False, "motivo": "La cola de trabajos llega con Turso."}


@router.get("/umbrales")
def umbrales() -> dict:
    return {"disponible": False, "puntos": [], "motivo": "El barrido sale de evals/."}


@router.get("/trazas")
def trazas() -> dict:
    return {"disponible": False, "trazas": [], "motivo": "Las trazas las escribe el worker."}
