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
from radar.ingesta.archivos import ErrorLectura, a_contrato, leer_inventario

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
    guardado = analisis is not None
    if analisis is None:
        # Sin análisis del agente (todavía no llega o el agente no corre), se muestra el texto
        # armado por código: la demo funciona con o sin agente (regla 6).
        analisis = _respaldo(grupo)
    return {
        "grupo": _grupo_json(grupo),
        "analisis": analisis.model_dump() if analisis else None,
        "guardado": guardado,
        "pendiente": analisis is None,
        "aprobacion": datos.aprobacion(producto),
    }


def _respaldo(grupo: Grupo):
    try:
        from radar.agente.respaldo import armar_respaldo

        return armar_respaldo(grupo)
    except Exception:  # noqa: BLE001 - el respaldo nunca debe tumbar el detalle
        return None


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


def _normalizador():
    """`normalizar(filas) -> (activos, cobertura)` de radar/ingesta/normalizador.py, o None si
    todavía no existe (se pidió esa firma en .coordinacion/normalizador.md)."""
    try:
        from radar.ingesta.normalizador import normalizar
    except ImportError:
        return None
    return normalizar


def _cruzar_inventario(filas: list) -> dict:
    """Guarda el inventario, normaliza, cruza contra las CVE guardadas y deja un trabajo de
    análisis. Sin normalizador solo guarda las filas y lo dice."""
    from radar import bd
    from radar.nucleo.corrida import correr

    normalizar = _normalizador()
    conexion = bd.conectar()
    try:
        bd.crear_esquema(conexion)
        bd.guardar_inventario(conexion, filas)
        if normalizar is None:
            return {"cruce": "pendiente", "motivo": "Falta el normalizador."}
        activos, cobertura = normalizar(filas)
        resultado = correr(conexion, activos, cobertura)
        trabajo = bd.crear_trabajo(conexion, "analizar", "inventario cargado desde el panel")
    finally:
        conexion.close()
    return {
        "cruce": "hecho",
        "resultado": resultado.resumen,
        "propuestos_resueltos": resultado.propuestos_resueltos[:50],
        "trabajo": trabajo,
    }


@router.post("/inventario")
async def cargar_inventario(archivo: Annotated[UploadFile, File()]) -> dict:
    contenido = await archivo.read()
    try:
        lectura = leer_inventario(contenido, archivo.filename)
    except ErrorLectura as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    respuesta = {
        "lectura": lectura.resumen(),
        "descartadas": [{"fila": d.fila, "motivo": d.motivo} for d in lectura.descartadas[:50]],
    }
    if obtener_datos().origen != "base":
        respuesta |= {"cruce": "pendiente", "motivo": "El panel está con datos de ejemplo."}
        return respuesta
    filas = [a_contrato(f) for f in lectura.filas]
    return respuesta | _cruzar_inventario(filas)


@router.post("/revisar", status_code=status.HTTP_202_ACCEPTED)
def revisar() -> dict:
    trabajo = obtener_datos().encolar("descargar", "pedido desde el panel")
    if trabajo is None:
        return {"encolado": False, "motivo": "Sin base no hay cola de trabajos."}
    return {"encolado": True, "trabajo": trabajo}


@router.get("/umbrales")
def umbrales() -> dict:
    return {"disponible": False, "puntos": [], "motivo": "El barrido sale de evals/."}


@router.get("/trazas")
def trazas() -> dict:
    lista = obtener_datos().trazas()
    if lista is None:
        return {"disponible": False, "trazas": [], "motivo": "Las trazas las escribe el worker."}
    return {"disponible": True, "trazas": lista}
