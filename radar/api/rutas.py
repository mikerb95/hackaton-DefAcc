"""Rutas de la API del panel (PLAN, sección 11).

Todas piden sesión o la clave compartida (`radar/api/acceso.py`); las que cambian algo piden
además el rol `analista`. Los datos vienen de
`radar/api/datos.py`, que hoy lee `radar/ejemplos.py`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
    status,
)
from pydantic import BaseModel, Field

from radar.api.acceso import exigir_clave, exigir_rol, quien
from radar.api.datos import obtener_datos
from radar.contratos import EstadoHallazgo, Grupo, Prioridad
from radar.ingesta.archivos import ErrorLectura, a_contrato, leer_inventario

router = APIRouter(prefix="/api", dependencies=[Depends(exigir_clave)])
ANALISTA = [Depends(exigir_rol("analista"))]


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
        "comandos": _comandos(grupo, datos.hallazgos(texto=producto)),
    }


def _comandos(grupo: Grupo, hallazgos: list) -> list[dict]:
    """Comandos de remediación del producto, armados por plantillas del código (nunca por el
    modelo). Vacío si el producto no tiene plantilla."""
    from radar.equipos.remediacion import comandos_de_grupo

    propios = [h for h in hallazgos if h.producto == grupo.producto]
    return [
        {"plataforma": c.plataforma, "texto": c.texto} for c in comandos_de_grupo(grupo, propios)
    ]


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


@router.post("/hallazgos/{id_hallazgo:path}/estado", dependencies=ANALISTA)
def cambiar_estado(id_hallazgo: str, cambio: CambioEstado, request: Request) -> dict:
    datos = obtener_datos()
    por = quien(request, cambio.por)
    nuevo = datos.cambiar_estado(id_hallazgo, cambio.estado, cambio.comentario, por)
    if nuevo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Hallazgo no encontrado.")
    return {"hallazgo": nuevo.model_dump(), "persistente": datos.persistente}


class Aprobacion(BaseModel):
    # La aprobación la hace una persona con nombre. Con sesión el nombre sale de la sesión;
    # con la clave compartida o en local hay que decir quién aprueba.
    por: str | None = Field(default=None, min_length=1, max_length=100, pattern=r"\S")


@router.post("/comunicado/{producto}/aprobar", dependencies=ANALISTA)
def aprobar(producto: str, cuerpo: Aprobacion, request: Request) -> dict:
    por = quien(request, cuerpo.por.strip() if cuerpo.por else None)
    if not por:
        raise HTTPException(422, "Falta quién aprueba el comunicado.")
    datos = obtener_datos()
    registro = datos.aprobar(producto, por)
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


def _cruce_con_agentes(conexion):
    """Si hay equipos con agente local, cruza todo el inventario guardado (archivos, reportes
    y sistema operativo) y devuelve el resultado; si no hay, None y el cruce es el de siempre.
    Cruzar solo el archivo propondría como resueltos los hallazgos que vienen de los agentes."""
    from radar.equipos import almacen
    from radar.equipos.cruce import recruzar

    if not almacen.hay_equipos(conexion):
        return None
    return recruzar(conexion).resultado


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
        resultado = _cruce_con_agentes(conexion)
        if resultado is None:
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


@router.post("/inventario", dependencies=ANALISTA)
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


@router.post("/revisar", status_code=status.HTTP_202_ACCEPTED, dependencies=ANALISTA)
def revisar() -> dict:
    trabajo = obtener_datos().encolar("descargar", "pedido desde el panel")
    if trabajo is None:
        return {"encolado": False, "motivo": "Sin base no hay cola de trabajos."}
    return {"encolado": True, "trabajo": trabajo}


@router.get("/umbrales")
def umbrales() -> dict:
    """Barrido de umbrales (radar/nucleo/umbrales.py): alertas inmediatas por cada par de
    umbrales EPSS y CVSS, con la celda vigente y el piso de KEV."""
    return {"disponible": True} | obtener_datos().umbrales()


@router.get("/trazas")
def trazas() -> dict:
    lista = obtener_datos().trazas()
    if lista is None:
        return {"disponible": False, "trazas": [], "motivo": "Las trazas las escribe el worker."}
    return {"disponible": True, "trazas": lista}


# ---- configuración: modelo de Claude (radar/ajustes.py) -------------------------------------

ADMIN = [Depends(exigir_rol("admin"))]


def _ajustes_json() -> dict:
    from radar import ajustes

    return {
        "modelos": [{"id": i, "nombre": n} for i, n in ajustes.MODELOS_CONOCIDOS.items()],
        "por_defecto": ajustes.MODELO_POR_DEFECTO,
        "usos": {uso: ajustes.modelo_vigente(uso).publico() for uso in ajustes.USOS},
    }


class CambioModelo(BaseModel):
    # None borra lo elegido en la consola y vuelve a mandar la variable de entorno.
    modelo: str | None = Field(default=None, max_length=64)


@router.get("/ajustes")
def leer_ajustes() -> dict:
    from radar import ajustes

    ajustes.olvidar_cache()
    return _ajustes_json()


@router.put("/ajustes/modelo/{uso}", dependencies=ADMIN)
def cambiar_modelo(uso: str, cambio: CambioModelo, request: Request) -> dict:
    from radar import ajustes, bd

    if uso not in ajustes.USOS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Uso desconocido.")
    conexion = bd.conectar()
    try:
        ajustes.guardar_modelo(
            conexion, uso, cambio.modelo, quien(request, request.state.identidad.nombre)
        )
    except ajustes.AjusteInvalido as error:
        raise HTTPException(422, str(error)) from error
    finally:
        conexion.close()
    return _ajustes_json()


# ---- configuración: avisos por ntfy (radar/avisos/ntfy.py) ----------------------------------

ESPERA_PRUEBA_NTFY_S = 10.0  # entre pruebas, para no inundar el tópico ni el límite de ntfy.sh
_ultima_prueba_ntfy = 0.0


@router.get("/ajustes/ntfy", dependencies=ADMIN)
def leer_ntfy() -> dict:
    from radar.avisos import ntfy

    return ntfy.estado_publico()


@router.post("/ajustes/ntfy/prueba", dependencies=ADMIN)
def probar_ntfy() -> dict:
    """Manda la notificación de confirmación al tópico configurado."""
    import time

    from radar.avisos import ntfy

    global _ultima_prueba_ntfy
    config = ntfy.configuracion()
    if config is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "ntfy no está configurado: falta NTFY_TOPICO (o no es válido).",
        )
    if time.monotonic() - _ultima_prueba_ntfy < ESPERA_PRUEBA_NTFY_S:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS, "Espera unos segundos antes de otra prueba."
        )
    _ultima_prueba_ntfy = time.monotonic()
    try:
        ntfy.enviar_prueba(config)
    except Exception as error:  # se informa sin detalles internos
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            f"ntfy no aceptó la notificación ({type(error).__name__}).",
        ) from error
    return {"enviado": True, **ntfy.estado_publico(config)}
