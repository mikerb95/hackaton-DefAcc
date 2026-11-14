"""Recepción del reporte de un agente local: valida, limita, limpia y reparte
(docs/plan-agente-local.md, secciones 5 y 6).

Topes del lado del servidor: 1 MB por reporte, 5000 programas y 160 caracteres por campo.
Lo que excede se recorta y se cuenta (queda en `equipos.recortes`); un programa mal
formado se descarta sin tumbar el resto del reporte.

Reparto:
- `so`, `hardware` y `postura` van a la tabla `equipos`.
- Los paquetes de la distribución (dpkg, rpm) van a `paquetes_so`: se cruzan contra OSV
  en el worker, nunca por CPE.
- El resto del software va a `inventario` con `fuente = "agente"` y entra al cruce del
  núcleo junto con lo cargado por archivo.
- El nombre del equipo se sanea a un hostname (RFC 1123) antes de guardarlo: es el canal
  de inyección que sobrevive al normalizador (docs/AMENAZAS.md).

El servidor nunca devuelve órdenes al agente.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from radar import bd
from radar.contratos import FilaInventario
from radar.equipos import almacen, postura
from radar.equipos.almacen import Equipo
from radar.equipos.contratos import (
    FUENTES_DE_DISTRIBUCION,
    MAX_PROGRAMAS,
    TAMANO_MAXIMO_REPORTE,
    ProgramaReportado,
    ReporteEquipo,
)
from radar.seguridad.equipos import nombre_equipo_valido, sanear_nombre_equipo

TRABAJO_SO = "cruzar_so"
DETALLE_ANALISIS = "reporte de un agente local"


class ErrorReporte(ValueError):
    """El reporte no se acepta. `codigo` es el estado HTTP con el que se responde."""

    def __init__(self, mensaje: str, codigo: int = 400):
        super().__init__(mensaje)
        self.codigo = codigo


def leer_reporte(cuerpo: bytes) -> tuple[ReporteEquipo, dict[str, int]]:
    """Valida el cuerpo y devuelve el reporte con el conteo de lo recortado o descartado."""
    if len(cuerpo) > TAMANO_MAXIMO_REPORTE:
        raise ErrorReporte(f"El reporte supera {TAMANO_MAXIMO_REPORTE // 1024} KB.", 413)
    try:
        datos = json.loads(cuerpo)
    except (ValueError, UnicodeDecodeError) as error:
        raise ErrorReporte("El reporte no es JSON.") from error
    if not isinstance(datos, dict):
        raise ErrorReporte("El reporte debe ser un objeto JSON.")

    recortes: dict[str, int] = {}
    crudos = datos.get("software")
    crudos = crudos if isinstance(crudos, list) else []
    if len(crudos) > MAX_PROGRAMAS:
        recortes["programas_de_mas"] = len(crudos) - MAX_PROGRAMAS
        crudos = crudos[:MAX_PROGRAMAS]
    programas: list[ProgramaReportado] = []
    descartados = 0
    for crudo in crudos:
        try:
            programas.append(ProgramaReportado.model_validate(crudo))
        except ValidationError:
            descartados += 1
    if descartados:
        recortes["programas_descartados"] = descartados

    try:
        reporte = ReporteEquipo.model_validate({**datos, "software": []})
    except ValidationError as error:
        campos = sorted({".".join(str(p) for p in e["loc"]) for e in error.errors()})
        raise ErrorReporte("Reporte no válido en: " + ", ".join(campos[:10]), 422) from error
    reporte.software = programas
    return reporte, recortes


def _sistema(reporte: ReporteEquipo) -> str | None:
    return " ".join(p for p in (reporte.so.nombre, reporte.so.version) if p) or None


def filas_de_inventario(
    reporte: ReporteEquipo, nombre: str, cargado: datetime
) -> list[FilaInventario]:
    """Software que se cruza por CPE. Los paquetes de la distribución no entran aquí."""
    sistema = _sistema(reporte)
    vistas: set[tuple[str, str]] = set()
    filas = []
    for p in reporte.software:
        if p.fuente in FUENTES_DE_DISTRIBUCION:
            continue
        llave = (p.programa.lower(), (p.version or "").lower())
        if llave in vistas:
            continue
        vistas.add(llave)
        filas.append(
            FilaInventario(
                equipo=nombre,
                programa=p.programa,
                version=p.version,
                proveedor=p.proveedor,
                sistema=sistema,
                fuente="agente",
                cargado=cargado,
            )
        )
    return filas


@dataclass
class Recibido:
    equipo_id: str
    nombre: str
    filas: int = 0
    paquetes: int = 0
    recortes: dict[str, int] = field(default_factory=dict)
    hallazgos_equipo: int = 0
    sin_revisar: list[str] = field(default_factory=list)
    cruce: dict[str, Any] | None = None
    trabajos: list[int] = field(default_factory=list)


def procesar(
    conexion: Any,
    equipo: Equipo,
    reporte: ReporteEquipo,
    recortes: dict[str, int] | None = None,
    ahora: datetime | None = None,
    cruzar: bool = True,
) -> Recibido:
    """Guarda el reporte, aplica las reglas de postura, cruza y deja los trabajos del worker.

    La fecha que cuenta es la del servidor: el reloj del equipo no es confiable.
    """
    ahora = ahora or datetime.now(UTC)
    recortes = dict(recortes or {})
    if not nombre_equipo_valido(reporte.nombre_equipo):
        recortes["nombre_saneado"] = 1
    nombre = almacen.nombre_libre(
        conexion, sanear_nombre_equipo(reporte.nombre_equipo, 0), equipo.id
    )

    almacen.guardar_reporte(
        conexion,
        equipo,
        nombre,
        reporte.agente_version,
        reporte.so,
        reporte.hardware,
        reporte.postura,
        recortes,
        ahora,
    )
    filas = filas_de_inventario(reporte, nombre, ahora)
    almacen.reemplazar_inventario(conexion, equipo.nombre, filas)
    paquetes = [p for p in reporte.software if p.fuente in FUENTES_DE_DISTRIBUCION]
    almacen.reemplazar_paquetes(conexion, equipo.id, paquetes)

    actual = almacen.leer_equipo(conexion, equipo.id)
    revision = postura.revisar(actual, ahora)
    almacen.reemplazar_hallazgos(conexion, equipo.id, postura.TIPOS, revision.hallazgos)

    recibido = Recibido(
        equipo_id=equipo.id,
        nombre=nombre,
        filas=len(filas),
        paquetes=len(paquetes),
        recortes=recortes,
        hallazgos_equipo=len(revision.hallazgos),
        sin_revisar=revision.sin_revisar,
    )
    if cruzar:
        from radar.equipos.cruce import recruzar

        recruce = recruzar(conexion)
        recibido.cruce = recruce.resultado.resumen | {"nuevos": len(recruce.nuevos)}
        # Solo se pide análisis si el reporte trajo hallazgos nuevos: dos reportes al día
        # por equipo no deben gastar créditos del modelo si nada cambió.
        if recruce.nuevos:
            recibido.trabajos.append(bd.crear_trabajo(conexion, "analizar", DETALLE_ANALISIS))
    if paquetes and not almacen.trabajo_pendiente(conexion, TRABAJO_SO, equipo.id):
        recibido.trabajos.append(bd.crear_trabajo(conexion, TRABAJO_SO, equipo.id))
    _marcar_planes(conexion, equipo.id)
    return recibido


def _marcar_planes(conexion: Any, equipo_id: str) -> None:
    """Planes de parcheo con resultado: este inventario es su verificación independiente.
    Un fallo aquí no puede tumbar la recepción del reporte (docs/plan-parcheo.md)."""
    from radar.equipos import parcheo_almacen

    try:
        parcheo_almacen.marcar_inventario_posterior(conexion, equipo_id, bd.ahora())
    except Exception as error:  # noqa: BLE001
        print(f"[radar] no se marcaron los planes de {equipo_id}: {error}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Aprobación en la consola
# ---------------------------------------------------------------------------


def recibir(
    conexion: Any,
    equipo: Equipo,
    reporte: ReporteEquipo,
    recortes: dict[str, int] | None = None,
    ahora: datetime | None = None,
) -> Recibido:
    """Punto de entrada de un reporte.

    Un equipo aprobado se procesa completo (`procesar`). Uno pendiente solo deja lo que
    TI necesita para decidir (nombre, sistema, hardware y postura) y guarda el reporte
    para cruzarlo al aprobar: su software no entra a `inventario` ni a los hallazgos. Así,
    quien consiga el token de inscripción solo puede crear equipos pendientes, no
    envenenar el inventario.
    """
    if not equipo.pendiente:
        return procesar(conexion, equipo, reporte, recortes, ahora)
    ahora = ahora or datetime.now(UTC)
    recortes = dict(recortes or {})
    if not nombre_equipo_valido(reporte.nombre_equipo):
        recortes["nombre_saneado"] = 1
    nombre = almacen.nombre_libre(
        conexion, sanear_nombre_equipo(reporte.nombre_equipo, 0), equipo.id
    )
    almacen.guardar_reporte(
        conexion,
        equipo,
        nombre,
        reporte.agente_version,
        reporte.so,
        reporte.hardware,
        reporte.postura,
        recortes,
        ahora,
    )
    guardado = json.dumps(
        {"reporte": reporte.model_dump(mode="json"), "recortes": recortes}, ensure_ascii=False
    )
    almacen.guardar_reporte_pendiente(conexion, equipo.id, guardado)
    return Recibido(equipo_id=equipo.id, nombre=nombre, recortes=recortes)


class ErrorAprobacion(ValueError):
    """El equipo no existe, está revocado o ya estaba aprobado."""


def aprobar(
    conexion: Any, equipo_id: str, por: str, ahora: datetime | None = None
) -> Recibido | None:
    """Una persona aprueba un equipo pendiente. Si ya había reportado, su último reporte
    se procesa y se cruza en ese momento; si no, entra con el próximo reporte."""
    if not por or not por.strip():
        raise ValueError("La aprobación la hace una persona: falta quién aprueba ('por')")
    guardado = almacen.leer_reporte_pendiente(conexion, equipo_id)
    if not almacen.marcar_aprobado(conexion, equipo_id, por.strip()):
        raise ErrorAprobacion(equipo_id)
    if not guardado:
        return None
    datos = json.loads(guardado)
    reporte = ReporteEquipo.model_validate(datos["reporte"])
    equipo = almacen.leer_equipo(conexion, equipo_id)
    return procesar(conexion, equipo, reporte, datos.get("recortes"), ahora)
