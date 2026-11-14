"""Cruce completo cuando hay equipos con agente local.

Sin agentes, una carga de inventario cruza solo lo que trae el archivo (como siempre).
Con agentes, el inventario tiene dos orígenes (archivos y reportes) y además el sistema
operativo de cada equipo, así que se cruza todo junto: si se cruzara solo una parte, la
corrida propondría como resueltos los hallazgos de la otra.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from radar import bd
from radar.config import Umbrales
from radar.equipos import almacen, so
from radar.nucleo.corrida import ResultadoCruce, correr


@dataclass
class Recruce:
    resultado: ResultadoCruce
    nuevos: list[str] = field(default_factory=list)  # ids de hallazgos que no existían


def recruzar(conexion: Any, usar_modelo: bool = False, umbrales: Umbrales | None = None) -> Recruce:
    """Normaliza todo el inventario guardado, agrega el sistema operativo de los equipos
    con agente y corre el cruce del núcleo."""
    from radar.ingesta.normalizador import normalizar

    filas = bd.leer_inventario(conexion)
    normalizacion = normalizar(filas, usar_modelo=usar_modelo)
    bd.guardar_decisiones_cpe(conexion, normalizacion.decisiones.values())
    activos = normalizacion.activos + so.activos_de_so(almacen.leer_equipos(conexion))
    antes = {h.id for h in bd.leer_hallazgos(conexion)}
    resultado = correr(conexion, activos, normalizacion.cobertura, umbrales)
    nuevos = sorted({h.id for h in resultado.hallazgos} - antes)
    return Recruce(resultado, nuevos)
