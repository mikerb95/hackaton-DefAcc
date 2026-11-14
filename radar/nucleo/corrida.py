"""Corrida completa del cruce: activos -> hallazgos, cobertura y grupos.

- `cruzar()` es pura: recibe activos, CVE y señales y devuelve el resultado.
- `correr()` lee de la base, cruza, guarda y propone cierres. Se usa al cargar un inventario
  nuevo (cruce contra todas las CVE ya guardadas, no solo las nuevas) y después de cada descarga.

Cierre automático: un hallazgo abierto que ya no aparece (el equipo dejó de tener la versión
afectada) se *propone* como resuelto en `propuestos_resueltos`. Nunca se cambia su estado:
la decisión humana manda.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from radar import bd
from radar.config import Umbrales
from radar.contratos import CVE, Activo, Cobertura, Grupo, Hallazgo, Senales
from radar.nucleo.agrupar import ESTADOS_CERRADOS, agrupar
from radar.nucleo.cruce import cruzar_activo
from radar.nucleo.prioridad import hallazgos_de_activo, ordenar


@dataclass
class ResultadoCruce:
    hallazgos: list[Hallazgo]
    cobertura: list[Cobertura]
    grupos: list[Grupo]
    propuestos_resueltos: list[str] = field(default_factory=list)

    @property
    def resumen(self) -> dict[str, int]:
        return {
            "hallazgos": len(self.hallazgos),
            "precisos": sum(1 for h in self.hallazgos if h.preciso),
            "en_kev": len({h.cve for h in self.hallazgos if h.kev}),
            "productos": len(self.grupos),
            "cobertura": len(self.cobertura),
            "propuestos_resueltos": len(self.propuestos_resueltos),
        }


def cruzar(
    activos: Iterable[Activo],
    cves: Iterable[CVE],
    senales: Senales,
    umbrales: Umbrales | None = None,
    detectado: datetime | None = None,
    cobertura_previa: Iterable[Cobertura] = (),
) -> ResultadoCruce:
    """Cruza activos contra CVE. `cobertura_previa` son las filas que el normalizador ya dejó
    fuera (sin CPE, por ejemplo) y se suman a la cobertura del resultado."""
    umbrales = umbrales or Umbrales.desde_entorno()
    detectado = detectado or datetime.now(UTC)
    lista_cves = list(cves)
    hallazgos: list[Hallazgo] = []
    cobertura = list(cobertura_previa)
    for activo in activos:
        r = cruzar_activo(activo, lista_cves)
        cobertura += r.cobertura
        hallazgos += hallazgos_de_activo(activo, r, senales, umbrales, detectado)
    return ResultadoCruce(
        hallazgos=ordenar(hallazgos),
        cobertura=cobertura,
        grupos=agrupar(hallazgos, umbrales),
    )


def correr(
    conexion: Any,
    activos: Iterable[Activo],
    cobertura_previa: Iterable[Cobertura] = (),
    umbrales: Umbrales | None = None,
    guardar: bool = True,
) -> ResultadoCruce:
    """Lee CVE y señales de la base, cruza y guarda hallazgos y cobertura."""
    lista = list(activos)
    pares = {p for a in lista for p in a.cpes}
    cves = bd.leer_cves(conexion, pares) if pares else []
    senales = bd.leer_senales(conexion, [c.id for c in cves])
    resultado = cruzar(lista, cves, senales, umbrales, cobertura_previa=cobertura_previa)

    nuevos = {h.id for h in resultado.hallazgos}
    resultado.propuestos_resueltos = sorted(
        h.id
        for h in bd.leer_hallazgos(conexion)
        if h.id not in nuevos and h.estado not in ESTADOS_CERRADOS
    )
    if guardar:
        bd.guardar_hallazgos(conexion, resultado.hallazgos)
        bd.guardar_cobertura(conexion, resultado.cobertura)
        # Los grupos se recalculan con el estado humano que ya estaba en la base.
        resultado.grupos = agrupar(
            [h for h in bd.leer_hallazgos(conexion) if h.id in nuevos], umbrales
        )
    return resultado
