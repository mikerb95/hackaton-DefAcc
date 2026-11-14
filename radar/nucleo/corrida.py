"""Corrida completa del cruce y reglas de aviso (PLAN, sección 8).

- `cruzar()` es pura: recibe activos, CVE y señales y devuelve el resultado.
- `correr()` lee de la base, cruza, guarda y aplica las reglas de corrida. Se usa al cargar un
  inventario nuevo (cruce contra todas las CVE ya guardadas, no solo las nuevas) y después de
  cada descarga.

Reglas de corrida:
- **El estado solo lo cambia una persona** (`bd.cambiar_estado`, con quién y comentario). La
  corrida actualiza los datos de la CVE y nunca pisa estado, comentario ni quién.
- **Cierre automático propuesto:** un hallazgo abierto que ya no aparece (el equipo dejó de
  tener la versión afectada) queda con `propuesto_resuelto` y sale en `propuestos_resueltos`.
  Su estado no cambia: lo cierra una persona.
- **Línea base silenciosa:** en la primera corrida (base sin hallazgos) todo lo acumulado queda
  como ya avisado, salvo lo reciente: CVE publicadas o agregadas a KEV en los últimos
  `VENTANA_LINEA_BASE` días. Así la primera carga no dispara cientos de avisos, pero lo que
  se está explotando esta semana sí se avisa.
- **Sin repetir avisos:** `pendientes_de_aviso()` devuelve solo lo no avisado, agrupado por
  producto (una acción por producto). Se marca con `marcar_avisado()` o al aprobar el
  comunicado (`bd.aprobar_comunicado`). Un hallazgo que sube a "inmediato" (por ejemplo, entra a
  KEV) se vuelve a avisar.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from radar import bd
from radar.config import Umbrales
from radar.contratos import CVE, Activo, Cobertura, Grupo, Hallazgo, Prioridad, Senales
from radar.nucleo.agrupar import ESTADOS_CERRADOS, agrupar
from radar.nucleo.cruce import candidatas, cruzar_activo, indexar
from radar.nucleo.prioridad import hallazgos_de_activo, ordenar

VENTANA_LINEA_BASE = timedelta(days=7)


@dataclass
class ResultadoCruce:
    hallazgos: list[Hallazgo]
    cobertura: list[Cobertura]
    grupos: list[Grupo]
    propuestos_resueltos: list[str] = field(default_factory=list)
    linea_base: bool = False
    silenciados: int = 0

    @property
    def resumen(self) -> dict[str, int | bool]:
        return {
            "hallazgos": len(self.hallazgos),
            "precisos": sum(1 for h in self.hallazgos if h.preciso),
            "en_kev": len({h.cve for h in self.hallazgos if h.kev}),
            "productos": len(self.grupos),
            "cobertura": len(self.cobertura),
            "propuestos_resueltos": len(self.propuestos_resueltos),
            "linea_base": self.linea_base,
            "silenciados": self.silenciados,
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
    indice = indexar(cves)
    hallazgos: list[Hallazgo] = []
    cobertura = list(cobertura_previa)
    for activo in activos:
        r = cruzar_activo(activo, candidatas(indice, activo.cpes))
        cobertura += r.cobertura
        hallazgos += hallazgos_de_activo(activo, r, senales, umbrales, detectado)
    return ResultadoCruce(
        hallazgos=ordenar(hallazgos),
        cobertura=cobertura,
        grupos=agrupar(hallazgos, umbrales),
    )


def cves_recientes(
    cves: Iterable[CVE], senales: Senales, ahora: datetime, ventana: timedelta
) -> set[str]:
    """CVE publicadas o agregadas a KEV dentro de la ventana: no se silencian en la línea base."""
    corte = ahora - ventana
    corte_dia: date = corte.date()
    recientes = {c.id for c in cves if c.publicada is not None and c.publicada >= corte}
    recientes |= {
        k.cve for k in senales.kev.values() if k.agregada is not None and k.agregada >= corte_dia
    }
    return recientes


def correr(
    conexion: Any,
    activos: Iterable[Activo],
    cobertura_previa: Iterable[Cobertura] = (),
    umbrales: Umbrales | None = None,
    guardar: bool = True,
    ahora: datetime | None = None,
    ventana_linea_base: timedelta = VENTANA_LINEA_BASE,
) -> ResultadoCruce:
    """Lee CVE y señales de la base, cruza y guarda aplicando las reglas de corrida."""
    ahora = ahora or datetime.now(UTC)
    lista = list(activos)
    pares = {p for a in lista for p in a.cpes}
    # Dos consultas para CVE y rangos, y dos para señales: en Turso cada una es una petición.
    cves = bd.leer_cves(conexion, pares, completas=False) if pares else []
    senales = bd.leer_senales(conexion, pares=pares) if pares else Senales()
    resultado = cruzar(lista, cves, senales, umbrales, ahora, cobertura_previa)

    anteriores = bd.leer_hallazgos(conexion)
    nuevos = {h.id for h in resultado.hallazgos}
    resultado.propuestos_resueltos = sorted(
        h.id for h in anteriores if h.id not in nuevos and h.estado not in ESTADOS_CERRADOS
    )
    resultado.linea_base = not anteriores
    if not guardar:
        return resultado

    bd.guardar_hallazgos(conexion, resultado.hallazgos)
    bd.marcar_propuestos(conexion, resultado.propuestos_resueltos)
    bd.guardar_cobertura(conexion, resultado.cobertura)

    if resultado.linea_base:
        recientes = cves_recientes(cves, senales, ahora, ventana_linea_base)
        silenciar = [h.id for h in resultado.hallazgos if h.cve not in recientes]
        bd.marcar_avisados(conexion, silenciar)
        resultado.silenciados = len(silenciar)

    # Se releen para que hallazgos y grupos traigan el estado humano y las marcas de aviso.
    guardados = {h.id: h for h in bd.leer_hallazgos(conexion) if h.id in nuevos}
    resultado.hallazgos = ordenar(guardados.values())
    resultado.grupos = agrupar(resultado.hallazgos, umbrales)
    return resultado


# ---------------------------------------------------------------------------
# Avisos
# ---------------------------------------------------------------------------


def _pendientes(hallazgos: Iterable[Hallazgo], prioridades: Iterable[Prioridad]) -> list[Hallazgo]:
    quiero = set(prioridades)
    return [
        h
        for h in hallazgos
        if not h.avisado
        and h.preciso
        and h.prioridad in quiero
        and h.estado not in ESTADOS_CERRADOS
        and not h.propuesto_resuelto
    ]


def pendientes_de_aviso(
    conexion: Any = None,
    prioridades: Iterable[Prioridad] = ("inmediato",),
    umbrales: Umbrales | None = None,
) -> list[Grupo]:
    """Lo que falta avisar, agrupado por producto. Por defecto, solo lo inmediato; el resumen
    semanal pide `prioridades=("semanal",)`. Los no precisos nunca generan aviso."""
    return agrupar(_pendientes(bd.leer_hallazgos(conexion), prioridades), umbrales)


def marcar_avisado(
    conexion: Any, producto: str, prioridades: Iterable[Prioridad] = ("inmediato",)
) -> int:
    """Marca como avisados los pendientes de un producto. Devuelve cuántos marcó."""
    ids = [h.id for h in _pendientes(bd.leer_hallazgos(conexion, producto), prioridades)]
    bd.marcar_avisados(conexion, ids)
    return len(ids)


# ---------------------------------------------------------------------------
# Carga completa de un inventario: lector -> normalizador -> cruce
# ---------------------------------------------------------------------------


def cargar_inventario(
    conexion: Any,
    origen: Any,
    nombre: str | None = None,
    usar_modelo: bool = False,
    umbrales: Umbrales | None = None,
) -> tuple[Any, Any, ResultadoCruce]:
    """Lee un archivo de inventario, lo normaliza, lo guarda y lo cruza (todo el inventario
    guardado si hay equipos con agente local; si no, solo el archivo).

    Devuelve (lectura, normalizacion, resultado). Por defecto sin el desempate con Claude, para
    que la base compartida sea reproducible; `usar_modelo=True` lo activa.
    """
    from radar.ingesta.archivos import a_contrato, leer_inventario
    from radar.ingesta.normalizador import normalizar

    bd.crear_esquema(conexion)
    lectura = leer_inventario(origen, nombre)
    filas = [a_contrato(f) for f in lectura.filas]
    normalizacion = normalizar(filas, usar_modelo=usar_modelo)
    bd.guardar_inventario(conexion, filas, reemplazar=True)

    # Con agentes locales inscritos el inventario tiene dos orígenes (archivo y reportes) más
    # el sistema operativo de cada equipo: se cruza todo junto. Cruzar solo el archivo
    # propondría como resueltos los hallazgos que vienen de los agentes.
    from radar.equipos import almacen

    if almacen.hay_equipos(conexion):
        from radar.equipos.cruce import recruzar

        resultado = recruzar(conexion, usar_modelo=usar_modelo, umbrales=umbrales).resultado
    else:
        bd.guardar_decisiones_cpe(conexion, normalizacion.decisiones.values())
        resultado = correr(conexion, normalizacion.activos, normalizacion.cobertura, umbrales)
    return lectura, normalizacion, resultado


def principal(argv: list[str] | None = None) -> int:
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser(description="Carga un inventario y corre el cruce")
    p.add_argument("archivo", type=Path, help="CSV o Excel de inventario")
    p.add_argument(
        "--con-modelo", action="store_true", help="Desempate del normalizador con Claude"
    )
    p.add_argument("--sqlite", type=Path, help="Fuerza un sqlite local en esta ruta")
    args = p.parse_args(argv)

    conexion = bd.conectar(ruta_sqlite=args.sqlite)
    try:
        if bd.contar(conexion, "cves") == 0:
            print("[corrida] La base no tiene CVE: corre antes worker.descargar", flush=True)
            return 1
        lectura, normalizacion, r = cargar_inventario(
            conexion, args.archivo, usar_modelo=args.con_modelo
        )
        epss = bd.contar(conexion, "epss")
    finally:
        conexion.close()
    print(f"[corrida] lectura: {lectura.resumen()}", flush=True)
    print(
        f"[corrida] normalizador: {len(normalizacion.activos)} activos, "
        f"{len(normalizacion.cobertura)} filas a cobertura",
        flush=True,
    )
    print(f"[corrida] cruce: {r.resumen}", flush=True)
    if epss == 0:
        print("[corrida] AVISO: la base no tiene EPSS; las prioridades no lo usan", flush=True)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(principal())
