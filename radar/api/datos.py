"""Origen de los datos que sirve la API.

Dos implementaciones con los mismos métodos:

- `DatosBase`: lee y escribe en la base con `radar/bd.py` (Turso si hay `TURSO_DATABASE_URL`
  y `TURSO_AUTH_TOKEN`, si no el sqlite local).
- `DatosEjemplo`: lee `radar/ejemplos.py` y guarda los cambios en memoria del proceso (en una
  función de Vercel se pierden entre invocaciones), por eso responde `persistente: False`.

`obtener_datos()` usa la base si Turso está configurado o si `RADAR_DATOS=base`; con
`RADAR_DATOS=ejemplos` fuerza los ejemplos.
"""

from __future__ import annotations

import os
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime

from radar import config, ejemplos
from radar.contratos import (
    ORDEN_PRIORIDAD,
    Analisis,
    Cobertura,
    Ejecucion,
    EstadoHallazgo,
    Grupo,
    Hallazgo,
)


def _armar_resumen(
    hallazgos: list[Hallazgo],
    cobertura: list[Cobertura],
    cruzados: int,
    ejecucion: Ejecucion | None,
    persistente: bool,
) -> dict:
    fuentes = dict(ejecucion.fuentes) if ejecucion else {}
    return {
        "revision": {
            "inicio": ejecucion.inicio if ejecucion else None,
            "fin": ejecucion.fin if ejecucion else None,
            "fuentes": fuentes,
            "caidas": [nombre for nombre, ok in fuentes.items() if not ok],
            "error": ejecucion.error if ejecucion else None,
        },
        "cifras": {
            "exigen_accion": sum(1 for h in hallazgos if h.prioridad == "inmediato"),
            "explotadas": len({h.cve for h in hallazgos if h.kev}),
            "semanal": sum(1 for h in hallazgos if h.prioridad == "semanal"),
            "equipos_afectados": len({e for h in hallazgos for e in h.equipos}),
        },
        "cobertura": {
            "cruzados": cruzados,
            "sin_evaluar": len(cobertura),
            "por_motivo": dict(Counter(c.motivo for c in cobertura)),
            "detalle": [c.model_dump() for c in cobertura[:200]],
        },
        "persistente": persistente,
    }


def _filtrar(
    lista: Iterable[Hallazgo], prioridad: str | None, kev: bool | None, texto: str | None
) -> list[Hallazgo]:
    lista = list(lista)
    if prioridad:
        lista = [h for h in lista if h.prioridad == prioridad]
    if kev is not None:
        lista = [h for h in lista if h.kev == kev]
    if texto:
        t = texto.casefold()
        lista = [
            h
            for h in lista
            if t in h.cve.casefold()
            or t in h.producto.casefold()
            or any(t in e.casefold() for e in h.equipos)
        ]
    return sorted(
        lista, key=lambda h: (ORDEN_PRIORIDAD[h.prioridad], not h.kev, -(h.cvss or 0.0), h.cve)
    )


def _ordenar_grupos(grupos: Iterable[Grupo]) -> list[Grupo]:
    return sorted(
        grupos,
        key=lambda g: (
            ORDEN_PRIORIDAD.get(g.prioridad or "boletin", 9),
            -len(g.en_kev),
            -(g.peor_cvss or 0.0),
        ),
    )


def _registro_aprobacion(producto: str, por: str | None) -> dict:
    return {"producto": producto, "por": por, "aprobado": datetime.now(UTC)}


class DatosEjemplo:
    persistente = False
    origen = "ejemplos"

    def __init__(self) -> None:
        self._hallazgos = {h.id: h.model_copy(deep=True) for h in ejemplos.HALLAZGOS}
        self._grupos = {g.producto: g for g in ejemplos.GRUPOS}
        self._analisis = {a.producto: a for a in ejemplos.ANALISIS if a.producto}
        self._aprobados: dict[str, dict] = {}

    def resumen(self) -> dict:
        ejecucion = ejemplos.EJECUCIONES[-1] if ejemplos.EJECUCIONES else None
        return _armar_resumen(
            list(self._hallazgos.values()),
            list(ejemplos.COBERTURA),
            len(ejemplos.ACTIVOS),
            ejecucion,
            self.persistente,
        )

    def hallazgos(self, prioridad=None, kev=None, texto=None) -> list[Hallazgo]:
        return _filtrar(self._hallazgos.values(), prioridad, kev, texto)

    def productos(self) -> list[Grupo]:
        return _ordenar_grupos(self._grupos.values())

    def grupo(self, producto: str) -> Grupo | None:
        return self._grupos.get(producto)

    def analisis(self, producto: str) -> Analisis | None:
        return self._analisis.get(producto)

    def aprobacion(self, producto: str) -> dict | None:
        return self._aprobados.get(producto)

    def cambiar_estado(
        self, id_hallazgo: str, estado: EstadoHallazgo, comentario: str | None, por: str | None
    ) -> Hallazgo | None:
        actual = self._hallazgos.get(id_hallazgo)
        if actual is None:
            return None
        nuevo = actual.model_copy(update={"estado": estado, "comentario": comentario, "por": por})
        self._hallazgos[id_hallazgo] = nuevo
        return nuevo

    def aprobar(self, producto: str, por: str | None) -> dict | None:
        # Basta con que el producto tenga hallazgos: sin análisis del agente se aprueba el
        # texto de respaldo.
        if producto not in self._grupos:
            return None
        self._aprobados[producto] = _registro_aprobacion(producto, por)
        return self._aprobados[producto]

    def trazas(self) -> list[dict] | None:
        return None

    def umbrales(self) -> dict:
        from radar.nucleo.umbrales import barrido

        return barrido(self._hallazgos.values())

    def encolar(self, tipo: str, detalle: str | None = None) -> int | None:
        return None


class DatosBase:
    """Lee y escribe con radar/bd.py. Abre una conexión por llamada: en Vercel cada
    invocación puede caer en un proceso distinto y turso_serverless va por HTTP."""

    persistente = True
    origen = "base"

    def _conexion(self, solo_lectura: bool = True):
        from radar import bd

        return bd, bd.conectar(solo_lectura=solo_lectura)

    def resumen(self) -> dict:
        bd, c = self._conexion()
        try:
            hallazgos = bd.leer_hallazgos(c)
            cobertura = bd.leer_cobertura(c)
            filas = bd.contar(c, "inventario")
            ejecucion = bd.ultima_ejecucion(c)
        finally:
            c.close()
        return _armar_resumen(
            hallazgos, cobertura, max(filas - len(cobertura), 0), ejecucion, self.persistente
        )

    def hallazgos(self, prioridad=None, kev=None, texto=None) -> list[Hallazgo]:
        bd, c = self._conexion()
        try:
            return _filtrar(bd.leer_hallazgos(c), prioridad, kev, texto)
        finally:
            c.close()

    def productos(self) -> list[Grupo]:
        bd, c = self._conexion()
        try:
            return _ordenar_grupos(bd.leer_grupos(c))
        finally:
            c.close()

    def grupo(self, producto: str) -> Grupo | None:
        return next((g for g in self.productos() if g.producto == producto), None)

    def analisis(self, producto: str) -> Analisis | None:
        bd, c = self._conexion()
        try:
            lista = bd.leer_analisis(c, producto)
        finally:
            c.close()
        return lista[0] if lista else None

    def aprobacion(self, producto: str) -> dict | None:
        bd, c = self._conexion()
        try:
            fila = bd.leer_aprobacion(c, producto)
        finally:
            c.close()
        if not fila:
            return None
        return {"producto": producto, "por": fila["aprobado_por"], "aprobado": fila["aprobado"]}

    def cambiar_estado(
        self, id_hallazgo: str, estado: EstadoHallazgo, comentario: str | None, por: str | None
    ) -> Hallazgo | None:
        bd, c = self._conexion(solo_lectura=False)
        try:
            if not bd.cambiar_estado(c, id_hallazgo, estado, por or "panel", comentario):
                return None
            return next((h for h in bd.leer_hallazgos(c) if h.id == id_hallazgo), None)
        finally:
            c.close()

    def aprobar(self, producto: str, por: str) -> dict | None:
        grupo = self.grupo(producto)
        if grupo is None:
            return None
        bd, c = self._conexion(solo_lectura=False)
        try:
            if not bd.leer_analisis(c, producto):
                # Sin análisis del agente se aprueba el texto de respaldo que se mostró: se
                # guarda primero para que quede constancia de qué se aprobó.
                from radar.agente.respaldo import armar_respaldo

                bd.guardar_analisis(c, armar_respaldo(grupo))
            if not bd.aprobar_comunicado(c, producto, por):
                return None
        finally:
            c.close()
        return self.aprobacion(producto)

    def trazas(self, limite: int = 100) -> list[dict]:
        bd, c = self._conexion()
        try:
            return bd.leer_trazas(c, limite)
        finally:
            c.close()

    def umbrales(self) -> dict:
        from radar.nucleo.umbrales import barrido_guardado

        _bd, c = self._conexion()
        try:
            return barrido_guardado(c)
        finally:
            c.close()

    def encolar(self, tipo: str, detalle: str | None = None) -> int | None:
        bd, c = self._conexion(solo_lectura=False)
        try:
            return bd.crear_trabajo(c, tipo, detalle)
        finally:
            c.close()


_datos: DatosEjemplo | DatosBase | None = None


def usar_base() -> bool:
    eleccion = os.environ.get("RADAR_DATOS", "").strip().lower()
    if eleccion in ("base", "ejemplos"):
        return eleccion == "base"
    return config.turso() is not None


def obtener_datos() -> DatosEjemplo | DatosBase:
    global _datos
    if _datos is None:
        _datos = DatosBase() if usar_base() else DatosEjemplo()
    return _datos
