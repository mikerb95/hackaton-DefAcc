"""Origen de los datos que sirve la API.

Hoy lee `radar/ejemplos.py`; cuando `radar/bd.py` esté listo, otra clase con los mismos
métodos leerá de Turso y `obtener_datos()` elegirá según haya o no `TURSO_DATABASE_URL`.

Los cambios de estado y aprobaciones de esta versión viven en memoria del proceso: en una
función de Vercel se pierden entre invocaciones. Por eso las respuestas llevan
`persistente: False` hasta que haya base.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from radar import ejemplos
from radar.contratos import ORDEN_PRIORIDAD, Analisis, EstadoHallazgo, Grupo, Hallazgo


class DatosEjemplo:
    persistente = False

    def __init__(self) -> None:
        self._hallazgos = {h.id: h.model_copy(deep=True) for h in ejemplos.HALLAZGOS}
        self._grupos = {g.producto: g for g in ejemplos.GRUPOS}
        self._analisis = {a.producto: a for a in ejemplos.ANALISIS if a.producto}
        self._aprobados: dict[str, dict] = {}

    # -- lectura ---------------------------------------------------------------

    def resumen(self) -> dict:
        hallazgos = list(self._hallazgos.values())
        ejecucion = ejemplos.EJECUCIONES[-1] if ejemplos.EJECUCIONES else None
        fuentes = dict(ejecucion.fuentes) if ejecucion else {}
        motivos = Counter(c.motivo for c in ejemplos.COBERTURA)
        equipos = {e for h in hallazgos for e in h.equipos}
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
                "equipos_afectados": len(equipos),
            },
            "cobertura": {
                "cruzados": len(ejemplos.ACTIVOS),
                "sin_evaluar": len(ejemplos.COBERTURA),
                "por_motivo": dict(motivos),
                "detalle": [c.model_dump() for c in ejemplos.COBERTURA],
            },
            "persistente": self.persistente,
        }

    def hallazgos(
        self,
        prioridad: str | None = None,
        kev: bool | None = None,
        texto: str | None = None,
    ) -> list[Hallazgo]:
        lista = list(self._hallazgos.values())
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
            lista,
            key=lambda h: (ORDEN_PRIORIDAD[h.prioridad], not h.kev, -(h.cvss or 0.0), h.cve),
        )

    def productos(self) -> list[Grupo]:
        return sorted(
            self._grupos.values(),
            key=lambda g: (
                ORDEN_PRIORIDAD.get(g.prioridad or "boletin", 9),
                -len(g.en_kev),
                -(g.peor_cvss or 0.0),
            ),
        )

    def grupo(self, producto: str) -> Grupo | None:
        return self._grupos.get(producto)

    def analisis(self, producto: str) -> Analisis | None:
        return self._analisis.get(producto)

    def aprobacion(self, producto: str) -> dict | None:
        return self._aprobados.get(producto)

    # -- escritura (en memoria hasta que haya Turso) ---------------------------

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
        if producto not in self._analisis:
            return None
        registro = {"producto": producto, "por": por, "aprobado": datetime.now(UTC)}
        self._aprobados[producto] = registro
        return registro


_datos: DatosEjemplo | None = None


def obtener_datos() -> DatosEjemplo:
    global _datos
    if _datos is None:
        _datos = DatosEjemplo()
    return _datos
