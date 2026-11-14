"""Barrido de umbrales para `GET /api/umbrales` y para evals/umbrales.py.

Con los hallazgos ya calculados, cuenta cuántas alertas inmediatas saldrían para cada
combinación de umbral de EPSS y de CVSS. KEV es inmediato siempre, sin importar los umbrales,
así que esas alertas son el piso de la gráfica.

Solo cuentan los hallazgos precisos y abiertos: los no precisos nunca son inmediatos y lo
mitigado o descartado ya no se avisa. Un EPSS ausente no cruza ningún umbral (no es cero, pero
tampoco se le supone un valor).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from radar import bd
from radar.config import Umbrales
from radar.contratos import Hallazgo
from radar.nucleo.agrupar import ESTADOS_CERRADOS

REJILLA_EPSS: tuple[float, ...] = (0.01, 0.02, 0.05, 0.10, 0.20, 0.30, 0.50, 0.70, 0.90, 1.01)
REJILLA_CVSS: tuple[float, ...] = (7.0, 7.5, 8.0, 8.5, 9.0, 9.5, 10.0, 10.1)
# 1.01 y 10.1 son "apagado": ningún valor real llega, así se ve qué aporta cada señal sola.


def es_inmediato(h: Hallazgo, umbral_epss: float, umbral_cvss: float) -> bool:
    if h.kev:
        return True
    if h.epss is not None and h.epss >= umbral_epss:
        return True
    return h.cvss is not None and h.cvss >= umbral_cvss


def _contar(hallazgos: Sequence[Hallazgo], umbral_epss: float, umbral_cvss: float) -> dict:
    alertas = [h for h in hallazgos if es_inmediato(h, umbral_epss, umbral_cvss)]
    return {
        "epss": umbral_epss,
        "cvss": umbral_cvss,
        "hallazgos": len(alertas),
        "productos": len({h.producto for h in alertas}),
        "cves": len({h.cve for h in alertas}),
        "equipos": len({e for h in alertas for e in h.equipos}),
    }


def barrido(
    hallazgos: Iterable[Hallazgo],
    rejilla_epss: Sequence[float] = REJILLA_EPSS,
    rejilla_cvss: Sequence[float] = REJILLA_CVSS,
    umbrales: Umbrales | None = None,
) -> dict[str, Any]:
    """Cuenta alertas inmediatas para cada par (EPSS, CVSS) de la rejilla.

    Devuelve un dict listo para JSON:
    - `celdas`: una por combinación, con hallazgos, productos (= comunicados, uno por
      producto), CVE y equipos alertados.
    - `solo_kev`: el piso, lo que es inmediato por KEV con cualquier umbral.
    - `actual`: la celda de los umbrales vigentes (variables de entorno).
    - `total`: hallazgos precisos y abiertos considerados.
    """
    umbrales = umbrales or Umbrales.desde_entorno()
    base = [h for h in hallazgos if h.preciso and h.estado not in ESTADOS_CERRADOS]
    kev = [h for h in base if h.kev]
    return {
        "rejilla_epss": list(rejilla_epss),
        "rejilla_cvss": list(rejilla_cvss),
        "celdas": [_contar(base, e, c) for e in rejilla_epss for c in rejilla_cvss],
        "solo_kev": {
            "hallazgos": len(kev),
            "productos": len({h.producto for h in kev}),
            "cves": len({h.cve for h in kev}),
            "equipos": len({e for h in kev for e in h.equipos}),
        },
        "actual": _contar(base, umbrales.epss, umbrales.cvss_inmediato),
        "total": len(base),
        "sin_epss": sum(1 for h in base if h.epss is None),
    }


def barrido_guardado(conexion: Any = None, **kwargs: Any) -> dict[str, Any]:
    """Barrido sobre los hallazgos guardados en la base."""
    return barrido(bd.leer_hallazgos(conexion), **kwargs)
