"""Agrupación por producto para comunicar (PLAN, sección 8). Una acción por producto."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from radar.config import Umbrales
from radar.contratos import ORDEN_PRIORIDAD, Grupo, Hallazgo
from radar.nucleo.cruce import objetivo_de_producto, objetivo_de_rango
from radar.nucleo.prioridad import RAZON_RANSOMWARE, gravedad, razon_epss
from radar.nucleo.versiones import leer

# Estados que ya no se comunican: la decisión humana manda.
ESTADOS_CERRADOS = frozenset({"mitigado", "descartado"})


def _orden_version(texto: str) -> tuple[int, object]:
    v = leer(texto)
    return (0, v) if v is not None else (1, texto)


def agrupar_producto(
    producto: str, hallazgos: list[Hallazgo], umbrales: Umbrales | None = None
) -> Grupo:
    umbrales = umbrales or Umbrales()
    versiones = sorted({h.version_instalada for h in hallazgos}, key=_orden_version)
    equipos = sorted({e for h in hallazgos for e in h.equipos})
    cves = sorted({h.cve for h in hallazgos})
    en_kev = sorted({h.cve for h in hallazgos if h.kev})
    ransomware = any(h.ransomware for h in hallazgos)
    cvss = [h.cvss for h in hallazgos if h.cvss is not None]
    epss = [h.epss for h in hallazgos if h.epss is not None]
    peor_cvss = max(cvss) if cvss else None
    peor_epss = max(epss) if epss else None
    no_precisas = sorted({h.cve for h in hallazgos if not h.preciso})

    objetivo = objetivo_de_producto(
        objetivo_de_rango(h.rango if h.preciso else None) for h in hallazgos
    )
    prioridad = min((h.prioridad for h in hallazgos), key=ORDEN_PRIORIDAD.__getitem__)

    razones: list[str] = []
    if en_kev:
        razones.append(f"{len(en_kev)} CVE con explotación confirmada en el mundo real (CISA KEV)")
    if ransomware:
        razones.append(RAZON_RANSOMWARE)
    if peor_epss is not None and peor_epss >= umbrales.epss:
        razones.append(razon_epss(peor_epss))
    if peor_cvss is not None:
        razones.append(f"Peor gravedad {gravedad(peor_cvss)}, CVSS {peor_cvss:.1f}")
    if no_precisas:
        razones.append(
            f"{len(no_precisas)} CVE sin versión en NVD (no precisas): hay que confirmarlas a mano"
        )
    if objetivo.tipo == "posterior_a":
        razones.append(
            f"NVD solo dice que está afectada hasta {objetivo.version} inclusive: "
            "no hay versión de arreglo exacta"
        )

    return Grupo(
        producto=producto,
        versiones=versiones,
        equipos=equipos,
        cves=cves,
        en_kev=en_kev,
        ransomware=ransomware,
        peor_cvss=peor_cvss,
        peor_epss=peor_epss,
        version_objetivo=objetivo.version,
        tipo_objetivo=objetivo.tipo,
        prioridad=prioridad,
        por_que=razones,
    )


def clave_orden(g: Grupo) -> tuple[int, int, float, str]:
    prioridad = ORDEN_PRIORIDAD[g.prioridad] if g.prioridad else len(ORDEN_PRIORIDAD)
    cvss = g.peor_cvss if g.peor_cvss is not None else -1.0
    return (prioridad, -len(g.en_kev), -cvss, g.producto)


def agrupar(
    hallazgos: Iterable[Hallazgo],
    umbrales: Umbrales | None = None,
    incluir_cerrados: bool = False,
) -> list[Grupo]:
    """Agrupa hallazgos por producto, ordenados por prioridad, KEV y peor CVSS.

    Por defecto deja fuera los hallazgos mitigados o descartados por una persona.
    """
    por_producto: dict[str, list[Hallazgo]] = defaultdict(list)
    for h in hallazgos:
        if not incluir_cerrados and h.estado in ESTADOS_CERRADOS:
            continue
        por_producto[h.producto].append(h)
    grupos = [agrupar_producto(p, hs, umbrales) for p, hs in por_producto.items()]
    return sorted(grupos, key=clave_orden)
