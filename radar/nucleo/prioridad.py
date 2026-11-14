"""Priorización en cuatro niveles y razones en texto (PLAN, sección 8).

| Prioridad   | Regla                                                                  |
|-------------|------------------------------------------------------------------------|
| inmediato   | Afecta algo propio y está en KEV, o EPSS >= 0.10, o CVSS >= 9.0         |
| semanal     | Afecta algo propio y CVSS >= 7.0, sin señal de explotación              |
| informativo | Afecta algo propio, sin lo anterior                                    |
| boletin     | Está en KEV pero no empareja con ningún activo                         |

Decisión del núcleo: un hallazgo no preciso (NVD no acota versión) queda en "informativo"
aunque tenga KEV o CVSS alto. Sus razones lo dicen y una persona decide. Sin esto, cada
versión sana de Chrome tendría 13 avisos inmediatos que no se pueden confirmar.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import date, datetime

from radar.config import Umbrales
from radar.contratos import (
    CVE,
    ORDEN_PRIORIDAD,
    Activo,
    Hallazgo,
    Prioridad,
    SenalEpss,
    Senales,
    SenalKev,
)
from radar.nucleo.cruce import Coincidencia, ResultadoActivo

RAZON_KEV = "Explotación confirmada en el mundo real (CISA KEV)"
RAZON_RANSOMWARE = "Usada en campañas de ransomware (CISA KEV)"
RAZON_NO_PRECISO = "NVD no acota versión para este producto: hay que confirmarlo a mano"
RAZON_SIN_CVSS = "Sin puntaje CVSS publicado"
RAZON_SIN_EPSS = "Sin dato de EPSS para esta CVE"


def gravedad(cvss: float) -> str:
    """Etiqueta de gravedad de CVSS (escala estándar, no depende de los umbrales)."""
    if cvss >= 9.0:
        return "crítica"
    if cvss >= 7.0:
        return "alta"
    if cvss >= 4.0:
        return "media"
    if cvss > 0.0:
        return "baja"
    return "nula"


def porcentaje(valor: float) -> str:
    pct = valor * 100
    return f"{pct:.0f}%" if pct >= 1 else f"{pct:.1f}%"


def razon_epss(epss: float) -> str:
    return f"Probabilidad de explotación del {porcentaje(epss)} en 30 días (EPSS)"


def razon_cvss(cvss: float) -> str:
    return f"Gravedad {gravedad(cvss)}, CVSS {cvss:.1f}"


def priorizar(
    cve: CVE,
    kev: SenalKev | None,
    epss: SenalEpss | None,
    umbrales: Umbrales,
    preciso: bool = True,
) -> tuple[Prioridad, list[str]]:
    """Prioridad de una CVE que afecta a un activo, con sus razones en texto legible."""
    razones: list[str] = []
    explotada = False

    if kev is not None:
        explotada = True
        razones.append(RAZON_KEV)
        if kev.ransomware:
            razones.append(RAZON_RANSOMWARE)

    if epss is None:
        razones.append(RAZON_SIN_EPSS)
    elif epss.epss >= umbrales.epss:
        explotada = True
        razones.append(razon_epss(epss.epss))

    if cve.cvss is None:
        razones.append(RAZON_SIN_CVSS)
    else:
        razones.append(razon_cvss(cve.cvss))

    if not preciso:
        razones.append(RAZON_NO_PRECISO)
        return "informativo", razones

    cvss = cve.cvss if cve.cvss is not None else -1.0
    if explotada or cvss >= umbrales.cvss_inmediato:
        return "inmediato", razones
    if cvss >= umbrales.cvss_semanal:
        return "semanal", razones
    return "informativo", razones


def armar_hallazgo(
    activo: Activo,
    coincidencia: Coincidencia,
    senales: Senales,
    umbrales: Umbrales,
    detectado: datetime | None = None,
) -> Hallazgo:
    cve = coincidencia.cve
    kev = senales.kev.get(cve.id)
    epss = senales.epss.get(cve.id)
    prioridad, razones = priorizar(cve, kev, epss, umbrales, coincidencia.preciso)
    return Hallazgo(
        id=f"{cve.id}|{activo.clave}",
        cve=cve.id,
        activo=activo.clave,
        producto=activo.producto,
        version_instalada=activo.version,
        equipos=sorted(set(activo.equipos)),
        prioridad=prioridad,
        por_que=razones,
        preciso=coincidencia.preciso,
        rango=coincidencia.rango,
        kev=kev is not None,
        ransomware=bool(kev and kev.ransomware),
        epss=epss.epss if epss else None,
        cvss=cve.cvss,
        detectado=detectado,
    )


def hallazgos_de_activo(
    activo: Activo,
    resultado: ResultadoActivo,
    senales: Senales,
    umbrales: Umbrales,
    detectado: datetime | None = None,
) -> list[Hallazgo]:
    return [
        armar_hallazgo(activo, c, senales, umbrales, detectado) for c in resultado.coincidencias
    ]


def clave_orden(h: Hallazgo) -> tuple[int, int, float, str]:
    """Prioridad, luego KEV, luego CVSS de mayor a menor (y el id para que sea estable)."""
    cvss = h.cvss if h.cvss is not None else -1.0
    return (ORDEN_PRIORIDAD[h.prioridad], 0 if h.kev else 1, -cvss, h.id)


def ordenar(hallazgos: Iterable[Hallazgo]) -> list[Hallazgo]:
    return sorted(hallazgos, key=clave_orden)


def boletin(
    cves_guardadas: Iterable[str],
    senales: Senales,
    hallazgos: Iterable[Hallazgo],
    agregadas_desde: date | None = None,
) -> list[SenalKev]:
    """CVE en KEV que tocan productos del inventario pero no emparejan con ningún activo.

    `cves_guardadas` son las CVE descargadas para los productos del inventario. Así el
    boletín no es el catálogo KEV entero: son las explotadas de productos propios cuya versión
    instalada no está afectada (o no se pudo comparar). Con `agregadas_desde` se limita a las
    agregadas a KEV desde esa fecha.
    """
    con_hallazgo = {h.cve for h in hallazgos}
    salida = []
    for cve_id in sorted(set(cves_guardadas)):
        kev = senales.kev.get(cve_id)
        if kev is None or cve_id in con_hallazgo:
            continue
        if agregadas_desde and (kev.agregada is None or kev.agregada < agregadas_desde):
            continue
        salida.append(kev)
    return salida
