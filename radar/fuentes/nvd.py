"""NVD API 2.0: conversión de la respuesta cruda al contrato CVE, y cliente de descarga.

La conversión es pura (sin red) para poder usarla con el snapshot local.
Reglas que aplica:
- Entradas `vulnerable: false` se ignoran (regla 3).
- Una CVE sin `configurations` queda con `sin_productos=True` y sin rangos.
- La versión fija de un CPE solo se guarda si es concreta: `*` y `-` cuentan como "sin versión".
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from radar.contratos import CVE, Rango, Referencia

# Preferencia de métrica: la más nueva que traiga la CVE.
_METRICAS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)


def _fecha(texto: str | None) -> datetime | None:
    if not texto:
        return None
    try:
        f = datetime.fromisoformat(texto)
    except ValueError:
        return None
    return f if f.tzinfo else f.replace(tzinfo=UTC)


def partir_cpe(criterio: str) -> tuple[str, str, str | None]:
    """Devuelve (vendor, producto, version) de un CPE 2.3. La versión es None si es * o -."""
    partes = criterio.split(":")
    vendor, producto, version = partes[3], partes[4], partes[5]
    return vendor, producto, None if version in ("*", "-", "") else version


def normalizar_par(par: str) -> str:
    """Par 'vendor:producto' sin los escapes de CPE (notepad\\+\\+ -> notepad++)."""
    return par.replace("\\", "").lower()


def _rango(m: dict[str, Any]) -> Rango:
    vendor, producto, version = partir_cpe(m["criteria"])
    return Rango(
        cpe=m["criteria"],
        vendor=vendor,
        producto=producto,
        version=version,
        desde=m.get("versionStartIncluding") or m.get("versionStartExcluding"),
        desde_incluye="versionStartIncluding" in m,
        hasta=m.get("versionEndIncluding") or m.get("versionEndExcluding"),
        hasta_incluye="versionEndIncluding" in m,
    )


def _metrica(metricas: dict[str, Any]) -> tuple[float | None, str | None, str | None, str | None]:
    for clave, version in _METRICAS:
        lista = metricas.get(clave) or []
        if not lista:
            continue
        # La primera que venga, como la respuesta conocida (semilla_respuesta.json). Suele ser
        # la del CNA; preferir la Primary de NVD cambia el peor CVSS de PuTTY 0.81 (3.7 -> 5.9)
        # y de MongoDB Compass 1.36.3 (7.5 -> 9.8).
        elegida = lista[0]
        datos = elegida.get("cvssData", {})
        severidad = datos.get("baseSeverity") or elegida.get("baseSeverity")
        return datos.get("baseScore"), severidad, datos.get("vectorString"), version
    return None, None, None, None


def cve_desde_nvd(item: dict[str, Any]) -> CVE:
    """Convierte un elemento de `vulnerabilities` de la API 2.0 en el contrato CVE."""
    c = item.get("cve", item)
    configuraciones = c.get("configurations") or []
    rangos: list[Rango] = []
    for conf in configuraciones:
        for nodo in conf.get("nodes", []):
            for m in nodo.get("cpeMatch", []):
                if m.get("vulnerable"):
                    rangos.append(_rango(m))
    cvss, severidad, vector, version_cvss = _metrica(c.get("metrics", {}))
    cwes = sorted(
        {
            d["value"]
            for w in c.get("weaknesses", [])
            for d in w.get("description", [])
            if d.get("value")
        }
    )
    vistas: set[str] = set()
    referencias: list[Referencia] = []
    for r in c.get("references", []):
        if r["url"] in vistas:
            continue
        vistas.add(r["url"])
        referencias.append(Referencia(url=r["url"], etiquetas=r.get("tags", [])))
    descripcion = next(
        (d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    return CVE(
        id=c["id"],
        publicada=_fecha(c.get("published")),
        modificada=_fecha(c.get("lastModified")),
        estado=c.get("vulnStatus"),
        descripcion=descripcion,
        cvss=cvss,
        severidad=severidad,
        vector=vector,
        version_cvss=version_cvss,
        cwes=cwes,
        referencias=referencias,
        rangos=rangos,
        sin_productos=not configuraciones,
    )


def cves_desde_respuesta(datos: dict[str, Any]) -> Iterator[CVE]:
    for item in datos.get("vulnerabilities", []):
        yield cve_desde_nvd(item)


def leer_snapshot(archivos: Iterable[Path]) -> dict[str, CVE]:
    """Lee archivos del snapshot (formato {'par', 'total', 'vulnerabilities'}) sin repetir CVE."""
    cves: dict[str, CVE] = {}
    for ruta in archivos:
        with open(ruta, encoding="utf-8") as f:
            datos = json.load(f)
        for cve in cves_desde_respuesta(datos):
            cves.setdefault(cve.id, cve)
    return cves
