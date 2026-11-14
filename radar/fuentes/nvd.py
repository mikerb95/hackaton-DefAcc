"""NVD API 2.0: conversión de la respuesta cruda al contrato CVE, y cliente de descarga.

La conversión es pura (sin red) para poder usarla con el snapshot local.
Reglas que aplica:
- Entradas `vulnerable: false` se ignoran (regla 3).
- Una CVE sin `configurations` queda con `sin_productos=True` y sin rangos.
- La versión fija de un CPE solo se guarda si es concreta: `*` y `-` cuentan como "sin versión".
"""

from __future__ import annotations

import json
import os
import time
import urllib.parse
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Self

import httpx

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
            if str(d.get("value", "")).startswith("CWE-")
        }
    )
    vistas: set[str] = set()
    referencias: list[Referencia] = []
    for r in c.get("references", []):
        if r["url"] in vistas:
            continue
        vistas.add(r["url"])
        referencias.append(Referencia(url=r["url"], etiquetas=r.get("tags", [])))
    textos = {d.get("lang"): d.get("value", "") for d in c.get("descriptions", [])}
    descripcion = textos.get("es") or textos.get("en") or ""
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


# ---------------------------------------------------------------------------
# Cliente en línea (PLAN, sección 7)
# ---------------------------------------------------------------------------

URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POR_PAGINA = 2000
VENTANA_MAXIMA = timedelta(days=120)
PAUSA_SIN_CLAVE = 6.0
PAUSA_CON_CLAVE = 0.7
INTENTOS = 6


class ErrorNvd(RuntimeError):
    """NVD no respondió tras los reintentos, o rechazó la clave (403)."""


def _fecha_nvd(f: datetime) -> str:
    """Formato que pide NVD: 2026-11-03T00:00:00.000, en UTC."""
    if f.tzinfo:
        f = f.astimezone(UTC).replace(tzinfo=None)
    return f.strftime("%Y-%m-%dT%H:%M:%S.000")


def ventanas(desde: datetime, hasta: datetime) -> list[tuple[datetime, datetime]]:
    """Parte un intervalo en ventanas de 120 días como máximo (límite de NVD)."""
    salida = []
    inicio = desde
    while inicio < hasta:
        fin = min(inicio + VENTANA_MAXIMA, hasta)
        salida.append((inicio, fin))
        inicio = fin
    return salida


class ClienteNvd:
    """Cliente de la API 2.0 con pausa entre peticiones, reintentos y paginación.

    - 429: espera lo que diga Retry-After (o 30 s) y reintenta.
    - 403: la clave no sirve; no reintenta.
    - 5xx y fallos de red: reintenta con espera creciente.
    """

    def __init__(
        self,
        clave: str | None = None,
        cliente: httpx.Client | None = None,
        pausa: float | None = None,
        dormir: Callable[[float], None] = time.sleep,
    ):
        self.clave = clave if clave is not None else os.environ.get("NVD_API_KEY") or None
        self.pausa = (
            pausa if pausa is not None else (PAUSA_CON_CLAVE if self.clave else PAUSA_SIN_CLAVE)
        )
        self._dormir = dormir
        self._propio = cliente is None
        cabeceras = {"User-Agent": "radar-vulnerabilidades/0.1"}
        if self.clave:
            cabeceras["apiKey"] = self.clave
        self._http = cliente or httpx.Client(timeout=httpx.Timeout(120.0))
        self._cabeceras = cabeceras
        self.peticiones = 0

    def cerrar(self) -> None:
        if self._propio:
            self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.cerrar()

    def _pedir(self, parametros: dict[str, Any]) -> dict[str, Any]:
        # noRejected va sin valor: NVD no acepta "noRejected=".
        url = f"{URL_NVD}?{urllib.parse.urlencode(parametros)}&noRejected"
        ultimo = ""
        for intento in range(INTENTOS):
            if self.peticiones:
                self._dormir(self.pausa)
            self.peticiones += 1
            try:
                r = self._http.get(url, headers=self._cabeceras)
            except httpx.HTTPError as e:
                ultimo = f"red: {e}"
                self._dormir(10 * (intento + 1))
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code == 403:
                raise ErrorNvd("NVD respondió 403: la clave no sirve (no se reintenta)")
            ultimo = f"HTTP {r.status_code}"
            if r.status_code == 429:
                try:
                    espera = float(r.headers.get("Retry-After", 30))
                except ValueError:
                    espera = 30.0
            elif r.status_code >= 500:
                espera = 10.0 * (intento + 1)
            else:
                raise ErrorNvd(f"NVD respondió {r.status_code}: {r.text[:200]}")
            self._dormir(espera)
        raise ErrorNvd(f"NVD no respondió tras {INTENTOS} intentos ({ultimo})")

    def _paginar(self, parametros: dict[str, Any]) -> Iterator[dict[str, Any]]:
        inicio = 0
        while True:
            datos = self._pedir({**parametros, "startIndex": inicio, "resultsPerPage": POR_PAGINA})
            items = datos.get("vulnerabilities", [])
            yield from items
            total = datos.get("totalResults", 0)
            inicio += datos.get("resultsPerPage", len(items)) or 0
            if inicio >= total or not items:
                return

    def crudas_por_par(
        self, par: str, desde: datetime | None = None, hasta: datetime | None = None
    ) -> Iterator[dict[str, Any]]:
        """Respuestas crudas de un par 'vendor:producto' (con el escape de CPE, como en NVD).

        Con `desde`, solo las modificadas desde esa fecha (lastModStartDate/EndDate, partido
        en ventanas de 120 días).
        """
        vendor, producto = par.split(":", 1)
        base = {"virtualMatchString": f"cpe:2.3:a:{vendor}:{producto}"}
        if desde is None:
            yield from self._paginar(base)
            return
        for ini, fin in ventanas(desde, hasta or datetime.now(UTC)):
            yield from self._paginar(
                {**base, "lastModStartDate": _fecha_nvd(ini), "lastModEndDate": _fecha_nvd(fin)}
            )

    def por_par(
        self, par: str, desde: datetime | None = None, hasta: datetime | None = None
    ) -> dict[str, CVE]:
        """CVE de un par, convertidas al contrato y sin repetir."""
        salida: dict[str, CVE] = {}
        for item in self.crudas_por_par(par, desde, hasta):
            cve = cve_desde_nvd(item)
            salida[cve.id] = cve
        return salida

    def una(self, cve_id: str) -> CVE | None:
        datos = self._pedir({"cveId": cve_id})
        items = datos.get("vulnerabilities", [])
        return cve_desde_nvd(items[0]) if items else None
