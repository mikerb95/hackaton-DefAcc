"""EPSS (FIRST). Una CVE que EPSS no conoce no aparece: no se le inventa un cero (regla 2).

Dos formas de bajarlo:
- `descargar_completo()`: el CSV diario con todas las CVE (una sola petición, unos MB).
- `consultar_api(ids)`: la API de FIRST en lotes de 100, para pocas CVE.
"""

from __future__ import annotations

import csv
import gzip
from collections.abc import Iterable
from datetime import date

import httpx

from radar.contratos import SenalEpss

URL_CSV = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
URL_API = "https://api.first.org/data/v1/epss"
LOTE_API = 100
TIEMPO = httpx.Timeout(60.0)
CABECERAS = {"User-Agent": "radar-vulnerabilidades/0.1"}


def leer_csv(texto: str, solo: set[str] | None = None) -> dict[str, SenalEpss]:
    """Lee el CSV de EPSS. La primera línea trae `#model_version:...,score_date:AAAA-MM-DD...`."""
    lineas = texto.splitlines()
    fecha: date | None = None
    if lineas and lineas[0].startswith("#"):
        for parte in lineas[0].lstrip("#").split(","):
            clave, _, valor = parte.partition(":")
            if clave.strip() == "score_date" and valor:
                fecha = date.fromisoformat(valor.strip()[:10])
        lineas = lineas[1:]
    if fecha is None:
        raise ValueError("El CSV de EPSS no trae score_date en la cabecera")
    salida: dict[str, SenalEpss] = {}
    for fila in csv.DictReader(lineas):
        cve = fila["cve"].strip()
        if solo is not None and cve not in solo:
            continue
        salida[cve] = SenalEpss(
            cve=cve, epss=float(fila["epss"]), percentil=float(fila["percentile"]), fecha=fecha
        )
    return salida


def descargar_completo(
    solo: Iterable[str] | None = None, cliente: httpx.Client | None = None
) -> dict[str, SenalEpss]:
    """Baja el CSV completo del día. Con `solo`, devuelve únicamente esas CVE."""
    propio = cliente is None
    cliente = cliente or httpx.Client(timeout=TIEMPO, headers=CABECERAS, follow_redirects=True)
    try:
        r = cliente.get(URL_CSV)
        r.raise_for_status()
        texto = gzip.decompress(r.content).decode("utf-8")
    finally:
        if propio:
            cliente.close()
    return leer_csv(texto, set(solo) if solo is not None else None)


def consultar_api(ids: Iterable[str], cliente: httpx.Client | None = None) -> dict[str, SenalEpss]:
    """Consulta la API de FIRST en lotes de 100."""
    lista = sorted(set(ids))
    propio = cliente is None
    cliente = cliente or httpx.Client(timeout=TIEMPO, headers=CABECERAS)
    salida: dict[str, SenalEpss] = {}
    try:
        for i in range(0, len(lista), LOTE_API):
            lote = lista[i : i + LOTE_API]
            r = cliente.get(URL_API, params={"cve": ",".join(lote), "limit": LOTE_API})
            r.raise_for_status()
            for d in r.json().get("data", []):
                salida[d["cve"]] = SenalEpss(
                    cve=d["cve"],
                    epss=float(d["epss"]),
                    percentil=float(d["percentile"]),
                    fecha=date.fromisoformat(d["date"]),
                )
    finally:
        if propio:
            cliente.close()
    return salida
