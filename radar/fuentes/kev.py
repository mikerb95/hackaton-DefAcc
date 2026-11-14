"""Catálogo KEV de CISA. Se empareja por ID de CVE, nunca por fabricante (regla 4)."""

from __future__ import annotations

from datetime import date
from typing import Any

from radar.contratos import SenalKev

URL_KEV = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def _dia(texto: str | None) -> date | None:
    if not texto:
        return None
    try:
        return date.fromisoformat(texto[:10])
    except ValueError:
        return None


def senal_desde_kev(v: dict[str, Any]) -> SenalKev:
    return SenalKev(
        cve=v["cveID"],
        fabricante=v.get("vendorProject"),
        producto=v.get("product"),
        accion=v.get("requiredAction"),
        agregada=_dia(v.get("dateAdded")),
        plazo=_dia(v.get("dueDate")),
        ransomware=(v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
    )


def leer_catalogo(datos: dict[str, Any]) -> dict[str, SenalKev]:
    """Convierte el JSON del catálogo en un diccionario indexado por ID de CVE."""
    return {v["cveID"]: senal_desde_kev(v) for v in datos.get("vulnerabilities", [])}
