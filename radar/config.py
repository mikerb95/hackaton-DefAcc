"""Configuración: variables de entorno y umbrales. Carga `.env` con python-dotenv.

Los secretos solo viven en `.env`; sus nombres están en `.env.example`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

RAIZ = Path(__file__).resolve().parent.parent
load_dotenv(RAIZ / ".env")


def _real(nombre: str, defecto: float) -> float:
    valor = os.environ.get(nombre)
    if valor is None or not valor.strip():
        return defecto
    try:
        return float(valor)
    except ValueError as e:
        raise ValueError(f"{nombre} debe ser un número, llegó {valor!r}") from e


@dataclass(frozen=True)
class Umbrales:
    """Umbrales de priorización (PLAN, sección 8). Ajustables por variable de entorno."""

    epss: float = 0.10
    cvss_inmediato: float = 9.0
    cvss_semanal: float = 7.0

    @classmethod
    def desde_entorno(cls) -> Umbrales:
        return cls(
            epss=_real("RADAR_UMBRAL_EPSS", cls.epss),
            cvss_inmediato=_real("RADAR_UMBRAL_CVSS_INMEDIATO", cls.cvss_inmediato),
            cvss_semanal=_real("RADAR_UMBRAL_CVSS_SEMANAL", cls.cvss_semanal),
        )


def turso() -> tuple[str, str] | None:
    """(url, token) de Turso, o None si aún no están configurados."""
    url = os.environ.get("TURSO_DATABASE_URL")
    token = os.environ.get("TURSO_AUTH_TOKEN")
    if url and token:
        return url, token
    return None


def ruta_sqlite_local() -> Path:
    """Base sqlite local, usada mientras no haya Turso (y para pruebas)."""
    return Path(os.environ.get("RADAR_SQLITE", RAIZ / "datos_locales" / "radar.db"))
