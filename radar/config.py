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
            epss=_real("CVE_UMBRAL_EPSS", cls.epss),
            cvss_inmediato=_real("CVE_UMBRAL_CVSS", cls.cvss_inmediato),
            cvss_semanal=_real("CVE_UMBRAL_CVSS_SEMANAL", cls.cvss_semanal),
        )


def turso(solo_lectura: bool = False) -> tuple[str, str] | None:
    """(url, token) de Turso, o None si aún no están configurados.

    Con `solo_lectura` usa TURSO_AUTH_TOKEN_LECTURA (herramientas del agente). Si ese token no
    existe devuelve None: nunca cae al token de escritura en silencio.
    """
    url = os.environ.get("TURSO_DATABASE_URL")
    token = os.environ.get("TURSO_AUTH_TOKEN_LECTURA" if solo_lectura else "TURSO_AUTH_TOKEN")
    if url and token:
        return url, token
    return None


def sqlite_explicito() -> Path | None:
    """Ruta de RADAR_SQLITE si está definida y no vacía. Si existe, gana siempre sobre Turso."""
    valor = (os.environ.get("RADAR_SQLITE") or "").strip()
    return Path(valor) if valor else None


def ruta_sqlite_local() -> Path:
    """Base sqlite local: RADAR_SQLITE o, si no está, datos_locales/radar.db."""
    return sqlite_explicito() or RAIZ / "datos_locales" / "radar.db"
