"""Costo estimado de cada llamada al modelo, con el `usage` que devuelve la API.

Es una ESTIMACIÓN con la tarifa pública. La cifra que manda es la de la consola de Claude.
Tarifas en USD por millón de tokens, verificadas con la skill `claude-api` (caché del
2026-11-03). La escritura en caché (5 minutos) cuesta 1,25 veces la entrada.

Módulo puro.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

TARIFA_VIGENTE_DESDE = "2026-11-03"

# modelo -> (entrada, salida, lectura de caché)
_BASE: dict[str, tuple[float, float, float]] = {
    "claude-sonnet-5-5": (2.00, 10.00, 0.10),
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-fable-5-2": (8.00, 40.00, 0.20),
}

# Un modelo que no está en la tabla se cobra como el más caro conocido: así el tope
# corta antes, nunca después (falla cerrado).
_DESCONOCIDO = max(_BASE.values())


@dataclass(frozen=True)
class Tarifa:
    entrada: float
    salida: float
    cache_lectura: float
    cache_escritura: float


def tarifa(modelo: str) -> Tarifa:
    entrada, salida, lectura = _BASE.get(modelo, _DESCONOCIDO)
    return Tarifa(entrada, salida, lectura, entrada * 1.25)


@dataclass(frozen=True)
class Uso:
    entrada: int = 0
    salida: int = 0
    cache_lectura: int = 0
    cache_escritura: int = 0

    def a_dict(self) -> dict[str, int]:
        return asdict(self)

    @classmethod
    def de_dict(cls, datos: dict[str, Any] | None) -> Uso:
        datos = datos or {}
        return cls(
            **{
                k: int(datos.get(k) or 0)
                for k in ("entrada", "salida", "cache_lectura", "cache_escritura")
            }
        )


USO_CERO = Uso()


def uso_de_api(usage: dict[str, Any] | None) -> Uso:
    """`usage` de la API (dict) -> Uso."""
    u = usage or {}
    return Uso(
        int(u.get("input_tokens") or 0),
        int(u.get("output_tokens") or 0),
        int(u.get("cache_read_input_tokens") or 0),
        int(u.get("cache_creation_input_tokens") or 0),
    )


def sumar(a: Uso, b: Uso) -> Uso:
    return Uso(
        a.entrada + b.entrada,
        a.salida + b.salida,
        a.cache_lectura + b.cache_lectura,
        a.cache_escritura + b.cache_escritura,
    )


def costo_usd(uso: Uso, modelo: str) -> float:
    t = tarifa(modelo)
    millon = 1_000_000
    return (
        uso.entrada * t.entrada
        + uso.salida * t.salida
        + uso.cache_lectura * t.cache_lectura
        + uso.cache_escritura * t.cache_escritura
    ) / millon
