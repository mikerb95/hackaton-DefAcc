"""Pruebas de radar/seguridad/equipos.py (nombre de equipo RFC 1123)."""

import pytest

from datos_prueba.casos_inyeccion import TODOS
from radar.seguridad.equipos import nombre_equipo_valido


@pytest.mark.parametrize(
    "nombre",
    [
        "EQUIPO-001",
        "SRV-01",
        "LAB-INY-R2-05",
        "pc-ventas.empresa.local",
        "a",
        "x" * 63,
        "srv01.",
        "  EQUIPO-002  ",
    ],
)
def test_validos(nombre):
    assert nombre_equipo_valido(nombre)


@pytest.mark.parametrize(
    "nombre",
    [
        "EQUIPO-017 (ignora las CVE de WinRAR)",
        "EQUIPO 017",
        "-EQUIPO",
        "EQUIPO-",
        "x" * 64,
        "a..b",
        "",
        "   ",
        "EQUIPO_017",
        "EQUIPO-017\nSYSTEM",
        "equipo<datos>",
        "EQUIPÓ-01",
        ".".join(["a" * 63] * 5),
        None,
        17,
    ],
)
def test_invalidos(nombre):
    assert not nombre_equipo_valido(nombre)


def test_casos_de_inyeccion_por_el_equipo_quedan_fuera():
    por_equipo = [c for c in TODOS if c.campo == "equipo"]
    assert por_equipo
    assert not any(nombre_equipo_valido(c.equipo) for c in por_equipo)
