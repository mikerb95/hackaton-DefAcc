"""Comparación de versiones: relleno con ceros, sufijos, metadatos y "no comparable"."""

import pytest

from radar.nucleo.versiones import comparable, comparar, leer, mayor


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("1.0", "1.0.0", 0),
        ("1", "1.0.0.0", 0),
        ("5.61", "5.61", 0),
        ("5.61", "5.62", -1),
        ("6.23", "6.3", 1),  # numérico, no lexicográfico
        ("10.0", "9.9.9", 1),
        ("156.0.8079.100", "157.0.8103.50", -1),
        ("25.001.20531", "25.1.20531", 0),  # ceros a la izquierda de Adobe
        ("8.9.6.4", "8.9.6", 1),
        ("v2.0", "2.0", 0),
    ],
)
def test_orden_numerico(a, b, esperado):
    assert comparar(a, b) == esperado


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("1.2.3-beta", "1.2.3", -1),  # error 1 del detector actual: el sufijo cuenta
        ("1.2.3-alpha", "1.2.3-beta", -1),
        ("1.2.3-beta", "1.2.3-rc1", -1),
        ("1.2.3-rc1", "1.2.3-rc2", -1),
        ("1.2.3rc1", "1.2.3-rc.1", 0),
        ("1.2.3-dev", "1.2.3-alpha", -1),
        ("1.2.4-beta", "1.2.3", 1),
        ("3.13.0b1", "3.13.0", -1),
    ],
)
def test_prelanzamiento(a, b, esperado):
    assert comparar(a, b) == esperado


def test_metadatos_de_compilacion_no_cuentan():
    assert comparar("17.0.9+9", "17.0.9") == 0
    assert comparar("17.0.9+9", "17.0.10") == -1


@pytest.mark.parametrize(
    "texto",
    [
        None,
        "",
        "   ",
        "28.1.1, build 4eba377",
        "2.45.1.windows.1",  # lo limpia el normalizador, no el núcleo
        "1.2.3.4.5",  # más de cuatro componentes
        "latest",
        "1.2.x",
        "1.2.3-hotfix",  # sufijo desconocido: no se adivina
    ],
)
def test_no_comparable(texto):
    assert leer(texto) is None
    assert not comparable(texto)
    assert comparar(texto, "1.0") is None
    assert comparar("1.0", texto) is None


def test_mayor_descarta_lo_ilegible():
    assert mayor(["4.68.0", "4.71.0", "basura", "4.7.0"]) == "4.71.0"
    assert mayor(["basura"]) is None
    assert mayor([]) is None
