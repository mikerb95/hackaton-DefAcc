"""Comparadores de versión de dpkg y rpm, y puntaje CVSS desde el vector (RF-821, RF-822).

Los casos de dpkg salen de la política de Debian (sección 5.6.12); los de rpm, del
comportamiento documentado de `rpmvercmp`. Los vectores CVSS, de la especificación 3.1.
"""

from __future__ import annotations

import pytest

from radar.nucleo.cvss import puntaje_base
from radar.nucleo.versiones_paquete import comparar, comparar_dpkg, comparar_rpm, mayor


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("1.0", "1.0", 0),
        ("1.0-1", "1.0-2", -1),
        ("1.10", "1.9", 1),
        ("1.0~rc1", "1.0", -1),
        ("1.0~rc1", "1.0~rc2", -1),
        ("1.0~~", "1.0~", -1),
        ("1:0.9", "2.0", 1),
        ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.9", 1),
        ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.30", -1),
        ("3.0.11-1~deb12u1", "3.0.11-1~deb12u2", -1),
        ("3.0.11-1~deb12u2", "3.0.11-1", -1),
        ("1.0a", "1.0+", -1),
        ("1.0", "1.0a", -1),
        ("2.36.1-8+deb11u1", "2.36.1-8", 1),
        ("1.0-1", "1.0", 1),
        ("007", "7", 0),
    ],
)
def test_dpkg(a, b, esperado):
    assert comparar_dpkg(a, b) == esperado
    assert comparar_dpkg(b, a) == -esperado


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("1.0", "1.0", 0),
        ("1:3.0.7-24.el9", "1:3.0.7-28.el9_4", -1),
        ("3.0.7-28.el9_4", "1:3.0.7-24.el9", -1),
        ("5.1.8-6.el9_1", "5.1.8-6.el9", 1),
        ("1.0~rc1", "1.0", -1),
        ("1.0^git1", "1.0", 1),
        ("1.0^git1", "1.0.1", -1),
        ("1.0a", "1.0.1", -1),
        ("2.10", "2.9", 1),
        ("1.0", "1.0-5", 0),
        ("1.b", "1.a", 1),
    ],
)
def test_rpm(a, b, esperado):
    assert comparar_rpm(a, b) == esperado
    assert comparar_rpm(b, a) == -esperado


def test_mayor_por_sistema():
    assert mayor(["3.0.2-0ubuntu1.9", "3.0.2-0ubuntu1.30", "3.0.2-0ubuntu1.12"], "dpkg") == (
        "3.0.2-0ubuntu1.30"
    )
    assert mayor(["1:3.0.7-24.el9", "1:3.0.7-28.el9_4"], "rpm") == "1:3.0.7-28.el9_4"
    assert mayor([], "dpkg") is None and mayor(["", " "], "rpm") is None
    assert comparar("1.0~a", "1.0", "dpkg") == -1


@pytest.mark.parametrize(
    ("vector", "esperado"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_desde_el_vector(vector, esperado):
    assert puntaje_base(vector) == esperado


def test_cvss_sin_puntaje_no_se_inventa():
    for vector in (None, "", "CVSS:4.0/AV:N/AC:L", "AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:X"):
        assert puntaje_base(vector) is None
