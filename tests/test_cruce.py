"""Regla de afectación, versión objetivo y validación contra la respuesta conocida."""

import pytest

from radar.contratos import Activo, Rango
from radar.fuentes.nvd import cve_desde_nvd
from radar.nucleo.cruce import (
    Afecta,
    Objetivo,
    afecta,
    cruzar_activo,
    objetivo_de_producto,
    objetivo_de_rango,
)

CPE = "cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*"


def rango(**kw) -> Rango:
    return Rango(cpe=CPE, vendor="rarlab", producto="winrar", **kw)


def activo(version, cpes=("rarlab:winrar",), equipos=("EQUIPO-001",)) -> Activo:
    return Activo(
        clave=f"WinRAR@{version}",
        producto="WinRAR",
        nombre="WinRAR",
        version=version or "",
        cpes=list(cpes),
        equipos=list(equipos),
    )


# ---------------------------------------------------------------------------
# Regla de afectación
# ---------------------------------------------------------------------------


def test_version_fija():
    r = rango(version="1.36.3")
    assert afecta(r, "1.36.3") is Afecta.SI
    assert afecta(r, "1.36.4") is Afecta.NO


def test_sin_version_ni_limites_afecta_a_todas():
    assert afecta(rango(), "1.0") is Afecta.TODAS


def test_frontera_inclusiva_superior():
    # CVE-2018-20250: versionEndIncluding 5.61, así que 5.61 sigue afectada.
    r = rango(hasta="5.61", hasta_incluye=True)
    assert afecta(r, "5.61") is Afecta.SI
    assert afecta(r, "5.62") is Afecta.NO


def test_frontera_excluyente_superior():
    # CVE-2025-8088: versionEndExcluding 7.13.
    r = rango(hasta="7.13", hasta_incluye=False)
    assert afecta(r, "7.12") is Afecta.SI
    assert afecta(r, "7.13") is Afecta.NO


def test_limite_inferior():
    r = rango(desde="4.62.0", desde_incluye=True, hasta="4.68.0")
    assert afecta(r, "4.61.9") is Afecta.NO
    assert afecta(r, "4.62.0") is Afecta.SI
    r_ex = rango(desde="4.62.0", desde_incluye=False, hasta="4.68.0")
    assert afecta(r_ex, "4.62.0") is Afecta.NO
    assert afecta(r_ex, "4.62.1") is Afecta.SI


def test_rango_ilegible_no_se_adivina():
    assert afecta(rango(hasta="raro"), "1.0") is Afecta.NO_COMPARABLE
    assert afecta(rango(version="x.y"), "1.0") is Afecta.NO_COMPARABLE


def test_prelanzamiento_dentro_del_rango():
    r = rango(hasta="2.0", hasta_incluye=False)
    assert afecta(r, "2.0-rc1") is Afecta.SI  # el detector actual lo daba por arreglado


# ---------------------------------------------------------------------------
# Cobertura: sin comparación no hay hallazgo
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "cpes", "motivo"),
    [
        ("28.1.1, build 4eba377", ("docker:docker",), "no_comparable"),
        ("", ("rarlab:winrar",), "sin_version"),
        ("4.2", (), "sin_cpe"),
    ],
)
def test_cobertura(version, cpes, motivo):
    cve = cve_desde_nvd(_cve_nvd("CVE-2099-0001", [{"criteria": CPE, "vulnerable": True}]))
    r = cruzar_activo(activo(version, cpes=cpes, equipos=("E1", "E2")), [cve])
    assert r.coincidencias == []
    assert [c.motivo for c in r.cobertura] == [motivo, motivo]
    assert [c.equipo for c in r.cobertura] == ["E1", "E2"]


# ---------------------------------------------------------------------------
# Conversión de NVD y elección de rango
# ---------------------------------------------------------------------------


def _cve_nvd(cve_id, matches, metricas=None):
    return {
        "cve": {
            "id": cve_id,
            "published": "2026-01-01T00:00:00.000",
            "lastModified": "2026-01-02T00:00:00.000",
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": "prueba"}],
            "metrics": metricas or {},
            "configurations": [{"nodes": [{"cpeMatch": matches}]}] if matches else [],
        }
    }


def test_vulnerable_false_se_ignora():
    cve = cve_desde_nvd(
        _cve_nvd(
            "CVE-2099-0002",
            [
                {"criteria": CPE, "vulnerable": False},
                {"criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "vulnerable": False},
            ],
        )
    )
    assert cve.rangos == []
    assert not cve.sin_productos
    assert cruzar_activo(activo("5.61"), [cve]).coincidencias == []


def test_sin_configurations_se_cuenta_aparte():
    cve = cve_desde_nvd(_cve_nvd("CVE-2099-0003", []))
    assert cve.sin_productos
    assert cve.rangos == []


def test_escape_de_cpe_se_normaliza():
    m = {
        "criteria": "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*",
        "vulnerable": True,
        "versionEndExcluding": "8.8.9",
    }
    cve = cve_desde_nvd(_cve_nvd("CVE-2099-0004", [m]))
    a = activo("8.8.8", cpes=("notepad-plus-plus:notepad++",))
    assert [c.cve.id for c in cruzar_activo(a, [cve]).coincidencias] == ["CVE-2099-0004"]


def test_manda_el_rango_mas_acotado_y_lo_preciso_gana():
    matches = [
        {"criteria": CPE, "vulnerable": True},  # todas
        {"criteria": CPE, "vulnerable": True, "versionEndExcluding": "7.0"},
        {
            "criteria": CPE,
            "vulnerable": True,
            "versionStartIncluding": "5.0",
            "versionEndExcluding": "6.0",
        },
    ]
    cve = cve_desde_nvd(_cve_nvd("CVE-2099-0005", matches))
    [c] = cruzar_activo(activo("5.61"), [cve]).coincidencias
    assert c.preciso
    assert (c.rango.desde, c.rango.hasta) == ("5.0", "6.0")


def test_dos_pares_docker_desktop():
    matches = [
        {
            "criteria": "cpe:2.3:a:docker:docker_desktop:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "versionStartIncluding": "4.62.0",
            "versionEndExcluding": "4.68.0",
        }
    ]
    cve = cve_desde_nvd(_cve_nvd("CVE-2026-5817", matches))
    solo_uno = activo("4.62.0", cpes=("docker:desktop",))
    ambos = activo("4.62.0", cpes=("docker:desktop", "docker:docker_desktop"))
    assert cruzar_activo(solo_uno, [cve]).coincidencias == []
    assert len(cruzar_activo(ambos, [cve]).coincidencias) == 1


# ---------------------------------------------------------------------------
# Versión objetivo
# ---------------------------------------------------------------------------


def test_objetivo_por_cve():
    assert objetivo_de_rango(rango(hasta="7.13")) == Objetivo("7.13", "exacta")
    # Error 2 del detector actual: con versionEndIncluding no se dice "actualizar a X".
    assert objetivo_de_rango(rango(hasta="5.61", hasta_incluye=True)) == Objetivo(
        "5.61", "posterior_a"
    )
    # Error 3: rango acotado por los dos lados sí tiene objetivo.
    assert objetivo_de_rango(rango(desde="4.62.0", desde_incluye=True, hasta="4.68.0")) == (
        Objetivo("4.68.0", "exacta")
    )
    assert objetivo_de_rango(rango(desde="4.0", desde_incluye=True)).tipo == "ninguna"
    assert objetivo_de_rango(rango()).tipo == "ninguna"
    assert objetivo_de_rango(None).tipo == "ninguna"


def test_objetivo_por_producto():
    assert objetivo_de_producto(
        [Objetivo("4.68.0", "exacta"), Objetivo("4.71.0", "exacta")]
    ) == Objetivo("4.71.0", "exacta")
    assert objetivo_de_producto(
        [Objetivo("7.13", "exacta"), Objetivo("5.61", "posterior_a")]
    ) == Objetivo("7.13", "exacta")
    assert objetivo_de_producto(
        [Objetivo("7.13", "exacta"), Objetivo("7.13", "posterior_a")]
    ) == Objetivo("7.13", "posterior_a")
    assert (
        objetivo_de_producto([Objetivo("7.13", "exacta"), Objetivo(None, "ninguna")]).tipo
        == "ninguna"
    )
    assert objetivo_de_producto([]).tipo == "ninguna"


# ---------------------------------------------------------------------------
# Respuesta conocida (60 casos del snapshot). Se salta si resources/ no está.
# ---------------------------------------------------------------------------


def _id_caso(caso):
    return f"{caso['par']}@{caso['version']}"


def test_respuesta_conocida_completa(respuesta_conocida, cves_por_par, snapshot_kev):
    """Detección del cruce contra los 60 casos: CVE precisas, no precisas, KEV y peor CVSS."""
    kev = {v["cveID"] for v in snapshot_kev["vulnerabilities"]}
    diferencias = []
    for caso in respuesta_conocida["casos"]:
        r = cruzar_activo(activo(caso["version"], cpes=(caso["par"],)), cves_por_par(caso["par"]))
        precisas = {c.cve.id for c in r.coincidencias if c.preciso}
        no_precisas = {c.cve.id for c in r.coincidencias if not c.preciso}
        cvss = [c.cve.cvss for c in r.coincidencias if c.preciso and c.cve.cvss is not None]
        obtenido = (
            sorted(precisas),
            sorted(no_precisas),
            sorted(precisas & kev),
            max(cvss) if cvss else None,
        )
        esperado = (
            sorted(caso["cves"]),
            sorted(caso["no_precisas"]),
            sorted(caso["kev"]),
            caso["peor_cvss"],
        )
        if obtenido != esperado:
            diferencias.append(_id_caso(caso))
    assert len(respuesta_conocida["casos"]) == 60
    assert diferencias == []


@pytest.mark.parametrize(
    ("par", "version", "objetivo"),
    [
        ("rarlab:winrar", "5.61", Objetivo("7.13", "exacta")),
        ("rarlab:winrar", "7.12", Objetivo("7.13", "exacta")),
        ("docker:docker_desktop", "4.62.0", Objetivo("4.71.0", "exacta")),
    ],
)
def test_objetivo_contra_snapshot(cves_por_par, par, version, objetivo):
    r = cruzar_activo(activo(version, cpes=(par,)), cves_por_par(par))
    assert objetivo_de_producto(objetivo_de_rango(c.rango) for c in r.coincidencias) == objetivo
