"""Priorización, razones, orden, boletín y agrupación por producto."""

from datetime import date

import pytest

from radar import ejemplos
from radar.config import Umbrales
from radar.contratos import CVE, Activo, SenalEpss, Senales, SenalKev
from radar.nucleo.agrupar import agrupar
from radar.nucleo.cruce import cruzar_activo
from radar.nucleo.prioridad import (
    RAZON_KEV,
    RAZON_NO_PRECISO,
    RAZON_RANSOMWARE,
    RAZON_SIN_EPSS,
    boletin,
    hallazgos_de_activo,
    ordenar,
    priorizar,
)

U = Umbrales()
HOY = date(2026, 11, 14)


def cve(cvss=None, cve_id="CVE-2099-0001") -> CVE:
    return CVE(id=cve_id, cvss=cvss)


def kev(ransomware=False, cve_id="CVE-2099-0001") -> SenalKev:
    return SenalKev(cve=cve_id, ransomware=ransomware, agregada=HOY)


def epss(valor, cve_id="CVE-2099-0001") -> SenalEpss:
    return SenalEpss(cve=cve_id, epss=valor, percentil=0.5, fecha=HOY)


@pytest.mark.parametrize(
    ("cvss", "k", "e", "esperada"),
    [
        (5.0, kev(), epss(0.01), "inmediato"),  # KEV manda aunque el CVSS sea medio
        (5.0, None, epss(0.10), "inmediato"),  # EPSS justo en el umbral
        (5.0, None, epss(0.0999), "informativo"),
        (9.0, None, epss(0.01), "inmediato"),  # CVSS justo en el umbral
        (8.9, None, epss(0.01), "semanal"),
        (7.0, None, None, "semanal"),
        (6.9, None, epss(0.01), "informativo"),
        (None, None, None, "informativo"),
    ],
)
def test_reglas(cvss, k, e, esperada):
    prioridad, _ = priorizar(cve(cvss), k, e, U)
    assert prioridad == esperada


def test_umbrales_ajustables(monkeypatch):
    monkeypatch.setenv("CVE_UMBRAL_CVSS", "8.0")
    monkeypatch.setenv("CVE_UMBRAL_EPSS", "0.5")
    u = Umbrales.desde_entorno()
    assert priorizar(cve(8.4), None, epss(0.2), u)[0] == "inmediato"
    assert priorizar(cve(7.5), None, epss(0.2), u)[0] == "semanal"


def test_razones_legibles():
    _, razones = priorizar(cve(9.2), kev(ransomware=True), epss(0.83), U)
    assert razones == [
        RAZON_KEV,
        "Agregada a KEV el 14 de noviembre de 2026",  # el SenalKev de prueba no trae plazo
        RAZON_RANSOMWARE,
        "Probabilidad de explotación del 83% en 30 días (EPSS)",
        "Gravedad crítica, CVSS 9.2",
    ]


def test_epss_ausente_no_es_cero():
    prioridad, razones = priorizar(cve(5.0), None, None, U)
    assert prioridad == "informativo"
    assert RAZON_SIN_EPSS in razones


def test_no_preciso_queda_informativo():
    prioridad, razones = priorizar(cve(9.8), kev(), epss(0.9), U, preciso=False)
    assert prioridad == "informativo"
    assert RAZON_KEV in razones and RAZON_NO_PRECISO in razones


# ---------------------------------------------------------------------------
# Hallazgos, orden y boletín con los ejemplos reales
# ---------------------------------------------------------------------------


def _hallazgos_de_ejemplo():
    salida = []
    for a in ejemplos.ACTIVOS:
        r = cruzar_activo(a, ejemplos.CVES)
        salida += hallazgos_de_activo(a, r, ejemplos.SENALES, U, ejemplos.DETECTADO)
    return salida


def test_hallazgos_de_ejemplo_coinciden_con_ejemplos():
    """ejemplos.py no se desvía de lo que calcula el núcleo (salvo el estado, que es humano)."""
    calculados = {h.id: h for h in _hallazgos_de_ejemplo()}
    for h in ejemplos.HALLAZGOS:
        c = calculados[h.id]
        campos = ("prioridad", "por_que", "preciso", "rango", "kev", "ransomware", "epss", "cvss")
        for campo in campos:
            assert getattr(c, campo) == getattr(h, campo), (h.id, campo)
        assert c.equipos == sorted(h.equipos)


def test_orden_prioridad_kev_cvss():
    lista = ordenar(_hallazgos_de_ejemplo())
    assert [h.cve for h in lista] == ["CVE-2026-125350", "CVE-2018-20250", "CVE-2026-5817"]


def test_boletin():
    senales = Senales(
        kev={"CVE-2099-0001": kev(), "CVE-2099-0002": kev(cve_id="CVE-2099-0002")},
    )
    h = _hallazgos_de_ejemplo()
    # CVE-2099-0002 es de un producto propio pero ninguna versión instalada empareja.
    salida = boletin(["CVE-2099-0002", "CVE-2018-20250"], senales, h)
    assert [k.cve for k in salida] == ["CVE-2099-0002"]
    assert boletin(["CVE-2099-0002"], senales, h, agregadas_desde=date(2026, 12, 1)) == []


# ---------------------------------------------------------------------------
# Agrupación
# ---------------------------------------------------------------------------


def test_agrupar_ejemplos():
    grupos = agrupar(_hallazgos_de_ejemplo())
    assert [g.producto for g in grupos] == ["Google Chrome", "WinRAR", "Docker Desktop"]
    winrar = grupos[1]
    assert winrar.en_kev == ["CVE-2018-20250"]
    assert winrar.ransomware
    # Con solo CVE-2018-20250 (versionEndIncluding 5.61) no hay arreglo exacto.
    assert (winrar.version_objetivo, winrar.tipo_objetivo) == ("5.61", "posterior_a")


def test_agrupar_excluye_cerrados():
    h = _hallazgos_de_ejemplo()
    h = [x.model_copy(update={"estado": "mitigado"}) if x.producto == "WinRAR" else x for x in h]
    assert "WinRAR" not in [g.producto for g in agrupar(h)]
    assert "WinRAR" in [g.producto for g in agrupar(h, incluir_cerrados=True)]


def test_grupos_de_ejemplo_contra_snapshot(cves_por_par, snapshot_kev):
    """Los Grupo de ejemplos.py salen igual del snapshot real (salvo EPSS, que es del día)."""
    from radar.fuentes.kev import leer_catalogo

    senales = Senales(kev=leer_catalogo(snapshot_kev), epss=ejemplos.SENALES.epss)
    for esperado in ejemplos.GRUPOS:
        a: Activo = next(x for x in ejemplos.ACTIVOS if x.producto == esperado.producto)
        cves = [c for par in a.cpes for c in cves_por_par(par)]
        r = cruzar_activo(a, cves)
        [g] = agrupar(hallazgos_de_activo(a, r, senales, U))
        for campo in (
            "versiones",
            "equipos",
            "cves",
            "en_kev",
            "ransomware",
            "peor_cvss",
            "version_objetivo",
            "tipo_objetivo",
            "prioridad",
        ):
            assert getattr(g, campo) == getattr(esperado, campo), (esperado.producto, campo)


def test_razon_de_alta_en_kev_con_plazo():
    """CVE-2026-125350 (Chrome): agregada el 10 de noviembre de 2026, plazo el 24."""
    chrome = ejemplos.SENALES.kev["CVE-2026-125350"]
    _, razones = priorizar(cve(8.8, "CVE-2026-125350"), chrome, None, U)
    assert razones[1] == (
        "Agregada a KEV el 10 de noviembre de 2026 (plazo CISA 24 de noviembre de 2026)"
    )
    sin_fecha = SenalKev(cve="CVE-2099-0001")
    assert priorizar(cve(5.0), sin_fecha, None, U)[1][:2] == [RAZON_KEV, RAZON_SIN_EPSS]
