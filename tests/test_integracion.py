"""Integración de punta a punta: inventario generado -> ingesta -> normalizador -> corrida.

Nada simulado: es el pipeline real contra la base local (solo lectura) o una base temporal
armada desde el snapshot. Lo esperado sale de la respuesta conocida, nunca del cruce.
"""

from __future__ import annotations

import pytest

from datos_prueba import respuesta


def _hay_cves() -> bool:
    """CVE para cruzar: la base local con datos, o el snapshot para armar una temporal."""
    from radar import bd, config
    from worker.descargar import SNAPSHOT

    if SNAPSHOT.exists():
        return True
    ruta = config.ruta_sqlite_local()
    if not ruta.exists():
        return False
    try:
        c = bd.conectar(solo_lectura=True, ruta_sqlite=ruta)
        try:
            return bd.contar(c, "cves") > 0
        finally:
            c.close()
    except Exception:  # noqa: BLE001 - base ilegible: se salta igual que si faltara
        return False


# CI y otros equipos no tienen resources/ ni datos_locales/: se salta limpio.
pytestmark = [
    pytest.mark.skipif(
        not respuesta.RUTA_SNAPSHOT.exists(), reason="falta resources/semilla_respuesta.json"
    ),
    pytest.mark.skipif(not _hay_cves(), reason="faltan resources/nvd_snapshot y datos_locales/"),
]


@pytest.fixture(scope="module")
def pipeline():
    from datos_prueba.integracion import medir_pipeline

    return medir_pipeline()


def test_pares_cve_version_y_kev(pipeline):
    assert pipeline["pares_cve_version_esperados"] == 735
    assert pipeline["pares_cve_version_correctos"] == 735
    assert pipeline["pares_cve_version_obtenidos"] == 735
    assert pipeline["kev_obtenidas"] == pipeline["kev_esperadas"] == 12


def test_deteccion_y_precision_por_equipo(pipeline):
    assert pipeline["pares_cve_equipo_esperados"] == 6500
    assert pipeline["deteccion_pct"] == 100.0
    assert pipeline["precision_pct"] == 100.0
    assert pipeline["falsos_positivos"] == 0


def test_no_precisos_aparte(pipeline):
    assert pipeline["no_precisos_por_activo_correctos"] == 1098
    assert pipeline["no_precisos_correctos"] == pipeline["no_precisos_esperados"]


def test_cobertura_por_motivo(pipeline):
    assert pipeline["cobertura_obtenida_por_motivo"] == pipeline["cobertura_esperada_por_motivo"]


def test_tabla_para_el_reporte():
    from datos_prueba.metricas import metricas_normalizador, tabla_markdown

    texto = tabla_markdown(metricas_normalizador())
    assert "## Normalizador" in texto and "735" in texto
    assert "de 30)" in texto  # la cifra no ajustada va con su n
    assert "—" not in texto and "–" not in texto
