"""Integración de punta a punta: inventario generado -> ingesta -> normalizador -> corrida.

Nada simulado: es el pipeline real contra la base local (solo lectura) o una base temporal
armada desde el snapshot. Lo esperado sale de la respuesta conocida, nunca del cruce.
"""

from __future__ import annotations

import pytest

from datos_prueba import respuesta

pytestmark = pytest.mark.skipif(
    not respuesta.RUTA_SNAPSHOT.exists(), reason="falta resources/semilla_respuesta.json"
)


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
    assert "—" not in texto and "–" not in texto
