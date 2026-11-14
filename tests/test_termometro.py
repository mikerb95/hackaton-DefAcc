"""Termómetro de exposición por equipo (RF-616). Sin red ni Claude."""

from __future__ import annotations

import pytest

from radar.api.termometro import banda, nivel, termometro
from tests.test_agente_api import _enviar, _inscribir, _reporte, cliente  # noqa: F401


def _fila(inmediato=0, semanal=0, informativo=0, **cambios):
    base = {
        "pendiente": False,
        "ultimo_reporte": "2026-11-14T15:00:00Z",
        "acciones": {"inmediato": inmediato, "semanal": semanal, "informativo": informativo},
    }
    return base | cambios


@pytest.mark.parametrize(
    ("conteo", "esperado"),
    [
        ((0, 0, 0), 0),
        ((0, 0, 1), 8),
        ((0, 0, 50), 24),
        ((0, 1, 0), 31),
        ((0, 1, 3), 34),
        ((0, 20, 0), 59),
        ((1, 0, 0), 70),
        ((1, 2, 1), 75),
        ((3, 0, 0), 90),
        ((9, 9, 9), 100),
    ],
)
def test_nivel_por_prioridad(conteo, esperado):
    assert nivel(*conteo) == esperado


def test_la_peor_prioridad_fija_el_tramo():
    # Muchas acciones menores nunca superan a una sola más grave.
    assert nivel(0, 0, 1000) < nivel(0, 1, 0)
    assert nivel(0, 1000, 1000) < nivel(1, 0, 0)
    assert banda(nivel(1, 0, 0)) == ("alto", "Alto")
    assert banda(nivel(0, 1, 0)) == ("medio", "Medio")
    assert banda(nivel(0, 0, 1)) == ("bajo", "Bajo")
    assert banda(85) == ("critico", "Crítico") and banda(84) == ("alto", "Alto")


def test_equipo_sin_revisar_no_marca_cero():
    pendiente = termometro(_fila(pendiente=True))
    assert not pendiente["medido"] and pendiente["nivel"] is None
    assert pendiente["etiqueta"] == "Sin cruzar"
    sin_reporte = termometro(_fila(ultimo_reporte=None))
    assert not sin_reporte["medido"] and sin_reporte["nivel"] is None
    limpio = termometro(_fila())
    assert limpio["medido"] and limpio["nivel"] == 0 and limpio["etiqueta"] == "Sin acciones"


def test_la_api_trae_el_termometro_en_lista_y_detalle(cliente):  # noqa: F811
    equipo_id, credencial = _inscribir(cliente)
    _enviar(cliente, credencial, _reporte(equipo_id))
    fila = cliente.get("/api/equipos").json()["equipos"][0]
    detalle = cliente.get(f"/api/equipos/{equipo_id}").json()["equipo"]
    # WinRAR 5.61 está en KEV: hay al menos una acción inmediata, así que marca alto o más.
    assert fila["termometro"]["medido"] and fila["termometro"]["nivel"] >= 60
    assert fila["termometro"]["banda"] in {"alto", "critico"}
    assert detalle["termometro"] == fila["termometro"]
    assert fila["termometro"]["acciones"] == fila["acciones"]
