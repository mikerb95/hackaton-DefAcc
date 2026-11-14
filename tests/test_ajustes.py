"""Modelo de Claude configurable: variable de entorno y consola (radar/ajustes.py)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from radar import ajustes, bd
from radar.api import cuentas
from radar.api import datos as modulo_datos

CLAVE = "una-clave-larga-de-prueba"


@pytest.fixture(autouse=True)
def _limpio(monkeypatch):
    for nombre in ("RADAR_MODELO", "RADAR_MODELO_ANALISTA", "RADAR_MODELO_DESEMPATE"):
        monkeypatch.delenv(nombre, raising=False)
    ajustes.olvidar_cache()
    yield
    ajustes.olvidar_cache()


def _guardar(uso, valor, por="Ana"):
    conexion = bd.conectar()
    try:
        ajustes.guardar_modelo(conexion, uso, valor, por)
    finally:
        conexion.close()


def test_sin_nada_usa_el_modelo_por_defecto():
    v = ajustes.modelo_vigente("analista")
    assert v.modelo == ajustes.MODELO_POR_DEFECTO == "claude-opus-5-5"
    assert v.origen == "defecto"


def test_variable_del_uso_gana_a_la_comun(monkeypatch):
    monkeypatch.setenv("RADAR_MODELO", "claude-haiku-5-5")
    monkeypatch.setenv("RADAR_MODELO_ANALISTA", "claude-sonnet-5-5")
    assert ajustes.modelo("analista") == "claude-sonnet-5-5"
    assert ajustes.modelo("desempate") == "claude-haiku-5-5"
    v = ajustes.modelo_vigente("desempate")
    assert v.origen == "variable" and v.variable == "RADAR_MODELO"


def test_variable_mal_formada_se_ignora(monkeypatch):
    monkeypatch.setenv("RADAR_MODELO_ANALISTA", "gpt-4; rm -rf /")
    assert ajustes.modelo("analista") == ajustes.MODELO_POR_DEFECTO


def test_consola_gana_a_la_variable_y_se_puede_soltar(monkeypatch):
    monkeypatch.setenv("RADAR_MODELO_ANALISTA", "claude-sonnet-5-5")
    _guardar("analista", "claude-haiku-5-5")
    v = ajustes.modelo_vigente("analista")
    assert (v.modelo, v.origen, v.por) == ("claude-haiku-5-5", "consola", "Ana")
    assert ajustes.modelo("desempate") == ajustes.MODELO_POR_DEFECTO
    _guardar("analista", None)
    assert ajustes.modelo("analista") == "claude-sonnet-5-5"


def test_consola_solo_acepta_modelos_conocidos():
    with pytest.raises(ajustes.AjusteInvalido):
        _guardar("analista", "claude-inventado-9")
    with pytest.raises(ajustes.AjusteInvalido):
        _guardar("otro", "claude-opus-5-5")


def test_base_ilegible_no_detiene(monkeypatch, tmp_path):
    monkeypatch.setenv("RADAR_SQLITE", str(tmp_path / "no-existe" / "x.db"))
    monkeypatch.setenv("RADAR_MODELO", "claude-sonnet-5-5")
    assert ajustes.modelo("analista") == "claude-sonnet-5-5"


def test_analista_lee_el_ajuste(monkeypatch):
    from radar.agente import analista

    monkeypatch.setenv("RADAR_MODELO_ANALISTA", "claude-sonnet-5-5")

    class Fuente:
        pass

    assert analista.opciones(Fuente(), True, None).model == "claude-sonnet-5-5"


# -- API y consola ---------------------------------------------------------------


def _cliente(monkeypatch, tmp_path) -> TestClient:
    for nombre in ("VERCEL", "TURSO_DATABASE_URL"):
        monkeypatch.delenv(nombre, raising=False)
    monkeypatch.setenv("CLAVE_ACCESO", "clave-compartida")
    monkeypatch.setenv("RADAR_SQLITE", str(tmp_path / "ajustes.db"))
    monkeypatch.setenv("RADAR_DATOS", "ejemplos")
    monkeypatch.setattr(modulo_datos, "_datos", None)
    cuentas.olvidar_sesiones()
    import app

    return TestClient(app.app)


def _sesion(cliente, usuario, rol):
    conexion = cuentas.conectar()
    try:
        cuentas.crear_usuario(conexion, usuario, usuario.title(), rol, CLAVE)
    finally:
        conexion.close()
    assert cliente.post("/api/sesion", json={"usuario": usuario, "clave": CLAVE}).status_code == 200


def test_api_admin_cambia_el_modelo(monkeypatch, tmp_path):
    cliente = _cliente(monkeypatch, tmp_path)
    _sesion(cliente, "ana", "admin")
    d = cliente.get("/api/ajustes").json()
    assert d["usos"]["analista"]["origen"] == "defecto"
    assert {m["id"] for m in d["modelos"]} >= {"claude-opus-5-5", "claude-sonnet-5-5"}

    r = cliente.put("/api/ajustes/modelo/analista", json={"modelo": "claude-sonnet-5-5"})
    assert r.status_code == 200
    u = r.json()["usos"]["analista"]
    assert (u["modelo"], u["origen"], u["por"]) == ("claude-sonnet-5-5", "consola", "Ana")
    assert ajustes.modelo("analista") == "claude-sonnet-5-5"

    r = cliente.put("/api/ajustes/modelo/analista", json={"modelo": None})
    assert r.json()["usos"]["analista"]["origen"] == "defecto"


def test_api_rechaza_modelo_desconocido_y_uso_desconocido(monkeypatch, tmp_path):
    cliente = _cliente(monkeypatch, tmp_path)
    _sesion(cliente, "ana", "admin")
    r = cliente.put("/api/ajustes/modelo/analista", json={"modelo": "claude-inventado-9"})
    assert r.status_code == 422
    assert cliente.put("/api/ajustes/modelo/otro", json={"modelo": None}).status_code == 404


def test_api_solo_admin_cambia(monkeypatch, tmp_path):
    cliente = _cliente(monkeypatch, tmp_path)
    _sesion(cliente, "luis", "analista")
    assert cliente.get("/api/ajustes").status_code == 200
    r = cliente.put("/api/ajustes/modelo/analista", json={"modelo": "claude-haiku-5-5"})
    assert r.status_code == 403
