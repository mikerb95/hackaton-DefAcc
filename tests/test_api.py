"""Pruebas de la API del panel (RF-601 a RF-606). Sin red ni Claude.

Con datos de ejemplo y con una base sqlite temporal (el mismo esquema de Turso).
"""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from radar.api import datos as modulo_datos
from radar.api.rutas import texto_objetivo
from radar.contratos import Grupo

RAIZ = Path(__file__).resolve().parent.parent
BASE_LOCAL = RAIZ / "datos_locales" / "radar.db"


def _cliente(monkeypatch, **entorno) -> TestClient:
    for nombre in ("CLAVE_ACCESO", "VERCEL", "RADAR_DATOS", "TURSO_DATABASE_URL"):
        monkeypatch.delenv(nombre, raising=False)
    for nombre, valor in entorno.items():
        monkeypatch.setenv(nombre, valor)
    monkeypatch.setattr(modulo_datos, "_datos", None)
    import app

    return TestClient(app.app)


@pytest.fixture
def cliente(monkeypatch):
    return _cliente(monkeypatch, RADAR_DATOS="ejemplos")


# -- acceso (RF-601) -----------------------------------------------------------


def test_clave_obligatoria_si_esta_configurada(monkeypatch):
    c = _cliente(monkeypatch, RADAR_DATOS="ejemplos", CLAVE_ACCESO="secreta")
    assert c.get("/api/resumen").status_code == 401
    assert c.get("/api/resumen", headers={"X-Clave-Acceso": "otra"}).status_code == 401
    assert c.get("/api/resumen", headers={"X-Clave-Acceso": "secreta"}).status_code == 200


def test_en_vercel_sin_clave_no_queda_abierta(monkeypatch):
    c = _cliente(monkeypatch, RADAR_DATOS="ejemplos", VERCEL="1")
    assert c.get("/api/resumen").status_code == 503


# -- lecturas (RF-602) ---------------------------------------------------------


def test_resumen_con_ejemplos(cliente):
    r = cliente.get("/api/resumen").json()
    assert r["persistente"] is False
    assert set(r["cifras"]) == {"exigen_accion", "explotadas", "semanal", "equipos_afectados"}
    assert r["revision"]["caidas"] == []
    assert sum(r["cobertura"]["por_motivo"].values()) == r["cobertura"]["sin_evaluar"]


def test_hallazgos_ordenados_y_filtrados(cliente):
    todos = cliente.get("/api/hallazgos").json()["hallazgos"]
    orden = {"inmediato": 0, "semanal": 1, "informativo": 2, "boletin": 3}
    assert [orden[h["prioridad"]] for h in todos] == sorted(orden[h["prioridad"]] for h in todos)
    solo_kev = cliente.get("/api/hallazgos", params={"kev": "true"}).json()["hallazgos"]
    assert solo_kev and all(h["kev"] for h in solo_kev)
    winrar = cliente.get("/api/hallazgos", params={"texto": "winrar"}).json()["hallazgos"]
    assert winrar and all(h["producto"] == "WinRAR" for h in winrar)
    assert cliente.get("/api/hallazgos", params={"prioridad": "otra"}).status_code == 422


def test_epss_ausente_viaja_como_null(cliente, monkeypatch):
    datos = modulo_datos.obtener_datos()
    primero = next(iter(datos._hallazgos))
    datos._hallazgos[primero] = datos._hallazgos[primero].model_copy(update={"epss": None})
    h = cliente.get("/api/hallazgos").json()["hallazgos"]
    assert any(x["epss"] is None for x in h)


def test_productos_y_analisis(cliente):
    productos = cliente.get("/api/productos").json()["productos"]
    assert all("objetivo_texto" in g and "n_equipos" in g for g in productos)
    r = cliente.get("/api/analisis/WinRAR").json()
    assert r["pendiente"] is False and r["analisis"]["producto"] == "WinRAR"
    assert cliente.get("/api/analisis/NoExiste").status_code == 404


# -- regla 5: nunca "actualizar a X" con versionEndIncluding (RF-603) -----------


@pytest.mark.parametrize(
    ("tipo", "version", "esperado"),
    [
        ("exacta", "7.13", "actualizar a 7.13"),
        ("posterior_a", "5.61", "posterior a 5.61"),
        ("ninguna", None, "sin versión objetivo conocida"),
    ],
)
def test_texto_objetivo(tipo, version, esperado):
    g = Grupo(producto="X", tipo_objetivo=tipo, version_objetivo=version)
    assert texto_objetivo(g) == esperado
    if tipo != "exacta":
        assert "actualizar a" not in texto_objetivo(g)


# -- escrituras (RF-604) -------------------------------------------------------


def test_cambiar_estado_y_aprobar(cliente):
    hid = cliente.get("/api/hallazgos").json()["hallazgos"][0]["id"]
    r = cliente.post(f"/api/hallazgos/{hid}/estado", json={"estado": "mitigado", "por": "ti"})
    assert r.status_code == 200 and r.json()["hallazgo"]["estado"] == "mitigado"
    assert cliente.post(f"/api/hallazgos/{hid}/estado", json={"estado": "x"}).status_code == 422
    assert (
        cliente.post("/api/hallazgos/no|existe/estado", json={"estado": "nuevo"}).status_code == 404
    )
    r = cliente.post("/api/comunicado/WinRAR/aprobar", json={"por": "ti"})
    assert r.status_code == 200
    assert cliente.get("/api/analisis/WinRAR").json()["aprobacion"]["por"] == "ti"


# -- carga de inventario (RF-605) ----------------------------------------------


def test_inventario_ilegible_responde_400(cliente):
    r = cliente.post("/api/inventario", files={"archivo": ("x.csv", b"a,b\n1,2\n")})
    assert r.status_code == 400 and "encabezado" in r.json()["detail"]


def test_inventario_con_ejemplos_no_cruza(cliente):
    csv = b"equipo,programa,version\nPC1,WinRAR,5.61\nPC2,,1\n"
    r = cliente.post("/api/inventario", files={"archivo": ("i.csv", csv)}).json()
    assert r["lectura"]["filas"] == 1 and r["descartadas"][0]["fila"] == 3
    assert r["cruce"] == "pendiente"


@pytest.mark.skipif(not BASE_LOCAL.exists(), reason="falta datos_locales/radar.db (descargar)")
def test_inventario_cruza_contra_la_base(monkeypatch, tmp_path):
    copia = tmp_path / "radar.db"
    shutil.copy(BASE_LOCAL, copia)
    # La base local es compartida: otro frente pudo dejar hallazgos de otro inventario.
    with sqlite3.connect(copia) as con:
        for tabla in ("hallazgos", "cobertura", "inventario", "analisis", "trabajos"):
            con.execute(f"DELETE FROM {tabla}")
    c = _cliente(monkeypatch, RADAR_DATOS="base", RADAR_SQLITE=str(copia))
    csv = b"equipo,programa,version\nPC1,WinRAR 5.61 (64-bit),5.61\nPC2,Programa Inventado,1.0\n"
    r = c.post("/api/inventario", files={"archivo": ("i.csv", csv)}).json()
    assert r["cruce"] == "hecho"
    assert r["resultado"]["en_kev"] > 0 and r["resultado"]["cobertura"] >= 1
    assert isinstance(r["trabajo"], int)
    productos = c.get("/api/productos").json()["productos"]
    assert [g["producto"] for g in productos] == ["WinRAR"]
    assert c.get("/api/resumen").json()["persistente"] is True
    assert c.post("/api/revisar").json()["encolado"] is True


# -- respaldo cuando no hay análisis del agente (RF-607) ------------------------


def test_detalle_sin_analisis_muestra_respaldo(cliente):
    datos = modulo_datos.obtener_datos()
    datos._analisis.pop("Docker Desktop")
    r = cliente.get("/api/analisis/Docker Desktop").json()
    assert r["pendiente"] is False and r["guardado"] is False
    assert r["analisis"]["origen"] == "respaldo"
    assert "Docker Desktop" in r["analisis"]["resumen"]
    assert cliente.post("/api/comunicado/Docker Desktop/aprobar", json={}).status_code == 200
    assert cliente.post("/api/comunicado/NoExiste/aprobar", json={}).status_code == 404
