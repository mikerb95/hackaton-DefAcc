"""Parcheo del lado servidor (RF-821 a RF-826, docs/plan-parcheo.md). Sin red ni Claude.

Usa la API del agente sobre la base temporal de `test_agente_api.py`: un Windows 11 23H2 con
WinRAR 5.61 (CVE en KEV), una CVE del propio Windows y el firewall apagado.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid

import pytest

from radar.equipos import parcheo_almacen
from radar.seguridad import ed25519
from radar.seguridad import plan_parcheo as catalogo
from tests.test_agente_api import _enviar, _inscribir, _reporte, cliente  # noqa: F401

SEMILLA = bytes(range(32))
PUBLICA = ed25519.clave_publica(SEMILLA)


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


@pytest.fixture
def equipo(cliente):  # noqa: F811
    equipo_id, credencial = _inscribir(cliente)
    assert _enviar(cliente, credencial, _reporte(equipo_id)).status_code == 202
    return equipo_id, credencial


@pytest.fixture
def con_clave(cliente):  # noqa: F811
    r = cliente.post("/api/parcheo/claves", json={"publica": _b64(PUBLICA), "nombre": "TI"})
    assert r.status_code == 200, r.text
    return r.json()["huella"]


def _propuesta(cliente, equipo_id):  # noqa: F811
    r = cliente.get(f"/api/equipos/{equipo_id}/parcheo")
    assert r.status_code == 200, r.text
    return r.json()


def _borrador(cliente, equipo_id, ids):  # noqa: F811
    return cliente.post(f"/api/equipos/{equipo_id}/parcheo/borrador", json={"acciones": ids})


def _firmado(cliente, equipo_id, ids, semilla=SEMILLA):  # noqa: F811
    r = _borrador(cliente, equipo_id, ids)
    assert r.status_code == 200, r.text
    canonico = r.json()["plan"]
    return canonico, _b64(ed25519.firmar(semilla, canonico.encode("ascii")))


def _registrar(cliente, equipo_id, canonico, firma):  # noqa: F811
    return cliente.post(
        f"/api/equipos/{equipo_id}/parcheo", json={"plan": canonico, "firma": firma}
    )


# -- propuesta (RF-821) --------------------------------------------------------


def test_propuesta_sale_del_catalogo_cerrado(cliente, equipo):  # noqa: F811
    equipo_id, _ = equipo
    propuesta = _propuesta(cliente, equipo_id)["propuesta"]
    ids = [a["id"] for a in propuesta["acciones"]]
    assert ids == ["app:RARLab.WinRAR", "postura:firewall", "so:windows_update"]
    winrar = propuesta["acciones"][0]
    assert winrar["ejecutor"] == "winget" and winrar["programa"] == "WinRAR 5.61 (64-bit)"
    assert winrar["en_kev"] and set(winrar["en_kev"]) <= set(winrar["cves"])
    assert propuesta["acciones"][2]["cves"] == ["CVE-2025-21202"]
    for accion in propuesta["acciones"]:
        assert catalogo.validar_accion(accion, "windows") is None
    # Lo que no se automatiza va a manuales con su motivo (cifrado de disco).
    assert any("cifr" in m["titulo"].lower() for m in propuesta["manuales"])


def test_equipo_pendiente_no_tiene_propuesta(cliente, monkeypatch):  # noqa: F811
    monkeypatch.setenv("AGENTE_APROBACION", "manual")
    equipo_id, credencial = _inscribir(cliente, nombre="PENDIENTE-1")
    _enviar(cliente, credencial, _reporte(equipo_id, "PENDIENTE-1"))
    propuesta = _propuesta(cliente, equipo_id)["propuesta"]
    assert propuesta["acciones"] == [] and "pendiente" in propuesta["motivo"]
    assert _borrador(cliente, equipo_id, ["postura:firewall"]).status_code == 409


# -- borrador, firma y registro (RF-822) ---------------------------------------


def test_flujo_completo_firma_entrega_y_resultado(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, credencial = equipo
    canonico, firma = _firmado(cliente, equipo_id, ["postura:firewall", "app:RARLab.WinRAR"])
    plan = json.loads(canonico)
    # El orden de ejecución lo pone el código: aplicaciones antes que postura.
    assert [a["id"] for a in plan["acciones"]] == ["app:RARLab.WinRAR", "postura:firewall"]
    assert plan["aprobado_por"] == "Modo local" and plan["equipo_id"] == equipo_id
    r = _registrar(cliente, equipo_id, canonico, firma)
    assert r.status_code == 200, r.text
    assert r.json()["clave"] == con_clave

    # El agente recibe exactamente lo firmado y lo verifica con su clave fijada.
    entrega = cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": credencial})
    assert entrega.status_code == 200
    datos = entrega.json()
    assert datos["plan"] == canonico
    assert ed25519.verificar(PUBLICA, datos["plan"].encode(), base64.b64decode(datos["firma"]))

    resultado = {
        "plan_id": plan["plan_id"],
        "equipo_id": equipo_id,
        "agente_version": "0.2.0",
        "estado": "ejecutado",
        "huella_plan": hashlib.sha256(canonico.encode()).hexdigest(),
        "inicio": "2026-11-14T20:00:00Z",
        "fin": "2026-11-14T20:05:00Z",
        "acciones": [
            {
                "id": "app:RARLab.WinRAR",
                "estado": "aplicado",
                "antes": {"version": "5.61"},
                "despues": {"version": "7.13"},
                "pasos": [{"orden": ["winget", "upgrade"], "codigo": 0, "salida": "ok\n<b>x"}],
            },
            {"id": "postura:firewall", "estado": "revertido", "motivo": "no verificó"},
        ],
    }
    r = cliente.post(
        "/api/agente/parcheo/resultado",
        content=json.dumps(resultado),
        headers={"X-Credencial-Equipo": credencial},
    )
    assert r.status_code == 202, r.text
    # Una sola vez por plan.
    otra = cliente.post(
        "/api/agente/parcheo/resultado",
        content=json.dumps(resultado),
        headers={"X-Credencial-Equipo": credencial},
    )
    assert otra.status_code == 409
    # Ya no se entrega.
    assert (
        cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": credencial}).status_code
        == 204
    )

    informe = cliente.get(f"/api/parcheo/{plan['plan_id']}/informe").json()
    assert informe["estado_general"] == "parcial"
    assert informe["conteo"]["aplicado"] == 1 and informe["conteo"]["revertido"] == 1
    salida = informe["acciones"][0]["resultado"]["pasos"][0]["salida"]
    assert "<" not in salida and "\n" not in salida  # texto del equipo limpio
    # Sin inventario posterior, el radar todavía no confirma nada.
    assert informe["verificado_por_radar"] is False
    assert informe["acciones"][0]["verificacion"]["estado"] == "pendiente"

    historial = _propuesta(cliente, equipo_id)["planes"]
    assert historial[0]["plan_id"] == plan["plan_id"] and historial[0]["estado"] == "ejecutado"


def test_inventario_posterior_confirma_en_el_radar(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, credencial = equipo
    canonico, firma = _firmado(cliente, equipo_id, ["app:RARLab.WinRAR", "postura:firewall"])
    assert _registrar(cliente, equipo_id, canonico, firma).status_code == 200
    plan = json.loads(canonico)
    resultado = {
        "plan_id": plan["plan_id"],
        "equipo_id": equipo_id,
        "estado": "ejecutado",
        "huella_plan": hashlib.sha256(canonico.encode()).hexdigest(),
        "fin": "2026-11-14T15:30:00Z",
        "acciones": [
            {"id": "app:RARLab.WinRAR", "estado": "aplicado"},
            {"id": "postura:firewall", "estado": "aplicado"},
        ],
    }
    cliente.post(
        "/api/agente/parcheo/resultado",
        content=json.dumps(resultado),
        headers={"X-Credencial-Equipo": credencial},
    )
    nuevo = _reporte(equipo_id, recogido="2026-11-14T16:00:00Z")
    nuevo["software"][0] |= {"programa": "WinRAR 7.13 (64-bit)", "version": "7.13"}
    nuevo["postura"]["firewall"] = "si"
    assert _enviar(cliente, credencial, nuevo).status_code == 202
    informe = cliente.get(f"/api/parcheo/{plan['plan_id']}/informe").json()
    assert informe["verificado_por_radar"] is True
    estados = [a["verificacion"]["estado"] for a in informe["acciones"]]
    assert estados == ["confirmada", "confirmada"]
    assert informe["exposicion"]["kev_siguen"] == []
    assert informe["estado_general"] == "exito"


def test_firma_de_otra_clave_no_se_guarda(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, _ = equipo
    canonico, _ = _firmado(cliente, equipo_id, ["postura:firewall"])
    ajena = _b64(ed25519.firmar(os.urandom(32), canonico.encode()))
    assert _registrar(cliente, equipo_id, canonico, ajena).status_code == 403


def test_plan_alterado_despues_de_firmar(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, _ = equipo
    canonico, firma = _firmado(cliente, equipo_id, ["app:RARLab.WinRAR"])
    plan = json.loads(canonico)
    plan["acciones"][0]["paquete"] = "Google.Chrome"
    alterado = catalogo.canonico(plan).decode()
    assert _registrar(cliente, equipo_id, alterado, firma).status_code == 403
    # Bien firmado pero fuera del catálogo (un ejecutor inventado) tampoco entra.
    plan["acciones"][0] |= {"ejecutor": "powershell", "paquete": "RARLab.WinRAR"}
    raro = catalogo.canonico(plan).decode()
    firma_rara = _b64(ed25519.firmar(SEMILLA, raro.encode()))
    assert _registrar(cliente, equipo_id, raro, firma_rara).status_code == 422


def test_accion_que_no_esta_en_la_propuesta(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, _ = equipo
    canonico, _ = _firmado(cliente, equipo_id, ["app:RARLab.WinRAR"])
    plan = json.loads(canonico)
    plan["acciones"][0]["minimo"] = "1.0"  # firmado bien, pero distinto de la propuesta
    otro = catalogo.canonico(plan).decode()
    r = _registrar(cliente, equipo_id, otro, _b64(ed25519.firmar(SEMILLA, otro.encode())))
    assert r.status_code == 409 and "no coincide" in r.json()["detail"]


def test_plan_de_otro_equipo_y_borrador_vencido(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, _ = equipo
    otro_id, credencial_otro = _inscribir(cliente, nombre="EQUIPO-099")
    _enviar(cliente, credencial_otro, _reporte(otro_id, "EQUIPO-099"))
    canonico, firma = _firmado(cliente, equipo_id, ["postura:firewall"])
    assert _registrar(cliente, otro_id, canonico, firma).status_code == 422
    plan = json.loads(canonico)
    plan["emitido"] = "2026-01-01T00:00:00Z"
    viejo = catalogo.canonico(plan).decode()
    r = _registrar(cliente, equipo_id, viejo, _b64(ed25519.firmar(SEMILLA, viejo.encode())))
    assert r.status_code == 409 and "venció" in r.json()["detail"]


def test_clave_revocada_y_un_plan_activo_por_equipo(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, credencial = equipo
    canonico, firma = _firmado(cliente, equipo_id, ["postura:firewall"])
    assert _registrar(cliente, equipo_id, canonico, firma).status_code == 200
    canonico2, firma2 = _firmado(cliente, equipo_id, ["app:RARLab.WinRAR"])
    assert _registrar(cliente, equipo_id, canonico2, firma2).status_code == 409
    plan_id = json.loads(canonico)["plan_id"]
    assert cliente.post(f"/api/parcheo/{plan_id}/cancelar").json()["cancelado"] is True
    # Un plan cancelado ya no se entrega.
    assert (
        cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": credencial}).status_code
        == 204
    )
    assert cliente.post(f"/api/parcheo/claves/{con_clave}/revocar").status_code == 200
    canonico3, firma3 = _firmado(cliente, equipo_id, ["app:RARLab.WinRAR"])
    assert _registrar(cliente, equipo_id, canonico3, firma3).status_code == 403


# -- lo que llama el agente (RF-823) -------------------------------------------


def test_el_agente_solo_ve_sus_planes(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, credencial = equipo
    otro_id, credencial_otro = _inscribir(cliente, nombre="EQUIPO-100")
    assert cliente.get("/api/agente/plan").status_code == 401
    assert cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": "x"}).status_code == 401
    canonico, firma = _firmado(cliente, equipo_id, ["postura:firewall"])
    _registrar(cliente, equipo_id, canonico, firma)
    assert (
        cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": credencial_otro}).status_code
        == 204
    )
    # El resultado de un plan ajeno o con otra huella se rechaza.
    plan = json.loads(canonico)
    base = {
        "plan_id": plan["plan_id"],
        "equipo_id": equipo_id,
        "estado": "ejecutado",
        "huella_plan": "0" * 64,
        "acciones": [],
    }
    r = cliente.post(
        "/api/agente/parcheo/resultado",
        content=json.dumps(base),
        headers={"X-Credencial-Equipo": credencial},
    )
    assert r.status_code == 409
    r = cliente.post(
        "/api/agente/parcheo/resultado",
        content=json.dumps(base | {"equipo_id": otro_id}),
        headers={"X-Credencial-Equipo": credencial_otro},
    )
    assert r.status_code == 404
    huella = hashlib.sha256(canonico.encode()).hexdigest()
    con_extra = base | {
        "huella_plan": huella,
        "acciones": [{"id": "app:Google.Chrome", "estado": "aplicado"}],
    }
    r = cliente.post(
        "/api/agente/parcheo/resultado",
        content=json.dumps(con_extra),
        headers={"X-Credencial-Equipo": credencial},
    )
    assert r.status_code == 422


def test_revocar_el_equipo_corta_la_entrega(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, credencial = equipo
    canonico, firma = _firmado(cliente, equipo_id, ["postura:firewall"])
    _registrar(cliente, equipo_id, canonico, firma)
    cliente.post(f"/api/equipos/{equipo_id}/revocar")
    assert (
        cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": credencial}).status_code
        == 403
    )


def test_claves_mal_formadas(cliente):  # noqa: F811
    corta = cliente.post("/api/parcheo/claves", json={"publica": _b64(b"x" * 31), "nombre": "a"})
    assert corta.status_code == 422
    assert (
        cliente.post("/api/parcheo/claves", json={"publica": "no-es-base64!" * 4, "nombre": "a"})
        .status_code
        == 422
    )
    ok = cliente.post("/api/parcheo/claves", json={"publica": _b64(PUBLICA), "nombre": "a"})
    assert ok.status_code == 200
    repetida = cliente.post("/api/parcheo/claves", json={"publica": _b64(PUBLICA), "nombre": "b"})
    assert repetida.status_code == 409


def test_plan_entregado_cuenta_las_entregas(cliente, equipo, con_clave, base_temporal):
    equipo_id, credencial = equipo
    canonico, firma = _firmado(cliente, equipo_id, ["postura:firewall"])
    _registrar(cliente, equipo_id, canonico, firma)
    for _ in range(2):
        cliente.get("/api/agente/plan", headers={"X-Credencial-Equipo": credencial})
    plan = parcheo_almacen.leer_plan(base_temporal, json.loads(canonico)["plan_id"])
    assert plan["estado"] == "entregado" and plan["entregas"] == 2


def test_id_de_plan_es_uuid_nuevo(cliente, equipo, con_clave):  # noqa: F811
    equipo_id, _ = equipo
    a = json.loads(_borrador(cliente, equipo_id, ["postura:firewall"]).json()["plan"])
    b = json.loads(_borrador(cliente, equipo_id, ["postura:firewall"]).json()["plan"])
    assert a["plan_id"] != b["plan_id"]
    uuid.UUID(a["plan_id"])
