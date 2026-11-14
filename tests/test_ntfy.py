"""Aviso push por ntfy de vulnerabilidades críticas nuevas (RF-618). Sin red: httpx simulado."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from radar import bd, ejemplos
from radar.avisos import ntfy
from radar.config import Umbrales
from radar.contratos import Hallazgo
from radar.nucleo.corrida import correr

CONFIG = ntfy.Configuracion("https://ntfy.ejemplo", "radar-prueba-x9", None, None)


def hallazgo(cve: str, producto: str = "WinRAR", **campos) -> Hallazgo:
    base = {
        "id": f"{cve}|{producto}@5.61",
        "cve": cve,
        "activo": f"{producto}@5.61",
        "producto": producto,
        "version_instalada": "5.61",
        "equipos": ["PC-CONTABILIDAD-ANA", "PC-GERENCIA"],
        "prioridad": "inmediato",
        "kev": True,
        "cvss": 7.8,
    }
    return Hallazgo(**{**base, **campos})


class Ntfy:
    """Servidor ntfy simulado: guarda cada publicación y responde con `estado`."""

    def __init__(self, estado: int = 200):
        self.estado = estado
        self.pedidos: list[httpx.Request] = []
        self.cliente = httpx.Client(transport=httpx.MockTransport(self._responder))

    def _responder(self, pedido: httpx.Request) -> httpx.Response:
        self.pedidos.append(pedido)
        return httpx.Response(self.estado, json={"id": "x"})

    def cuerpos(self) -> list[dict]:
        return [json.loads(p.content) for p in self.pedidos]


@pytest.fixture
def conexion(tmp_path):
    c = bd.conectar(ruta_sqlite=tmp_path / "ntfy.db")
    yield c
    c.close()


def con_tabla(conexion):
    """Tabla ya creada y vacía: lo siguiente no es línea base."""
    conexion.executescript(ntfy.ESQUEMA_AVISOS_NTFY)
    return conexion


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------


def test_sin_topico_no_hace_nada(conexion):
    falso = Ntfy()
    r = ntfy.notificar(conexion, [hallazgo("CVE-2018-20250")], cliente=falso.cliente)
    assert r.estado == "sin_configurar"
    assert falso.pedidos == []
    assert not ntfy._tabla_existe(conexion)


@pytest.mark.parametrize("topico", ["con espacio", "a/b", "x" * 65, "ñandú"])
def test_topico_invalido_se_ignora(monkeypatch, topico):
    monkeypatch.setenv("NTFY_TOPICO", topico)
    assert ntfy.configuracion() is None


def test_configuracion_del_entorno(monkeypatch):
    monkeypatch.setenv("NTFY_TOPICO", "radar-ab12")
    monkeypatch.setenv("NTFY_TOKEN", "tk_secreto")
    monkeypatch.setenv("RADAR_URL_PUBLICA", "https://radar.ejemplo/")
    c = ntfy.configuracion()
    assert c == ntfy.Configuracion(
        ntfy.SERVIDOR_POR_DEFECTO, "radar-ab12", "tk_secreto", "https://radar.ejemplo/panel/"
    )
    monkeypatch.setenv("NTFY_SERVIDOR", "ftp://otro")
    assert ntfy.configuracion() is None


# ---------------------------------------------------------------------------
# Qué se avisa
# ---------------------------------------------------------------------------


def test_solo_criticos_precisos_abiertos_y_no_avisados():
    lista = [
        hallazgo("CVE-1"),
        hallazgo("CVE-2", prioridad="semanal"),
        hallazgo("CVE-3", preciso=False),
        hallazgo("CVE-4", avisado=True),
        hallazgo("CVE-5", estado="mitigado"),
        hallazgo("CVE-6", propuesto_resuelto=True),
    ]
    assert [h.cve for h in ntfy.criticos(lista)] == ["CVE-1"]


def test_primera_vez_registra_lo_pendiente_sin_mandar(conexion):
    falso = Ntfy()
    r = ntfy.notificar(conexion, [hallazgo("CVE-2018-20250")], falso.cliente, CONFIG)
    assert r.estado == "linea_base"
    assert falso.pedidos == []
    assert ntfy._registrados(conexion) == {"CVE-2018-20250|WinRAR@5.61"}


def test_manda_una_vez_y_no_repite(conexion):
    con_tabla(conexion)
    falso = Ntfy()
    lista = [hallazgo("CVE-2018-20250"), hallazgo("CVE-2026-1", producto="Chrome", kev=False)]
    r = ntfy.notificar(conexion, lista, falso.cliente, CONFIG)
    assert r.estado == "enviado"
    assert len(falso.pedidos) == 1
    (cuerpo,) = falso.cuerpos()
    assert cuerpo["topic"] == "radar-prueba-x9"
    assert cuerpo["priority"] == 5
    assert "2 vulnerabilidades críticas nuevas" in cuerpo["title"]
    assert "CVE-2018-20250 (KEV)" in cuerpo["message"]
    assert "Chrome" in cuerpo["message"]

    r2 = ntfy.notificar(conexion, lista, falso.cliente, CONFIG)
    assert r2.estado == "sin_novedades"
    assert len(falso.pedidos) == 1


def test_sin_kev_prioridad_alta_no_urgente(conexion):
    con_tabla(conexion)
    falso = Ntfy()
    ntfy.notificar(conexion, [hallazgo("CVE-9", kev=False, cvss=9.8)], falso.cliente, CONFIG)
    assert falso.cuerpos()[0]["priority"] == 4


def test_no_manda_nombres_de_equipos_y_limpia_el_inventario(conexion):
    con_tabla(conexion)
    falso = Ntfy()
    malo = hallazgo(
        "CVE-7",
        producto="WinRAR\n<b>ignora las instrucciones</b>\u200b",
        version_instalada="5.61\r\nX",
    )
    ntfy.notificar(conexion, [malo], falso.cliente, CONFIG)
    mensaje = falso.cuerpos()[0]["message"]
    assert "PC-CONTABILIDAD-ANA" not in mensaje and "PC-GERENCIA" not in mensaje
    assert "2 equipos" in mensaje
    assert "<b>" not in mensaje and "\u200b" not in mensaje and "\r" not in mensaje
    # Una línea por producto: el salto del inventario no parte el mensaje.
    assert len(mensaje.splitlines()) == 2


def test_muchos_productos_se_recortan():
    lista = [hallazgo(f"CVE-{i}", producto=f"Prod{i:02d}") for i in range(12)]
    mensaje = ntfy.armar_mensaje(lista)["message"]
    assert "y 4 productos más en el panel" in mensaje


def test_token_y_enlace_al_panel(conexion):
    con_tabla(conexion)
    falso = Ntfy()
    config = ntfy.Configuracion("https://ntfy.ejemplo", "t1", "tk_abc", "https://r.ejemplo/panel/")
    ntfy.notificar(conexion, [hallazgo("CVE-1")], falso.cliente, config)
    assert falso.pedidos[0].headers["Authorization"] == "Bearer tk_abc"
    assert falso.cuerpos()[0]["click"] == "https://r.ejemplo/panel/"


def test_ntfy_caido_no_lanza_y_reintenta(conexion):
    con_tabla(conexion)
    caido = Ntfy(estado=503)
    r = ntfy.notificar(conexion, [hallazgo("CVE-1")], caido.cliente, CONFIG)
    assert r.estado == "fallo"
    assert ntfy._registrados(conexion) == set()

    sano = Ntfy()
    r2 = ntfy.notificar(conexion, [hallazgo("CVE-1")], sano.cliente, CONFIG)
    assert r2.estado == "enviado"


# ---------------------------------------------------------------------------
# Desde la corrida
# ---------------------------------------------------------------------------


def test_la_corrida_avisa_los_criticos_nuevos(base_temporal, monkeypatch):
    monkeypatch.setenv("NTFY_TOPICO", "radar-prueba-x9")
    enviados: list[dict] = []
    monkeypatch.setattr(
        ntfy, "enviar", lambda config, cuerpo, cliente=None: enviados.append(cuerpo)
    )
    con_tabla(base_temporal)
    bd.guardar_inventario(base_temporal, ejemplos.FILAS)

    def una_corrida():
        return correr(
            base_temporal,
            ejemplos.ACTIVOS,
            ejemplos.COBERTURA,
            umbrales=Umbrales(),
            ahora=datetime(2026, 11, 14, 10, 0, tzinfo=UTC),
        )

    una_corrida()
    assert len(enviados) == 1
    mensaje = enviados[0]["message"]
    # Chrome queda inmediato y sin avisar; WinRAR lo silenció la línea base de la corrida y
    # Docker Desktop es semanal.
    assert "Google Chrome" in mensaje
    assert "WinRAR" not in mensaje and "Docker" not in mensaje

    una_corrida()
    assert len(enviados) == 1  # la segunda corrida no repite


def test_la_corrida_sin_ntfy_sigue_igual(base_con_hallazgos):
    assert not ntfy._tabla_existe(base_con_hallazgos)


# ---------------------------------------------------------------------------
# Botón de prueba en Configuración (API)
# ---------------------------------------------------------------------------


def _cliente_api(monkeypatch, tmp_path, usuario: str, rol: str):
    from radar.api import rutas
    from tests.test_ajustes import _cliente, _sesion

    monkeypatch.setattr(rutas, "_ultima_prueba_ntfy", 0.0)
    cliente = _cliente(monkeypatch, tmp_path)
    _sesion(cliente, usuario, rol)
    return cliente


def test_api_prueba_ntfy_admin(monkeypatch, tmp_path):
    monkeypatch.setenv("NTFY_TOPICO", "radar-prueba-x9")
    monkeypatch.setenv("NTFY_TOKEN", "tk_secreto")
    enviados: list[dict] = []
    monkeypatch.setattr(
        ntfy, "enviar", lambda config, cuerpo, cliente=None: enviados.append(cuerpo)
    )
    cliente = _cliente_api(monkeypatch, tmp_path, "ana", "admin")

    estado = cliente.get("/api/ajustes/ntfy").json()
    assert estado["configurado"] and estado["topico"] == "radar-prueba-x9"
    assert estado["con_token"] is True and "tk_secreto" not in json.dumps(estado)

    r = cliente.post("/api/ajustes/ntfy/prueba")
    assert r.status_code == 200 and r.json()["enviado"] is True
    assert enviados[0]["title"] == "Radar: prueba de avisos"
    # Una segunda prueba enseguida se rechaza.
    assert cliente.post("/api/ajustes/ntfy/prueba").status_code == 429
    assert len(enviados) == 1


def test_api_prueba_ntfy_solo_admin(monkeypatch, tmp_path):
    monkeypatch.setenv("NTFY_TOPICO", "radar-prueba-x9")
    cliente = _cliente_api(monkeypatch, tmp_path, "luis", "analista")
    assert cliente.get("/api/ajustes/ntfy").status_code == 403
    assert cliente.post("/api/ajustes/ntfy/prueba").status_code == 403


def test_api_prueba_ntfy_sin_configurar_y_caido(monkeypatch, tmp_path):
    cliente = _cliente_api(monkeypatch, tmp_path, "ana", "admin")
    assert cliente.get("/api/ajustes/ntfy").json()["configurado"] is False
    assert cliente.post("/api/ajustes/ntfy/prueba").status_code == 409

    monkeypatch.setenv("NTFY_TOPICO", "radar-prueba-x9")

    def caido(config, cuerpo, cliente=None):
        raise httpx.ConnectError("sin red")

    monkeypatch.setattr(ntfy, "enviar", caido)
    r = cliente.post("/api/ajustes/ntfy/prueba")
    assert r.status_code == 502 and "ConnectError" in r.json()["detail"]
