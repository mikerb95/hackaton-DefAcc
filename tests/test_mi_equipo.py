"""Aviso y vista del equipo para quien lo usa (radar/api/mi_equipo.py y agente_local/aviso.py).

Sin red ni Claude: el servidor con la base temporal de las pruebas del agente y el lado del
agente con archivos en tmp_path y notificaciones simuladas.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import pytest

from agente_local import aviso
from agente_local.envio import ErrorEnvio
from radar.api import mi_equipo
from tests.test_agente_api import _enviar, _inscribir, _reporte, cliente  # noqa: F401

CABECERA = "X-Credencial-Equipo"
EQUIPO = "0f8fad5b-d9cb-469f-a165-70867728950e"


# -- enlace firmado -------------------------------------------------------------


def test_enlace_firmado_vence_y_no_se_falsifica(monkeypatch):
    monkeypatch.setenv("CLAVE_ACCESO", "clave-de-prueba")
    enlace, vence = mi_equipo.firmar_enlace(EQUIPO, ahora=1_800_000_000)
    assert vence == 1_800_000_000 + mi_equipo.VIGENCIA
    assert mi_equipo.verificar_enlace(enlace, ahora=1_800_000_001) == EQUIPO
    assert mi_equipo.verificar_enlace(enlace, ahora=vence + 1) is None
    # Otro equipo con la misma firma, otra fecha o una firma cambiada no valen.
    otro = enlace.replace(EQUIPO, "1f8fad5b-d9cb-469f-a165-70867728950e")
    assert mi_equipo.verificar_enlace(otro, ahora=1_800_000_001) is None
    assert mi_equipo.verificar_enlace(enlace[:-1] + "A", ahora=1_800_000_001) in (None, EQUIPO)
    assert mi_equipo.verificar_enlace(enlace.replace(str(vence), str(vence + 9)), 0) is None
    assert mi_equipo.verificar_enlace("", 0) is None
    # Cambiar la clave invalida los enlaces anteriores.
    monkeypatch.setenv("CLAVE_ACCESO", "otra")
    assert mi_equipo.verificar_enlace(enlace, ahora=1_800_000_001) is None


def test_en_vercel_sin_secreto_no_hay_enlaces(monkeypatch):
    for nombre in ("CLAVE_ACCESO", "RADAR_SECRETO_ENLACES"):
        monkeypatch.delenv(nombre, raising=False)
    monkeypatch.setenv("VERCEL", "1")
    with pytest.raises(Exception, match="secreto"):
        mi_equipo.firmar_enlace(EQUIPO)


# -- rutas ------------------------------------------------------------------------


def test_aviso_del_agente_y_vista_simple(cliente):  # noqa: F811
    equipo_id, credencial = _inscribir(cliente)
    _enviar(cliente, credencial, _reporte(equipo_id))

    assert cliente.get("/api/agente/aviso").status_code == 401
    r = cliente.get("/api/agente/aviso", headers={CABECERA: credencial})
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["equipo"] == "EQUIPO-017" and a["acciones"]["inmediato"] >= 1
    assert a["explotadas"] >= 1  # WinRAR está en KEV en los ejemplos
    assert a["ruta"] == "/mi-equipo/" and a["enlace"].startswith("eq1.")
    assert "credencial" not in json.dumps(a)

    sin = cliente.get("/api/mi-equipo")
    assert sin.status_code == 401
    malo = cliente.get("/api/mi-equipo", headers={"X-Enlace-Equipo": a["enlace"][:-2] + "xx"})
    assert malo.status_code == 401

    v = cliente.get("/api/mi-equipo", headers={"X-Enlace-Equipo": a["enlace"]})
    assert v.status_code == 200, v.text
    d = v.json()
    assert d["equipo"]["nombre"] == "EQUIPO-017"
    titulos = [t["titulo"] for t in d["tareas"]]
    assert "Actualiza WinRAR" in titulos
    winrar = next(t for t in d["tareas"] if t["titulo"] == "Actualiza WinRAR")
    assert winrar["cuando"] == "hoy" and winrar["explotada"]
    assert winrar["comandos"] == ["winget upgrade --id RARLab.WinRAR --exact"]
    assert "5.61" in winrar["detalle"]
    # Lo urgente va primero.
    orden = [t["cuando"] for t in d["tareas"]]
    assert orden == sorted(orden, key=["hoy", "esta_semana", "cuando_puedas"].index)
    assert d["parcheo"]["reinicio_pendiente"] is False
    # Ni la credencial ni datos de otros equipos.
    assert "credencial" not in json.dumps(d)


def test_el_enlace_no_sirve_tras_revocar_el_equipo(cliente):  # noqa: F811
    equipo_id, credencial = _inscribir(cliente)
    _enviar(cliente, credencial, _reporte(equipo_id))
    enlace = cliente.get("/api/agente/aviso", headers={CABECERA: credencial}).json()["enlace"]
    assert cliente.post(f"/api/equipos/{equipo_id}/revocar").status_code == 200
    assert cliente.get("/api/mi-equipo", headers={"X-Enlace-Equipo": enlace}).status_code == 403
    assert cliente.get("/api/agente/aviso", headers={CABECERA: credencial}).status_code == 403
    assert cliente.delete(f"/api/equipos/{equipo_id}").status_code == 200
    assert cliente.get("/api/mi-equipo", headers={"X-Enlace-Equipo": enlace}).status_code == 404


# -- agente: lo que guarda el servicio ---------------------------------------------


def _crudo(**cambios) -> dict:
    token = "eq1." + EQUIPO + ".1800000000." + "A" * 43
    base = {
        "equipo": "PC-ANA",
        "medido": True,
        "nivel": 80,
        "banda": "alto",
        "acciones": {"inmediato": 2, "semanal": 1, "informativo": 0},
        "explotadas": 1,
        "reinicio_pendiente": False,
        "reinicio_desde": None,
        "parcheo_en_curso": False,
        "ruta": "/mi-equipo/",
        "enlace": token,
        "vence": "2027-01-15T00:00:00+00:00",
    }
    return base | cambios


def test_depurar_arma_el_enlace_con_la_url_propia():
    a = aviso.depurar(_crudo(ruta="https://malo.example/x", extra="ignorar"), "https://radar.x")
    assert a["enlace"] == "https://radar.x/mi-equipo/#t=" + _crudo()["enlace"]
    assert "extra" not in a and "ruta" not in a
    assert a["acciones"] == {"inmediato": 2, "semanal": 1, "informativo": 0}


@pytest.mark.parametrize(
    "enlace",
    ["javascript:alert(1)", "https://malo.example/#t=x", "eq1.algo", 7, None],
)
def test_depurar_rechaza_enlaces_con_otra_forma(enlace):
    with pytest.raises(ErrorEnvio):
        aviso.depurar(_crudo(enlace=enlace), "https://radar.x")


def test_depurar_acota_tipos_y_textos():
    a = aviso.depurar(
        _crudo(
            equipo="X" * 500 + "\x1b[31m",
            acciones={"inmediato": "9", "semanal": True, "informativo": -3},
            banda="<script>",
            reinicio_pendiente="si",
        ),
        "https://radar.x",
    )
    assert len(a["equipo"]) == 80 and "\x1b" not in a["equipo"]
    assert a["acciones"] == {"inmediato": 0, "semanal": 0, "informativo": 0}
    assert a["banda"] is None and a["reinicio_pendiente"] is False


def test_guardar_y_leer(tmp_path):
    datos = aviso.depurar(_crudo(), "https://radar.x")
    ruta = aviso.guardar(tmp_path, datos)
    assert ruta == tmp_path / "aviso" / "aviso.json"
    assert not ruta.stat().st_mode & 0o022
    assert aviso.leer(tmp_path) == datos


def test_leer_desconfia_de_un_archivo_escribible_por_otros(tmp_path):
    ruta = aviso.guardar(tmp_path, aviso.depurar(_crudo(), "https://radar.x"))
    ruta.chmod(0o666)
    assert aviso.leer(tmp_path) is None


def test_leer_rechaza_un_enlace_cambiado_a_mano(tmp_path):
    datos = aviso.depurar(_crudo(), "https://radar.x")
    datos["enlace"] = "http://phishing.example/mi-equipo/#t=" + _crudo()["enlace"]
    aviso.guardar(tmp_path, datos)
    assert aviso.leer(tmp_path) is None


# -- agente: lo que ve la persona -----------------------------------------------------


def _aviso(**cambios) -> dict:
    return aviso.depurar(_crudo(**cambios), "https://radar.x")


def test_mensaje_por_urgencia():
    titulo, cuerpo = aviso.mensaje(_aviso(), arranque=None)
    assert titulo == "Tu equipo necesita atención"
    assert cuerpo.startswith("2 actualizaciones para hoy, 1 para esta semana.")
    assert "ataques reales" in cuerpo
    solo_semana = _aviso(acciones={"inmediato": 0, "semanal": 3}, explotadas=0)
    assert aviso.mensaje(solo_semana, None) == ("Tu equipo tiene pendientes", "3 para esta semana.")
    nada = _aviso(acciones={"inmediato": 0, "semanal": 0, "informativo": 4})
    assert aviso.mensaje(nada, None) is None


def test_el_reinicio_se_olvida_si_el_equipo_ya_arranco_despues():
    desde = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
    a = _aviso(
        acciones={"inmediato": 0, "semanal": 0},
        explotadas=0,
        reinicio_pendiente=True,
        reinicio_desde=desde.isoformat(),
    )
    antes = (desde - timedelta(hours=1)).timestamp()
    despues = (desde + timedelta(hours=1)).timestamp()
    assert aviso.mensaje(a, antes)[1] == "Reinicia el equipo para terminar de instalar."
    assert aviso.mensaje(a, despues) is None
    # Sin saber cuándo arrancó, se avisa (fuente caída no es cero).
    assert aviso.mensaje(a, None) is not None


def test_no_repite_el_mismo_aviso_antes_de_tiempo():
    ahora = time.time()
    assert aviso.toca_avisar("h1", {}, ahora)
    assert not aviso.toca_avisar("h1", {"huella": "h1", "momento": ahora - 60}, ahora)
    assert aviso.toca_avisar("h1", {"huella": "h1", "momento": ahora - aviso.REPETIR_CADA}, ahora)
    assert aviso.toca_avisar("h2", {"huella": "h1", "momento": ahora}, ahora)


def test_avisar_muestra_una_vez_y_recuerda(tmp_path, monkeypatch):
    monkeypatch.setattr(aviso, "carpeta_memoria", lambda: tmp_path / "persona")
    monkeypatch.setattr(aviso, "ultimo_arranque", lambda: None)
    aviso.guardar(tmp_path, _aviso())
    mostradas = []

    def mostrar(titulo, cuerpo, enlace):
        mostradas.append((titulo, enlace))
        return True

    assert aviso.avisar(tmp_path, mostrar=mostrar).startswith("Aviso mostrado")
    assert aviso.avisar(tmp_path, mostrar=mostrar) == "Aviso ya mostrado hace poco."
    assert aviso.avisar(tmp_path, forzar=True, mostrar=mostrar).startswith("Aviso mostrado")
    assert len(mostradas) == 2
    assert mostradas[0][1].startswith("https://radar.x/mi-equipo/#t=eq1.")


def test_avisar_sin_aviso_guardado(tmp_path):
    assert "Todavía no hay aviso" in aviso.avisar(tmp_path, mostrar=lambda *a: True)


def test_actualizar_pide_con_la_credencial_y_no_la_guarda(tmp_path):
    from agente_local.envio import Estado

    estado = Estado(tmp_path)
    estado.datos.update({"credencial": "c" * 40, "url": "https://radar.x"})
    vistas = []

    class Respuesta:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return json.dumps(_crudo()).encode()

    def abrir(peticion, timeout):
        vistas.append(peticion)
        return Respuesta()

    datos = aviso.actualizar(estado, abrir=abrir)
    assert vistas[0].full_url == "https://radar.x/api/agente/aviso"
    assert vistas[0].get_method() == "GET"
    assert vistas[0].get_header("X-credencial-equipo") == "c" * 40
    guardado = (tmp_path / "aviso" / "aviso.json").read_text(encoding="utf-8")
    assert "c" * 40 not in guardado
    assert datos["enlace"].startswith("https://radar.x/mi-equipo/#t=")
