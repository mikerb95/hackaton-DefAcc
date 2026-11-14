"""Pruebas de cuentas del panel: usuarios, sesión, roles, tokens de inscripción y paquetes
del agente (RF-610 a RF-614). Sin red ni Claude; sqlite en tmp_path."""

from __future__ import annotations

import uuid
import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from radar.api import cuentas, paquetes
from radar.api import datos as modulo_datos

CLAVE = "una-clave-larga-de-prueba"


def _cliente(monkeypatch, tmp_path, **entorno) -> TestClient:
    for nombre in ("CLAVE_ACCESO", "VERCEL", "TURSO_DATABASE_URL", "AGENTE_TOKEN_INSCRIPCION"):
        monkeypatch.delenv(nombre, raising=False)
    monkeypatch.setenv("RADAR_SQLITE", str(tmp_path / "cuentas.db"))
    monkeypatch.setenv("RADAR_DATOS", entorno.pop("RADAR_DATOS", "ejemplos"))
    for nombre, valor in entorno.items():
        monkeypatch.setenv(nombre, valor)
    monkeypatch.setattr(modulo_datos, "_datos", None)
    cuentas.olvidar_sesiones()
    import app

    return TestClient(app.app)


def _usuario(usuario: str, rol: str, clave: str = CLAVE) -> cuentas.Usuario:
    conexion = cuentas.conectar()
    try:
        return cuentas.crear_usuario(conexion, usuario, usuario.title(), rol, clave)
    finally:
        conexion.close()


def _entrar(cliente, usuario: str, clave: str = CLAVE):
    return cliente.post("/api/sesion", json={"usuario": usuario, "clave": clave})


@pytest.fixture
def cliente(monkeypatch, tmp_path):
    # Con CLAVE_ACCESO definida no hay modo local abierto: sin sesión ni clave, 401.
    return _cliente(monkeypatch, tmp_path, CLAVE_ACCESO="clave-compartida")


# -- contraseñas y usuarios (RF-610) -------------------------------------------


def test_clave_cifrada_con_scrypt_y_sal():
    a, b = cuentas.cifrar_clave(CLAVE), cuentas.cifrar_clave(CLAVE)
    assert a != b and a.startswith("scrypt$") and CLAVE not in a
    assert cuentas.clave_correcta(CLAVE, a)
    assert not cuentas.clave_correcta("otra-clave-larga", a)
    assert not cuentas.clave_correcta(CLAVE, "texto-cualquiera")


def test_usuario_valida_datos(cliente):
    with pytest.raises(cuentas.ErrorCuenta, match="al menos"):
        _usuario("ana", "admin", "corta")
    with pytest.raises(cuentas.ErrorCuenta, match="Rol"):
        _usuario("ana", "jefe")
    with pytest.raises(cuentas.ErrorCuenta, match="letras"):
        _usuario("ana pérez; drop", "admin")
    _usuario("Ana", "admin")
    with pytest.raises(cuentas.ErrorCuenta, match="Ya existe"):
        _usuario("ana", "lector")


def test_no_queda_sin_administrador(cliente):
    ana = _usuario("ana", "admin")
    conexion = cuentas.conectar()
    try:
        with pytest.raises(cuentas.ErrorCuenta, match="administrador"):
            cuentas.cambiar_usuario(conexion, ana.id, rol="lector")
        with pytest.raises(cuentas.ErrorCuenta, match="administrador"):
            cuentas.cambiar_usuario(conexion, ana.id, activo=False)
    finally:
        conexion.close()


# -- sesión (RF-611) -------------------------------------------------------------


def test_entrar_salir_y_cookie(cliente):
    assert cliente.get("/api/sesion").json() == {"usuario": None, "hay_usuarios": False}
    _usuario("ana", "analista")
    assert cliente.get("/api/resumen").status_code == 401
    r = _entrar(cliente, "ana", "equivocada-larga")
    assert r.status_code == 401 and "incorrectos" in r.json()["detail"]
    r = _entrar(cliente, "ANA")
    assert r.status_code == 200 and r.json()["usuario"]["rol"] == "analista"
    galleta = r.headers["set-cookie"].lower()
    assert "httponly" in galleta and "samesite=strict" in galleta
    assert cliente.get("/api/sesion").json()["usuario"]["usuario"] == "ana"
    assert cliente.get("/api/resumen").status_code == 200
    cliente.delete("/api/sesion")
    assert cliente.get("/api/resumen").status_code == 401


def test_usuario_inexistente_responde_igual(cliente):
    _usuario("ana", "admin")
    a = _entrar(cliente, "nadie")
    b = _entrar(cliente, "ana", "equivocada-larga")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_bloqueo_tras_fallos(cliente):
    _usuario("ana", "admin")
    for _ in range(cuentas.FALLOS_PERMITIDOS):
        assert _entrar(cliente, "ana", "equivocada-larga").status_code == 401
    # Bloqueado incluso con la contraseña correcta.
    assert _entrar(cliente, "ana").status_code == 429


def test_usuario_desactivado_pierde_la_sesion(cliente):
    _usuario("admin", "admin")
    beto = _usuario("beto", "lector")
    otro = TestClient(cliente.app)
    assert _entrar(otro, "beto").status_code == 200
    assert otro.get("/api/resumen").status_code == 200
    _entrar(cliente, "admin")
    r = cliente.patch(f"/api/usuarios/{beto.id}", json={"activo": False})
    assert r.status_code == 200 and r.json()["usuario"]["activo"] is False
    assert otro.get("/api/resumen").status_code == 401
    assert _entrar(otro, "beto").status_code == 401


def test_cambiar_mi_clave(cliente):
    _usuario("ana", "lector")
    _entrar(cliente, "ana")
    nueva = "otra-clave-bien-larga"
    r = cliente.put("/api/sesion/clave", json={"actual": "mala-mala-mala", "nueva": nueva})
    assert r.status_code == 403
    assert (
        cliente.put("/api/sesion/clave", json={"actual": CLAVE, "nueva": "corta"}).status_code
        == 422
    )
    assert (
        cliente.put("/api/sesion/clave", json={"actual": CLAVE, "nueva": nueva}).status_code == 200
    )
    assert cliente.get("/api/resumen").status_code == 401
    assert _entrar(cliente, "ana", nueva).status_code == 200


# -- roles y compatibilidad (RF-612) --------------------------------------------


def test_lector_no_cambia_nada(cliente):
    _usuario("lia", "lector")
    _entrar(cliente, "lia")
    hid = cliente.get("/api/hallazgos").json()["hallazgos"][0]["id"]
    assert (
        cliente.post(f"/api/hallazgos/{hid}/estado", json={"estado": "en_curso"}).status_code == 403
    )
    assert cliente.post("/api/comunicado/WinRAR/aprobar", json={}).status_code == 403
    assert cliente.get("/api/usuarios").status_code == 403
    assert cliente.get("/api/tokens").status_code == 403


def test_analista_aprueba_con_su_nombre(cliente):
    _usuario("ana", "analista")
    _entrar(cliente, "ana")
    # Con sesión no hace falta decir quién: sale de la sesión, y lo declarado no la pisa.
    r = cliente.post("/api/comunicado/WinRAR/aprobar", json={"por": "otra persona"})
    assert r.status_code == 200
    assert cliente.get("/api/analisis/WinRAR").json()["aprobacion"]["por"] == "Ana"
    assert cliente.get("/api/usuarios").status_code == 403


def test_clave_compartida_sigue_valiendo(cliente):
    cabecera = {"X-Clave-Acceso": "clave-compartida"}
    assert cliente.get("/api/resumen", headers=cabecera).status_code == 200
    assert cliente.get("/api/usuarios", headers=cabecera).status_code == 200
    # Con la clave hay que decir quién aprueba, como antes.
    assert (
        cliente.post("/api/comunicado/WinRAR/aprobar", json={}, headers=cabecera).status_code == 422
    )


def test_admin_gestiona_usuarios(cliente):
    _usuario("admin", "admin")
    _entrar(cliente, "admin")
    r = cliente.post(
        "/api/usuarios",
        json={"usuario": "beto", "nombre": "Beto", "rol": "analista", "clave": CLAVE},
    )
    assert r.status_code == 201 and "clave" not in r.json()["usuario"]
    repetido = {"usuario": "beto", "nombre": "B", "rol": "lector", "clave": CLAVE}
    assert cliente.post("/api/usuarios", json=repetido).status_code == 409
    nombres = [u["usuario"] for u in cliente.get("/api/usuarios").json()["usuarios"]]
    assert nombres == ["admin", "beto"]


# -- tokens de inscripción (RF-613) ---------------------------------------------


@pytest.fixture
def con_base(monkeypatch, tmp_path, base_temporal):
    c = _cliente(
        monkeypatch,
        tmp_path,
        RADAR_DATOS="base",
        CLAVE_ACCESO="clave-compartida",
        RADAR_SQLITE=str(tmp_path / "base_temporal.db"),
    )
    _usuario("admin", "admin")
    _entrar(c, "admin")
    return c


def _inscribir(cliente, token: str):
    return cliente.post(
        "/api/agente/inscribir",
        json={"token": token, "equipo_id": str(uuid.uuid4()), "nombre_equipo": "PC-01"},
    )


def test_token_del_panel_inscribe_y_se_agota(con_base):
    sin_tokens = _inscribir(con_base, "rdr_nada")
    assert sin_tokens.status_code == 401
    r = con_base.post("/api/tokens", json={"horas": 1, "usos_max": 2, "etiqueta": "Oficina"})
    assert r.status_code == 201
    token = r.json()["token"]
    assert token.startswith("rdr_") and r.json()["ficha"]["estado"] == "vigente"
    assert con_base.get("/api/equipos").json()["inscripcion_abierta"] is True
    assert _inscribir(con_base, token).status_code == 200
    assert _inscribir(con_base, token).status_code == 200
    assert _inscribir(con_base, token).status_code == 401
    ficha = con_base.get("/api/tokens").json()["tokens"][0]
    assert ficha["estado"] == "agotado" and ficha["usos"] == 2 and ficha["pista"] == token[-4:]
    # En la base solo queda la huella.
    conexion = cuentas.conectar()
    try:
        filas = conexion.execute("SELECT huella, pista FROM tokens_inscripcion").fetchall()
    finally:
        conexion.close()
    assert filas and all(token not in fila for fila in filas)


def test_equipo_repetido_devuelve_el_uso(con_base):
    token = con_base.post("/api/tokens", json={"usos_max": 2}).json()["token"]
    cuerpo = {"token": token, "equipo_id": str(uuid.uuid4()), "nombre_equipo": "PC-01"}
    assert con_base.post("/api/agente/inscribir", json=cuerpo).status_code == 200
    assert con_base.post("/api/agente/inscribir", json=cuerpo).status_code == 409
    assert con_base.get("/api/tokens").json()["tokens"][0]["usos"] == 1


def test_token_revocado_o_vencido_no_inscribe(con_base):
    r = con_base.post("/api/tokens", json={"usos_max": 5}).json()
    assert con_base.delete(f"/api/tokens/{r['ficha']['id']}").status_code == 200
    assert _inscribir(con_base, r["token"]).status_code == 401
    assert con_base.get("/api/tokens").json()["tokens"][0]["estado"] == "revocado"

    vencido = con_base.post("/api/tokens", json={"usos_max": 5}).json()
    conexion = cuentas.conectar()
    try:
        conexion.execute(
            "UPDATE tokens_inscripcion SET vence = '2000-01-01T00:00:00+00:00' WHERE id = ?",
            [vencido["ficha"]["id"]],
        )
        conexion.commit()
    finally:
        conexion.close()
    assert _inscribir(con_base, vencido["token"]).status_code == 401
    assert con_base.post("/api/tokens", json={"horas": 0}).status_code == 422


def test_solo_admin_revoca_equipos(con_base):
    token = con_base.post("/api/tokens", json={}).json()["token"]
    _inscribir(con_base, token)
    equipo = con_base.get("/api/equipos").json()["equipos"][0]["id"]
    _usuario("ana", "analista")
    otro = TestClient(con_base.app)
    _entrar(otro, "ana")
    assert otro.post(f"/api/equipos/{equipo}/revocar").status_code == 403
    assert con_base.post(f"/api/equipos/{equipo}/revocar").status_code == 200


# -- paquetes del agente (RF-614) ------------------------------------------------


@pytest.mark.parametrize("sistema", ["windows", "linux"])
def test_paquete_publicado_al_dia_y_limpio(sistema):
    publicado = paquetes.DESTINO / paquetes.nombre_zip(sistema)
    assert publicado.read_bytes() == paquetes.armar(sistema), (
        "Zip desactualizado: uv run python -m radar.api.paquetes"
    )
    nombres = zipfile.ZipFile(BytesIO(publicado.read_bytes())).namelist()
    assert "agente_local/instalacion/ejecutar.py" in nombres
    prohibidos = (".env", "resources", "__pycache__", "token", ".db")
    assert not [n for n in nombres if any(p in n.lower() for p in prohibidos)]
    instalador = "instalar.ps1" if sistema == "windows" else "instalar.sh"
    assert f"agente_local/instalacion/{instalador}" in nombres


def test_admin_aprueba_equipo_con_su_nombre(con_base, monkeypatch):
    monkeypatch.delenv("AGENTE_APROBACION", raising=False)
    token = con_base.post("/api/tokens", json={}).json()["token"]
    assert _inscribir(con_base, token).status_code == 200
    equipo = con_base.get("/api/equipos").json()["equipos"][0]
    assert equipo["pendiente"] is True
    # Con sesión no se escribe quién aprueba: sale de la sesión.
    r = con_base.post(f"/api/equipos/{equipo['id']}/aprobar", json={})
    assert r.status_code == 200 and r.json()["aprobado"] is True
    assert con_base.get("/api/equipos").json()["equipos"][0]["pendiente"] is False
