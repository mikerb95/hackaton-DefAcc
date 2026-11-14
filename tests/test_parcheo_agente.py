"""Parcheo en el agente local (RF-827 a RF-834, docs/plan-parcheo.md).

Nada de esto ejecuta un programa real: los ejecutores corren contra un corredor simulado y
un registro de Windows de mentira. Lo que se prueba es la promesa: el agente nunca deja el
equipo peor de lo que estaba y nunca miente en el resultado.
"""

from __future__ import annotations

import base64
import filecmp
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from agente_local import ed25519, parcheo, parcheo_linux, parcheo_windows
from agente_local import plan_parcheo as catalogo
from agente_local.parcheo import Previo, Respaldo, Verificacion

RAIZ = Path(__file__).resolve().parent.parent
SEMILLA = bytes(range(32))
PUBLICA = ed25519.clave_publica(SEMILLA)
EQUIPO = "0f8e2b7c-1a2b-4c3d-8e9f-001122334455"
AHORA = datetime(2026, 11, 14, 20, 0, tzinfo=UTC)


def _accion_winget(**cambios: Any) -> dict[str, Any]:
    return {
        "id": "app:RARLab.WinRAR",
        "tipo": "aplicacion",
        "ejecutor": "winget",
        "titulo": "Actualizar WinRAR a 7.13 o posterior",
        "cves": ["CVE-2023-38831"],
        "en_kev": ["CVE-2023-38831"],
        "prioridad": "inmediato",
        "paquete": "RARLab.WinRAR",
        "programa": "WinRAR 6.22 (64-bit)",
        "version_actual": "6.22",
        "minimo": "7.13",
        "estricto": False,
    } | cambios


def _plan(acciones: list[dict[str, Any]] | None = None, **cambios: Any) -> dict[str, Any]:
    return {
        "version": 1,
        "plan_id": str(uuid.uuid4()),
        "equipo_id": EQUIPO,
        "plataforma": "windows",
        "emitido": "2026-11-14T19:50:00Z",
        "vence": "2026-11-17T19:50:00Z",
        "aprobado_por": "Ana Pérez",
        "acciones": acciones or [_accion_winget()],
    } | cambios


def _entrega(plan: dict[str, Any], semilla: bytes = SEMILLA) -> dict[str, str]:
    texto = catalogo.canonico(plan)
    return {
        "plan": texto.decode(),
        "firma": base64.b64encode(ed25519.firmar(semilla, texto)).decode(),
    }


@pytest.fixture
def config(tmp_path):
    c = parcheo.Config(tmp_path)
    c.habilitar([base64.b64encode(PUBLICA).decode()])
    return c


# -- copias exactas y firma ------------------------------------------------------


def test_servidor_y_agente_usan_el_mismo_codigo():
    for nombre in ("ed25519.py", "plan_parcheo.py"):
        assert filecmp.cmp(
            RAIZ / "agente_local" / nombre, RAIZ / "radar" / "seguridad" / nombre, shallow=False
        ), f"{nombre} difiere entre agente_local y radar/seguridad"


def test_ed25519_vectores_rfc8032():
    secreto = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    publica = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    firma = bytes.fromhex(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    assert ed25519.clave_publica(secreto) == publica
    assert ed25519.firmar(secreto, b"\x72") == firma
    assert ed25519.verificar(publica, b"\x72", firma)
    assert not ed25519.verificar(publica, b"\x73", firma)
    alterada = bytearray(firma)
    alterada[40] ^= 1
    assert not ed25519.verificar(publica, b"\x72", bytes(alterada))
    # Entradas mal formadas son firmas inválidas, nunca excepciones.
    assert not ed25519.verificar(publica[:31], b"", firma)
    assert not ed25519.verificar(publica, b"", firma[:63])
    assert not ed25519.verificar(b"\xff" * 32, b"", firma)
    assert not ed25519.verificar("texto", b"", firma)  # type: ignore[arg-type]


def test_ed25519_coincide_con_la_libreria_de_referencia():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    for largo in (0, 1, 64, 1000):
        clave = Ed25519PrivateKey.generate()
        publica = clave.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        mensaje = bytes(range(256))[: largo % 256] * (largo // 256 + 1)
        assert ed25519.verificar(publica, mensaje, clave.sign(mensaje))


# -- catálogo cerrado ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("cambio", "motivo"),
    [
        ({"ejecutor": "powershell"}, "ejecutor desconocido"),
        ({"paquete": "Evil.Corp"}, "lista blanca"),
        ({"paquete": "RARLab.WinRAR; calc"}, "lista blanca"),
        ({"comando": "curl x | sh"}, "campos no permitidos"),
        ({"titulo": "linea\nnueva"}, "título"),
        ({"minimo": "7.13 && calc"}, "minimo"),
        ({"cves": ["CVE-2023-1; rm"]}, "CVE"),
        ({"estricto": True, "minimo": None}, "estricto sin mínimo"),
        ({"tipo": "so"}, "tipo incorrecto"),
    ],
)
def test_catalogo_rechaza_lo_que_no_es_suyo(cambio, motivo):
    assert motivo in (catalogo.validar_accion(_accion_winget(**cambio), "windows") or "")


def test_catalogo_por_plataforma_y_paquetes():
    assert "no corresponde" in catalogo.validar_accion(_accion_winget(), "debian")
    apt = {
        "id": "pkg:openssl",
        "tipo": "paquetes",
        "ejecutor": "apt",
        "titulo": "Actualizar openssl",
        "cves": [],
        "en_kev": [],
        "prioridad": "semanal",
        "paquetes": ["openssl", "libssl3"],
        "minimos": {"openssl": "3.0.2-0ubuntu1.18"},
    }
    assert catalogo.validar_accion(apt, "debian") is None
    assert catalogo.validar_accion(apt | {"paquetes": ["openssl", "$(id)"]}, "debian")
    assert catalogo.validar_accion(apt | {"paquetes": ["a"] * 2}, "debian")  # repetidos
    assert catalogo.validar_accion(apt | {"minimos": {"otro": "1.0"}}, "debian")
    postura = {
        "id": "postura:cifrado_disco",
        "tipo": "postura",
        "ejecutor": "postura_windows",
        "titulo": "Cifrar",
        "regla": "cifrado_disco",
    }
    assert "no automatizable" in catalogo.validar_accion(postura, "windows")


def test_validar_plan_forma_exacta():
    catalogo.validar_plan(_plan())
    with pytest.raises(catalogo.PlanInvalido):
        catalogo.validar_plan(_plan() | {"extra": 1})
    with pytest.raises(catalogo.PlanInvalido):
        catalogo.validar_plan(_plan(acciones=[_accion_winget(), _accion_winget()]))
    with pytest.raises(catalogo.PlanInvalido):
        catalogo.validar_plan(_plan(vence="2026-11-14T19:00:00Z"))
    with pytest.raises(catalogo.PlanInvalido):
        catalogo.validar_plan(_plan(version=2))


# -- verificación del plan en el equipo ----------------------------------------------


def test_plan_bien_firmado_se_acepta(config):
    plan = _plan()
    aceptado, bytes_plan = parcheo.verificar_plan(_entrega(plan), config, EQUIPO, "windows", AHORA)
    assert aceptado == plan and bytes_plan == catalogo.canonico(plan)


@pytest.mark.parametrize(
    ("preparar", "motivo"),
    [
        (lambda p: _entrega(p, bytes(32)), "firma"),
        (lambda p: _entrega(p) | {"firma": "no-base64!"}, "mal codificados"),
        (lambda p: {"plan": json.dumps(p), "firma": _entrega(p)["firma"]}, "firma"),
        (lambda p: _entrega(p | {"equipo_id": str(uuid.uuid4())}), "otro equipo"),
        (
            lambda p: _entrega(
                p
                | {
                    "plataforma": "debian",
                    "acciones": [
                        {
                            "id": "postura:firewall",
                            "tipo": "postura",
                            "ejecutor": "postura_debian",
                            "titulo": "Firewall",
                            "regla": "firewall",
                        }
                    ],
                }
            ),
            "es para debian",
        ),
        (
            lambda p: _entrega(
                p | {"vence": "2026-11-14T19:00:00Z", "emitido": "2026-11-10T00:00:00Z"}
            ),
            "venció",
        ),
        (lambda p: _entrega(p | {"emitido": "2026-11-15T00:00:00Z"}), "futuro"),
        (lambda p: _entrega(p | {"acciones": [_accion_winget(ejecutor="cmd")]}), "catálogo"),
        (lambda p: {"plan": None}, "sin plan"),
    ],
)
def test_planes_que_se_rechazan_sin_tocar_nada(config, preparar, motivo):
    with pytest.raises(parcheo.Rechazo, match=motivo):
        parcheo.verificar_plan(preparar(_plan()), config, EQUIPO, "windows", AHORA)


def test_la_clave_de_la_entrega_no_cuenta(config):
    # Un servidor tomado podría mandar su propia clave junto al plan: se ignora.
    otra = bytes([7]) * 32
    entrega = _entrega(_plan(), otra) | {
        "clave": base64.b64encode(ed25519.clave_publica(otra)).decode()
    }
    with pytest.raises(parcheo.Rechazo, match="firma"):
        parcheo.verificar_plan(entrega, config, EQUIPO, "windows", AHORA)


def test_un_plan_no_se_ejecuta_dos_veces(config, tmp_path):
    plan = _plan()
    config.registrar_ejecutado(plan["plan_id"])
    with pytest.raises(parcheo.Rechazo, match="ya se ejecutó"):
        parcheo.verificar_plan(_entrega(plan), parcheo.Config(tmp_path), EQUIPO, "windows", AHORA)


def test_config_sin_clave_no_habilita(tmp_path):
    c = parcheo.Config(tmp_path)
    assert not c.habilitado
    with pytest.raises(ValueError):
        c.habilitar(["corta"])
    with pytest.raises(ValueError):
        c.habilitar([base64.b64encode(b"x" * 31).decode()])
    assert not parcheo.Config(tmp_path).habilitado


# -- orquestación ------------------------------------------------------------------


class Doble:
    """Ejecutor de prueba con un estado de mentira: 'version'."""

    def __init__(
        self,
        inicial="6.22",
        resultado="7.13",
        reversible=True,
        previo=None,
        falla_aplicar=False,
        revierte=True,
        verifica=None,
    ):
        self.estado = {"version": inicial}
        self.resultado = resultado
        self.reversible = reversible
        self.previo = previo or Previo()
        self.falla_aplicar = falla_aplicar
        self.revierte = revierte
        self.verifica = verifica
        self.llamadas: list[str] = []

    def medir(self, accion):
        self.llamadas.append("medir")
        return dict(self.estado)

    def prechequear(self, accion, antes):
        self.llamadas.append("prechequear")
        return self.previo

    def respaldar(self, accion, antes, previo):
        self.llamadas.append("respaldar")
        return Respaldo(self.reversible, "" if self.reversible else "sin versión previa")

    def aplicar(self, accion, previo):
        self.llamadas.append("aplicar")
        self.estado["version"] = self.resultado
        if self.falla_aplicar:
            raise RuntimeError("el instalador devolvió 1603")
        return {}

    def verificar(self, accion, antes, despues, aplicado):
        self.llamadas.append("verificar")
        if self.verifica is not None:
            return self.verifica
        return Verificacion(despues["version"] == "7.13", "versión")

    def revertir(self, accion, antes, respaldo):
        self.llamadas.append("revertir")
        if self.revierte:
            self.estado = dict(antes)

    def igual(self, accion, a, b):
        return a.get("version") == b.get("version")


def _correr(doble):
    return parcheo.ejecutar_accion(_accion_winget(), doble, parcheo.Corredor())


def test_accion_aplicada_y_verificada():
    fila = _correr(Doble())
    assert fila["estado"] == "aplicado"
    assert fila["antes"] == {"version": "6.22"} and fila["despues"] == {"version": "7.13"}


def test_falla_verificacion_y_se_revierte():
    doble = Doble(resultado="6.99")
    fila = _correr(doble)
    assert fila["estado"] == "revertido" and doble.estado == {"version": "6.22"}
    assert "revertir" in doble.llamadas


def test_falla_sin_cambios_no_revierte():
    doble = Doble(resultado="6.22")
    fila = _correr(doble)
    assert fila["estado"] == "sin_cambios" and "revertir" not in doble.llamadas


def test_falla_irreversible_se_reporta_como_tal():
    fila = _correr(Doble(resultado="6.99", reversible=False))
    assert fila["estado"] == "fallido_sin_revertir" and "No reversible" in fila["motivo"]


def test_reversion_que_no_vuelve_al_estado_previo():
    fila = _correr(Doble(resultado="6.99", revierte=False))
    assert fila["estado"] == "fallido_sin_revertir" and "no coincide" in fila["motivo"]


def test_excepcion_al_aplicar_termina_medida():
    doble = Doble(falla_aplicar=True)  # alcanzó a cambiar y luego lanzó
    fila = _correr(doble)
    assert fila["estado"] == "revertido" and "1603" in fila["motivo"]


def test_prechequeo_final_no_toca_nada():
    doble = Doble(previo=Previo(parcheo.YA_AL_DIA, "ya cumple"))
    fila = _correr(doble)
    assert fila["estado"] == "ya_al_dia" and "aplicar" not in doble.llamadas


def test_si_no_se_puede_medir_se_omite():
    class SinMedida(Doble):
        def medir(self, accion):
            raise OSError("registro ilegible")

    fila = _correr(SinMedida())
    assert fila["estado"] == "omitido" and "registro ilegible" in fila["motivo"]


def test_plan_completo_orden_diario_y_contrato_del_servidor(tmp_path):
    from radar.equipos.parcheo_reporte import ResultadoPlan

    wu = {
        "id": "so:windows_update",
        "tipo": "so",
        "ejecutor": "windows_update",
        "titulo": "Windows Update",
        "cves": [],
        "en_kev": [],
        "prioridad": "semanal",
        "categorias": ["seguridad"],
    }
    firewall = {
        "id": "postura:firewall",
        "tipo": "postura",
        "ejecutor": "postura_windows",
        "titulo": "Firewall",
        "regla": "firewall",
    }
    plan = _plan([wu, firewall, _accion_winget()])
    llamados: list[str] = []
    contexto = parcheo.Contexto(
        ejecutores={"winget": Doble(), "postura_windows": Doble(), "windows_update": Doble()},
        corredor=parcheo.Corredor(),
        punto_restauracion=lambda d: llamados.append(d) or {"creado": False, "detalle": "apagada"},
        reinicio_pendiente=lambda: True,
    )
    diario = parcheo.Diario(tmp_path, plan["plan_id"])
    resultado = parcheo.ejecutar_plan(plan, catalogo.canonico(plan), contexto, diario)
    # Orden fijo: aplicación, postura y al final el sistema operativo.
    assert [a["id"] for a in resultado["acciones"]] == [
        "app:RARLab.WinRAR",
        "postura:firewall",
        "so:windows_update",
    ]
    # Sin punto de restauración, Windows Update (irreversible) no corre.
    assert resultado["acciones"][2]["estado"] == "omitido"
    assert "punto de restauración" in resultado["acciones"][2]["motivo"]
    assert resultado["reinicio_pendiente"] is True and len(llamados) == 1
    eventos = [e["evento"] for e in diario.leer()]
    assert eventos[0] == "inicio_plan" and eventos[-1] == "fin_plan"
    assert eventos.count("inicio_accion") == 3 == eventos.count("fin_accion")
    # El resultado cumple el contrato que valida el servidor.
    ResultadoPlan.model_validate_json(json.dumps(resultado))


def test_plan_interrumpido_se_reporta_sin_reintentar(tmp_path):
    plan = _plan()
    diario = parcheo.Diario(tmp_path, plan["plan_id"])
    diario.escribir("inicio_plan", huella="a" * 64, inicio="2026-11-14T20:00:00Z")
    diario.escribir("inicio_accion", id="app:RARLab.WinRAR")
    with open(diario.ruta, "a", encoding="utf-8") as archivo:
        archivo.write('{"evento": "fin_acc')  # corte de luz a mitad de línea
    assert parcheo.diarios_abiertos(tmp_path) == [diario.ruta]
    doble = Doble(inicial="7.13")
    contexto = parcheo.Contexto(ejecutores={"winget": doble}, corredor=parcheo.Corredor())
    resultado = parcheo.recuperar_interrumpido(diario, plan, contexto)
    assert resultado["estado"] == "interrumpido"
    accion = resultado["acciones"][0]
    assert accion["estado"] == "interrumpido" and accion["despues"] == {"version": "7.13"}
    assert "aplicar" not in doble.llamadas


def test_candado_impide_dos_corridas(tmp_path):
    with parcheo.Candado(tmp_path), pytest.raises(parcheo.Ocupado):
        parcheo.Candado(tmp_path).__enter__()
    # Un candado viejo (proceso muerto) no bloquea para siempre.
    ruta = tmp_path / parcheo.CANDADO
    ruta.write_text("123")
    import os

    viejo = (datetime.now() - timedelta(hours=parcheo.HORAS_CANDADO + 1)).timestamp()
    os.utime(ruta, (viejo, viejo))
    with parcheo.Candado(tmp_path):
        pass
    assert not ruta.exists()


# -- piezas de Windows -------------------------------------------------------------


class CorredorFalso(parcheo.Corredor):
    """Responde según el primer argumento que coincida en `respuestas`."""

    def __init__(self, respuestas: dict[str, Any]):
        super().__init__()
        self.respuestas = respuestas
        self.ordenes: list[list[str]] = []

    def correr(self, orden, tiempo=600, entorno=None, anotar=True):
        self.ordenes.append(list(orden))
        texto = " ".join(orden)
        for clave, valor in self.respuestas.items():
            if clave in texto:
                codigo, salida = valor(orden) if callable(valor) else valor
                break
        else:
            codigo, salida = 0, ""
        paso = {"orden": list(orden), "codigo": codigo, "salida": salida, "duracion": 0.0}
        if anotar:
            self.pasos.append(paso)
        return paso


def test_nombre_base_y_versiones():
    assert parcheo_windows.nombre_base("WinRAR 6.22 (64-bit)") == "winrar"
    assert parcheo_windows.nombre_base("WinRAR 7.13 (64-bit)") == "winrar"
    assert parcheo_windows.nombre_base("7-Zip 24.08 (x64)") == "7-zip"
    assert parcheo_windows.nombre_base("Mozilla Firefox (x64 es-ES)") == "mozilla firefox x64 es-es"
    assert parcheo_windows.cumple("7.13", "7.13", estricto=False)
    assert not parcheo_windows.cumple("7.13", "7.13", estricto=True)
    assert parcheo_windows.cumple("24.10", "24.9", estricto=False)
    assert not parcheo_windows.cumple(None, "1.0", estricto=False)
    salida = "Encontrado WinRAR [RARLab.WinRAR]\nVersión\n-------\n7.13.0\n7.12.0\n6.22.0\n"
    assert parcheo_windows.versiones_de_show(salida) == ["7.13.0", "7.12.0", "6.22.0"]


def _winget(registro: list[dict], usuario: list[dict] | None = None, respuestas=None):
    corredor = CorredorFalso(respuestas or {})
    return (
        parcheo_windows.Winget(
            corredor,
            leer_maquina=lambda: list(registro),
            leer_usuario=lambda: list(usuario or []),
            winget="winget.exe",
        ),
        corredor,
    )


def test_winget_de_punta_a_punta():
    registro = [{"programa": "WinRAR 6.22 (64-bit)", "version": "6.22"}]

    def actualizar(orden):
        registro[0] = {"programa": "WinRAR 7.13 (64-bit)", "version": "7.13"}
        return 0, "Instalado correctamente"

    ejecutor, corredor = _winget(
        registro,
        respuestas={" show ": (0, "Versión\n-------\n7.13\n6.22\n"), " upgrade ": actualizar},
    )
    fila = parcheo.ejecutar_accion(_accion_winget(), ejecutor, corredor)
    assert fila["estado"] == "aplicado" and fila["reversible"] is True
    upgrade = next(o for o in corredor.ordenes if "upgrade" in o)
    assert upgrade[:6] == ["winget.exe", "upgrade", "--id", "RARLab.WinRAR", "--exact", "--silent"]
    assert all(" " not in parte for parte in upgrade)  # argumentos sueltos, sin shell


def test_winget_que_queda_a_medias_se_revierte():
    registro = [{"programa": "WinRAR 6.22 (64-bit)", "version": "6.22"}]

    def actualizar(orden):
        registro[0] = {"programa": "WinRAR 7.00 (64-bit)", "version": "7.00"}
        return 0, ""

    def reinstalar(orden):
        registro[0] = {"programa": "WinRAR 6.22 (64-bit)", "version": "6.22"}
        return 0, ""

    ejecutor, corredor = _winget(
        registro,
        respuestas={
            " show ": (0, "6.22\n7.00\n"),
            " upgrade ": actualizar,
            " install ": reinstalar,
        },
    )
    fila = parcheo.ejecutar_accion(_accion_winget(), ejecutor, corredor)
    assert fila["estado"] == "revertido"
    install = next(o for o in corredor.ordenes if "install" in o)
    assert install[install.index("--version") + 1] == "6.22"


def test_winget_ignora_entradas_de_usuario_al_verificar():
    # Cualquier usuario puede escribir en HKCU "WinRAR 99 (64-bit)": no cuenta.
    registro = [{"programa": "WinRAR 6.22 (64-bit)", "version": "6.22"}]
    ejecutor, _ = _winget(registro, usuario=[{"programa": "WinRAR 99 (64-bit)", "version": "99"}])
    assert ejecutor.medir(_accion_winget())["version"] == "6.22"
    solo_usuario, _ = _winget([], usuario=[{"programa": "WinRAR 6.22 (64-bit)", "version": "6.22"}])
    previo = solo_usuario.prechequear(_accion_winget(), solo_usuario.medir(_accion_winget()))
    assert previo.final == "omitido" and "un usuario" in previo.motivo


def test_winget_ausente_o_ya_al_dia():
    sin, _ = _winget([{"programa": "WinRAR 6.22 (64-bit)", "version": "6.22"}])
    sin._winget = None
    assert sin.prechequear(_accion_winget(), {"version": "6.22"}).final == "omitido"
    al_dia, _ = _winget([])
    assert al_dia.prechequear(_accion_winget(), {"version": "7.20"}).final == "ya_al_dia"


def test_postura_windows_firewall_revierte_al_estado_medido():
    estado = {"Domain": "True", "Private": "False", "Public": "False"}

    def leer(orden):
        filas = [{"n": n, "e": e} for n, e in estado.items()]
        return 0, json.dumps(filas)

    def aplicar(orden):
        estado.update(Private="True")  # una directiva deja Public apagado
        return 0, ""

    def revertir(orden):
        estado.update(Domain="True", Private="False", Public="False")
        return 0, ""

    corredor = CorredorFalso(
        {
            "Get-NetFirewallProfile": leer,
            "-Profile Domain,Public,Private -Enabled True": aplicar,
            "-Profile Domain -Enabled": revertir,
        }
    )
    accion = {
        "id": "postura:firewall",
        "tipo": "postura",
        "ejecutor": "postura_windows",
        "titulo": "Firewall",
        "regla": "firewall",
    }
    fila = parcheo.ejecutar_accion(accion, parcheo_windows.PosturaWindows(corredor), corredor)
    assert fila["estado"] == "revertido" and "Public" in fila["motivo"]
    guion = next(o for o in corredor.ordenes if "-Profile Domain -Enabled" in " ".join(o))[-1]
    assert "Domain -Enabled True" in guion and "Public -Enabled False" in guion


# -- piezas de Linux ---------------------------------------------------------------


def test_lectores_de_apt_y_dpkg():
    simulacion = (
        "Inst libssl3 [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])\n"
        "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])\n"
        "Inst nueva-dep (1.0 Ubuntu [amd64])\n"
        "Conf libssl3 (3.0.2-0ubuntu1.18 Ubuntu:22.04/jammy-security [amd64])\n"
    )
    instala, quita = parcheo_linux.leer_simulacion_apt(simulacion)
    assert instala["openssl"] == ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.18")
    assert instala["nueva-dep"] == (None, "1.0") and quita == []
    _, quita = parcheo_linux.leer_simulacion_apt("Remv postfix [3.6.4]\n")
    assert quita == ["postfix"]
    dpkg = "openssl\t3.0.2-0ubuntu1.10\tii \nlibssl3:amd64\t3.0.2\tii \nviejo\t1.0\trc \n"
    assert parcheo_linux.leer_dpkg_query(dpkg) == {
        "openssl": "3.0.2-0ubuntu1.10",
        "libssl3": "3.0.2",
    }
    madison = "   openssl | 3.0.2-0ubuntu1.18 | http://archive jammy-security\n   openssl | 3.0.2-0ubuntu1 | x\n"
    assert parcheo_linux.versiones_de_madison(madison) == {"3.0.2-0ubuntu1.18", "3.0.2-0ubuntu1"}


@pytest.mark.parametrize(
    ("a", "b", "esperado"),
    [
        ("1.0", "1.0", 0),
        ("1.0", "1.1", -1),
        ("1.10", "1.9", 1),
        ("1.0~rc1", "1.0", -1),
        ("1.0a", "1.0", 1),
        ("2.0", "1.99", 1),
        ("1:1.0-1", "0:2.0-1", 1),
        ("0:3.0.7-24.el9", "0:3.0.7-27.el9", -1),
    ],
)
def test_comparacion_rpm(a, b, esperado):
    comparar = parcheo_linux.rpm_evr_cmp if ":" in a else parcheo_linux.rpmvercmp
    assert comparar(a, b) == esperado


def test_apt_no_sigue_si_quitaria_paquetes():
    corredor = CorredorFalso(
        {
            "dpkg-query": (0, "openssl\t3.0.2-0ubuntu1.10\tii \n"),
            "--compare-versions": (1, ""),
            "apt-get update": (0, ""),
            "apt-get -s": (
                0,
                "Remv postfix [3.6.4]\nInst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.18 x)\n",
            ),
        }
    )
    accion = {
        "id": "pkg:openssl",
        "tipo": "paquetes",
        "ejecutor": "apt",
        "titulo": "openssl",
        "paquetes": ["openssl"],
        "minimos": {"openssl": "3.0.2-0ubuntu1.18"},
    }
    fila = parcheo.ejecutar_accion(accion, parcheo_linux.Apt(corredor), corredor)
    assert fila["estado"] == "omitido" and "postfix" in fila["motivo"]
    assert not any("--only-upgrade" in o and "-s" not in o for o in corredor.ordenes)


def test_apt_de_punta_a_punta(tmp_path):
    versiones = {"openssl": "3.0.2-0ubuntu1.10"}

    def consulta(orden):
        return 0, "".join(f"{p}\t{v}\tii \n" for p, v in versiones.items())

    def instalar(orden):
        versiones["openssl"] = "3.0.2-0ubuntu1.18"
        return 0, ""

    corredor = CorredorFalso(
        {
            "dpkg-query": consulta,
            "--compare-versions 3.0.2-0ubuntu1.10": (1, ""),
            "--compare-versions": (0, ""),
            "apt-get update": (0, ""),
            "apt-get -s": (0, "Inst openssl [3.0.2-0ubuntu1.10] (3.0.2-0ubuntu1.18 x)\n"),
            "madison": (0, " openssl | 3.0.2-0ubuntu1.10 | x\n"),
            "--only-upgrade openssl": instalar,
            "dpkg --audit": (0, ""),
        }
    )
    accion = {
        "id": "pkg:openssl",
        "tipo": "paquetes",
        "ejecutor": "apt",
        "titulo": "openssl",
        "paquetes": ["openssl"],
        "minimos": {"openssl": "3.0.2-0ubuntu1.18"},
    }
    fila = parcheo.ejecutar_accion(accion, parcheo_linux.Apt(corredor, cache=tmp_path), corredor)
    assert fila["estado"] == "aplicado" and fila["reversible"] is True
    assert fila["cumple_minimo"] is True


def test_ufw_no_se_activa_si_cortaria_el_ssh():
    corredor = CorredorFalso(
        {
            "ufw status": (0, "Status: inactive\n"),
            "is-active ssh": (0, "active\n"),
            "ufw show added": (0, "Added user rules (see 'ufw status' for running firewall):\n"),
        }
    )
    accion = {
        "id": "postura:firewall",
        "tipo": "postura",
        "ejecutor": "postura_debian",
        "titulo": "Firewall",
        "regla": "firewall",
    }
    fila = parcheo.ejecutar_accion(accion, parcheo_linux.PosturaLinux(corredor, "debian"), corredor)
    assert fila["estado"] == "omitido" and "SSH" in fila["motivo"]
    assert not any("enable" in o for o in corredor.ordenes)
    assert parcheo_linux.regla_ssh("ufw allow 22/tcp")
    assert parcheo_linux.regla_ssh("ufw allow OpenSSH")


def test_actualizaciones_automaticas_debian_restaura_el_archivo(tmp_path):
    destino = tmp_path / "etc/apt/apt.conf.d/20auto-upgrades"
    destino.parent.mkdir(parents=True)
    destino.write_text('APT::Periodic::Unattended-Upgrade "0";\n')

    corredor = CorredorFalso({"dpkg-query": (0, "ii ")})
    postura = parcheo_linux.PosturaLinux(corredor, "debian", raiz=tmp_path)
    accion = {
        "id": "postura:actualizaciones_automaticas",
        "tipo": "postura",
        "ejecutor": "postura_debian",
        "titulo": "Actualizaciones",
        "regla": "actualizaciones_automaticas",
    }
    antes = postura.medir(accion)
    respaldo = postura.respaldar(accion, antes, Previo())
    postura.aplicar(accion, Previo())
    assert postura.medir(accion)["unattended"] == "1"
    postura.revertir(accion, antes, respaldo)
    assert destino.read_text() == 'APT::Periodic::Unattended-Upgrade "0";\n'


# -- la orden completa con la red simulada -------------------------------------------


class RespuestaFalsa:
    def __init__(self, cuerpo: bytes):
        self.cuerpo = cuerpo

    def read(self, _maximo=None):
        return self.cuerpo

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def test_orden_parchear_de_punta_a_punta(tmp_path, monkeypatch):
    from agente_local import envio, orden_parcheo, reporte

    estado = envio.Estado(tmp_path)
    estado.datos.update(equipo_id=EQUIPO, credencial="c" * 43, url="http://localhost:8000")
    estado.guardar()
    parcheo.Config(tmp_path).habilitar([base64.b64encode(PUBLICA).decode()])
    plan = _plan(
        emitido=catalogo.fecha(datetime.now(UTC)),
        vence=catalogo.fecha(datetime.now(UTC) + timedelta(hours=1)),
    )
    entrega = _entrega(plan)
    enviados: list[tuple[str, dict]] = []

    def abrir(peticion, timeout=None):
        if peticion.get_method() == "GET":
            return RespuestaFalsa(json.dumps(entrega).encode())
        enviados.append((peticion.full_url, json.loads(peticion.data)))
        return RespuestaFalsa(b'{"recibido": true}')

    monkeypatch.setattr(orden_parcheo, "plataforma_local", lambda: "windows")
    monkeypatch.setattr(reporte, "armar_reporte", lambda equipo_id: {"equipo_id": equipo_id})
    args = type(
        "Args",
        (),
        {
            "datos": str(tmp_path),
            "plan": None,
            "programado": False,
            "ensayo": False,
            "contexto": parcheo.Contexto(
                ejecutores={"winget": Doble()}, corredor=parcheo.Corredor()
            ),
        },
    )()
    assert orden_parcheo.orden_parchear(args, abrir) == 0
    rutas = [u.rsplit("/api/", 1)[1] for u, _ in enviados]
    # Primero el resultado, después el inventario para que el radar verifique.
    assert rutas == ["agente/parcheo/resultado", "agente/reporte"]
    assert enviados[0][1]["acciones"][0]["estado"] == "aplicado"
    assert parcheo.pendientes(tmp_path / "parcheo") == []
    # La segunda vez, el mismo plan se rechaza localmente y no se ejecuta otra vez.
    enviados.clear()
    assert orden_parcheo.orden_parchear(args, abrir) == 1
    assert enviados == []


def test_resultado_sin_red_queda_pendiente_y_se_reintenta(tmp_path, monkeypatch):
    from agente_local import envio, orden_parcheo, reporte

    estado = envio.Estado(tmp_path)
    estado.datos.update(equipo_id=EQUIPO, credencial="c" * 43, url="http://localhost:8000")
    estado.guardar()
    parcheo.Config(tmp_path).habilitar([base64.b64encode(PUBLICA).decode()])
    ahora = datetime.now(UTC)
    entrega = _entrega(
        _plan(emitido=catalogo.fecha(ahora), vence=catalogo.fecha(ahora + timedelta(hours=1)))
    )
    red = {"arriba": False}
    enviados: list[str] = []

    def abrir(peticion, timeout=None):
        if peticion.get_method() == "GET":
            return RespuestaFalsa(json.dumps(entrega).encode() if not enviados else b"")
        if not red["arriba"]:
            raise OSError("sin red")
        enviados.append(peticion.full_url)
        return RespuestaFalsa(b"{}")

    monkeypatch.setattr(orden_parcheo, "plataforma_local", lambda: "windows")
    monkeypatch.setattr(reporte, "armar_reporte", lambda equipo_id: {"equipo_id": equipo_id})
    args = type(
        "Args",
        (),
        {
            "datos": str(tmp_path),
            "plan": None,
            "programado": True,
            "ensayo": False,
            "contexto": parcheo.Contexto(
                ejecutores={"winget": Doble()}, corredor=parcheo.Corredor()
            ),
        },
    )()
    assert orden_parcheo.orden_parchear(args, abrir) == 2
    assert len(parcheo.pendientes(tmp_path / "parcheo")) == 1
    red["arriba"] = True
    entrega_vacia = {}
    entrega.clear()
    entrega.update(entrega_vacia)
    assert orden_parcheo.orden_parchear(args, abrir) == 0
    assert parcheo.pendientes(tmp_path / "parcheo") == []
    assert any(u.endswith("/api/agente/parcheo/resultado") for u in enviados)


def test_sin_habilitar_no_pide_nada(tmp_path):
    from agente_local import orden_parcheo

    def abrir(*_a, **_k):
        raise AssertionError("no debía tocar la red")

    args = type(
        "Args", (), {"datos": str(tmp_path), "plan": None, "programado": True, "ensayo": False}
    )()
    assert orden_parcheo.orden_parchear(args, abrir) == 0
