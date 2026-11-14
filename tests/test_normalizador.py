"""Pruebas del normalizador (radar/ingesta/normalizador.py).

Ninguna llama a Claude: el desempate con modelo se prueba con un sustituto inyectado.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from radar.contratos import FilaInventario
from radar.ingesta import normalizador as nz

CARGADO = datetime(2026, 11, 14, tzinfo=UTC)


@pytest.fixture(scope="module")
def dic():
    return nz.diccionario_por_defecto()


def fila(programa, version, equipo="EQUIPO-001", proveedor=None):
    return FilaInventario(
        equipo=equipo,
        programa=programa,
        version=version,
        proveedor=proveedor,
        fuente="csv",
        cargado=CARGADO,
    )


# --- versión -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("programa", "version", "esperado"),
    [
        ("WinRAR 5.61 (64-bit)", "5.61", ("5.61", None)),
        ("Python 3.12.10 (64-bit)", "3.12.10150.0", ("3.12.10", None)),  # instalador MSI
        ("Python 3.11.15 (64-bit)", "3.11.15", ("3.11.15", None)),
        ("Git", "2.45.1.windows.1", ("2.45.1", None)),
        ("Eclipse Temurin JDK with Hotspot 17.0.9+9 (x64)", "17.0.9+9", ("17.0.9", None)),
        ("Notepad++ (64-bit x64)", "8.9.6.4", ("8.9.6.4", None)),
        ("Docker", "28.1.1, build 4eba377", (None, "no_comparable")),
        ("Lector PDF Corporativo", "", (None, "sin_version")),
        ("Lector PDF Corporativo", None, (None, "sin_version")),
        ("Mozilla Firefox 156.0.1 (x64 es-ES)", None, ("156.0.1", None)),  # del nombre
    ],
)
def test_version_comparable(programa, version, esperado):
    assert nz.version_comparable(programa, version) == esperado


@pytest.mark.parametrize(
    ("programa", "limpio"),
    [
        ("WinRAR 6.22 (32-bit)", "WinRAR"),
        ("7-Zip 24.09 (x64 edition)", "7-Zip"),
        ("Notepad++ (64-bit x64)", "Notepad++"),
        ("Mozilla Firefox 156.0.1 (x64 es-ES)", "Mozilla Firefox"),
        ("Eclipse Temurin JDK with Hotspot 17.0.9+9 (x64)", "Eclipse Temurin JDK with Hotspot"),
        ("Adobe Acrobat Reader DC - Español", "Adobe Acrobat Reader DC"),
        ("PuTTY release 0.81 (64-bit)", "PuTTY"),
        ("TeamViewer 14", "TeamViewer"),
    ],
)
def test_limpiar_nombre(programa, limpio):
    assert nz.limpiar_nombre(programa) == limpio


# --- trampas: tabla de alias -------------------------------------------------


@pytest.mark.parametrize(
    ("nombre", "pares"),
    [
        ("Eclipse Temurin JDK with Hotspot", ("oracle:openjdk",)),
        ("Docker Desktop", ("docker:desktop", "docker:docker_desktop")),
        ("nginx", ("f5:nginx",)),
        ("Notepad++", ("notepad-plus-plus:notepad\\+\\+",)),
        ("Adobe Acrobat Reader", ("adobe:acrobat_reader_dc",)),
        ("Java 8 Update", ("oracle:jdk", "oracle:jre", "oracle:openjdk")),
        ("NoSQLBooster for MongoDB", ()),
    ],
)
def test_alias_de_trampas(dic, nombre, pares):
    assert nz.decidir(nombre, dic).pares == pares


def test_sin_alias_temurin_cae_en_un_cpe_sin_cve(dic):
    # Prueba de que la tabla hace falta: el diccionario sí tiene eclipse:temurin.
    d = nz.decidir("Eclipse Temurin", dic, usar_alias=False)
    assert d.pares == ("eclipse:temurin",)


def test_nosqlbooster_nunca_recibe_mongodb(dic):
    d = nz.decidir("NoSQLBooster for MongoDB", dic, usar_alias=False)
    assert "mongodb:mongodb" not in d.pares


# --- rapidfuzz y desempates --------------------------------------------------


# Nombres que no están en la semilla: miden si el método generaliza o solo memorizó.
FUERA_DE_SEMILLA = [
    ("Google Chrome (64-bit)", None, "google:chrome"),
    ("Mozilla Firefox ESR (x64 en-US)", "Mozilla", "mozilla:firefox_esr"),
    ("Mozilla Thunderbird (x64 es-ES)", "Mozilla", "mozilla:thunderbird"),
    ("Microsoft Edge", "Microsoft Corporation", "microsoft:edge"),
    ("Wireshark 4.2.5 x64", None, "wireshark:wireshark"),
    ("FileZilla Client 3.67.0", None, "filezilla-project:filezilla_client"),
    ("KeePass Password Safe 2.57", None, "keepass:password_safe"),
    ("Oracle VM VirtualBox 7.0.18", "Oracle Corporation", "oracle:vm_virtualbox"),
    ("Visual Studio Code", "Microsoft Corporation", "microsoft:visual_studio_code"),
    ("LibreOffice 24.8.3.2", None, "libreoffice:libreoffice"),
    ("Git", "The Git Development Community", "git-scm:git"),
    ("Python 3.10.11 (64-bit)", "Python Software Foundation", "python:python"),
]


@pytest.mark.parametrize(("programa", "proveedor", "par"), FUERA_DE_SEMILLA)
def test_generaliza_fuera_de_la_semilla(dic, programa, proveedor, par):
    assert nz.decidir(nz.limpiar_nombre(programa), dic, proveedor).pares == (par,)


def test_producto_ausente_de_nvd_queda_sin_cpe(dic):
    # slack:slack no existe; antes caía en jenkins:slack (plugin) o en "slac".
    assert nz.decidir("Slack", dic, "Slack Technologies").pares == ()
    assert nz.decidir("Herramienta Interna XYZ", dic).pares == ()


def test_plugins_de_jenkins_solo_si_se_nombra_jenkins(dic):
    assert all(not c.par.startswith("jenkins:") for c in dic.candidatos("Git"))
    assert any(c.par.startswith("jenkins:") for c in dic.candidatos("Jenkins Git"))


def test_empate_python_lo_resuelve_el_proveedor(dic):
    sin = nz.decidir("Python", dic)
    con = nz.decidir("Python", dic, "Python Software Foundation")
    assert sin.empate and sin.pares == ("python:python",) and sin.confianza < 1
    assert not con.empate and con.pares == ("python:python",)


# --- desempate con modelo (sustituto, sin API) -------------------------------


def test_sin_bandera_no_se_llama_al_modelo(dic, monkeypatch):
    monkeypatch.delenv("RADAR_DESEMPATE_MODELO", raising=False)

    def prohibido(*_):
        raise AssertionError("no debe llamarse al modelo sin la bandera")

    r = nz.normalizar([fila("Python 3.13.9 (64-bit)", "3.13.9")], dic, desempatar=prohibido)
    assert r.activos[0].cpes == ["python:python"]


def test_modelo_elige_solo_entre_candidatos(dic):
    vistos = []

    def falso(nombre, candidatos):
        vistos.append([c.par for c in candidatos])
        return 1  # el segundo

    d = nz.decidir("Python", dic, usar_modelo=True, desempatar=falso)
    assert d.metodo == "modelo"
    assert d.pares == (vistos[0][1],)
    assert len(vistos[0]) <= 5


def test_modelo_dice_ninguno_va_a_cobertura(dic):
    r = nz.normalizar(
        [fila("Python 3.13.9 (64-bit)", "3.13.9")],
        dic,
        usar_modelo=True,
        desempatar=lambda *_: None,
    )
    assert not r.activos and r.cobertura[0].motivo == "sin_cpe"


# --- normalizar --------------------------------------------------------------


def test_normalizar_agrupa_por_producto_y_version(dic):
    filas = [
        fila("WinRAR 5.61 (64-bit)", "5.61", "EQUIPO-007", "win.rar GmbH"),
        fila("WinRAR 5.61 (64-bit)", "5.61", "EQUIPO-031", "win.rar GmbH"),
        fila("WinRAR 7.13 (64-bit)", "7.13", "EQUIPO-002", "win.rar GmbH"),
        fila("Docker Desktop", "4.62.0", "EQUIPO-011", "Docker Inc."),
        fila("Docker", "28.1.1, build 4eba377", "EQUIPO-011", "Docker Inc."),
        fila("Sistema Contable Interno", "4.2", "EQUIPO-003"),
    ]
    r = nz.normalizar(filas, dic)
    por_clave = {a.clave: a for a in r.activos}
    assert set(por_clave) == {"WinRAR@5.61", "WinRAR@7.13", "Docker Desktop@4.62.0"}
    assert por_clave["WinRAR@5.61"].equipos == ["EQUIPO-007", "EQUIPO-031"]
    assert por_clave["WinRAR@5.61"].cpes == ["rarlab:winrar"]
    assert por_clave["Docker Desktop@4.62.0"].cpes == ["docker:desktop", "docker:docker_desktop"]
    assert {(c.programa, c.motivo) for c in r.cobertura} == {
        ("Docker", "no_comparable"),
        ("Sistema Contable Interno", "sin_cpe"),
    }


def test_nombre_canonico_comun_a_todas_las_versiones(dic):
    r = nz.normalizar(
        [
            fila("Adobe Acrobat Reader (64-bit)", "25.001.20531"),
            fila("Adobe Acrobat Reader DC - Español", "26.002.21901", "EQUIPO-002"),
            fila("TeamViewer 14", "14.7.1965"),
            fila("TeamViewer", "15.70.0", "EQUIPO-002"),
        ],
        dic,
    )
    assert {a.clave for a in r.activos} == {
        "Adobe Acrobat Reader@25.001.20531",
        "Adobe Acrobat Reader@26.002.21901",
        "TeamViewer@14.7.1965",
        "TeamViewer@15.70.0",
    }


def test_nombre_enorme_no_se_compara(dic):
    r = nz.normalizar([fila("Google Chrome. " + "x" * 3000, "156.0.8079.100")], dic)
    assert not r.activos and r.cobertura[0].motivo == "sin_cpe"


# --- medición contra la respuesta conocida -----------------------------------


@pytest.mark.skipif(
    not (
        nz.Path(__file__).resolve().parent.parent / "resources" / "semilla_respuesta.json"
    ).exists(),
    reason="falta resources/semilla_respuesta.json",
)
def test_medicion_contra_respuesta_conocida(tmp_path, monkeypatch):
    from datos_prueba import generar, medir_normalizador

    monkeypatch.setattr(generar, "CARPETA_SALIDA", tmp_path)
    monkeypatch.setattr(medir_normalizador, "CARPETA_SALIDA", tmp_path)
    generar.main(["--salida", str(tmp_path), "--sin-excel"])
    r = medir_normalizador.medir("inventario")
    completo = r["variantes"]["completo"]
    assert completo["exactitud_pct"] == 100.0
    assert completo["cobertura_correcta_pct"] == 100.0
    assert completo["par_prohibido_asignado"] == 0
    assert completo["relleno_con_cpe"] == 0
    # La tabla de alias y el desempate aportan sobre las líneas base.
    assert r["variantes"]["solo_difuso"]["exactitud_pct"] < completo["exactitud_pct"]
    assert (
        r["variantes"]["nombre_exacto"]["exactitud_pct"]
        < r["variantes"]["solo_difuso"]["exactitud_pct"]
    )
