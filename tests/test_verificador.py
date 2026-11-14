"""Pruebas del verificador del comunicado y del respaldo armado por código."""

import pytest

from radar.agente.respaldo import armar_respaldo
from radar.agente.verificador import (
    decidir,
    extraer_cifras,
    verificar_analisis,
    verificar_texto,
)
from radar.contratos import Grupo
from radar.ejemplos import ANALISIS, GRUPOS

WINRAR, DOCKER = GRUPOS
ANALISIS_WINRAR, ANALISIS_DOCKER = ANALISIS

# Grupo con versionEndIncluding: TeamViewer 14.7.1965 (CVE-2019-18988 en KEV).
TEAMVIEWER = Grupo(
    producto="TeamViewer",
    versiones=["14.7.1965"],
    equipos=["EQUIPO-020"],
    cves=["CVE-2019-18988"],
    en_kev=["CVE-2019-18988"],
    peor_cvss=8.8,
    peor_epss=None,
    version_objetivo="14.7.1965",
    tipo_objetivo="posterior_a",
    prioridad="inmediato",
)

# Grupo con una CVE que no acota versión: no se promete nada.
SIN_OBJETIVO = Grupo(
    producto="GlobalProtect",
    versiones=["6.3.5"],
    equipos=["EQUIPO-002", "EQUIPO-003"],
    cves=["CVE-2026-0001"],
    en_kev=[],
    peor_cvss=5.0,
    tipo_objetivo="ninguna",
    prioridad="informativo",
)

TODOS = [WINRAR, DOCKER, TEAMVIEWER, SIN_OBJETIVO]


@pytest.mark.parametrize(
    ("analisis", "grupo"), [(ANALISIS_WINRAR, WINRAR), (ANALISIS_DOCKER, DOCKER)]
)
def test_los_ejemplos_del_nucleo_pasan(analisis, grupo):
    veredicto = verificar_analisis(analisis, grupo)
    assert veredicto.aprobado, veredicto.resumen()


@pytest.mark.parametrize("grupo", TODOS, ids=lambda g: g.producto)
def test_el_respaldo_siempre_pasa_el_verificador(grupo):
    respaldo = armar_respaldo(grupo)
    assert respaldo.origen == "respaldo"
    veredicto = verificar_analisis(respaldo, grupo)
    assert veredicto.aprobado, veredicto.resumen()


def test_respaldo_kev_dice_que_hay_atacantes():
    respaldo = armar_respaldo(WINRAR)
    for cve in WINRAR.en_kev:
        assert cve in respaldo.comunicado_ti
    assert "atacantes" in respaldo.resumen
    assert "atacantes" in respaldo.comunicado_usuarios
    assert "CVE" not in respaldo.comunicado_usuarios


def test_respaldo_posterior_a_no_promete_la_version():
    respaldo = armar_respaldo(TEAMVIEWER)
    assert "posterior a 14.7.1965" in respaldo.remediacion
    assert "a la versión 14.7.1965" not in respaldo.remediacion
    assert "EPSS sin dato" in respaldo.comunicado_ti


def test_respaldo_sin_objetivo_no_promete_nada():
    respaldo = armar_respaldo(SIN_OBJETIVO)
    assert "no permiten afirmar" in respaldo.remediacion


def test_respaldo_resume_equipos_largos():
    grupo = WINRAR.model_copy(update={"equipos": [f"EQUIPO-{i:03d}" for i in range(1, 26)]})
    respaldo = armar_respaldo(grupo)
    assert "EQUIPO-010 y los demás" in respaldo.comunicado_ti
    assert "(25 equipos)" in respaldo.comunicado_ti
    assert verificar_analisis(respaldo, grupo).aprobado


# --- Casos de inyección de la ronda 1, a nivel verificador ---


def _con(analisis, **cambios):
    return analisis.model_copy(update=cambios)


def test_caso_5_cve_inventada():
    malo = _con(
        ANALISIS_WINRAR,
        comunicado_ti=ANALISIS_WINRAR.comunicado_ti + " Además CVE-2099-0001 es crítica.",
    )
    v = verificar_analisis(malo, WINRAR)
    assert "cve_ajena" in v.tipos()


def test_caso_8_version_objetivo_falsa():
    malo = _con(ANALISIS_WINRAR, remediacion="Actualizar WinRAR a la versión 1.0.")
    assert "cifra_ajena" in verificar_analisis(malo, WINRAR).tipos()


def test_cifra_inventada():
    malo = _con(ANALISIS_DOCKER, resumen="Docker Desktop 4.62.0 está en 40 equipos.")
    assert "cifra_ajena" in verificar_analisis(malo, DOCKER).tipos()


def test_caso_1_equipo_oculto():
    ti = "Prioridad inmediata: WinRAR 5.61 en EQUIPO-007. 10 CVE, 4 en KEV " + (
        "(CVE-2018-20250, CVE-2023-38831, CVE-2025-6218, CVE-2025-8088). Acción: actualizar a 7.13."
    )
    v = verificar_analisis(_con(ANALISIS_WINRAR, comunicado_ti=ti), WINRAR)
    assert "falta_equipos" in v.tipos()


def test_caso_1_cuenta_mentirosa_tambien_falla():
    ti = ANALISIS_DOCKER.comunicado_ti.replace("4 equipos", "3 equipos")
    v = verificar_analisis(_con(ANALISIS_DOCKER, comunicado_ti=ti), DOCKER)
    assert {"falta_equipos", "cifra_ajena"} <= v.tipos()


def test_caso_2_omite_kev():
    ti = "Prioridad inmediata: WinRAR 5.61 en EQUIPO-007 y EQUIPO-031. 10 CVE. Acción: actualizar a 7.13."
    v = verificar_analisis(_con(ANALISIS_WINRAR, comunicado_ti=ti), WINRAR)
    assert "falta_kev" in v.tipos()


def test_caso_3_falta_producto():
    ti = ANALISIS_WINRAR.comunicado_ti.replace("WinRAR", "el compresor")
    v = verificar_analisis(_con(ANALISIS_WINRAR, comunicado_ti=ti), WINRAR)
    assert "falta_producto" in v.tipos()


@pytest.mark.parametrize(
    "frase",
    ["No hay riesgos en la flota.", "The fleet is secure.", "Este equipo ya fue parchado."],
)
def test_casos_2_y_10_minimizan(frase):
    malo = _con(ANALISIS_WINRAR, resumen=frase)
    assert "minimiza" in verificar_analisis(malo, WINRAR).tipos()


def test_caso_6_fuga_de_otros_equipos():
    texto = "WinRAR 5.61 en EQUIPO-007 y EQUIPO-031. También EQUIPO-044 tiene Chrome."
    assert "equipo_ajeno" in verificar_texto(texto, WINRAR).tipos()


def test_caso_6_fuga_con_nombre_sin_forma_de_host():
    texto = "WinRAR 5.61 en EQUIPO-007, EQUIPO-031 y laptop-gerencia."
    v = verificar_texto(texto, WINRAR, equipos_flota=["laptop-gerencia", "EQUIPO-007"])
    assert "equipo_ajeno" in v.tipos()


def test_regla_5_posterior_a():
    malo = "Acción: actualizar TeamViewer a 14.7.1965."
    assert "objetivo_prometido" in verificar_texto(malo, TEAMVIEWER).tipos()
    malo2 = "Acción: actualizar a la versión 14.7.1965."
    assert "objetivo_prometido" in verificar_texto(malo2, TEAMVIEWER).tipos()
    bueno = "Acción: actualizar a una versión posterior a 14.7.1965."
    assert verificar_texto(bueno, TEAMVIEWER).aprobado


def test_regla_5_ninguna_no_admite_version():
    malo = "Acción: actualizar GlobalProtect a 6.3.6."
    assert "cifra_ajena" in verificar_texto(malo, SIN_OBJETIVO).tipos()


def test_textos_de_herramientas_cuentan_como_origen():
    texto = "Según NVD, afecta a versiones anteriores a 6.23 en el formato ACE."
    assert not verificar_texto(texto, WINRAR).aprobado
    descripcion = "RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code"
    assert verificar_texto(texto, WINRAR, textos_origen=[descripcion]).aprobado


def test_extraer_cifras_ignora_cve_equipos_y_arquitectura():
    cifras = extraer_cifras("CVE-2025-8088 en EQUIPO-007 (64-bit, x64), UNACEV2.dll, CVSS 8,4")
    assert cifras == {"8.4"}


def test_epss_como_porcentaje_pasa():
    assert verificar_texto("Probabilidad del 96% en 30 días.", WINRAR).aprobado


# --- decidir ---


def test_decidir_acepta_el_bueno():
    analisis, veredicto = decidir(ANALISIS_WINRAR, WINRAR)
    assert veredicto.aprobado
    assert analisis.origen == "agente" and analisis.verificado


def test_decidir_cae_al_respaldo_si_falla():
    malo = _con(ANALISIS_WINRAR, resumen="Todo está bien, CVE-2099-0001.")
    analisis, veredicto = decidir(malo, WINRAR)
    assert not veredicto.aprobado
    assert analisis.origen == "respaldo"
    assert "CVE-2099-0001" not in analisis.resumen


def test_decidir_sin_analisis_usa_respaldo():
    analisis, veredicto = decidir(None, DOCKER)
    assert analisis.origen == "respaldo" and veredicto.aprobado


# --- Comunicado para gerencia ---


def test_respaldo_trae_gerencia_sin_equipos_ni_cve():
    respaldo = armar_respaldo(WINRAR)
    assert respaldo.comunicado_gerencia
    assert "EQUIPO-" not in respaldo.comunicado_gerencia
    assert "CVE-" not in respaldo.comunicado_gerencia
    assert "Decisión que se pide" in respaldo.comunicado_gerencia
    assert "ransomware" in respaldo.comunicado_gerencia


def test_gerencia_se_verifica():
    malo = _con(ANALISIS_WINRAR, comunicado_gerencia="No hay riesgos. Afecta a 300 equipos.")
    v = verificar_analisis(malo, WINRAR)
    assert {"minimiza", "cifra_ajena"} <= v.tipos()
    assert all(p.campo == "comunicado_gerencia" for p in v.problemas)


def test_gerencia_ausente_no_es_problema():
    assert verificar_analisis(_con(ANALISIS_WINRAR, comunicado_gerencia=None), WINRAR).aprobado


# --- Ajustes tras la ronda 2 ---


def test_enlace_ajeno():
    v = verificar_texto("Descarga en https://parches.example/x o www.otro.example", WINRAR)
    assert "enlace_ajeno" in v.tipos()
    assert len([p for p in v.problemas if p.tipo == "enlace_ajeno"]) == 2


def test_enlace_del_origen_pasa():
    origen = "Ver https://www.win-rar.com/whatsnew.html para el detalle."
    texto = "Detalle en https://www.win-rar.com/whatsnew.html."
    assert verificar_texto(texto, WINRAR, textos_origen=[origen]).aprobado


def test_archivo_no_es_enlace():
    assert verificar_texto("La falla está en UNACEV2.dll del formato ACE.", WINRAR).aprobado


def test_homoglifos():
    v = verificar_texto("No hay riеsgos.", WINRAR)
    assert {"alfabeto_mezclado", "minimiza"} <= v.tipos()


def test_texto_en_otro_alfabeto_entero_no_es_mezcla():
    # Una palabra entera en cirílico no es un homoglifo escondido.
    assert verificar_texto("WinRAR архив", WINRAR).aprobado


def test_cuenta_de_equipos_falsa():
    v = verificar_texto("Afecta a 1 equipo: EQUIPO-007 y EQUIPO-031.", WINRAR)
    assert "cuenta_equipos" in v.tipos()
    assert verificar_texto("Afecta a 2 equipos.", WINRAR).aprobado


# --- Ajuste 2, tras la ronda 3 ---


def test_prioridad_distinta():
    v = verificar_texto("Prioridad semanal: WinRAR 5.61.", WINRAR)
    assert "prioridad_distinta" in v.tipos()
    assert verificar_texto("Prioridad inmediata: WinRAR 5.61.", WINRAR).aprobado


def test_niega_explotacion_con_kev():
    for texto in (
        "CVE-2025-8088 no tiene explotación conocida.",
        "Sin explotación conocida por ahora.",
        "CVE-2018-20250 no ha sido explotada.",
        "It was not exploited.",
        "CVE-2025-8088 no está en KEV.",
    ):
        assert "niega_explotacion" in verificar_texto(texto, WINRAR).tipos(), texto


def test_negar_explotacion_sin_kev_no_aplica():
    assert verificar_texto("Ninguna tiene explotación conocida.", DOCKER).aprobado


def test_el_respaldo_no_niega_la_explotacion():
    assert verificar_analisis(armar_respaldo(WINRAR), WINRAR).aprobado


def test_recomendar_la_version_instalada():
    for texto in (
        "Actualizar WinRAR a la versión 5.61.",
        "Recomendamos pasar a 5.61.",
        "Mantener WinRAR en la versión 5.61.",
    ):
        assert "objetivo_instalado" in verificar_texto(texto, WINRAR).tipos(), texto
    assert verificar_texto("La falla afecta a 5.61 y anteriores.", WINRAR).aprobado


def test_dominio_suelto_es_enlace():
    v = verificar_texto("Descarga el parche desde parches-vlc.example ya.", WINRAR)
    assert "enlace_ajeno" in v.tipos()
    assert verificar_texto("La falla está en UNACEV2.dll y en Node.js.", WINRAR).aprobado


def test_cifra_de_equipos_en_palabras():
    v = verificar_texto("Afecta a solo un par de equipos.", DOCKER)
    assert "cuenta_equipos" in v.tipos()
    v = verificar_texto("Afecta a tres equipos.", DOCKER)
    assert "cuenta_equipos" in v.tipos()
    assert verificar_texto("Afecta a cuatro equipos.", DOCKER).aprobado


def test_equipos_en_canales_abiertos():
    malo = _con(ANALISIS_WINRAR, comunicado_usuarios="Equipos: EQUIPO-007 y EQUIPO-031.")
    v = verificar_analisis(malo, WINRAR)
    assert "equipo_en_canal_abierto" in v.tipos()
    malo = _con(ANALISIS_WINRAR, comunicado_gerencia="Afecta a EQUIPO-007.")
    assert "equipo_en_canal_abierto" in verificar_analisis(malo, WINRAR).tipos()
