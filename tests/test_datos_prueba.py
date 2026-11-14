"""Pruebas del generador del inventario de prueba y de su respuesta conocida.

Necesitan resources/semilla_respuesta.json (privado, fuera del repositorio): si no está,
se saltan. datos_prueba/generados/ tampoco se sube; los archivos se generan en una carpeta
temporal.
"""

from __future__ import annotations

import json
from collections import Counter

import pytest

from datos_prueba import generar, respuesta, semilla

hay_snapshot = pytest.mark.skipif(
    not respuesta.RUTA_SNAPSHOT.exists(), reason="falta resources/semilla_respuesta.json"
)


@pytest.fixture(scope="module")
def generado():
    return generar.generar()


@hay_snapshot
def test_semilla_fija_reproduce_lo_mismo(generado):
    filas, resp = generar.generar()
    assert filas == generado[0]
    assert resp == generado[1]


@hay_snapshot
def test_totales_coinciden_con_semilla_md(generado):
    t = generado[1]["totales"]
    # SEMILLA.md: 735 pares CVE y versión precisos y 12 CVE distintas en KEV.
    assert t["pares_cve_version_precisos"] == 735
    assert t["kev_distintas"] == 12
    assert t["equipos"] == 52


@hay_snapshot
def test_distribucion_por_version(generado):
    filas, _ = generado
    cuenta = Counter((f["programa"], f["version"]) for f in filas)
    for c in semilla.CASOS:
        assert cuenta[(c.nombre, c.version_campo)] == c.equipos, c


@hay_snapshot
def test_una_version_por_producto_y_equipo(generado):
    _, resp = generado
    vistos = Counter(
        (f["equipo"], f["producto"]) for f in resp["filas"] if f["tipo"] in ("vulnerable", "sano")
    )
    assert max(vistos.values()) == 1


@hay_snapshot
def test_relleno_entre_15_y_25_por_equipo(generado):
    _, resp = generado
    por_equipo = Counter(f["equipo"] for f in resp["filas"] if f["tipo"] == "relleno")
    assert set(por_equipo) == set(semilla.EQUIPOS + semilla.SERVIDORES)
    assert all(15 <= n <= 25 for n in por_equipo.values())


@hay_snapshot
def test_casos_frontera(generado):
    _, resp = generado
    por_clave = {f["clave"]: f for f in resp["filas"] if "clave" in f}
    assert "CVE-2018-20250" in por_clave["WinRAR@5.61"]["kev"]  # inclusiva
    assert "CVE-2023-38831" not in por_clave["WinRAR@6.23"]["cves"]  # excluyente
    assert por_clave["WinRAR@7.13"]["tipo"] == "sano"
    # Docker Desktop 4.62.0: solo el segundo par encuentra las CVE.
    d = por_clave["Docker Desktop@4.62.0"]
    assert d["cves_por_par"]["docker:desktop"] == []
    assert len(d["cves_por_par"]["docker:docker_desktop"]) == 2
    # Python: se compara con la versión del nombre, no con la del instalador.
    p = por_clave["Python@3.12.10"]
    assert p["version"] == "3.12.10150.0" and len(p["cves"]) == 12
    assert por_clave["Git@2.45.1"]["kev"] == ["CVE-2025-48384"]
    assert por_clave["Notepad++@8.8.8"]["pares"] == ["notepad-plus-plus:notepad\\+\\+"]


@hay_snapshot
def test_cobertura_con_motivos_del_contrato(generado):
    from typing import get_args

    from radar.contratos import MotivoCobertura

    _, resp = generado
    cob = [f for f in resp["filas"] if f["tipo"] == "cobertura"]
    assert {f["motivo"] for f in cob} <= set(get_args(MotivoCobertura))
    nosql = [f for f in cob if f["programa"].startswith("NoSQLBooster")]
    assert nosql and nosql[0]["par_prohibido"] == "mongodb:mongodb"


@hay_snapshot
def test_inyeccion_va_en_filas_aparte(generado):
    _filas, resp = generar.generar(con_inyeccion=True)
    iny = [f for f in resp["filas"] if f["tipo"] == "inyeccion"]
    assert len(iny) == 10
    # Las filas medidas no cambian al agregar la inyección.
    assert (
        resp["totales"]["pares_cve_activo_precisos"]
        == generado[1]["totales"]["pares_cve_activo_precisos"]
    )


@pytest.fixture(scope="module")
def archivos(tmp_path_factory):
    """datos_prueba/generados/ no se sube: se generan los archivos en una carpeta temporal."""
    if not respuesta.RUTA_SNAPSHOT.exists():
        pytest.skip("falta resources/semilla_respuesta.json")
    carpeta = tmp_path_factory.mktemp("generados")
    generar.main(["--salida", str(carpeta)])
    return carpeta


def test_dos_corridas_dan_los_mismos_bytes(archivos, tmp_path):
    generar.main(["--salida", str(tmp_path)])
    for nombre in ("inventario.csv", "inventario.xlsx", "inventario_respuesta.json"):
        assert (archivos / nombre).read_bytes() == (tmp_path / nombre).read_bytes(), nombre


@pytest.mark.parametrize("extension", ["csv", "xlsx"])
def test_la_ingesta_lee_el_inventario_completo(archivos, extension):
    from radar.ingesta.archivos import leer_inventario

    resp = json.loads((archivos / "inventario_respuesta.json").read_text(encoding="utf-8"))
    lectura = leer_inventario(archivos / f"inventario.{extension}")
    assert len(lectura.filas) == resp["totales"]["filas"]
    assert lectura.duplicadas == 0 and not lectura.descartadas
    leidas = {(f["equipo"], f["programa"], f["version"]) for f in lectura.filas}
    esperadas = {(f["equipo"], f["programa"], f["version"]) for f in resp["filas"]}
    assert leidas == esperadas
