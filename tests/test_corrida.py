"""Corrida completa: inventario generado -> activos -> cruce contra el snapshot en sqlite.

Simula un normalizador perfecto (toma pares y versión comparable de la respuesta del
generador) para medir solo el núcleo. Las cifras esperadas salen de
datos_prueba/generados/inventario_respuesta.json, que no se calcula con el cruce.
Se salta si falta el snapshot o el inventario generado.
"""

import json
from collections import Counter, defaultdict

import pytest

from radar import bd
from radar.contratos import Activo, Cobertura
from radar.nucleo.corrida import correr
from tests.conftest import RAIZ, SNAPSHOT

INVENTARIO = RAIZ / "datos_prueba" / "generados" / "inventario_respuesta.json"


@pytest.fixture(scope="module")
def respuesta_generada():
    if not INVENTARIO.exists():
        pytest.skip("Falta datos_prueba/generados (uv run python -m datos_prueba.generar)")
    return json.loads(INVENTARIO.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def base_cargada(tmp_path_factory):
    if not SNAPSHOT.exists():
        pytest.skip("Falta resources/nvd_snapshot")
    from worker.descargar import descargar_desde_snapshot

    ruta = tmp_path_factory.mktemp("bd") / "radar.db"
    c = bd.conectar(ruta_sqlite=ruta)
    descargar_desde_snapshot(c, SNAPSHOT, con_epss=False)
    c.close()
    return ruta


def activos_y_cobertura(respuesta):
    """Activos agrupados por clave, como los entregaría un normalizador perfecto."""
    por_clave = defaultdict(list)
    cobertura_previa = []
    activos = []
    for f in respuesta["filas"]:
        if f["tipo"] in ("vulnerable", "sano"):
            por_clave[f["clave"]].append(f)
        elif f["tipo"] == "cobertura" and f["motivo"] == "sin_cpe":
            cobertura_previa.append(
                Cobertura(
                    equipo=f["equipo"],
                    programa=f["programa"],
                    version=f["version"],
                    motivo="sin_cpe",
                )
            )
        elif f["tipo"] == "cobertura":
            # Con CPE pero sin versión o con versión ilegible: la detecta el núcleo.
            activos.append(
                Activo(
                    clave=f"{f['programa']}@{f['version']}",
                    producto=f["programa"],
                    nombre=f["programa"],
                    version=f["version"] or "",
                    cpes=["docker:docker"],
                    equipos=[f["equipo"]],
                )
            )
    for clave, filas in por_clave.items():
        f = filas[0]
        activos.append(
            Activo(
                clave=clave,
                producto=f["producto"],
                nombre=f["programa"],
                version=f["version_comparable"],
                cpes=f["pares"],
                equipos=sorted({x["equipo"] for x in filas}),
            )
        )
    return activos, cobertura_previa


def test_cifras_globales(respuesta_generada, base_cargada):
    t = respuesta_generada["totales"]
    activos, cobertura_previa = activos_y_cobertura(respuesta_generada)
    c = bd.conectar(ruta_sqlite=base_cargada)
    r = correr(c, activos, cobertura_previa, guardar=False)
    c.close()

    precisos = [h for h in r.hallazgos if h.preciso]
    assert len({(h.cve, h.activo) for h in precisos}) == t["pares_cve_version_precisos"]
    assert sum(len(h.equipos) for h in precisos) == t["pares_cve_activo_precisos"]
    assert (
        sum(len(h.equipos) for h in r.hallazgos if not h.preciso)
        == t["pares_cve_activo_no_precisos"]
    )
    assert len({h.cve for h in precisos}) == t["cve_distintas"]
    assert sorted({h.cve for h in precisos if h.kev}) == t["kev"]
    assert len({e for h in precisos if h.kev for e in h.equipos}) == t["equipos_con_kev"]
    assert Counter(x.motivo for x in r.cobertura) == Counter(t["cobertura_por_motivo"])


def test_grupos_y_cierre(respuesta_generada, base_cargada, tmp_path):
    import shutil

    ruta = tmp_path / "radar.db"
    shutil.copy(base_cargada, ruta)
    activos, cobertura_previa = activos_y_cobertura(respuesta_generada)
    c = bd.conectar(ruta_sqlite=ruta)
    r = correr(c, activos, cobertura_previa)

    chrome = next(g for g in r.grupos if g.producto == "Google Chrome")
    # Solo cuentan los equipos con hallazgo preciso (156 y 157.0.8103.60), no los sanos.
    assert chrome.versiones == ["156.0.8079.100", "157.0.8103.60"]
    assert chrome.n_equipos == 30
    assert (chrome.version_objetivo, chrome.tipo_objetivo) == ("157.0.8103.78", "exacta")
    winrar = next(g for g in r.grupos if g.producto == "WinRAR")
    assert (winrar.version_objetivo, winrar.tipo_objetivo, winrar.prioridad) == (
        "7.13",
        "exacta",
        "inmediato",
    )

    # Una persona marca un hallazgo; luego WinRAR desaparece del inventario.
    h = next(x for x in r.hallazgos if x.producto == "WinRAR")
    bd.cambiar_estado(c, h.id, "en_curso", "ana@empresa.example")
    sin_winrar = [a for a in activos if a.producto != "WinRAR"]
    r2 = correr(c, sin_winrar, cobertura_previa)
    assert r2.propuestos_resueltos
    assert all("WinRAR@" in x for x in r2.propuestos_resueltos)
    # Se propone, no se cambia: el estado humano sigue intacto.
    [leido] = [x for x in bd.leer_hallazgos(c) if x.id == h.id]
    assert leido.estado == "en_curso"
    c.close()
