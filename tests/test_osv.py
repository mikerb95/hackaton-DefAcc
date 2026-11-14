"""Cruce de paquetes Linux contra OSV (RF-816 a RF-818). OSV va con transporte simulado:
ninguna prueba sale a la red. Las formas de las respuestas son las reales de la API
(comprobadas el 14 de noviembre de 2026).
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime

import httpx
import pytest

from radar import bd
from radar.config import Umbrales
from radar.contratos import SenalEpss, Senales, SenalKev
from radar.equipos import almacen, paquetes
from radar.equipos.contratos import (
    HardwareReportado,
    PosturaReportada,
    ProgramaReportado,
    SistemaReportado,
)
from radar.fuentes import osv
from worker import equipos as worker

ECO = "Ubuntu:22.04:LTS"
EQUIPO_ID = "0b6f4c1e-8d2a-4f3b-9c7d-1a2b3c4d5e6f"
AHORA = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)

AVISO_UBUNTU = {
    "id": "UBUNTU-CVE-2023-2975",
    "modified": "2025-01-01T00:00:00Z",
    "upstream": ["CVE-2023-2975"],
    "related": ["USN-6450-1"],
    "severity": [
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"},
        {"type": "Ubuntu", "score": "low"},
    ],
    "affected": [
        {
            "package": {"name": "openssl", "ecosystem": ECO},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.12"}],
                }
            ],
        },
        {
            "package": {"name": "openssl", "ecosystem": "Ubuntu:20.04:LTS"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.1f-9"}]}
            ],
        },
    ],
}
AVISO_GRAVE = {
    "id": "UBUNTU-CVE-2022-3602",
    "modified": "2025-02-02T00:00:00Z",
    "upstream": ["CVE-2022-3602"],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [
        {
            "package": {"name": "openssl", "ecosystem": ECO},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "3.0.2-0ubuntu1.30"}],
                }
            ],
        }
    ],
}
AVISO_SIN_ARREGLO = {
    "id": "UBUNTU-CVE-2024-0001",
    "modified": "2025-03-03T00:00:00Z",
    "upstream": ["CVE-2024-0001"],
    "affected": [
        {
            "package": {"name": "bash", "ecosystem": ECO},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
        }
    ],
}
AVISOS = {a["id"]: a for a in (AVISO_UBUNTU, AVISO_GRAVE, AVISO_SIN_ARREGLO)}


# -- cliente de OSV (RF-816) ---------------------------------------------------


@pytest.mark.parametrize(
    ("distro", "version", "esperado"),
    [
        ("ubuntu", "22.04", "Ubuntu:22.04:LTS"),
        ("Ubuntu", "24.04.1", "Ubuntu:24.04:LTS"),
        ("ubuntu", "23.10", "Ubuntu:23.10"),
        ("ubuntu", "23.04", "Ubuntu:23.04"),
        ("debian", "12", "Debian:12"),
        ("rocky", "9.4", "Rocky Linux:9"),
        ("almalinux", "8.10", "AlmaLinux:8"),
        ("arch", "rolling", None),
        ("fedora", "40", None),
        ("ubuntu", None, None),
        (None, "22.04", None),
        ("ubuntu", "ignora", None),
    ],
)
def test_ecosistema(distro, version, esperado):
    assert osv.ecosistema(distro, version) == esperado


def test_reducir_deja_cve_vector_y_arreglos():
    r = osv.reducir(AVISO_UBUNTU)
    assert r["cves"] == ["CVE-2023-2975"] and r["vector"].startswith("CVSS:3.1/")
    assert osv.arreglos_de(r, ECO, "openssl") == ["3.0.2-0ubuntu1.12"]
    assert osv.arreglos_de(r, ECO, "otro") == []
    # Un aviso cuyo id ya es una CVE, o con el alias en `aliases`, también cuenta.
    assert osv.reducir({"id": "CVE-2024-1", "affected": []})["cves"] == []
    alias = osv.reducir({"id": "RLSA-2024:6783", "aliases": ["CVE-2024-6119", "GHSA-x"]})
    assert alias["cves"] == ["CVE-2024-6119"] and alias["vector"] is None


def _transporte(avisos_por_paquete: dict[str, list[str]], vistas: list | None = None, caidos=()):
    """Simula OSV: `querybatch` responde por nombre de paquete y `vulns/{id}` el detalle."""

    def responder(peticion: httpx.Request) -> httpx.Response:
        if vistas is not None:
            vistas.append(peticion)
        if peticion.url.path.endswith("/querybatch"):
            resultados = []
            for consulta in json.loads(peticion.content)["queries"]:
                nombre = consulta["package"]["name"]
                ids = avisos_por_paquete.get(nombre, [])
                if consulta.get("page_token") == "segunda":
                    resultados.append(
                        {"vulns": [{"id": ids[-1], "modified": AVISOS[ids[-1]]["modified"]}]}
                    )
                elif nombre == "paginado":
                    resultados.append(
                        {
                            "vulns": [{"id": ids[0], "modified": AVISOS[ids[0]]["modified"]}],
                            "next_page_token": "segunda",
                        }
                    )
                else:
                    vulns = [{"id": i, "modified": AVISOS[i]["modified"]} for i in ids]
                    resultados.append({"vulns": vulns} if vulns else {})
            return httpx.Response(200, json={"results": resultados})
        id_aviso = peticion.url.path.rsplit("/", 1)[-1]
        if id_aviso in caidos:
            return httpx.Response(500)
        return httpx.Response(200, json=AVISOS[id_aviso])

    return httpx.Client(transport=httpx.MockTransport(responder))


def test_consulta_por_lote_sigue_la_paginacion():
    cliente = _transporte({"paginado": ["UBUNTU-CVE-2023-2975", "UBUNTU-CVE-2022-3602"]})
    consultas = [osv.Consulta("paginado", "1.0", ECO), osv.Consulta("limpio", "1.0", ECO)]
    respuesta = osv.consultar_lote(consultas, cliente)
    assert set(respuesta[consultas[0]]) == {"UBUNTU-CVE-2023-2975", "UBUNTU-CVE-2022-3602"}
    assert respuesta[consultas[1]] == {}


# -- armado de hallazgos (RF-817) ----------------------------------------------


def _equipo(conexion, distro="ubuntu", version="22.04") -> almacen.Equipo:
    bd.crear_esquema(conexion)
    almacen.inscribir(conexion, EQUIPO_ID, "srv-ubuntu-01", "0.1.0")
    equipo = almacen.leer_equipo(conexion, EQUIPO_ID)
    so = SistemaReportado(familia="linux", nombre="Ubuntu", version=version, distro=distro)
    almacen.guardar_reporte(
        conexion,
        equipo,
        equipo.nombre,
        "0.1.0",
        so,
        HardwareReportado(),
        PosturaReportada(),
        {},
        AHORA,
    )
    programas = [
        ProgramaReportado(
            programa="libssl3",
            version="3.0.2-0ubuntu1.10",
            fuente="dpkg",
            origen="openssl",
            version_origen="3.0.2-0ubuntu1.10",
        ),
        ProgramaReportado(
            programa="openssl",
            version="3.0.2-0ubuntu1.10",
            fuente="dpkg",
            origen="openssl",
            version_origen="3.0.2-0ubuntu1.10",
        ),
        ProgramaReportado(
            programa="bash",
            version="5.1-6ubuntu1.1",
            fuente="dpkg",
            origen="bash",
            version_origen="5.1-6ubuntu1.1",
        ),
        ProgramaReportado(
            programa="coreutils",
            version="8.32-4.1ubuntu1.2",
            fuente="dpkg",
            origen="coreutils",
            version_origen="8.32-4.1ubuntu1.2",
        ),
    ]
    almacen.reemplazar_paquetes(conexion, EQUIPO_ID, programas)
    return almacen.leer_equipo(conexion, EQUIPO_ID)


def test_agrupa_por_paquete_fuente_en_debian_y_por_binario_en_rpm():
    filas = [
        {
            "nombre": "libssl3",
            "version": "3.0.2-1",
            "origen": "openssl",
            "version_origen": "3.0.2-1",
        },
        {
            "nombre": "openssl",
            "version": "3.0.2-1",
            "origen": "openssl",
            "version_origen": "3.0.2-1",
        },
    ]
    por_fuente = paquetes.agrupar_paquetes(filas, ECO)
    assert [(p.nombre, p.binarios) for p in por_fuente] == [("openssl", ["libssl3", "openssl"])]
    por_binario = paquetes.agrupar_paquetes(filas, "Rocky Linux:9")
    assert [p.nombre for p in por_binario] == ["libssl3", "openssl"]


def test_un_hallazgo_por_paquete_con_la_mayor_version_de_arreglo(base_temporal):
    equipo = _equipo(base_temporal)
    lista = paquetes.agrupar_paquetes(almacen.leer_paquetes(base_temporal, EQUIPO_ID), ECO)
    avisos = {i: osv.reducir(a) for i, a in AVISOS.items()}
    por_paquete = {
        ("openssl", "3.0.2-0ubuntu1.10"): ["UBUNTU-CVE-2023-2975", "UBUNTU-CVE-2022-3602"],
        ("bash", "5.1-6ubuntu1.1"): ["UBUNTU-CVE-2024-0001"],
    }
    hallazgos = paquetes.armar_hallazgos(
        equipo, ECO, lista, por_paquete, avisos, Senales(), umbrales=Umbrales(), ahora=AHORA
    )
    por_clave = {h.clave: h for h in hallazgos}
    assert set(por_clave) == {"openssl", "bash"}  # coreutils no tiene avisos

    openssl = por_clave["openssl"]
    assert openssl.prioridad == "inmediato" and openssl.detalle["peor_cvss"] == 9.8
    assert openssl.detalle["version_arreglo"] == "3.0.2-0ubuntu1.30"
    assert openssl.detalle["cves"] == ["CVE-2022-3602", "CVE-2023-2975"]
    assert openssl.comandos == [
        "sudo apt-get update && sudo apt-get install --only-upgrade libssl3 openssl"
    ]
    assert "Sin dato de EPSS para sus CVE" in openssl.por_que  # EPSS ausente no es cero

    bash = por_clave["bash"]
    assert bash.prioridad == "informativo" and bash.comandos == []
    assert bash.detalle["version_arreglo"] is None and bash.detalle["peor_cvss"] is None
    assert any("no tienen arreglo publicado" in r for r in bash.por_que)
    assert "Sin puntaje CVSS publicado" in bash.por_que


def test_kev_y_epss_se_emparejan_por_id_de_cve(base_temporal):
    equipo = _equipo(base_temporal)
    lista = paquetes.agrupar_paquetes(almacen.leer_paquetes(base_temporal, EQUIPO_ID), ECO)
    senales = Senales(
        kev={"CVE-2024-0001": SenalKev(cve="CVE-2024-0001", ransomware=True)},
        epss={
            "CVE-2023-2975": SenalEpss(
                cve="CVE-2023-2975", epss=0.4, percentil=0.9, fecha=date(2026, 11, 14)
            )
        },
    )
    hallazgos = paquetes.armar_hallazgos(
        equipo,
        ECO,
        lista,
        {
            ("openssl", "3.0.2-0ubuntu1.10"): ["UBUNTU-CVE-2023-2975"],
            ("bash", "5.1-6ubuntu1.1"): ["UBUNTU-CVE-2024-0001"],
        },
        {i: osv.reducir(a) for i, a in AVISOS.items()},
        senales,
        umbrales=Umbrales(),
        ahora=AHORA,
    )
    por_clave = {h.clave: h for h in hallazgos}
    assert por_clave["bash"].prioridad == "inmediato"
    assert por_clave["bash"].detalle["en_kev"] == ["CVE-2024-0001"]
    assert por_clave["bash"].detalle["ransomware"] is True
    # CVSS 5.3 solo no llega, pero EPSS 40 % sí.
    assert por_clave["openssl"].prioridad == "inmediato"
    assert any("40%" in r for r in por_clave["openssl"].por_que)


# -- revisión completa y worker (RF-818) ---------------------------------------


def test_revisar_equipo_guarda_y_usa_la_cache(base_temporal):
    equipo = _equipo(base_temporal)
    vistas: list = []
    cliente = _transporte({"openssl": ["UBUNTU-CVE-2023-2975", "UBUNTU-CVE-2022-3602"]}, vistas)
    r = paquetes.revisar_equipo(base_temporal, equipo, cliente, Umbrales(), AHORA, con_epss=False)
    assert (r.cruzado, r.paquetes, r.avisos, r.hallazgos) == (True, 3, 2, 1)
    guardados = almacen.leer_hallazgos(base_temporal, EQUIPO_ID)
    assert [h.clave for h in guardados] == ["openssl"] and guardados[0].tipo == "paquete"
    detalles = [v for v in vistas if "/vulns/" in v.url.path]
    assert len(detalles) == 2

    # Segunda vez: los avisos no cambiaron, no se vuelven a bajar.
    vistas.clear()
    paquetes.revisar_equipo(base_temporal, equipo, cliente, Umbrales(), AHORA, con_epss=False)
    assert [v for v in vistas if "/vulns/" in v.url.path] == []

    # El paquete se actualizó: OSV ya no lo reporta y el hallazgo desaparece.
    limpio = _transporte({})
    paquetes.revisar_equipo(base_temporal, equipo, limpio, Umbrales(), AHORA, con_epss=False)
    assert almacen.leer_hallazgos(base_temporal, EQUIPO_ID) == []


def test_aviso_sin_detalle_se_cuenta_y_no_se_inventa(base_temporal):
    equipo = _equipo(base_temporal)
    cliente = _transporte(
        {"openssl": ["UBUNTU-CVE-2023-2975", "UBUNTU-CVE-2022-3602"]},
        caidos={"UBUNTU-CVE-2022-3602"},
    )
    r = paquetes.revisar_equipo(base_temporal, equipo, cliente, Umbrales(), AHORA, con_epss=False)
    assert r.avisos_sin_detalle == 1 and "sin detalle" in r.resumen
    h = almacen.leer_hallazgos(base_temporal, EQUIPO_ID)[0]
    assert h.detalle["cves"] == ["CVE-2023-2975"] and h.detalle["peor_cvss"] == 5.3
    assert any("sin detalle" in razon for razon in h.por_que)


def test_distribucion_sin_fuente_de_avisos_no_se_cruza(base_temporal):
    equipo = _equipo(base_temporal, "arch", "rolling")
    r = paquetes.revisar_equipo(base_temporal, equipo, _transporte({}), con_epss=False)
    assert not r.cruzado and "arch" in r.motivo


def test_osv_caido_no_borra_lo_guardado_y_el_trabajo_queda_fallido(base_temporal):
    equipo = _equipo(base_temporal)
    bueno = _transporte({"openssl": ["UBUNTU-CVE-2022-3602"]})
    paquetes.revisar_equipo(base_temporal, equipo, bueno, Umbrales(), AHORA, con_epss=False)

    caido = httpx.Client(transport=httpx.MockTransport(lambda p: httpx.Response(503)))
    bd.crear_trabajo(base_temporal, "cruzar_so", EQUIPO_ID)
    assert worker.atender_cola(base_temporal, caido, con_epss=False) == 1
    trabajo = bd.leer_trabajos(base_temporal)[0]
    assert trabajo.estado == "fallido" and "OSV no respondió" in trabajo.detalle
    # Fuente caída no es "sin hallazgos": lo anterior sigue ahí.
    assert [h.clave for h in almacen.leer_hallazgos(base_temporal, EQUIPO_ID)] == ["openssl"]
    ejecucion = bd.ultima_ejecucion(base_temporal, "cruzar_so")
    assert ejecucion.fuentes == {"osv": False} and ejecucion.error


def test_el_worker_atiende_la_cola_y_registra_la_ejecucion(base_temporal):
    _equipo(base_temporal)
    bd.crear_trabajo(base_temporal, "cruzar_so", EQUIPO_ID)
    bd.crear_trabajo(base_temporal, "cruzar_so", "equipo-que-no-existe")
    bd.crear_trabajo(base_temporal, "analizar", "no es de este worker")
    cliente = _transporte({"openssl": ["UBUNTU-CVE-2022-3602"]})
    assert worker.atender_cola(base_temporal, cliente, con_epss=False) == 2
    estados = {t.detalle.split(":")[0]: t.estado for t in bd.leer_trabajos(base_temporal)}
    assert estados["srv-ubuntu-01"] == "hecho"
    assert estados["equipo equipo-que-no-existe no existe"] == "fallido"
    assert estados["no es de este worker"] == "pendiente"
    assert worker.cruzar_todos(base_temporal, cliente, con_epss=False) == 1
    assert bd.ultima_ejecucion(base_temporal, "cruzar_so").fuentes == {"osv": True}
