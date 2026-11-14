"""bd.py sobre sqlite local (mismo esquema que Turso) y worker/descargar.py --desde-snapshot."""

import shutil

import pytest

from radar import bd, ejemplos
from radar.config import Umbrales
from radar.contratos import Activo
from radar.nucleo.cruce import cruzar_activo
from radar.nucleo.prioridad import hallazgos_de_activo
from tests.conftest import SNAPSHOT, archivo_de_par


@pytest.fixture
def conexion(tmp_path):
    c = bd.conectar(ruta_sqlite=tmp_path / "radar.db")
    bd.crear_esquema(c)
    yield c
    c.close()


def test_ida_y_vuelta_de_cves(conexion):
    bd.guardar_cves(conexion, ejemplos.CVES)
    leidas = {c.id: c for c in bd.leer_cves(conexion)}
    for c in ejemplos.CVES:
        assert leidas[c.id] == c
    solo_docker = bd.leer_cves(conexion, ["docker:docker_desktop"])
    assert [c.id for c in solo_docker] == ["CVE-2026-5817"]


def test_guardar_cves_reemplaza_rangos(conexion):
    bd.guardar_cves(conexion, ejemplos.CVES)
    bd.guardar_cves(conexion, ejemplos.CVES)
    total = sum(len(c.rangos) for c in ejemplos.CVES)
    assert bd.contar(conexion, "cve_rangos") == total


def test_senales(conexion):
    bd.guardar_kev(conexion, ejemplos.SENALES.kev)
    bd.guardar_epss(conexion, ejemplos.SENALES.epss)
    assert bd.leer_senales(conexion) == ejemplos.SENALES
    parcial = bd.leer_senales(conexion, ["CVE-2026-5817"])
    assert list(parcial.epss) == ["CVE-2026-5817"] and parcial.kev == {}


def test_corrida_automatica_no_pisa_la_decision_humana(conexion):
    h = ejemplos.HALLAZGOS[0]
    bd.guardar_hallazgos(conexion, [h])
    assert bd.cambiar_estado(conexion, h.id, "en_curso", "ana@empresa.example", "Parche el lunes")
    # Nueva corrida: cambian los datos de la CVE y el hallazgo llega como "nuevo".
    otra = h.model_copy(update={"cvss": 9.9, "estado": "nuevo", "comentario": None, "por": None})
    bd.guardar_hallazgos(conexion, [otra])
    [leido] = bd.leer_hallazgos(conexion)
    assert leido.cvss == 9.9
    assert (leido.estado, leido.por, leido.comentario) == (
        "en_curso",
        "ana@empresa.example",
        "Parche el lunes",
    )
    assert leido.detectado == h.detectado


def test_ida_y_vuelta_hallazgos_cobertura_analisis(conexion):
    bd.guardar_hallazgos(conexion, ejemplos.HALLAZGOS)
    assert {h.id: h for h in bd.leer_hallazgos(conexion)} == {h.id: h for h in ejemplos.HALLAZGOS}
    bd.guardar_cobertura(conexion, ejemplos.COBERTURA)
    assert bd.leer_cobertura(conexion) == ejemplos.COBERTURA
    for a in ejemplos.ANALISIS:
        bd.guardar_analisis(conexion, a)
        assert bd.leer_analisis(conexion, a.producto) == [a]
    assert bd.leer_analisis(conexion) == sorted(ejemplos.ANALISIS, key=lambda a: a.producto)
    bd.guardar_inventario(conexion, ejemplos.FILAS)
    assert bd.leer_inventario(conexion) == ejemplos.FILAS


def test_cola_de_trabajos(conexion):
    uno = bd.crear_trabajo(conexion, "analizar", "WinRAR")
    bd.crear_trabajo(conexion, "descargar")
    t = bd.tomar_trabajo(conexion, "analizar")
    assert (t.id, t.estado) == (uno, "en_curso")
    assert bd.tomar_trabajo(conexion, "analizar") is None
    bd.terminar_trabajo(conexion, uno, ok=True)
    assert bd.leer_trabajos(conexion)[-1].estado == "hecho"


def test_solo_lectura_rechaza_escrituras(tmp_path):
    ruta = tmp_path / "radar.db"
    c = bd.conectar(ruta_sqlite=ruta)
    bd.crear_esquema(c)
    c.close()
    lectura = bd.conectar(solo_lectura=True, ruta_sqlite=ruta)
    assert lectura.execute("SELECT count(*) FROM kev").fetchone() == (0,)
    for sql in (
        "DELETE FROM kev",
        "UPDATE hallazgos SET estado = 'mitigado'",
        "SELECT 1; DROP TABLE kev",
        "  insert into kev (cve) values ('x')",
    ):
        with pytest.raises(bd.EscrituraNoPermitida):
            lectura.execute(sql)
    lectura.close()


def test_descarga_desde_snapshot_y_cruce(tmp_path):
    """Snapshot reducido (WinRAR y los dos pares de Docker) -> sqlite -> cruce."""
    if not SNAPSHOT.exists():
        pytest.skip("Falta resources/nvd_snapshot")
    from worker.descargar import descargar_desde_snapshot

    carpeta = tmp_path / "snap"
    carpeta.mkdir()
    for par in ("rarlab:winrar", "docker:desktop", "docker:docker_desktop"):
        shutil.copy(archivo_de_par(par), carpeta)
    shutil.copy(SNAPSHOT / "kev.json", carpeta)

    c = bd.conectar(ruta_sqlite=tmp_path / "radar.db")
    ejecucion = descargar_desde_snapshot(c, carpeta, con_epss=False)
    assert ejecucion.fuentes == {"kev": True, "nvd": True, "epss": False}
    assert bd.ultima_ejecucion(c, "descargar").fuentes == ejecucion.fuentes

    winrar = next(a for a in ejemplos.ACTIVOS if a.producto == "WinRAR")
    r = cruzar_activo(winrar, bd.leer_cves(c, winrar.cpes))
    assert len([x for x in r.coincidencias if x.preciso]) == 10
    senales = bd.leer_senales(c, [x.cve.id for x in r.coincidencias])
    hallazgos = hallazgos_de_activo(winrar, r, senales, Umbrales())
    assert sorted(h.cve for h in hallazgos if h.kev) == [
        "CVE-2018-20250",
        "CVE-2023-38831",
        "CVE-2025-6218",
        "CVE-2025-8088",
    ]
    # EPSS no se bajó: queda None, nunca 0.
    assert all(h.epss is None for h in hallazgos)

    docker: Activo = next(a for a in ejemplos.ACTIVOS if a.producto == "Docker Desktop")
    r = cruzar_activo(docker, bd.leer_cves(c, docker.cpes))
    assert sorted(x.cve.id for x in r.coincidencias) == ["CVE-2026-5817", "CVE-2026-5843"]
    c.close()


def test_fuente_caida_queda_registrada(tmp_path):
    from worker.descargar import descargar_desde_snapshot

    vacia = tmp_path / "vacia"
    vacia.mkdir()
    c = bd.conectar(ruta_sqlite=tmp_path / "radar.db")
    ejecucion = descargar_desde_snapshot(c, vacia, con_epss=False)
    assert ejecucion.fuentes == {"kev": False, "nvd": False, "epss": False}
    assert ejecucion.error
    c.close()


def test_insercion_por_lotes_de_varias_filas(conexion):
    """Turso hace una petición HTTP por `execute`: hay que meter muchas filas en cada una."""

    class Contador:
        def __init__(self, c):
            self.c, self.llamadas = c, 0

        def execute(self, sql, parametros=()):
            self.llamadas += 1
            return self.c.execute(sql, parametros)

        def executemany(self, *_):
            raise AssertionError("executemany hace una petición por fila en Turso")

        def commit(self):
            self.c.commit()

    contador = Contador(conexion)
    filas = [(f"CVE-2099-{i:05d}", 0.5, 0.5, "2026-11-14") for i in range(1000)]
    bd._en_lotes(contador, "INSERT INTO epss (cve, epss, percentil, fecha) VALUES (?,?,?,?)", filas)
    assert contador.llamadas == 5  # 225 filas por sentencia (900 parámetros / 4)
    assert bd.contar(conexion, "epss") == 1000


def test_aislamiento_de_pruebas():
    """Ninguna prueba llega a la base compartida, a Turso ni a NVD con la clave real."""
    import os

    from radar import config

    assert config.turso() is None
    assert "NVD_API_KEY" not in os.environ
    assert "datos_locales" not in str(config.ruta_sqlite_local())


def test_base_con_hallazgos(base_con_hallazgos):
    hallazgos = {h.producto: h for h in bd.leer_hallazgos(base_con_hallazgos)}
    assert set(hallazgos) == {"WinRAR", "Google Chrome", "Docker Desktop"}
    assert hallazgos["Docker Desktop"].prioridad == "semanal"
    assert bd.contar(base_con_hallazgos, "inventario") == len(ejemplos.FILAS)
