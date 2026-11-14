"""Estados de un hallazgo y reglas de corrida: decisión humana, línea base silenciosa,
sin repetir avisos, cierre propuesto, aprobación del comunicado y barrido de umbrales."""

from datetime import UTC, date, datetime

import pytest

from radar import bd, ejemplos
from radar.config import Umbrales
from radar.contratos import SenalKev
from radar.nucleo.corrida import correr, marcar_avisado, pendientes_de_aviso
from radar.nucleo.umbrales import barrido

AHORA = datetime(2026, 11, 14, 10, 0, tzinfo=UTC)
U = Umbrales()


@pytest.fixture
def conexion(tmp_path):
    c = bd.conectar(ruta_sqlite=tmp_path / "radar.db")
    bd.crear_esquema(c)
    bd.guardar_cves(c, ejemplos.CVES)
    bd.guardar_kev(c, ejemplos.SENALES.kev)
    bd.guardar_epss(c, ejemplos.SENALES.epss)
    yield c
    c.close()


def correr_ejemplos(c, activos=None):
    return correr(c, activos or ejemplos.ACTIVOS, umbrales=U, ahora=AHORA)


def productos(grupos):
    return [g.producto for g in grupos]


# ---------------------------------------------------------------------------
# Cambio de estado: solo una persona, con quién y comentario
# ---------------------------------------------------------------------------


def test_cambio_de_estado_validado(conexion):
    correr_ejemplos(conexion)
    hid = "CVE-2018-20250|WinRAR@5.61"
    with pytest.raises(ValueError, match="Estado no válido"):
        bd.cambiar_estado(conexion, hid, "cerrado", "ana")
    with pytest.raises(ValueError, match="persona"):
        bd.cambiar_estado(conexion, hid, "en_curso", "  ")
    with pytest.raises(ValueError, match="comentario"):
        bd.cambiar_estado(conexion, hid, "descartado", "ana")
    with pytest.raises(ValueError, match="comentario"):
        bd.cambiar_estado(conexion, hid, "mitigado", "ana", "   ")
    assert bd.cambiar_estado(conexion, hid, "en_curso", "ana")
    assert bd.cambiar_estado(conexion, hid, "mitigado", "ana", "Actualizado a 7.13")
    assert not bd.cambiar_estado(conexion, "no|existe", "en_curso", "ana")
    [h] = bd.leer_hallazgos(conexion, "WinRAR")
    assert (h.estado, h.por, h.comentario) == ("mitigado", "ana", "Actualizado a 7.13")


def test_la_corrida_nunca_pisa_el_estado(conexion):
    correr_ejemplos(conexion)
    hid = "CVE-2026-125350|Google Chrome@156.0.8079.100"
    bd.cambiar_estado(conexion, hid, "descartado", "ana", "Equipos de laboratorio")
    r = correr_ejemplos(conexion)
    [h] = [x for x in r.hallazgos if x.id == hid]
    assert (h.estado, h.por, h.comentario) == ("descartado", "ana", "Equipos de laboratorio")


# ---------------------------------------------------------------------------
# Línea base silenciosa y sin repetir avisos
# ---------------------------------------------------------------------------


def test_linea_base_silencia_lo_acumulado_pero_no_lo_reciente(conexion):
    r = correr_ejemplos(conexion)
    assert r.linea_base
    # WinRAR (KEV de 2022) y Docker (publicada en mayo) quedan como ya avisados. Chrome entró
    # a KEV el 10 de noviembre: dentro de la ventana de 7 días, se avisa.
    assert r.silenciados == 2
    assert productos(pendientes_de_aviso(conexion, umbrales=U)) == ["Google Chrome"]
    assert not correr_ejemplos(conexion).linea_base


def test_sin_repetir_avisos(conexion):
    correr_ejemplos(conexion)
    assert marcar_avisado(conexion, "Google Chrome") == 1
    assert pendientes_de_aviso(conexion, umbrales=U) == []
    correr_ejemplos(conexion)  # la siguiente corrida no reabre lo avisado
    assert pendientes_de_aviso(conexion, umbrales=U) == []


def test_subir_a_inmediato_vuelve_a_avisar(conexion):
    correr_ejemplos(conexion)
    [docker] = bd.leer_hallazgos(conexion, "Docker Desktop")
    assert (docker.prioridad, docker.avisado) == ("semanal", True)
    # CVE-2026-5817 entra a KEV: información nueva.
    bd.guardar_kev(
        conexion,
        {
            **ejemplos.SENALES.kev,
            "CVE-2026-5817": SenalKev(cve="CVE-2026-5817", agregada=date(2026, 11, 14)),
        },
    )
    correr_ejemplos(conexion)
    [docker] = bd.leer_hallazgos(conexion, "Docker Desktop")
    assert (docker.prioridad, docker.avisado) == ("inmediato", False)
    assert "Docker Desktop" in productos(pendientes_de_aviso(conexion, umbrales=U))


def test_pendientes_semanales(conexion):
    correr_ejemplos(conexion)
    conexion.execute("UPDATE hallazgos SET avisado = 0")
    semanal = pendientes_de_aviso(conexion, prioridades=("semanal",), umbrales=U)
    assert productos(semanal) == ["Docker Desktop"]


# ---------------------------------------------------------------------------
# Cierre automático propuesto
# ---------------------------------------------------------------------------


def test_cierre_propuesto_y_reaparicion(conexion):
    correr_ejemplos(conexion)
    hid = "CVE-2018-20250|WinRAR@5.61"
    bd.cambiar_estado(conexion, hid, "en_curso", "ana")
    sin_winrar = [a for a in ejemplos.ACTIVOS if a.producto != "WinRAR"]
    r = correr_ejemplos(conexion, sin_winrar)
    assert r.propuestos_resueltos == [hid]
    [h] = bd.leer_hallazgos(conexion, "WinRAR")
    assert h.propuesto_resuelto and h.estado == "en_curso"  # se propone, no se cierra
    # Un hallazgo propuesto no genera aviso.
    conexion.execute("UPDATE hallazgos SET avisado = 0")
    assert "WinRAR" not in productos(pendientes_de_aviso(conexion, umbrales=U))
    # Si vuelve a aparecer, deja de estar propuesto.
    correr_ejemplos(conexion)
    [h] = bd.leer_hallazgos(conexion, "WinRAR")
    assert not h.propuesto_resuelto


def test_lo_cerrado_no_se_propone(conexion):
    correr_ejemplos(conexion)
    bd.cambiar_estado(conexion, "CVE-2018-20250|WinRAR@5.61", "mitigado", "ana", "Hecho")
    sin_winrar = [a for a in ejemplos.ACTIVOS if a.producto != "WinRAR"]
    assert correr_ejemplos(conexion, sin_winrar).propuestos_resueltos == []


# ---------------------------------------------------------------------------
# Aprobación del comunicado, trazas y migración
# ---------------------------------------------------------------------------


def test_aprobar_comunicado(conexion):
    correr_ejemplos(conexion)
    chrome = ejemplos.ANALISIS[0].model_copy(update={"producto": "Google Chrome"})
    assert not bd.aprobar_comunicado(conexion, "Google Chrome", "ana")  # sin análisis
    bd.guardar_analisis(conexion, chrome)
    with pytest.raises(ValueError):
        bd.aprobar_comunicado(conexion, "Google Chrome", "")
    assert bd.aprobar_comunicado(conexion, "Google Chrome", "ana")
    assert bd.leer_aprobacion(conexion, "Google Chrome")["aprobado_por"] == "ana"
    assert pendientes_de_aviso(conexion, umbrales=U) == []  # aprobado = avisado
    # Un análisis nuevo borra la aprobación: lo aprobado era otro texto.
    bd.guardar_analisis(conexion, chrome)
    assert bd.leer_aprobacion(conexion, "Google Chrome") is None


def test_trazas(conexion):
    bd.guardar_traza(conexion, "consultar_hallazgos", '{"producto": "WinRAR"}', "permitida")
    bd.guardar_traza(conexion, "cambiar_estado", "{}", "negada")
    trazas = bd.leer_trazas(conexion, 10)
    assert [t["decision"] for t in trazas] == ["negada", "permitida"]
    assert set(trazas[0]) == {"momento", "herramienta", "entrada", "decision"}


def test_migracion_agrega_columnas(tmp_path):
    c = bd.conectar(ruta_sqlite=tmp_path / "vieja.db")
    c.execute(
        "CREATE TABLE analisis (producto TEXT PRIMARY KEY, contenido TEXT, "
        "verificado INTEGER, origen TEXT, creado TEXT)"
    )
    c.execute(
        "CREATE TABLE hallazgos (id TEXT PRIMARY KEY, cve TEXT NOT NULL, activo TEXT "
        "NOT NULL, producto TEXT NOT NULL, version_instalada TEXT, equipos TEXT, "
        "prioridad TEXT NOT NULL, por_que TEXT, preciso INTEGER, rango TEXT, kev INTEGER, "
        "ransomware INTEGER, epss REAL, cvss REAL, estado TEXT NOT NULL DEFAULT 'nuevo', "
        "comentario TEXT, por TEXT, detectado TEXT, avisado INTEGER DEFAULT 0)"
    )
    bd.crear_esquema(c)
    bd.crear_esquema(c)  # idempotente
    columnas = {f[1] for f in c.execute("PRAGMA table_info(analisis)").fetchall()}
    assert {"aprobado", "aprobado_por"} <= columnas
    columnas = {f[1] for f in c.execute("PRAGMA table_info(hallazgos)").fetchall()}
    assert "propuesto_resuelto" in columnas
    c.close()


# ---------------------------------------------------------------------------
# Barrido de umbrales
# ---------------------------------------------------------------------------


def test_barrido_de_umbrales():
    hallazgos = list(ejemplos.HALLAZGOS)  # WinRAR y Chrome en KEV; Docker CVSS 8.8 sin KEV
    b = barrido(hallazgos, rejilla_epss=[0.001, 0.10, 1.01], rejilla_cvss=[8.5, 9.0], umbrales=U)
    celdas = {(c["epss"], c["cvss"]): c for c in b["celdas"]}
    assert b["solo_kev"]["hallazgos"] == 2
    assert celdas[(1.01, 9.0)]["hallazgos"] == 2  # piso: solo KEV
    assert celdas[(1.01, 8.5)]["hallazgos"] == 3  # Docker entra por CVSS
    assert celdas[(0.001, 9.0)]["hallazgos"] == 3  # Docker entra por EPSS (0.00224)
    assert b["actual"] == celdas[(0.10, 9.0)]
    assert b["actual"]["productos"] == 2
    assert b["total"] == 3


def test_barrido_excluye_cerrados_y_no_precisos():
    h = list(ejemplos.HALLAZGOS)
    h[0] = h[0].model_copy(update={"estado": "mitigado"})
    h[1] = h[1].model_copy(update={"preciso": False})
    h[2] = h[2].model_copy(update={"epss": None})
    b = barrido(h, rejilla_epss=[0.0], rejilla_cvss=[10.1], umbrales=U)
    assert b["total"] == 1
    assert b["celdas"][0]["hallazgos"] == 0  # EPSS ausente no cruza ni el umbral 0
    assert b["sin_epss"] == 1


def test_importar_trazas_del_plugin(conexion, tmp_path):
    import json

    lineas = [
        {
            "hora": "2026-11-14T15:11:38Z",
            "evento": "PreToolUse",
            "herramienta": "mcp__plugin_radar_radar__cargar_inventario",
            "decision": "ask",
        },
        {
            "hora": "2026-11-14T15:11:40Z",
            "evento": "PreToolUse",
            "decision": "deny",
            "error": "TypeError",
        },
        {
            "hora": "2026-11-14T15:12:23Z",
            "evento": "PostToolUse",
            "herramienta": "mcp__plugin_radar_radar__equipos_expuestos",
            "largo": 11119,
            "senales": ["ignora_instrucciones"],
            "retenido": False,
        },
        {
            "hora": "2026-11-14T15:12:24Z",
            "evento": "PostToolUse",
            "herramienta": "x",
            "senales": [],
            "retenido": False,
        },
        {
            "hora": "2026-11-14T15:12:25Z",
            "evento": "PostToolUse",
            "herramienta": "x",
            "retenido": True,
            "error": "ValueError",
        },
    ]
    ruta = tmp_path / "traza.jsonl"
    texto = "\n".join(json.dumps(x) for x in lineas)
    ruta.write_text(
        texto
        + "\nesto no es json\n"
        + json.dumps({"hora": "z", "nota": "\x1b[31m" + "a" * 900})
        + "\n"
    )
    assert bd.importar_trazas(conexion, ruta) == 6
    assert bd.importar_trazas(conexion, ruta) == 0  # reimportar no duplica
    decisiones = [t["decision"] for t in reversed(bd.leer_trazas(conexion, 10))]
    assert decisiones[:5] == ["aprobacion_pedida", "negada", "limpiada", "permitida", "negada"]
    ultima = bd.leer_trazas(conexion, 1)[0]
    assert len(ultima["entrada"]) <= 300 and "\x1b" not in ultima["entrada"]


def test_vaciar_inventario_conserva_fuentes_y_trazas(tmp_path, capsys):
    ruta = tmp_path / "demo.db"
    c = bd.conectar(ruta_sqlite=ruta)
    bd.crear_esquema(c)
    bd.guardar_cves(c, ejemplos.CVES)
    bd.guardar_kev(c, ejemplos.SENALES.kev)
    bd.guardar_epss(c, ejemplos.SENALES.epss)
    bd.guardar_inventario(c, ejemplos.FILAS)
    correr(c, ejemplos.ACTIVOS, umbrales=U, ahora=AHORA)
    bd.guardar_analisis(c, ejemplos.ANALISIS[0])
    bd.aprobar_comunicado(c, "WinRAR", "ana")
    bd.crear_trabajo(c, "analizar", "WinRAR")
    bd.guardar_traza(c, "x", "{}", "permitida")
    c.close()

    # Sin --si no borra nada y dice a qué base apunta.
    assert bd.principal(["vaciar-inventario", "--sqlite", str(ruta)]) == 1
    salida = capsys.readouterr().out
    assert f"local {ruta}" in salida and "--si" in salida
    c = bd.conectar(ruta_sqlite=ruta)
    assert bd.contar(c, "hallazgos") == 3
    c.close()

    assert bd.principal(["vaciar-inventario", "--si", "--sqlite", str(ruta)]) == 0
    c = bd.conectar(ruta_sqlite=ruta)
    for tabla in bd.TABLAS_DEL_INVENTARIO:
        assert bd.contar(c, tabla) == 0, tabla
    assert bd.leer_aprobacion(c, "WinRAR") is None
    for tabla, n in (("cves", 3), ("kev", 3), ("epss", 5), ("trazas", 1)):
        assert bd.contar(c, tabla) == n, tabla
    c.close()


def test_cargar_archivo_con_agentes_no_propone_cerrar_lo_de_los_agentes(conexion, tmp_path):
    """Con agentes inscritos, una carga de archivo cruza todo el inventario guardado."""
    from radar.contratos import FilaInventario
    from radar.equipos import almacen
    from radar.nucleo.corrida import cargar_inventario

    # Un equipo con agente local reporta WinRAR 5.61 (afectado por CVE-2018-20250, KEV).
    almacen.inscribir(
        conexion, "equipo-uuid-1", "PC-AGENTE", "0.1.0", "c" * 43, "ABCD-EFGH", aprobar=True
    )
    fila = FilaInventario(
        equipo="PC-AGENTE",
        programa="WinRAR 5.61 (64-bit)",
        version="5.61",
        proveedor="win.rar GmbH",
        fuente="agente",
        cargado=AHORA,
    )
    almacen.reemplazar_inventario(conexion, "PC-AGENTE", [fila])

    from radar.equipos.cruce import recruzar

    antes = {h.id for h in recruzar(conexion, umbrales=U).resultado.hallazgos}
    assert any(h.startswith("CVE-2018-20250|") for h in antes)

    # Se sube un archivo que no trae a PC-AGENTE.
    csv = tmp_path / "otro.csv"
    csv.write_text("equipo,programa,version\nPC-ARCHIVO,Google Chrome,156.0.8079.100\n")
    _, _, r = cargar_inventario(conexion, csv, umbrales=U)

    winrar = [h for h in r.hallazgos if h.cve == "CVE-2018-20250"]
    assert winrar and "PC-AGENTE" in winrar[0].equipos  # sigue cruzado
    assert not any(x.startswith("CVE-2018-20250|") for x in r.propuestos_resueltos)
    assert bd.contar(conexion, "inventario") == 2  # el archivo no borró lo del agente


def test_hay_equipos_sin_tabla_no_falla(tmp_path):
    """Base creada antes del agente local, abierta en solo lectura: no hay tabla `equipos`."""
    import sqlite3

    from radar.equipos import almacen

    ruta = tmp_path / "vieja.db"
    with sqlite3.connect(ruta) as c:
        c.execute("CREATE TABLE inventario (id INTEGER PRIMARY KEY)")
    lectura = bd.conectar(solo_lectura=True, ruta_sqlite=ruta)
    assert almacen.hay_equipos(lectura) is False
    lectura.close()

    c = bd.conectar(ruta_sqlite=ruta)
    bd.crear_esquema(c)
    assert almacen.hay_equipos(c) is False
    almacen.inscribir(c, "uuid-1", "PC-1", "0.1.0", "c" * 43, "ABCD-EFGH")
    assert almacen.hay_equipos(c) is True
    c.close()
