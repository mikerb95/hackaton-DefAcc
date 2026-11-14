"""Integración de punta a punta, medida contra la respuesta conocida.

    inventario generado (CSV) -> radar.ingesta.archivos.leer_inventario
        -> radar.ingesta.normalizador.normalizar -> radar.nucleo.corrida.correr

Todo es el pipeline real: ningún paso usa la respuesta conocida para decidir. La respuesta
(datos_prueba/respuesta.py, que sale del snapshot y nunca del cruce) solo se usa al final
para contar.

La corrida se hace con `guardar=False` sobre una conexión de solo lectura: no escribe en la
base compartida. Por defecto usa el sqlite local (`datos_locales/radar.db`); si no tiene
CVE, arma una base temporal desde resources/nvd_snapshot sin EPSS.

    uv run python -m datos_prueba.integracion
"""

from __future__ import annotations

import json
import tempfile
from collections import Counter
from pathlib import Path

from datos_prueba import generar
from radar import bd
from radar.ingesta.archivos import a_contrato, leer_inventario
from radar.ingesta.normalizador import normalizar
from radar.nucleo.corrida import correr

MEDIDOS = ("vulnerable", "sano")


def _pct(a: int, b: int) -> float | None:
    return round(100 * a / b, 1) if b else None


def _pares(pares) -> tuple[str, ...]:
    return tuple(sorted(p.replace("\\", "") for p in pares))


def _base(ruta: Path | None) -> tuple[object, str]:
    """Conexión de solo lectura con CVE cargadas, y de dónde salió."""
    from radar import config

    ruta = ruta or config.ruta_sqlite_local()
    if ruta.exists():
        c = bd.conectar(solo_lectura=True, ruta_sqlite=ruta)
        if bd.contar(c, "cves"):
            return c, str(ruta)
        c.close()
    from worker.descargar import SNAPSHOT, descargar_desde_snapshot

    temporal = Path(tempfile.mkdtemp(prefix="radar_integracion_")) / "radar.db"
    c = bd.conectar(ruta_sqlite=temporal)
    descargar_desde_snapshot(c, SNAPSHOT, con_epss=False)
    c.close()
    return bd.conectar(solo_lectura=True, ruta_sqlite=temporal), f"snapshot -> {temporal}"


def medir_pipeline(ruta_bd: Path | None = None, con_inyeccion: bool = False) -> dict:
    """Corre el pipeline completo y compara contra la respuesta conocida."""
    filas_gen, resp = generar.generar(con_inyeccion=con_inyeccion)
    with tempfile.TemporaryDirectory() as tmp:
        csv = Path(tmp) / "inventario.csv"
        generar.escribir_csv(filas_gen, csv)
        lectura = leer_inventario(csv)
    filas = [a_contrato(f) for f in lectura.filas]
    activos, cobertura_normalizador = normalizar(filas)

    conexion, origen_bd = _base(ruta_bd)
    try:
        r = correr(conexion, activos, cobertura_normalizador, guardar=False)
    finally:
        conexion.close()

    # Lo esperado, por (CVE, equipo) y por (CVE, producto y versión).
    medidas = [f for f in resp["filas"] if f["tipo"] in MEDIDOS]
    esp_eq = {(c, f["equipo"]) for f in medidas for c in f["cves"]}
    esp_np = {(c, f["equipo"]) for f in medidas for c in f["no_precisas"]}
    # Por activo: 7 CVE no precisas (BEAST, CRIME, Logjam...) listan a Chrome y Firefox a la
    # vez; en un equipo con los dos cuentan una vez por equipo y dos por activo (1098).
    esp_np_act = {(c, f["equipo"], _pares(f["pares"])) for f in medidas for c in f["no_precisas"]}
    esp_ver = {(c, par, f["version_comparable"])
               for f in medidas for par, cves in f["cves_por_par"].items() for c in cves}
    esp_kev = {c for f in medidas for c in f["kev"]}

    # Lo obtenido por el pipeline.
    por_clave = {a.clave: a for a in activos}
    precisos = [h for h in r.hallazgos if h.preciso]
    obt_eq = {(h.cve, e) for h in precisos for e in h.equipos}
    no_precisos = [h for h in r.hallazgos if not h.preciso]
    obt_np = {(h.cve, e) for h in no_precisos for e in h.equipos}
    obt_np_act = {(h.cve, e, _pares(por_clave[h.activo].cpes)) for h in no_precisos for e in h.equipos}
    obt_kev = {h.cve for h in precisos if h.kev}
    # Por par: un hallazgo trae el rango que emparejó, y con él el par.
    obt_ver = set()
    for h in precisos:
        par = h.rango.par if h.rango else None
        if par is None:
            pares = por_clave[h.activo].cpes
            par = pares[0] if len(pares) == 1 else None
        obt_ver.add((h.cve, par, h.version_instalada))

    def _sin_escape(conjunto):
        return {(c, (p or "").replace("\\", ""), v) for c, p, v in conjunto}

    esp_ver_n, obt_ver_n = _sin_escape(esp_ver), _sin_escape(obt_ver)
    tp_eq = len(esp_eq & obt_eq)
    fp_eq = obt_eq - esp_eq
    fn_eq = esp_eq - obt_eq

    cob_esperada = Counter(f["motivo"] for f in resp["filas"] if f["tipo"] == "cobertura")
    cob_obtenida = Counter(c.motivo for c in r.cobertura)
    # La cobertura del relleno (programas internos sin CPE) se cuenta aparte.
    relleno = {(f["equipo"], f["programa"]) for f in resp["filas"] if f["tipo"] == "relleno"}
    inyeccion = {(f["equipo"], f["programa"]) for f in resp["filas"] if f["tipo"] == "inyeccion"}
    cob_medible = Counter(
        c.motivo for c in r.cobertura
        if (c.equipo, c.programa) not in relleno and (c.equipo, c.programa) not in inyeccion
    )

    return {
        "origen_bd": origen_bd,
        "snapshot": resp["snapshot"],
        "filas_leidas": len(filas),
        "activos": len(activos),
        "pares_cve_version_esperados": len(esp_ver_n),
        "pares_cve_version_obtenidos": len(obt_ver_n),
        "pares_cve_version_correctos": len(esp_ver_n & obt_ver_n),
        "pares_cve_equipo_esperados": len(esp_eq),
        "pares_cve_equipo_obtenidos": len(obt_eq),
        "pares_cve_equipo_correctos": tp_eq,
        "deteccion_pct": _pct(tp_eq, len(esp_eq)),
        "precision_pct": _pct(tp_eq, len(obt_eq)),
        "falsos_positivos": len(fp_eq),
        "falsos_negativos": len(fn_eq),
        "no_precisos_esperados": len(esp_np),
        "no_precisos_obtenidos": len(obt_np),
        "no_precisos_correctos": len(esp_np & obt_np),
        "no_precisos_por_activo_esperados": len(esp_np_act),
        "no_precisos_por_activo_obtenidos": len(obt_np_act),
        "no_precisos_por_activo_correctos": len(esp_np_act & obt_np_act),
        "kev_esperadas": len(esp_kev),
        "kev_obtenidas": len(obt_kev),
        "kev_faltantes": sorted(esp_kev - obt_kev),
        "kev_sobrantes": sorted(obt_kev - esp_kev),
        "cobertura_esperada_por_motivo": dict(sorted(cob_esperada.items())),
        "cobertura_obtenida_por_motivo": dict(sorted(cob_medible.items())),
        "cobertura_total_por_motivo": dict(sorted(cob_obtenida.items())),
        "productos": len(r.grupos),
        "muestra_falsos_positivos": sorted(fp_eq)[:10],
        "muestra_falsos_negativos": sorted(fn_eq)[:10],
    }


def main() -> None:
    m = medir_pipeline()
    print(json.dumps(m, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()
