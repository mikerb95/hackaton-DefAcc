"""Vista por equipo para el panel: qué está mal en cada equipo y cómo resolverlo.

Todo sale de código: hallazgos de aplicaciones (cruce del núcleo), del sistema operativo,
de paquetes de la distribución y de postura, cada uno con sus pasos y, donde hay plantilla,
su comando. Aquí no participa ningún modelo.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from radar import bd
from radar.contratos import ORDEN_PRIORIDAD, Grupo, Hallazgo
from radar.equipos import almacen, postura, remediacion
from radar.equipos.almacen import Equipo
from radar.equipos.contratos import HallazgoEquipo
from radar.fuentes import osv
from radar.nucleo.agrupar import ESTADOS_CERRADOS, agrupar

MAX_COBERTURA = 100


def _abiertos_del_equipo(hallazgos: list[Hallazgo], nombre: str) -> list[Hallazgo]:
    return [
        h
        for h in hallazgos
        if nombre in h.equipos and h.estado not in ESTADOS_CERRADOS and not h.propuesto_resuelto
    ]


def _peor(prioridades: list[str]) -> str | None:
    return min(prioridades, key=ORDEN_PRIORIDAD.__getitem__) if prioridades else None


def _conteo(prioridades: list[str]) -> dict[str, int]:
    cuenta = Counter(prioridades)
    return {p: cuenta.get(p, 0) for p in ("inmediato", "semanal", "informativo")}


def _fila(equipo: Equipo, productos: list[Grupo], propios: list[HallazgoEquipo]) -> dict[str, Any]:
    prioridades = [g.prioridad for g in productos if g.prioridad] + [h.prioridad for h in propios]
    datos = equipo.resumen()
    datos.pop("hardware")
    datos["peor_prioridad"] = _peor(prioridades)
    datos["acciones"] = _conteo(prioridades)
    datos["n_acciones"] = len(prioridades)
    return datos


def lista(conexion: Any) -> list[dict[str, Any]]:
    """Equipos con agente, del más expuesto al menos expuesto."""
    equipos = almacen.leer_equipos(conexion)
    if not equipos:
        return []
    hallazgos = bd.leer_hallazgos(conexion)
    por_equipo: dict[str, list[HallazgoEquipo]] = {}
    for h in almacen.leer_hallazgos(conexion):
        por_equipo.setdefault(h.equipo_id, []).append(h)
    filas = [
        _fila(
            e,
            agrupar(_abiertos_del_equipo(hallazgos, e.nombre)),
            por_equipo.get(e.id, []),
        )
        for e in equipos
    ]
    return sorted(
        filas,
        key=lambda f: (
            ORDEN_PRIORIDAD.get(f["peor_prioridad"] or "", 9),
            -f["acciones"]["inmediato"],
            f["nombre"].lower(),
        ),
    )


def _producto(grupo: Grupo, hallazgos: list[Hallazgo], es_windows: bool) -> dict[str, Any]:
    from radar.agente.respaldo import remediacion as texto_remediacion

    propios = [h for h in hallazgos if h.producto == grupo.producto]
    comandos = remediacion.comandos_de_grupo(grupo, propios) if es_windows else []
    return {
        "producto": grupo.producto,
        "versiones": sorted({h.version_instalada for h in propios}),
        "prioridad": grupo.prioridad,
        "n_cves": grupo.n_cves,
        "en_kev": grupo.en_kev,
        "ransomware": grupo.ransomware,
        "peor_cvss": grupo.peor_cvss,
        "peor_epss": grupo.peor_epss,
        "por_que": grupo.por_que,
        "pasos": texto_remediacion(grupo),
        "comandos": [c.texto for c in comandos],
    }


def _sin_cruzar(equipo: Equipo) -> str | None:
    """Motivo por el que los paquetes de un Linux no se cruzan, o None si sí se cruzan."""
    if equipo.so is None or equipo.so.familia != "linux":
        return None
    if osv.ecosistema(equipo.so.distro, equipo.so.version) is None:
        return (
            f"Paquetes de la distribución sin cruzar: no hay fuente de avisos para "
            f"{equipo.so.distro or 'esta distribución'} {equipo.so.version or ''}".strip()
        )
    return None


def detalle(conexion: Any, equipo_id: str) -> dict[str, Any] | None:
    equipo = almacen.leer_equipo(conexion, equipo_id)
    if equipo is None:
        return None
    abiertos = _abiertos_del_equipo(bd.leer_hallazgos(conexion), equipo.nombre)
    # El grupo se arma solo con las versiones que tiene este equipo: la versión objetivo y
    # la prioridad son las suyas, no las de toda la flota.
    grupos = agrupar(abiertos)
    es_windows = equipo.so is not None and equipo.so.familia == "windows"
    propios = sorted(
        almacen.leer_hallazgos(conexion, equipo_id),
        key=lambda h: (ORDEN_PRIORIDAD[h.prioridad], h.tipo, h.clave),
    )
    sin_revisar = postura.revisar(equipo).sin_revisar if equipo.ultimo_reporte else []
    if motivo := _sin_cruzar(equipo):
        sin_revisar.append(motivo)
    cobertura = [c for c in bd.leer_cobertura(conexion) if c.equipo == equipo.nombre]
    datos = _fila(equipo, grupos, propios)
    datos["hardware"] = equipo.hardware.model_dump() if equipo.hardware else None
    return {
        "equipo": datos,
        "productos": [_producto(g, abiertos, es_windows) for g in grupos],
        "hallazgos_equipo": [h.model_dump(mode="json") for h in propios],
        "sin_revisar": sin_revisar,
        "cobertura": {
            "sin_evaluar": len(cobertura),
            "por_motivo": dict(Counter(c.motivo for c in cobertura)),
            "detalle": [c.model_dump() for c in cobertura[:MAX_COBERTURA]],
        },
        "paquetes_so": conexion.execute(
            "SELECT count(*) FROM paquetes_so WHERE equipo_id = ?", [equipo_id]
        ).fetchone()[0],
    }
