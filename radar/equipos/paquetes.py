"""Cruce de los paquetes de una distribución Linux contra OSV
(docs/plan-agente-local.md, sección 7).

No se usa el CPE de NVD para paquetes de distribución: las distribuciones parchan sin
cambiar la versión de origen y el cruce por CPE daría falsos positivos en masa. OSV
compara contra la versión del paquete de la distribución.

- `armar_hallazgos()` es pura: recibe los paquetes, lo que respondió OSV y las señales, y
  devuelve un hallazgo por paquete (una acción por paquete, como una acción por producto).
- `revisar_equipo()` hace la red (OSV y, si falta, EPSS), usa la caché de avisos y guarda.

KEV y EPSS se aplican igual que en el resto del radar: por ID de CVE (regla 4). Un EPSS
que falta no es cero (regla 2).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from radar import bd
from radar.config import Umbrales
from radar.contratos import Prioridad, Senales
from radar.equipos import almacen, remediacion
from radar.equipos.almacen import Equipo
from radar.equipos.contratos import HallazgoEquipo, id_hallazgo
from radar.fuentes import epss as fuente_epss
from radar.fuentes import osv
from radar.nucleo import versiones_paquete
from radar.nucleo.cvss import puntaje_base
from radar.nucleo.prioridad import (
    RAZON_KEV,
    RAZON_RANSOMWARE,
    RAZON_SIN_CVSS,
    razon_cvss,
    razon_epss,
)

TIPO = "paquete"
RAZON_SIN_EPSS = "Sin dato de EPSS para sus CVE"
MAX_CVES_EN_DETALLE = 40


@dataclass
class Paquete:
    """Un paquete a consultar en OSV, con los binarios instalados que salen de él."""

    nombre: str  # el nombre por el que publica OSV: fuente en Debian y Ubuntu, binario en RPM
    version: str
    binarios: list[str] = field(default_factory=list)


def agrupar_paquetes(filas: Iterable[dict[str, Any]], ecosistema: str) -> list[Paquete]:
    """Agrupa los paquetes instalados por el nombre con el que OSV publica los avisos."""
    por_fuente = osv.usa_paquete_fuente(ecosistema)
    grupos: dict[tuple[str, str], Paquete] = {}
    for f in filas:
        if por_fuente:
            nombre = f.get("origen") or f["nombre"]
            version = f.get("version_origen") or f["version"]
        else:
            nombre, version = f["nombre"], f["version"]
        paquete = grupos.setdefault((nombre, version), Paquete(nombre, version))
        if f["nombre"] not in paquete.binarios:
            paquete.binarios.append(f["nombre"])
    return sorted(grupos.values(), key=lambda p: (p.nombre, p.version))


def _prioridad(
    en_kev: bool, epss: float | None, cvss: float | None, umbrales: Umbrales
) -> Prioridad:
    if en_kev or (epss is not None and epss >= umbrales.epss):
        return "inmediato"
    if cvss is not None and cvss >= umbrales.cvss_inmediato:
        return "inmediato"
    if cvss is not None and cvss >= umbrales.cvss_semanal:
        return "semanal"
    return "informativo"


def armar_hallazgos(
    equipo: Equipo,
    ecosistema: str,
    paquetes: Iterable[Paquete],
    avisos_por_paquete: dict[tuple[str, str], Iterable[str]],
    avisos: dict[str, dict[str, Any]],
    senales: Senales,
    cvss_de_nvd: dict[str, float] | None = None,
    umbrales: Umbrales | None = None,
    ahora: datetime | None = None,
) -> list[HallazgoEquipo]:
    """Un hallazgo por paquete afectado.

    `avisos_por_paquete`: ids de aviso por (nombre, versión). `avisos`: detalle reducido de
    cada aviso (`osv.reducir`). Un aviso cuyo detalle no se pudo bajar cuenta, pero sin
    sus CVE ni su arreglo: nunca se inventan.
    """
    umbrales = umbrales or Umbrales.desde_entorno()
    ahora = ahora or datetime.now(UTC)
    cvss_de_nvd = cvss_de_nvd or {}
    sistema: versiones_paquete.Sistema = "dpkg" if osv.usa_paquete_fuente(ecosistema) else "rpm"
    plataforma = "debian" if sistema == "dpkg" else "rhel"
    hallazgos: list[HallazgoEquipo] = []

    for paquete in paquetes:
        ids = sorted(set(avisos_por_paquete.get((paquete.nombre, paquete.version), ())))
        if not ids:
            continue
        cves: set[str] = set()
        arreglos: list[str] = []
        puntajes: list[float] = []
        sin_arreglo = sin_detalle = 0
        for id_aviso in ids:
            aviso = avisos.get(id_aviso)
            if aviso is None:
                sin_detalle += 1
                continue
            cves.update(aviso.get("cves") or [])
            propios = osv.arreglos_de(aviso, ecosistema, paquete.nombre)
            if propios:
                arreglos += propios
            else:
                sin_arreglo += 1
            vector = puntaje_base(aviso.get("vector"))
            if vector is not None:
                puntajes.append(vector)
        puntajes += [cvss_de_nvd[c] for c in cves if c in cvss_de_nvd]

        en_kev = sorted(c for c in cves if c in senales.kev)
        ransomware = any(senales.kev[c].ransomware for c in en_kev)
        valores_epss = [senales.epss[c].epss for c in cves if c in senales.epss]
        peor_epss = max(valores_epss) if valores_epss else None
        peor_cvss = max(puntajes) if puntajes else None
        arreglo = versiones_paquete.mayor(arreglos, sistema)

        razones: list[str] = []
        if en_kev:
            razones.append(RAZON_KEV)
            if ransomware:
                razones.append(RAZON_RANSOMWARE)
        if peor_epss is None:
            razones.append(RAZON_SIN_EPSS)
        elif peor_epss >= umbrales.epss:
            razones.append(razon_epss(peor_epss))
        razones.append(razon_cvss(peor_cvss) if peor_cvss is not None else RAZON_SIN_CVSS)
        if sin_arreglo:
            razones.append(
                f"{sin_arreglo} de {len(ids)} avisos todavía no tienen arreglo publicado por "
                "la distribución"
            )
        if sin_detalle:
            razones.append(f"{sin_detalle} avisos sin detalle: OSV no respondió por ellos")

        comando = None
        if arreglo:
            unico = ids[0] if len(ids) == 1 else None
            comando = remediacion.comando_paquetes(plataforma, paquete.binarios, unico)
            pasos = (
                f"Actualizar {paquete.nombre} a la versión {arreglo} o posterior con el "
                "gestor de paquetes de la distribución."
            )
        else:
            pasos = (
                f"La distribución todavía no publica una versión de arreglo para "
                f"{paquete.nombre}. Revisar el aviso y aplicar la mitigación que indique."
            )
        orden = sorted(cves, key=lambda c: (c not in senales.kev, c))
        hallazgos.append(
            HallazgoEquipo(
                id=id_hallazgo(equipo.id, TIPO, paquete.nombre),
                equipo_id=equipo.id,
                tipo=TIPO,
                clave=paquete.nombre,
                titulo=f"{paquete.nombre} {paquete.version}",
                prioridad=_prioridad(bool(en_kev), peor_epss, peor_cvss, umbrales),
                por_que=razones,
                pasos=pasos,
                comandos=[comando.texto] if comando else [],
                detalle={
                    "ecosistema": ecosistema,
                    "version_instalada": paquete.version,
                    "version_arreglo": arreglo,
                    "binarios": paquete.binarios[:MAX_CVES_EN_DETALLE],
                    "avisos": len(ids),
                    "n_cves": len(cves),
                    "cves": orden[:MAX_CVES_EN_DETALLE],
                    "en_kev": en_kev,
                    "ransomware": ransomware,
                    "peor_cvss": peor_cvss,
                    "peor_epss": peor_epss,
                },
                detectado=ahora,
            )
        )
    return hallazgos


@dataclass
class ResultadoPaquetes:
    cruzado: bool
    motivo: str | None = None
    paquetes: int = 0
    hallazgos: int = 0
    avisos: int = 0
    avisos_sin_detalle: int = 0
    epss_ok: bool = True

    @property
    def resumen(self) -> str:
        if not self.cruzado:
            return f"sin cruzar: {self.motivo}"
        texto = (
            f"{self.paquetes} paquetes, {self.avisos} avisos de OSV, {self.hallazgos} paquetes "
            "afectados"
        )
        if self.avisos_sin_detalle:
            texto += f", {self.avisos_sin_detalle} avisos sin detalle"
        if not self.epss_ok:
            texto += "; EPSS no respondió (sin dato, no cero)"
        return texto


def _cvss_guardado(conexion: Any, cves: list[str]) -> dict[str, float]:
    salida: dict[str, float] = {}
    for i in range(0, len(cves), bd.LOTE):
        lote = cves[i : i + bd.LOTE]
        for cve, cvss in conexion.execute(
            f"SELECT id, cvss FROM cves WHERE id IN ({bd._marcadores(len(lote))})", lote
        ).fetchall():
            if cvss is not None:
                salida[cve] = cvss
    return salida


def revisar_equipo(
    conexion: Any,
    equipo: Equipo,
    cliente: httpx.Client | None = None,
    umbrales: Umbrales | None = None,
    ahora: datetime | None = None,
    con_epss: bool = True,
) -> ResultadoPaquetes:
    """Cruza los paquetes del equipo contra OSV y reemplaza sus hallazgos de paquete.

    Si OSV no responde lanza `httpx.HTTPError` y no toca lo guardado: fuente caída no es
    "sin hallazgos".
    """
    if equipo.so is None or equipo.so.familia != "linux":
        return ResultadoPaquetes(False, "el equipo no es Linux")
    ecosistema = osv.ecosistema(equipo.so.distro, equipo.so.version)
    if ecosistema is None:
        return ResultadoPaquetes(
            False, f"sin fuente de avisos para {equipo.so.distro} {equipo.so.version}"
        )
    paquetes = agrupar_paquetes(almacen.leer_paquetes(conexion, equipo.id), ecosistema)
    consultas = {osv.Consulta(p.nombre, p.version, ecosistema): p for p in paquetes}
    respuestas = osv.consultar_lote(consultas, cliente)

    avisos_por_paquete: dict[tuple[str, str], list[str]] = defaultdict(list)
    modificados: dict[str, str] = {}
    for consulta, ids in respuestas.items():
        avisos_por_paquete[(consulta.paquete, consulta.version)] += list(ids)
        modificados.update(ids)

    avisos = almacen.leer_avisos(conexion, modificados)
    faltan = [i for i, m in modificados.items() if avisos.get(i, {}).get("modified") != m]
    nuevos = []
    sin_detalle = 0
    for id_aviso in sorted(faltan):
        try:
            nuevos.append(osv.descargar_aviso(id_aviso, cliente))
        except (httpx.HTTPError, ValueError):
            # Si hay una copia anterior del aviso se sigue usando; si no, cuenta sin detalle.
            sin_detalle += id_aviso not in avisos
    almacen.guardar_avisos(conexion, nuevos)
    avisos.update({a["id"]: a for a in nuevos})

    cves = sorted({c for a in avisos.values() for c in a.get("cves") or []})
    senales = bd.leer_senales(conexion, cves)
    epss_ok = True
    sin_epss = [c for c in cves if c not in senales.epss]
    if con_epss and sin_epss:
        try:
            nuevas = fuente_epss.consultar_api(sin_epss)
            bd.guardar_epss(conexion, nuevas)
            senales.epss.update(nuevas)
        except (httpx.HTTPError, OSError, ValueError, KeyError):
            epss_ok = False

    hallazgos = armar_hallazgos(
        equipo,
        ecosistema,
        paquetes,
        avisos_por_paquete,
        avisos,
        senales,
        _cvss_guardado(conexion, cves),
        umbrales,
        ahora,
    )
    almacen.reemplazar_hallazgos(conexion, equipo.id, [TIPO], hallazgos)
    return ResultadoPaquetes(
        cruzado=True,
        paquetes=len(paquetes),
        hallazgos=len(hallazgos),
        avisos=len(modificados),
        avisos_sin_detalle=sin_detalle,
        epss_ok=epss_ok,
    )
