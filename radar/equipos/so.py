"""Sistema operativo de los equipos: Windows como activo del cruce y fin de soporte.

Windows (docs/plan-agente-local.md, sección 7). Comprobado contra NVD el 14 de noviembre
de 2026: las CVE de Windows traen un CPE por versión (`microsoft:windows_11_23h2`,
`microsoft:windows_10_22h2`, `microsoft:windows_server_2022`) y un rango por build
(`versionEndExcluding 10.0.22631.4751`). Con el build completo que reporta el agente
(`CurrentBuild` más `UBR`), el sistema entra al cruce del núcleo como un activo más: la
misma regla de afectación, la misma prioridad y la misma agrupación por producto.

Linux no se cruza aquí: sus paquetes van contra OSV (`radar/equipos/paquetes.py`).

Fin de soporte: con la copia de endoflife.date (`radar/fuentes/finsoporte.py`). Si el
ciclo no se reconoce, no hay hallazgo: va a cobertura (sin comparación no hay hallazgo).
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from typing import Any

from radar.contratos import Activo
from radar.equipos.almacen import Equipo
from radar.equipos.contratos import SistemaReportado
from radar.fuentes import finsoporte

_BUILD = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")
BUILD_WINDOWS_11 = 22000

# Build base de cada Windows Server con su producto en el CPE de NVD.
_SERVIDORES = {
    14393: ("Windows Server 2016", "windows_server_2016", "2016"),
    17763: ("Windows Server 2019", "windows_server_2019", "2019"),
    20348: ("Windows Server 2022", "windows_server_2022", "2022"),
    25398: ("Windows Server 2022 23H2", "windows_server_2022_23h2", "23h2-ac"),
    26100: ("Windows Server 2025", "windows_server_2025", "2025"),
}

# Distribución (ID de os-release) -> producto en endoflife.date.
_DISTRIBUCIONES = {
    "ubuntu": "ubuntu",
    "debian": "debian",
    "rhel": "rhel",
    "rocky": "rocky-linux",
    "almalinux": "almalinux",
    "centos": "centos",
}


@dataclass(frozen=True)
class Windows:
    """Un Windows reconocido: nombre para las personas, par de CPE y ciclo de soporte."""

    producto: str  # "Windows 11 23H2"
    par: str  # "microsoft:windows_11_23h2"
    build: str  # "10.0.22631.4317"
    servidor: bool
    ciclo: str | None  # ciclo en endoflife.date, o None si no se reconoce


def _clase_de_edicion(edicion: str | None) -> str:
    """ "w" (Home y Pro), "e" (Enterprise y Education), "e-lts" o "iot-lts" (LTSC)."""
    bajo = (edicion or "").lower()
    if "iot" in bajo and bajo.endswith("s"):
        return "iot-lts"
    if bajo.startswith("enterprises") or bajo == "enterprisesn":
        return "e-lts"
    if "enterprise" in bajo or "education" in bajo:
        return "e"
    return "w"


def _ciclo_cliente(base: str, edicion: str | None, catalogo: dict[str, Any] | None) -> str | None:
    candidatos = [
        c["ciclo"] for c in finsoporte.ciclos("windows", catalogo) if c.get("build") == base
    ]
    if not candidatos:
        return None
    clase = _clase_de_edicion(edicion)
    for sufijo in (f"-{clase}", ""):
        for ciclo in candidatos:
            if sufijo and ciclo.endswith(sufijo):
                return ciclo
            if not sufijo and not re.search(r"-(w|e|e-lts|iot|iot-lts)$", ciclo):
                return ciclo
    return None


def reconocer_windows(
    so: SistemaReportado, catalogo: dict[str, Any] | None = None
) -> Windows | None:
    """Reconoce un Windows por su build. None si el build falta o no es comparable."""
    if so.familia != "windows" or not so.build:
        return None
    m = _BUILD.match(so.build.strip())
    if not m:
        return None
    numero = int(m.group(3))
    base = f"{m.group(1)}.{m.group(2)}.{numero}"
    if "server" in (so.nombre or "").lower():
        servidor = _SERVIDORES.get(numero)
        if servidor is None:
            return None
        nombre, producto, ciclo = servidor
        return Windows(nombre, f"microsoft:{producto}", so.build.strip(), True, ciclo)
    version = (so.version or "").strip().lower()
    if not re.fullmatch(r"[0-9]{2}h[12]|[0-9]{4}", version):
        return None
    familia = "11" if numero >= BUILD_WINDOWS_11 else "10"
    return Windows(
        producto=f"Windows {familia} {version.upper()}",
        par=f"microsoft:windows_{familia}_{version}",
        build=so.build.strip(),
        servidor=False,
        ciclo=_ciclo_cliente(base, so.edicion, catalogo),
    )


def activos_de_so(equipos: Iterable[Equipo]) -> list[Activo]:
    """Un activo por cada Windows y build distintos, con los equipos que lo tienen."""
    grupos: dict[tuple[str, str, str], list[str]] = defaultdict(list)
    for equipo in equipos:
        if equipo.revocado or equipo.so is None:
            continue
        windows = reconocer_windows(equipo.so)
        if windows is not None:
            grupos[(windows.producto, windows.par, windows.build)].append(equipo.nombre)
    return [
        Activo(
            clave=f"{producto}@{build}",
            producto=producto,
            nombre=producto,
            version=build,
            cpes=[par],
            equipos=sorted(nombres),
            confianza_cpe=1.0,
        )
        for (producto, par, build), nombres in sorted(grupos.items())
    ]


def pares_de_so(equipos: Iterable[Equipo]) -> list[str]:
    """Pares de CPE de los Windows de la flota, para que el worker baje sus CVE de NVD."""
    return sorted({a.cpes[0] for a in activos_de_so(equipos)})


# ---------------------------------------------------------------------------
# Fin de soporte
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Soporte:
    """Qué se sabe del soporte de un sistema. `fin` en None: no se sabe o no tiene fecha."""

    sistema: str  # nombre para las personas: "Windows 10 22H2", "Ubuntu 20.04"
    conocido: bool  # False: el ciclo no se reconoció, va a cobertura
    fin: date | None = None

    def vencido(self, hoy: date) -> bool:
        return self.conocido and self.fin is not None and self.fin < hoy


def _fin(producto: str, ciclo: str, catalogo: dict[str, Any] | None) -> tuple[bool, date | None]:
    for c in finsoporte.ciclos(producto, catalogo):
        if c["ciclo"] == ciclo:
            return True, finsoporte.fecha(c)
    return False, None


def soporte(so: SistemaReportado, catalogo: dict[str, Any] | None = None) -> Soporte:
    if so.familia == "windows":
        windows = reconocer_windows(so, catalogo)
        if windows is None or windows.ciclo is None:
            return Soporte(so.nombre or "Windows", conocido=False)
        producto = "windows-server" if windows.servidor else "windows"
        conocido, fin = _fin(producto, windows.ciclo, catalogo)
        return Soporte(windows.producto, conocido, fin)

    nombre = " ".join(p for p in (so.nombre, so.version) if p) or "Linux"
    producto = _DISTRIBUCIONES.get((so.distro or "").lower())
    if producto is None or not so.version:
        return Soporte(nombre, conocido=False)
    partes = so.version.split(".")
    if not partes[0].isdigit():
        return Soporte(nombre, conocido=False)
    ciclo = ".".join(partes[:2]) if producto == "ubuntu" and len(partes) >= 2 else partes[0]
    conocido, fin = _fin(producto, ciclo, catalogo)
    return Soporte(nombre, conocido, fin)
