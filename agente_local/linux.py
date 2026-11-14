"""Recolector de Linux: paquetes de la distribución, sistema, hardware y postura.

Decisiones (docs/plan-agente-local.md, sección 4):
- Los paquetes se reportan con la versión de la distribución, sufijo incluido
  (`3.0.2-0ubuntu1.18`). El radar no los cruza contra el CPE de NVD (las distribuciones
  parchan sin cambiar la versión de origen), sino contra OSV.
- En Debian y Ubuntu también se reporta el paquete fuente (`${source:Package}`): los
  avisos de esas distribuciones en OSV van por paquete fuente, no por binario.
- En RPM la versión se arma como `epoca:version-release`, que es como la publica OSV.
- Cada dato de postura es "si", "no" o "desconocido". Nunca se adivina.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from agente_local.comun import (
    DESCONOCIDO,
    NO,
    SI,
    ejecutar,
    ejecutar_con_codigo,
    json_o_nada,
    texto,
)

FORMATO_DPKG = "${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\t${source:Package}\\t${source:Version}\\n"
FORMATO_RPM = "%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\t%{VENDOR}\\t%{SOURCERPM}\\n"

DMI = Path("/sys/class/dmi/id")
# Tipos de chasis de SMBIOS que son portátiles.
CHASIS_PORTATIL = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}
CHASIS_FIJO = {3, 4, 5, 6, 7, 13, 15, 16, 17, 23, 24, 35}


def _leer(ruta: Path) -> str | None:
    try:
        return texto(ruta.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Paquetes
# ---------------------------------------------------------------------------


def leer_dpkg(salida: str) -> list[dict[str, Any]]:
    """Paquetes instalados de la salida de `dpkg-query -W -f FORMATO_DPKG`."""
    paquetes = []
    for linea in salida.splitlines():
        partes = linea.split("\t")
        if len(partes) < 6:
            continue
        nombre, version, _arq, estado, fuente, version_fuente = (p.strip() for p in partes[:6])
        # "ii " es instalado. "rc " (borrado con configuración) ya no está en el equipo.
        if not nombre or not version or not estado.startswith("ii"):
            continue
        paquetes.append(
            {
                "programa": nombre,
                "version": version,
                "proveedor": None,
                "fuente": "dpkg",
                "ambito": "maquina",
                "origen": fuente or nombre,
                "version_origen": version_fuente or version,
            }
        )
    return paquetes


def leer_rpm(salida: str) -> list[dict[str, Any]]:
    """Paquetes de la salida de `rpm -qa --queryformat FORMATO_RPM`."""
    paquetes = []
    for linea in salida.splitlines():
        partes = linea.split("\t")
        if len(partes) < 7:
            continue
        nombre, epoca, version, release, _arq, proveedor, fuente = (p.strip() for p in partes[:7])
        # gpg-pubkey no es un paquete: es la llave con la que se firman.
        if not nombre or not version or nombre == "gpg-pubkey":
            continue
        completa = f"{version}-{release}" if release else version
        if epoca.isdigit() and epoca != "0":
            completa = f"{epoca}:{completa}"
        paquetes.append(
            {
                "programa": nombre,
                "version": completa,
                "proveedor": None if proveedor in ("", "(none)") else proveedor,
                "fuente": "rpm",
                "ambito": "maquina",
                "origen": origen_de_srpm(fuente) or nombre,
                "version_origen": completa,
            }
        )
    return paquetes


def origen_de_srpm(srpm: str) -> str | None:
    """Nombre del paquete fuente a partir del archivo `nombre-version-release.src.rpm`."""
    if not srpm or srpm == "(none)":
        return None
    base = srpm.removesuffix(".rpm").removesuffix(".src").removesuffix(".nosrc")
    partes = base.rsplit("-", 2)
    return partes[0] if len(partes) == 3 and partes[0] else None


def leer_snap(salida: str) -> list[dict[str, Any]]:
    """Paquetes de `snap list` (columnas: Name Version Rev Tracking Publisher Notes)."""
    paquetes = []
    for linea in salida.splitlines()[1:]:
        partes = linea.split()
        if len(partes) < 2:
            continue
        proveedor = partes[4].rstrip("*✓") if len(partes) > 4 else None
        paquetes.append(
            {
                "programa": partes[0],
                "version": partes[1],
                "proveedor": proveedor or None,
                "fuente": "snap",
                "ambito": "maquina",
            }
        )
    return paquetes


def leer_flatpak(salida: str) -> list[dict[str, Any]]:
    """Paquetes de `flatpak list --app --columns=name,version,application`."""
    paquetes = []
    for linea in salida.splitlines():
        partes = [p.strip() for p in linea.split("\t")]
        if not partes or not partes[0]:
            continue
        paquetes.append(
            {
                "programa": partes[0],
                "version": partes[1] if len(partes) > 1 and partes[1] else None,
                "proveedor": None,
                "fuente": "flatpak",
                "ambito": "maquina",
            }
        )
    return paquetes


def software() -> list[dict[str, Any]]:
    paquetes: list[dict[str, Any]] = []
    if shutil.which("dpkg-query"):
        salida = ejecutar(["dpkg-query", "-W", "-f", FORMATO_DPKG])
        paquetes += leer_dpkg(salida or "")
    elif shutil.which("rpm"):
        salida = ejecutar(["rpm", "-qa", "--queryformat", FORMATO_RPM])
        paquetes += leer_rpm(salida or "")
    if shutil.which("snap"):
        paquetes += leer_snap(ejecutar(["snap", "list"]) or "")
    if shutil.which("flatpak"):
        salida = ejecutar(["flatpak", "list", "--app", "--columns=name,version,application"])
        paquetes += leer_flatpak(salida or "")
    return paquetes


# ---------------------------------------------------------------------------
# Sistema operativo y hardware
# ---------------------------------------------------------------------------


def leer_os_release(contenido: str) -> dict[str, str]:
    datos: dict[str, str] = {}
    for linea in contenido.splitlines():
        clave, separador, valor = linea.partition("=")
        if not separador or clave.startswith("#"):
            continue
        valor = valor.strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "\"'":
            valor = valor[1:-1]
        datos[clave.strip()] = valor
    return datos


def armar_sistema(os_release: dict[str, str], kernel: str | None, maquina: str | None) -> dict:
    arquitectura = {"x86_64": "x64", "aarch64": "arm64", "i686": "x86"}.get(maquina or "", maquina)
    return {
        "familia": "linux",
        "nombre": os_release.get("NAME") or "Linux",
        "version": os_release.get("VERSION_ID") or None,
        "build": None,
        "kernel": kernel,
        "arquitectura": arquitectura,
        "edicion": os_release.get("VERSION_CODENAME") or None,
        "distro": (os_release.get("ID") or "").lower() or None,
        "parches": [],
    }


def sistema() -> dict[str, Any]:
    contenido = _leer(Path("/etc/os-release")) or _leer(Path("/usr/lib/os-release")) or ""
    try:
        uname = os.uname()
        kernel, maquina = uname.release, uname.machine
    except AttributeError:  # no es un sistema POSIX
        kernel, maquina = None, None
    return armar_sistema(leer_os_release(contenido), kernel, maquina)


def _ram_gb() -> float | None:
    contenido = _leer(Path("/proc/meminfo")) or ""
    for linea in contenido.splitlines():
        if linea.startswith("MemTotal:"):
            partes = linea.split()
            if len(partes) >= 2 and partes[1].isdigit():
                return round(int(partes[1]) / 1024**2, 1)
    return None


def _cpu() -> str | None:
    contenido = _leer(Path("/proc/cpuinfo")) or ""
    for linea in contenido.splitlines():
        if linea.lower().startswith(("model name", "hardware")):
            return texto(linea.partition(":")[2])
    return None


def es_portatil(chasis: str | None) -> str:
    if not chasis or not chasis.isdigit():
        return DESCONOCIDO
    tipo = int(chasis)
    if tipo in CHASIS_PORTATIL:
        return SI
    if tipo in CHASIS_FIJO:
        return NO
    return DESCONOCIDO


def hardware() -> dict[str, Any]:
    tpm = _leer(Path("/sys/class/tpm/tpm0/tpm_version_major"))
    return {
        "fabricante": _leer(DMI / "sys_vendor"),
        "modelo": _leer(DMI / "product_name"),
        "bios": _leer(DMI / "bios_version"),
        "cpu": _cpu(),
        "ram_gb": _ram_gb(),
        "tpm": f"{tpm}.0" if tpm and tpm.isdigit() else None,
        "portatil": es_portatil(_leer(DMI / "chassis_type")),
    }


# ---------------------------------------------------------------------------
# Postura
# ---------------------------------------------------------------------------


def firewall_de_salidas(ufw: str | None, firewalld: tuple[int, str] | None) -> str:
    if ufw is not None:
        primera = ufw.strip().splitlines()[0].lower() if ufw.strip() else ""
        if "inactive" in primera or "inactivo" in primera:
            return NO
        if "active" in primera or "activo" in primera:
            return SI
    if firewalld is not None:
        codigo, salida = firewalld
        if codigo == 0 and "running" in salida and "not running" not in salida:
            return SI
        if "not running" in salida:
            return NO
    return DESCONOCIDO


def _firewall() -> str:
    ufw = ejecutar(["ufw", "status"]) if shutil.which("ufw") else None
    firewalld = None
    if shutil.which("firewall-cmd"):
        firewalld = ejecutar_con_codigo(["firewall-cmd", "--state"])
    return firewall_de_salidas(ufw, firewalld)


def control_de_acceso(getenforce: str | None, apparmor: str | None) -> str:
    """SELinux en modo Enforcing o AppArmor cargado. Se reporta dentro de `antivirus`:
    en Linux es el control obligatorio de acceso el que cumple ese papel."""
    if getenforce is not None:
        modo = getenforce.strip().lower()
        if modo == "enforcing":
            return SI
        if modo in ("permissive", "disabled"):
            return NO
    if apparmor is not None:
        valor = apparmor.strip().upper()
        if valor == "Y":
            return SI
        if valor == "N":
            return NO
    return DESCONOCIDO


def _control_de_acceso() -> str:
    getenforce = ejecutar(["getenforce"]) if shutil.which("getenforce") else None
    apparmor = _leer(Path("/sys/module/apparmor/parameters/enabled"))
    return control_de_acceso(getenforce, apparmor)


def actualizaciones_de_configuracion(apt: str | None, dnf: str | None) -> str:
    """Actualizaciones automáticas según `20auto-upgrades` (apt) o `automatic.conf` (dnf)."""
    if apt is not None:
        for linea in apt.splitlines():
            if "Unattended-Upgrade" in linea and not linea.strip().startswith("//"):
                return SI if '"1"' in linea else NO
        return NO
    if dnf is not None:
        for linea in dnf.splitlines():
            clave, _, valor = linea.partition("=")
            if clave.strip() == "apply_updates":
                return SI if valor.strip().lower() in ("yes", "true", "1") else NO
        return NO
    return DESCONOCIDO


def _actualizaciones() -> str:
    apt = _leer(Path("/etc/apt/apt.conf.d/20auto-upgrades"))
    dnf = _leer(Path("/etc/dnf/automatic.conf"))
    if apt is None and dnf is None:
        # Sin archivo de configuración: si existe apt o dnf, no están activadas.
        if shutil.which("apt-get") or shutil.which("dnf"):
            return NO
        return DESCONOCIDO
    return actualizaciones_de_configuracion(apt, dnf)


def cifrado_de_lsblk(salida: str | None) -> str:
    """ "si" si el sistema de archivos raíz está sobre un dispositivo de tipo crypt."""
    datos = json_o_nada(salida)
    if not isinstance(datos, dict):
        return DESCONOCIDO
    encontrado: list[bool] = []

    def recorrer(nodos: list, cifrado: bool) -> None:
        for nodo in nodos:
            if not isinstance(nodo, dict):
                continue
            actual = cifrado or nodo.get("type") == "crypt"
            puntos = nodo.get("mountpoints") or [nodo.get("mountpoint")]
            if "/" in puntos:
                encontrado.append(actual)
            recorrer(nodo.get("children") or [], actual)

    recorrer(datos.get("blockdevices") or [], False)
    if not encontrado:
        return DESCONOCIDO
    return SI if all(encontrado) else NO


def _cifrado() -> str:
    if not shutil.which("lsblk"):
        return DESCONOCIDO
    return cifrado_de_lsblk(ejecutar(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS"]))


def arranque_seguro_de_mokutil(salida: str | None) -> str:
    if not salida:
        return DESCONOCIDO
    bajo = salida.lower()
    if "secureboot enabled" in bajo:
        return SI
    if "secureboot disabled" in bajo:
        return NO
    return DESCONOCIDO


def _arranque_seguro() -> str:
    if not shutil.which("mokutil"):
        return DESCONOCIDO
    resultado = ejecutar_con_codigo(["mokutil", "--sb-state"])
    return arranque_seguro_de_mokutil(resultado[1] if resultado else None)


def postura() -> dict[str, str]:
    return {
        "firewall": _firewall(),
        "antivirus": _control_de_acceso(),
        # En Linux no hay firmas de antivirus que revisar: no aplica, no se adivina.
        "firmas_al_dia": DESCONOCIDO,
        "cifrado_disco": _cifrado(),
        "secure_boot": _arranque_seguro(),
        "actualizaciones_automaticas": _actualizaciones(),
    }


def recoger(solo_software: bool = False) -> dict[str, Any]:
    vacio = {
        "firewall": DESCONOCIDO,
        "antivirus": DESCONOCIDO,
        "firmas_al_dia": DESCONOCIDO,
        "cifrado_disco": DESCONOCIDO,
        "secure_boot": DESCONOCIDO,
        "actualizaciones_automaticas": DESCONOCIDO,
    }
    return {
        "so": sistema(),
        "hardware": hardware() if not solo_software else {"portatil": DESCONOCIDO},
        "postura": vacio if solo_software else postura(),
        "software": software(),
    }
