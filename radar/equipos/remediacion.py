"""Comandos de remediación armados por código (docs/plan-agente-local.md, sección 9).

El modelo explica y redacta; nunca inventa un comando. Todo comando sale de una plantilla
cerrada de este archivo, y cada pieza variable (nombre de paquete, identificador de
winget, versión, aviso) se valida contra un patrón estricto antes de entrar: si no lo
cumple, no hay comando. Así el nombre de un programa o de un paquete, que es texto no
confiable, no puede colar `curl ... | sh` en las instrucciones.

El verificador (`radar/equipos/comandos.py`) compara luego lo que diga el texto contra el
conjunto de comandos que salió de aquí.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from radar.contratos import Grupo, Hallazgo
from radar.fuentes.nvd import normalizar_par

Plataforma = Literal["windows", "debian", "rhel"]

# Piezas variables de un comando. Nada de espacios, comillas ni signos de shell.
_PAQUETE_DEB = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,99}$")
_PAQUETE_RPM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._\-]{0,99}$")
_ID_WINGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+\-]*(?:\.[A-Za-z0-9+\-]+){1,5}$")
_VERSION = re.compile(r"^[0-9][0-9A-Za-z.\-]{0,39}$")
_AVISO_RPM = re.compile(r"^[A-Z]{2,6}-\d{4}:\d{3,6}$")

MAX_PAQUETES_POR_COMANDO = 12

# Identificador de winget por par de CPE. Tabla curada a mano: un producto que no está
# aquí no recibe comando (se actualiza desde el sitio del fabricante). Por verificar cada
# identificador con `winget show --id <Id>` antes de usarlo en producción.
WINGET: dict[str, str] = {
    "rarlab:winrar": "RARLab.WinRAR",
    "7-zip:7-zip": "7zip.7zip",
    "google:chrome": "Google.Chrome",
    "mozilla:firefox": "Mozilla.Firefox",
    "videolan:vlc_media_player": "VideoLAN.VLC",
    "notepad-plus-plus:notepad++": "Notepad++.Notepad++",
    "git-scm:git": "Git.Git",
    "docker:docker_desktop": "Docker.DockerDesktop",
    "docker:desktop": "Docker.DockerDesktop",
    "putty:putty": "PuTTY.PuTTY",
    "zoom:zoom": "Zoom.Zoom",
    "microsoft:visual_studio_code": "Microsoft.VisualStudioCode",
    "wireshark:wireshark": "WiresharkFoundation.Wireshark",
    "keepass:keepass": "DominikReichl.KeePass",
    "teamviewer:teamviewer": "TeamViewer.TeamViewer",
    "oracle:vm_virtualbox": "Oracle.VirtualBox",
    "libreoffice:libreoffice": "TheDocumentFoundation.LibreOffice",
    "winscp:winscp": "WinSCP.WinSCP",
    "nodejs:node.js": "OpenJS.NodeJS",
}


@dataclass(frozen=True)
class Comando:
    plataforma: Plataforma
    texto: str


def distro_a_plataforma(distro: str | None) -> Plataforma | None:
    """Gestor de paquetes según el `ID` de os-release."""
    distro = (distro or "").lower()
    if distro in ("ubuntu", "debian"):
        return "debian"
    if distro in ("rhel", "rocky", "almalinux", "centos", "fedora"):
        return "rhel"
    return None


# ---------------------------------------------------------------------------
# Aplicaciones de Windows
# ---------------------------------------------------------------------------


def id_winget(pares: Iterable[str]) -> str | None:
    for par in pares:
        identificador = WINGET.get(normalizar_par(par))
        if identificador and _ID_WINGET.match(identificador):
            return identificador
    return None


def comando_winget(pares: Iterable[str], version: str | None = None) -> Comando | None:
    """`winget upgrade` del producto. Con `version` (solo si la fuente da una versión de
    arreglo exacta) la fija; sin ella, actualiza a la más reciente del catálogo."""
    identificador = id_winget(pares)
    if identificador is None:
        return None
    texto = f"winget upgrade --id {identificador} --exact"
    if version and _VERSION.match(version):
        texto += f" --version {version}"
    return Comando("windows", texto)


def pares_de_hallazgos(hallazgos: Iterable[Hallazgo]) -> list[str]:
    return sorted({h.rango.par for h in hallazgos if h.rango is not None})


def comandos_de_grupo(grupo: Grupo, hallazgos: Iterable[Hallazgo]) -> list[Comando]:
    """Comandos permitidos para remediar un producto. Regla 5: solo se fija la versión si
    el objetivo es exacto; con "posterior a" o sin objetivo no se promete ninguna."""
    version = grupo.version_objetivo if grupo.tipo_objetivo == "exacta" else None
    comando = comando_winget(pares_de_hallazgos(hallazgos), version)
    return [comando] if comando else []


# ---------------------------------------------------------------------------
# Paquetes de distribuciones Linux
# ---------------------------------------------------------------------------


def comando_paquetes(
    plataforma: Plataforma, paquetes: Iterable[str], aviso: str | None = None
) -> Comando | None:
    """Actualiza paquetes instalados con el gestor de la distribución.

    Los nombres que no cumplen el patrón se descartan; si no queda ninguno, no hay comando.
    En RHEL y derivados, con `aviso` se usa `dnf upgrade --advisory`.
    """
    if plataforma == "debian":
        validos = sorted({p for p in paquetes if _PAQUETE_DEB.match(p)})
        if not validos:
            return None
        nombres = " ".join(validos[:MAX_PAQUETES_POR_COMANDO])
        return Comando(
            "debian", f"sudo apt-get update && sudo apt-get install --only-upgrade {nombres}"
        )
    if plataforma == "rhel":
        if aviso and _AVISO_RPM.match(aviso):
            return Comando("rhel", f"sudo dnf upgrade --advisory {aviso}")
        validos = sorted({p for p in paquetes if _PAQUETE_RPM.match(p)})
        if not validos:
            return None
        return Comando("rhel", "sudo dnf upgrade " + " ".join(validos[:MAX_PAQUETES_POR_COMANDO]))
    return None


# ---------------------------------------------------------------------------
# Postura: pasos en texto y, donde hay un comando fijo, el comando
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Arreglo:
    pasos: str
    comandos: tuple[str, ...] = ()


_POSTURA_WINDOWS: dict[str, Arreglo] = {
    "firewall": Arreglo(
        "Activar el firewall en los tres perfiles: Configuración, Privacidad y seguridad, "
        "Seguridad de Windows, Firewall y protección de red.",
        ("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",),
    ),
    "antivirus": Arreglo(
        "Activar la protección en tiempo real: Seguridad de Windows, Protección contra virus "
        "y amenazas, Administrar la configuración. Si hay otro antivirus, revisar su consola.",
        ("Set-MpPreference -DisableRealtimeMonitoring $false",),
    ),
    "firmas_al_dia": Arreglo(
        "Actualizar las firmas del antivirus: Seguridad de Windows, Protección contra virus "
        "y amenazas, Actualizaciones de protección.",
        ("Update-MpSignature",),
    ),
    "cifrado_disco": Arreglo(
        "Cifrar el disco del sistema con BitLocker (o Cifrado de dispositivo en las ediciones "
        "Home): Configuración, Privacidad y seguridad, Cifrado de dispositivo. Guardar la "
        "clave de recuperación antes de empezar.",
    ),
    "actualizaciones_automaticas": Arreglo(
        "Quitar la directiva que apaga Windows Update: Directiva de grupo, Configuración del "
        "equipo, Plantillas administrativas, Componentes de Windows, Windows Update, "
        "Configurar actualizaciones automáticas.",
    ),
    "secure_boot": Arreglo(
        "Activar Secure Boot en la configuración UEFI del equipo (se entra al encender). "
        "Requiere disco en GPT y arranque UEFI.",
    ),
}

_POSTURA_DEBIAN: dict[str, Arreglo] = {
    "firewall": Arreglo("Activar el firewall del sistema.", ("sudo ufw enable",)),
    "antivirus": Arreglo(
        "Activar AppArmor, el control de acceso de la distribución.",
        ("sudo systemctl enable --now apparmor",),
    ),
    "cifrado_disco": Arreglo(
        "El disco del sistema no está cifrado. Cifrarlo con LUKS exige reinstalar o migrar "
        "los datos: planearlo con respaldo.",
    ),
    "actualizaciones_automaticas": Arreglo(
        "Activar las actualizaciones de seguridad automáticas.",
        (
            "sudo apt-get install unattended-upgrades",
            "sudo dpkg-reconfigure -plow unattended-upgrades",
        ),
    ),
    "secure_boot": Arreglo("Activar Secure Boot en la configuración UEFI del equipo."),
}

_POSTURA_RHEL: dict[str, Arreglo] = {
    "firewall": Arreglo(
        "Activar el firewall del sistema.", ("sudo systemctl enable --now firewalld",)
    ),
    "antivirus": Arreglo(
        "Poner SELinux en modo Enforcing: en /etc/selinux/config dejar SELINUX=enforcing y "
        "reiniciar.",
        ("sudo setenforce 1",),
    ),
    "cifrado_disco": _POSTURA_DEBIAN["cifrado_disco"],
    "actualizaciones_automaticas": Arreglo(
        "Activar las actualizaciones automáticas con dnf-automatic (apply_updates = yes en "
        "/etc/dnf/automatic.conf).",
        ("sudo dnf install dnf-automatic", "sudo systemctl enable --now dnf-automatic.timer"),
    ),
    "secure_boot": _POSTURA_DEBIAN["secure_boot"],
}

_POSTURA = {"windows": _POSTURA_WINDOWS, "debian": _POSTURA_DEBIAN, "rhel": _POSTURA_RHEL}
_SIN_PLATAFORMA = Arreglo("Revisar la configuración del equipo con el responsable de TI.")


def arreglo_de_postura(regla: str, plataforma: Plataforma | None) -> Arreglo:
    return _POSTURA.get(plataforma or "", {}).get(regla, _SIN_PLATAFORMA)


def arreglo_de_soporte(sistema: str, familia: str) -> Arreglo:
    if familia == "windows":
        return Arreglo(
            f"{sistema} ya no recibe parches de seguridad. Actualizar a una versión con "
            "soporte (Configuración, Windows Update) o reemplazar el equipo si no la admite. "
            "Si la organización contrató actualizaciones extendidas (ESU), confirmar que este "
            "equipo las recibe."
        )
    return Arreglo(
        f"{sistema} ya no recibe parches de seguridad de la distribución. Migrar a una "
        "versión con soporte."
    )


def comandos_fijos() -> set[str]:
    """Todos los comandos de postura de este archivo (para el verificador)."""
    return {
        c for tabla in _POSTURA.values() for arreglo in tabla.values() for c in arreglo.comandos
    }
