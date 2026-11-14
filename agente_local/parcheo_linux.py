"""Ejecutores del catálogo para Linux (docs/plan-parcheo.md, sección 4). Solo librería estándar.

- `apt` (Debian, Ubuntu): `apt-get install --only-upgrade` de los paquetes del plan. Antes
  simula: si la simulación quitaría algún paquete, no se hace. Revierte con
  `apt-get install paquete=versión_previa` si la versión previa sigue disponible.
- `dnf` (RHEL y derivados): `dnf upgrade` o `dnf upgrade --advisory`. Revierte con
  `dnf history undo` de la transacción que creó.
- `postura_debian`, `postura_rhel`: firewall (sin cortar el SSH), AppArmor y actualizaciones
  automáticas. Revierten al estado medido antes.

Corre como root (servicio de systemd): no usa `sudo`. Los argumentos salen del plan ya
validado por el catálogo (nombres de paquete sin espacios ni signos de shell) y se pasan sin
shell.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from agente_local.parcheo import (
    OMITIDO,
    YA_AL_DIA,
    Corredor,
    Previo,
    Respaldo,
    Verificacion,
)

TIEMPO_APT = 3600
ENTORNO_APT = {
    "DEBIAN_FRONTEND": "noninteractive",
    "NEEDRESTART_MODE": "a",  # needrestart no pregunta ni reinicia servicios por su cuenta
    "APT_LISTCHANGES_FRONTEND": "none",
}
OPCIONES_APT = [
    "-y",
    "-q",
    "-o",
    "DPkg::Lock::Timeout=600",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
]
REINICIO_DEBIAN = Path("/var/run/reboot-required")
AUTO_UPGRADES = Path("/etc/apt/apt.conf.d/20auto-upgrades")
CONTENIDO_AUTO_UPGRADES = (
    'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'
)
DNF_AUTOMATIC = Path("/etc/dnf/automatic.conf")

_INST = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+)")
_REMV = re.compile(r"^Remv (\S+)")


# ---------------------------------------------------------------------------
# Comparación de versiones
# ---------------------------------------------------------------------------


def dpkg_cumple(corredor: Corredor, version: str | None, minimo: str | None) -> bool | None:
    """`dpkg --compare-versions version ge minimo`. None si no se pudo comparar."""
    if not version or not minimo:
        return None
    paso = corredor.correr(["dpkg", "--compare-versions", version, "ge", minimo], 30, anotar=False)
    if paso["codigo"] is None:
        return None
    return paso["codigo"] == 0


def _rpm_segmentos(texto: str) -> list[str]:
    return re.findall(r"~|\^|\d+|[A-Za-z]+", texto)


def rpmvercmp(a: str, b: str) -> int:
    """Comparación de versión o de release como la de rpm (-1, 0, 1)."""
    if a == b:
        return 0
    sa, sb = _rpm_segmentos(a), _rpm_segmentos(b)
    while sa or sb:
        x = sa.pop(0) if sa else None
        y = sb.pop(0) if sb else None
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":
            if x is None:
                return -1
            if y is None:
                return 1
            if x != y:
                return 1 if x == "^" else -1
            continue
        if x is None:
            return -1
        if y is None:
            return 1
        if x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        if x.isdigit():
            if int(x) != int(y):
                return 1 if int(x) > int(y) else -1
        elif x != y:
            return 1 if x > y else -1
    return 0


def rpm_evr_cmp(a: str, b: str) -> int:
    """Compara 'epoca:version-release'. Época vacía o '(none)' cuenta como 0."""

    def partir(evr: str) -> tuple[int, str, str]:
        epoca, _, resto = evr.rpartition(":") if ":" in evr else ("0", "", evr)
        version, _, release = resto.partition("-")
        try:
            numero = int(epoca) if epoca not in ("", "(none)") else 0
        except ValueError:
            numero = 0
        return numero, version, release

    ea, va, ra = partir(a)
    eb, vb, rb = partir(b)
    if ea != eb:
        return 1 if ea > eb else -1
    return rpmvercmp(va, vb) or (rpmvercmp(ra, rb) if ra and rb else 0)


# ---------------------------------------------------------------------------
# apt
# ---------------------------------------------------------------------------


def leer_dpkg_query(salida: str) -> dict[str, str]:
    """Versiones instaladas ('ii') de `dpkg-query -W -f '${Package}\\t${Version}\\t${db:Status-Abbrev}\\n'`."""
    versiones: dict[str, str] = {}
    for linea in salida.splitlines():
        partes = linea.split("\t")
        if len(partes) >= 3 and partes[2].startswith("ii") and partes[1]:
            versiones[partes[0].split(":")[0]] = partes[1]
    return versiones


def leer_simulacion_apt(salida: str) -> tuple[dict[str, tuple[str | None, str]], list[str]]:
    """De `apt-get -s`: {paquete: (versión previa o None si es nuevo, versión nueva)} y la
    lista de paquetes que se quitarían."""
    instala: dict[str, tuple[str | None, str]] = {}
    quita: list[str] = []
    for linea in salida.splitlines():
        if m := _INST.match(linea):
            instala[m.group(1).split(":")[0]] = (m.group(2), m.group(3))
        elif m := _REMV.match(linea):
            quita.append(m.group(1))
    return instala, quita


def versiones_de_madison(salida: str) -> set[str]:
    versiones = set()
    for linea in salida.splitlines():
        partes = [p.strip() for p in linea.split("|")]
        if len(partes) >= 2 and partes[1]:
            versiones.add(partes[1])
    return versiones


class Apt:
    def __init__(self, corredor: Corredor, cache: Path = Path("/var/cache/apt/archives")):
        self.corredor = corredor
        self.cache = cache

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]:
        paso = self.corredor.correr(
            [
                "dpkg-query",
                "-W",
                "-f",
                "${Package}\\t${Version}\\t${db:Status-Abbrev}\\n",
                *accion["paquetes"],
            ],
            60,
            anotar=False,
        )
        if paso["codigo"] is None:
            raise RuntimeError("dpkg-query no está disponible")
        versiones = leer_dpkg_query(paso["salida"])
        return {p: versiones.get(p) for p in accion["paquetes"]}

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo:
        instalados = [p for p in accion["paquetes"] if antes.get(p)]
        if not instalados:
            return Previo(OMITIDO, "ninguno de los paquetes del plan está instalado")
        minimos = accion.get("minimos") or {}
        if (
            minimos
            and all(
                dpkg_cumple(self.corredor, antes[p], minimos[p]) for p in instalados if p in minimos
            )
            and any(p in minimos for p in instalados)
        ):
            return Previo(YA_AL_DIA, "las versiones instaladas ya cumplen el arreglo")
        actualizar = self.corredor.correr(
            ["apt-get", "update", "-q", "-o", "DPkg::Lock::Timeout=600"], 900, ENTORNO_APT
        )
        if actualizar["codigo"] != 0:
            return Previo(OMITIDO, "no se pudo actualizar la lista de paquetes (apt-get update)")
        simulacion = self.corredor.correr(
            ["apt-get", "-s", "-q", "install", "--only-upgrade", *instalados], 300, ENTORNO_APT
        )
        if simulacion["codigo"] != 0:
            return Previo(OMITIDO, "la simulación de apt-get falló")
        instala, quita = leer_simulacion_apt(simulacion["salida"])
        if quita:
            return Previo(
                OMITIDO,
                f"la actualización quitaría paquetes ({', '.join(quita[:8])}): se deja para TI",
            )
        nuevas = {p: v[1] for p, v in instala.items() if p in instalados and v[0]}
        if not nuevas:
            return Previo(
                OMITIDO,
                "el repositorio configurado todavía no ofrece una versión nueva de estos paquetes",
            )
        extra = sorted(p for p, v in instala.items() if v[0] is None)
        return Previo(
            datos={"nuevas": nuevas, "previas": {p: antes[p] for p in nuevas}, "extra": extra}
        )

    def _disponible(self, paquete: str, version: str) -> bool:
        paso = self.corredor.correr(["apt-cache", "madison", paquete], 60, anotar=False)
        if version in versiones_de_madison(paso["salida"] or ""):
            return True
        archivo = version.replace(":", "%3a")
        return any(self.cache.glob(f"{paquete}_{archivo}_*.deb"))

    def respaldar(self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo) -> Respaldo:
        previas = previo.datos["previas"]
        faltan = [p for p, v in previas.items() if not self._disponible(p, v)]
        if faltan:
            return Respaldo(
                False,
                f"la versión previa de {', '.join(faltan[:6])} ya no está en el repositorio",
                previo.datos,
            )
        return Respaldo(True, datos=previo.datos)

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]:
        paso = self.corredor.correr(
            [
                "apt-get",
                *OPCIONES_APT,
                "install",
                "--only-upgrade",
                *sorted(previo.datos["nuevas"]),
            ],
            TIEMPO_APT,
            ENTORNO_APT,
        )
        if paso["codigo"] != 0:
            raise RuntimeError(f"apt-get terminó con código {paso['codigo']}")
        return {"nuevas": previo.datos["nuevas"]}

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion:
        nuevas = aplicado["nuevas"]
        distintas = [p for p, v in nuevas.items() if despues.get(p) != v]
        if distintas:
            return Verificacion(
                False, f"no quedaron en la versión esperada: {', '.join(distintas[:6])}"
            )
        auditoria = self.corredor.correr(["dpkg", "--audit"], 120, anotar=False)
        if auditoria["codigo"] == 0 and auditoria["salida"].strip():
            return Verificacion(False, "dpkg reporta paquetes a medio configurar")
        minimos = accion.get("minimos") or {}
        comparables = [p for p in nuevas if p in minimos]
        cumple = (
            all(dpkg_cumple(self.corredor, despues[p], minimos[p]) for p in comparables)
            if comparables
            else None
        )
        texto = ", ".join(f"{p} {antes.get(p)} -> {despues.get(p)}" for p in sorted(nuevas))[:400]
        if cumple is False:
            texto += ". El repositorio entregó una versión menor al arreglo de la fuente"
        return Verificacion(True, texto, REINICIO_DEBIAN.exists(), cumple)

    def revertir(self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo) -> None:
        self.corredor.correr(["dpkg", "--configure", "-a"], 900, ENTORNO_APT)
        previas = respaldo.datos.get("previas") or {}
        self.corredor.correr(
            [
                "apt-get",
                *OPCIONES_APT,
                "--allow-downgrades",
                "install",
                *[f"{p}={v}" for p, v in sorted(previas.items())],
            ],
            TIEMPO_APT,
            ENTORNO_APT,
        )

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool:
        return all(a.get(p) == b.get(p) for p in accion["paquetes"])


# ---------------------------------------------------------------------------
# dnf
# ---------------------------------------------------------------------------


def leer_rpm_q(salida: str) -> dict[str, str]:
    versiones: dict[str, str] = {}
    for linea in salida.splitlines():
        partes = linea.split("\t")
        if len(partes) == 2 and partes[1]:
            versiones[partes[0]] = partes[1].replace("(none):", "0:")
    return versiones


def ultima_transaccion(salida: str) -> int | None:
    ids = [int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\s*\|", salida, re.MULTILINE)]
    return max(ids) if ids else None


class Dnf:
    def __init__(self, corredor: Corredor):
        self.corredor = corredor

    def _paquetes(self, accion: dict[str, Any]) -> list[str]:
        return list(accion.get("paquetes") or [])

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]:
        paquetes = self._paquetes(accion)
        if not paquetes:
            return {}
        paso = self.corredor.correr(
            ["rpm", "-q", "--qf", "%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\n", *paquetes],
            60,
            anotar=False,
        )
        if paso["codigo"] is None:
            raise RuntimeError("rpm no está disponible")
        versiones = leer_rpm_q(paso["salida"])
        return {p: versiones.get(p) for p in paquetes}

    def _transaccion(self) -> int | None:
        paso = self.corredor.correr(["dnf", "-q", "history", "list"], 120, anotar=False)
        return ultima_transaccion(paso["salida"] or "") if paso["codigo"] == 0 else None

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo:
        paquetes = self._paquetes(accion)
        instalados = [p for p in paquetes if antes.get(p)]
        if paquetes and not instalados:
            return Previo(OMITIDO, "ninguno de los paquetes del plan está instalado")
        minimos = accion.get("minimos") or {}
        comparables = [p for p in instalados if p in minimos]
        if comparables and all(rpm_evr_cmp(antes[p], minimos[p]) >= 0 for p in comparables):
            return Previo(YA_AL_DIA, "las versiones instaladas ya cumplen el arreglo")
        objetivo = ["--advisory", accion["aviso"]] if accion.get("aviso") else instalados
        revision = self.corredor.correr(["dnf", "-q", "check-update", *objetivo], 900)
        if revision["codigo"] == 0:
            return Previo(
                OMITIDO,
                "el repositorio configurado todavía no ofrece una versión nueva de estos paquetes",
            )
        if revision["codigo"] != 100:
            return Previo(OMITIDO, "no se pudo consultar el repositorio (dnf check-update)")
        simulacion = self.corredor.correr(["dnf", "--assumeno", "upgrade", *objetivo], 900)
        texto = simulacion["salida"] or ""
        if re.search(r"^\s*Removing", texto, re.MULTILINE):
            return Previo(OMITIDO, "la actualización quitaría paquetes: se deja para TI")
        return Previo(datos={"objetivo": objetivo, "transaccion": self._transaccion()})

    def respaldar(self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo) -> Respaldo:
        if previo.datos.get("transaccion") is None:
            return Respaldo(False, "no se pudo leer el historial de dnf", previo.datos)
        return Respaldo(True, datos=previo.datos)

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]:
        paso = self.corredor.correr(["dnf", "-y", "upgrade", *previo.datos["objetivo"]], TIEMPO_APT)
        if paso["codigo"] != 0:
            raise RuntimeError(f"dnf terminó con código {paso['codigo']}")
        return {}

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion:
        instalados = [p for p in self._paquetes(accion) if antes.get(p)]
        faltan = [p for p in instalados if not despues.get(p)]
        if faltan:
            return Verificacion(False, f"desaparecieron paquetes: {', '.join(faltan[:6])}")
        minimos = accion.get("minimos") or {}
        comparables = [p for p in instalados if p in minimos]
        cumple = (
            all(rpm_evr_cmp(despues[p], minimos[p]) >= 0 for p in comparables)
            if comparables
            else None
        )
        cambiaron = [p for p in instalados if despues[p] != antes[p]]
        if instalados and not cambiaron:
            return Verificacion(False, "ningún paquete cambió de versión")
        paso = self.corredor.correr(["needs-restarting", "-r"], 120, anotar=False)
        reinicio = paso["codigo"] == 1
        texto = ", ".join(f"{p} {antes[p]} -> {despues[p]}" for p in cambiaron)[:400]
        if cumple is False:
            texto += ". El repositorio entregó una versión menor al arreglo de la fuente"
        return Verificacion(True, texto or "aviso aplicado", reinicio, cumple)

    def revertir(self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo) -> None:
        previa = respaldo.datos.get("transaccion")
        actual = self._transaccion()
        if previa is None or actual is None or actual <= previa:
            raise RuntimeError("dnf no registró una transacción nueva que deshacer")
        self.corredor.correr(["dnf", "-y", "history", "undo", str(actual)], TIEMPO_APT)

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool:
        return all(a.get(p) == b.get(p) for p in self._paquetes(accion))


# ---------------------------------------------------------------------------
# Postura
# ---------------------------------------------------------------------------


def _leer(ruta: Path) -> str | None:
    try:
        return ruta.read_text(encoding="utf-8")
    except OSError:
        return None


def _escribir(ruta: Path, contenido: str | None) -> None:
    """Escribe de forma atómica; con None borra el archivo."""
    if contenido is None:
        ruta.unlink(missing_ok=True)
        return
    temporal = ruta.with_name(ruta.name + ".radar-tmp")
    temporal.write_text(contenido, encoding="utf-8")
    os.chmod(temporal, 0o644)
    os.replace(temporal, ruta)


def regla_ssh(salida: str) -> bool:
    """True si `ufw show added` (o la lista de servicios de firewalld) deja pasar SSH."""
    bajo = salida.lower()
    return bool(re.search(r"\b(22|openssh|ssh)\b", bajo))


class PosturaLinux:
    def __init__(self, corredor: Corredor, plataforma: str, raiz: Path = Path("/")):
        self.corredor = corredor
        self.plataforma = plataforma
        self.raiz = raiz

    def _ruta(self, ruta: Path) -> Path:
        return self.raiz / ruta.relative_to("/")

    def _systemctl(self, verbo: str, unidad: str) -> str:
        paso = self.corredor.correr(["systemctl", verbo, unidad], 60, anotar=False)
        return (paso["salida"] or "").strip().splitlines()[0] if paso["salida"] else ""

    def _ssh_activo(self) -> bool:
        return any(self._systemctl("is-active", u) == "active" for u in ("ssh", "sshd"))

    def _instalado(self, paquete: str) -> bool:
        if self.plataforma == "debian":
            paso = self.corredor.correr(
                ["dpkg-query", "-W", "-f", "${db:Status-Abbrev}", paquete], 30, anotar=False
            )
            return paso["codigo"] == 0 and paso["salida"].startswith("ii")
        paso = self.corredor.correr(["rpm", "-q", paquete], 30, anotar=False)
        return paso["codigo"] == 0

    # -- medir -----------------------------------------------------------------

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]:
        regla = accion["regla"]
        if regla == "firewall" and self.plataforma == "debian":
            paso = self.corredor.correr(["ufw", "status"], 60, anotar=False)
            if paso["codigo"] is None:
                return {"ufw": "no_instalado"}
            primera = (paso["salida"] or "").strip().splitlines()[:1]
            estado = (
                "inactive"
                if primera and "inactive" in primera[0].lower()
                else ("active" if primera and "active" in primera[0].lower() else "desconocido")
            )
            return {"ufw": estado}
        if regla == "firewall":
            return {
                "activo": self._systemctl("is-active", "firewalld"),
                "habilitado": self._systemctl("is-enabled", "firewalld"),
            }
        if regla == "antivirus":
            modulo = _leer(self._ruta(Path("/sys/module/apparmor/parameters/enabled")))
            return {
                "modulo": (modulo or "").strip() or None,
                "activo": self._systemctl("is-active", "apparmor"),
                "habilitado": self._systemctl("is-enabled", "apparmor"),
            }
        if self.plataforma == "debian":
            contenido = _leer(self._ruta(AUTO_UPGRADES))
            return {
                "paquete": "si" if self._instalado("unattended-upgrades") else "no",
                "archivo": "si" if contenido is not None else "no",
                "unattended": "1"
                if contenido
                and re.search(
                    r'^\s*APT::Periodic::Unattended-Upgrade\s+"1"', contenido, re.MULTILINE
                )
                else "0",
            }
        contenido = _leer(self._ruta(DNF_AUTOMATIC))
        aplica = bool(
            contenido
            and re.search(
                r"^\s*apply_updates\s*=\s*(yes|true|1)\s*$", contenido, re.MULTILINE | re.IGNORECASE
            )
        )
        return {
            "paquete": "si" if self._instalado("dnf-automatic") else "no",
            "aplica": "si" if aplica else "no",
            "temporizador": self._systemctl("is-enabled", "dnf-automatic.timer"),
        }

    # -- prechequear -----------------------------------------------------------

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo:
        regla = accion["regla"]
        if regla == "firewall" and self.plataforma == "debian":
            if antes.get("ufw") == "no_instalado":
                return Previo(OMITIDO, "ufw no está instalado")
            if antes.get("ufw") == "active":
                return Previo(YA_AL_DIA, "el firewall ya está activo")
            if self._ssh_activo():
                reglas = self.corredor.correr(["ufw", "show", "added"], 60)
                if not regla_ssh(reglas["salida"] or ""):
                    return Previo(
                        OMITIDO,
                        "activar ufw cortaría el acceso por SSH: agregar antes una regla "
                        "(ufw allow OpenSSH) y volver a aprobar",
                    )
            return Previo()
        if regla == "firewall":
            if antes.get("habilitado") in ("", "not-found") and antes.get("activo") != "active":
                return Previo(OMITIDO, "firewalld no está instalado")
            if antes.get("activo") == "active" and antes.get("habilitado") == "enabled":
                return Previo(YA_AL_DIA, "firewalld ya está activo")
            if self._ssh_activo():
                servicios = self.corredor.correr(["firewall-offline-cmd", "--list-services"], 60)
                if servicios["codigo"] != 0 or not regla_ssh(servicios["salida"] or ""):
                    return Previo(
                        OMITIDO,
                        "activar firewalld podría cortar el acceso por SSH: la zona por "
                        "defecto no permite ssh",
                    )
            return Previo()
        if regla == "antivirus":
            if antes.get("modulo") == "Y":
                return Previo(YA_AL_DIA, "AppArmor ya está cargado")
            if antes.get("habilitado") in ("", "not-found"):
                return Previo(OMITIDO, "AppArmor no está instalado")
            return Previo()
        if self.plataforma == "debian":
            if antes.get("paquete") == "si" and antes.get("unattended") == "1":
                return Previo(YA_AL_DIA, "las actualizaciones automáticas ya están activas")
            return Previo()
        if (
            antes.get("paquete") == "si"
            and antes.get("aplica") == "si"
            and antes.get("temporizador") == "enabled"
        ):
            return Previo(YA_AL_DIA, "dnf-automatic ya aplica las actualizaciones")
        return Previo()

    # -- respaldar y aplicar ---------------------------------------------------

    def respaldar(self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo) -> Respaldo:
        datos: dict[str, Any] = {}
        if accion["regla"] == "actualizaciones_automaticas":
            ruta = AUTO_UPGRADES if self.plataforma == "debian" else DNF_AUTOMATIC
            datos["archivo"] = _leer(self._ruta(ruta))
        return Respaldo(True, datos=datos)

    def _correr_o_fallar(
        self, orden: list[str], tiempo: int = 300, entorno: dict | None = None
    ) -> None:
        paso = self.corredor.correr(orden, tiempo, entorno)
        if paso["codigo"] != 0:
            raise RuntimeError(f"{orden[0]} terminó con código {paso['codigo']}")

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]:
        regla = accion["regla"]
        if regla == "firewall" and self.plataforma == "debian":
            self._correr_o_fallar(["ufw", "--force", "enable"])
        elif regla == "firewall":
            self._correr_o_fallar(["systemctl", "enable", "--now", "firewalld"])
        elif regla == "antivirus":
            self._correr_o_fallar(["systemctl", "enable", "--now", "apparmor"])
        elif self.plataforma == "debian":
            if not self._instalado("unattended-upgrades"):
                self._correr_o_fallar(
                    ["apt-get", *OPCIONES_APT, "install", "unattended-upgrades"],
                    TIEMPO_APT,
                    ENTORNO_APT,
                )
            _escribir(self._ruta(AUTO_UPGRADES), CONTENIDO_AUTO_UPGRADES)
        else:
            if not self._instalado("dnf-automatic"):
                self._correr_o_fallar(["dnf", "-y", "install", "dnf-automatic"], TIEMPO_APT)
            ruta = self._ruta(DNF_AUTOMATIC)
            contenido = _leer(ruta) or "[commands]\n"
            if re.search(r"^\s*apply_updates\s*=", contenido, re.MULTILINE):
                contenido = re.sub(
                    r"^\s*apply_updates\s*=.*$",
                    "apply_updates = yes",
                    contenido,
                    flags=re.MULTILINE,
                )
            else:
                contenido = contenido.replace(
                    "[commands]\n", "[commands]\napply_updates = yes\n", 1
                )
            _escribir(ruta, contenido)
            self._correr_o_fallar(["systemctl", "enable", "--now", "dnf-automatic.timer"])
        return {}

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion:
        regla = accion["regla"]
        if regla == "firewall" and self.plataforma == "debian":
            ok = despues.get("ufw") == "active"
        elif regla == "firewall":
            ok = despues.get("activo") == "active"
        elif regla == "antivirus":
            ok = despues.get("modulo") == "Y"
            if not ok:
                return Verificacion(
                    False, "el módulo AppArmor sigue sin cargar (¿desactivado en el arranque?)"
                )
        elif self.plataforma == "debian":
            ok = despues.get("paquete") == "si" and despues.get("unattended") == "1"
        else:
            ok = despues.get("aplica") == "si" and despues.get("temporizador") == "enabled"
        return Verificacion(ok, "activo" if ok else "no quedó activo")

    def revertir(self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo) -> None:
        regla = accion["regla"]
        if regla == "firewall" and self.plataforma == "debian":
            if antes.get("ufw") != "active":
                self.corredor.correr(["ufw", "--force", "disable"], 120)
            return
        if regla in ("firewall", "antivirus"):
            unidad = "firewalld" if regla == "firewall" else "apparmor"
            if antes.get("habilitado") != "enabled":
                self.corredor.correr(["systemctl", "disable", unidad], 120)
            if antes.get("activo") != "active":
                self.corredor.correr(["systemctl", "stop", unidad], 120)
            return
        if self.plataforma == "debian":
            _escribir(self._ruta(AUTO_UPGRADES), respaldo.datos.get("archivo"))
            if antes.get("paquete") != "si":
                self.corredor.correr(
                    ["apt-get", *OPCIONES_APT, "remove", "unattended-upgrades"],
                    TIEMPO_APT,
                    ENTORNO_APT,
                )
            return
        _escribir(self._ruta(DNF_AUTOMATIC), respaldo.datos.get("archivo"))
        if antes.get("temporizador") != "enabled":
            self.corredor.correr(["systemctl", "disable", "--now", "dnf-automatic.timer"], 120)
        if antes.get("paquete") != "si":
            self.corredor.correr(["dnf", "-y", "remove", "dnf-automatic"], TIEMPO_APT)

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool:
        return a == b


def reinicio_pendiente(corredor: Corredor, plataforma: str) -> bool:
    if plataforma == "debian":
        return REINICIO_DEBIAN.exists()
    paso = corredor.correr(["needs-restarting", "-r"], 120, anotar=False)
    return paso["codigo"] == 1


def contexto(corredor: Corredor, plataforma: str) -> dict[str, Any]:
    """Ejecutores y ganchos de Linux para `parcheo.Contexto`."""
    ejecutores: dict[str, Any] = {f"postura_{plataforma}": PosturaLinux(corredor, plataforma)}
    if plataforma == "debian":
        ejecutores["apt"] = Apt(corredor)
    else:
        ejecutores["dnf"] = Dnf(corredor)
    return {
        "ejecutores": ejecutores,
        "punto_restauracion": None,
        "reinicio_pendiente": lambda: reinicio_pendiente(corredor, plataforma),
    }
