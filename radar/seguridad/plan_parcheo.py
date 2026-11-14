"""Plan de parcheo: forma canónica y catálogo cerrado de acciones (docs/plan-parcheo.md).

Lo usan los dos lados con el mismo código: `radar/seguridad/plan_parcheo.py` es copia exacta
de este archivo (una prueba lo compara). El servidor arma y valida el plan antes de guardarlo;
el agente lo vuelve a validar después de verificar la firma y antes de tocar nada. Solo
librería estándar.

La regla de fondo: una acción no lleva comandos en texto. Lleva un `ejecutor` de una lista
fija y parámetros que cumplen patrones estrictos (sin espacios ni signos de shell). El agente
arma los argumentos con sus propias plantillas y los ejecuta sin shell. Así, aunque alguien
consiguiera firmar un plan, solo podría pedir lo que el agente ya sabe hacer: actualizar
paquetes de una lista blanca, instalar actualizaciones de seguridad y endurecer la postura.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any

VERSION_PLAN = 1
VIGENCIA_HORAS = 72
MAX_ACCIONES = 40
MAX_PAQUETES = 12
MAX_CVES_ACCION = 60
MARGEN_RELOJ_MINUTOS = 10  # el reloj del equipo puede ir adelantado o atrasado

PLATAFORMAS = ("windows", "debian", "rhel")
TIPOS = ("aplicacion", "paquetes", "postura", "so")  # también es el orden de ejecución
PRIORIDADES = ("inmediato", "semanal", "informativo")

# Piezas variables. Nada de espacios, comillas ni signos de shell.
PAQUETE_DEB = re.compile(r"^[a-z0-9][a-z0-9+.\-]{0,99}$")
PAQUETE_RPM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._\-]{0,99}$")
ID_WINGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+\-]*(?:\.[A-Za-z0-9+\-]+){1,5}$")
VERSION = re.compile(r"^[0-9][0-9A-Za-z.\-]{0,39}$")
VERSION_PAQUETE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+~:\-_]{0,79}$")
AVISO_RPM = re.compile(r"^[A-Z]{2,6}-\d{4}:\d{3,6}$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ID_ACCION = re.compile(r"^[a-z]{2,10}:[A-Za-z0-9+._\-]{1,100}$")
UUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$")
FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f  ]")

# Identificadores de winget que el agente acepta actualizar. Es la misma tabla curada del
# servidor (`radar/equipos/remediacion.py::WINGET`); una prueba comprueba que coinciden.
WINGET_PERMITIDOS = frozenset(
    {
        "RARLab.WinRAR",
        "7zip.7zip",
        "Google.Chrome",
        "Mozilla.Firefox",
        "VideoLAN.VLC",
        "Notepad++.Notepad++",
        "Git.Git",
        "Docker.DockerDesktop",
        "PuTTY.PuTTY",
        "Zoom.Zoom",
        "Microsoft.VisualStudioCode",
        "WiresharkFoundation.Wireshark",
        "DominikReichl.KeePass",
        "TeamViewer.TeamViewer",
        "Oracle.VirtualBox",
        "TheDocumentFoundation.LibreOffice",
        "WinSCP.WinSCP",
        "OpenJS.NodeJS",
    }
)

# Reglas de postura que el agente sabe aplicar y deshacer, por plataforma. Cifrado de disco,
# Secure Boot y SELinux quedan fuera: no se hacen ni se deshacen sin riesgo desde un agente.
POSTURA_AUTOMATICA: dict[str, frozenset[str]] = {
    "windows": frozenset({"firewall", "antivirus", "firmas_al_dia"}),
    "debian": frozenset({"firewall", "antivirus", "actualizaciones_automaticas"}),
    "rhel": frozenset({"firewall", "actualizaciones_automaticas"}),
}
CATEGORIAS_WINDOWS_UPDATE = frozenset({"seguridad", "criticas"})

EJECUTORES: dict[str, tuple[str, str]] = {
    # ejecutor: (plataforma, tipo)
    "winget": ("windows", "aplicacion"),
    "windows_update": ("windows", "so"),
    "apt": ("debian", "paquetes"),
    "dnf": ("rhel", "paquetes"),
    "postura_windows": ("windows", "postura"),
    "postura_debian": ("debian", "postura"),
    "postura_rhel": ("rhel", "postura"),
}

_COMUNES = {"id", "tipo", "ejecutor", "titulo", "cves", "en_kev", "prioridad"}
_PROPIOS: dict[str, set[str]] = {
    "winget": {"paquete", "programa", "version_actual", "minimo", "estricto"},
    "windows_update": {"categorias"},
    "apt": {"paquetes", "minimos"},
    "dnf": {"paquetes", "aviso", "minimos"},
    "postura_windows": {"regla"},
    "postura_debian": {"regla"},
    "postura_rhel": {"regla"},
}
_CAMPOS_PLAN = {
    "version",
    "plan_id",
    "equipo_id",
    "plataforma",
    "emitido",
    "vence",
    "aprobado_por",
    "acciones",
}


class PlanInvalido(ValueError):
    """El plan no cumple la forma o el catálogo. El mensaje es apto para el reporte."""


def canonico(plan: dict[str, Any]) -> bytes:
    """Bytes exactos que se firman: claves ordenadas, sin espacios, solo ASCII."""
    return json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def huella_plan(canonico_bytes: bytes) -> str:
    return hashlib.sha256(canonico_bytes).hexdigest()


def fecha(momento: datetime) -> str:
    return momento.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def leer_fecha(texto: str) -> datetime:
    return datetime.strptime(texto, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _texto_humano(valor: Any, largo: int) -> bool:
    return isinstance(valor, str) and 0 < len(valor) <= largo and not _CONTROL.search(valor)


def _lista(valor: Any, patron: re.Pattern, maximo: int, vacia: bool = False) -> bool:
    if not isinstance(valor, list) or len(valor) > maximo or (not valor and not vacia):
        return False
    return all(isinstance(v, str) and patron.match(v) for v in valor) and len(set(valor)) == len(
        valor
    )


def _minimos(valor: Any, paquetes: list[str]) -> bool:
    if not isinstance(valor, dict) or len(valor) > MAX_PAQUETES:
        return False
    return all(
        k in paquetes and isinstance(v, str) and VERSION_PAQUETE.match(v) for k, v in valor.items()
    )


def validar_accion(accion: Any, plataforma: str) -> str | None:
    """None si la acción es del catálogo; si no, el motivo."""
    if not isinstance(accion, dict):
        return "acción que no es un objeto"
    ejecutor = accion.get("ejecutor")
    if ejecutor not in EJECUTORES:
        return f"ejecutor desconocido: {str(ejecutor)[:40]!r}"
    su_plataforma, su_tipo = EJECUTORES[ejecutor]
    if su_plataforma != plataforma:
        return f"{ejecutor} no corresponde a {plataforma}"
    if accion.get("tipo") != su_tipo:
        return f"tipo incorrecto para {ejecutor}"
    sobran = set(accion) - _COMUNES - _PROPIOS[ejecutor]
    if sobran:
        return f"campos no permitidos en {ejecutor}: {', '.join(sorted(sobran))[:80]}"
    if not isinstance(accion.get("id"), str) or not ID_ACCION.match(accion["id"]):
        return "identificador de acción inválido"
    if not _texto_humano(accion.get("titulo"), 200):
        return "título inválido"
    if not _lista(accion.get("cves", []), CVE, MAX_CVES_ACCION, vacia=True):
        return "lista de CVE inválida"
    if not _lista(accion.get("en_kev", []), CVE, MAX_CVES_ACCION, vacia=True):
        return "lista de KEV inválida"
    if accion.get("prioridad") not in (*PRIORIDADES, None):
        return "prioridad inválida"

    if ejecutor == "winget":
        if accion.get("paquete") not in WINGET_PERMITIDOS or not ID_WINGET.match(accion["paquete"]):
            return "paquete de winget fuera de la lista blanca"
        if not _texto_humano(accion.get("programa"), 160):
            return "nombre de programa inválido"
        for campo in ("version_actual", "minimo"):
            valor = accion.get(campo)
            if valor is not None and not (isinstance(valor, str) and VERSION.match(valor)):
                return f"{campo} inválido"
        if not isinstance(accion.get("estricto", False), bool):
            return "estricto inválido"
        if accion.get("estricto") and not accion.get("minimo"):
            return "estricto sin mínimo"
    elif ejecutor == "windows_update":
        categorias = accion.get("categorias")
        if (
            not isinstance(categorias, list)
            or not categorias
            or not set(categorias) <= CATEGORIAS_WINDOWS_UPDATE
        ):
            return "categorías de Windows Update inválidas"
    elif ejecutor == "apt":
        if not _lista(accion.get("paquetes"), PAQUETE_DEB, MAX_PAQUETES):
            return "paquetes de apt inválidos"
        if not _minimos(accion.get("minimos", {}), accion["paquetes"]):
            return "versiones mínimas inválidas"
    elif ejecutor == "dnf":
        paquetes, aviso = accion.get("paquetes"), accion.get("aviso")
        if aviso is not None:
            if not (isinstance(aviso, str) and AVISO_RPM.match(aviso)):
                return "aviso de dnf inválido"
            if paquetes is not None and not _lista(paquetes, PAQUETE_RPM, MAX_PAQUETES):
                return "paquetes de dnf inválidos"
        elif not _lista(paquetes, PAQUETE_RPM, MAX_PAQUETES):
            return "paquetes de dnf inválidos"
        if not _minimos(accion.get("minimos", {}), paquetes or []):
            return "versiones mínimas inválidas"
    elif accion.get("regla") not in POSTURA_AUTOMATICA[plataforma]:
        return f"regla de postura no automatizable: {str(accion.get('regla'))[:40]!r}"
    return None


def validar_plan(plan: Any) -> None:
    """Lanza `PlanInvalido` si el plan no tiene la forma exacta o sale del catálogo.

    No mira la firma, la vigencia ni el equipo: eso depende de quién valida.
    """
    if not isinstance(plan, dict):
        raise PlanInvalido("el plan no es un objeto")
    if set(plan) != _CAMPOS_PLAN:
        raise PlanInvalido("campos del plan incorrectos")
    if plan["version"] != VERSION_PLAN:
        raise PlanInvalido(f"versión de plan no soportada: {plan['version']!r}")
    for campo, patron in (("plan_id", UUID), ("equipo_id", UUID)):
        if not isinstance(plan[campo], str) or not patron.match(plan[campo]):
            raise PlanInvalido(f"{campo} inválido")
    if plan["plataforma"] not in PLATAFORMAS:
        raise PlanInvalido("plataforma inválida")
    for campo in ("emitido", "vence"):
        if not isinstance(plan[campo], str) or not FECHA.match(plan[campo]):
            raise PlanInvalido(f"{campo} inválido")
    if leer_fecha(plan["vence"]) <= leer_fecha(plan["emitido"]):
        raise PlanInvalido("el plan vence antes de emitirse")
    if not _texto_humano(plan["aprobado_por"], 100):
        raise PlanInvalido("aprobado_por inválido")
    acciones = plan["acciones"]
    if not isinstance(acciones, list) or not 0 < len(acciones) <= MAX_ACCIONES:
        raise PlanInvalido("lista de acciones vacía o demasiado larga")
    ids = set()
    for accion in acciones:
        motivo = validar_accion(accion, plan["plataforma"])
        if motivo:
            raise PlanInvalido(motivo)
        if accion["id"] in ids:
            raise PlanInvalido("acción repetida")
        ids.add(accion["id"])


def en_orden(acciones: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Orden de ejecución: aplicaciones, paquetes, postura y al final el sistema operativo
    (es lo que suele pedir reinicio). Dentro de cada tipo, el orden del plan."""
    return sorted(acciones, key=lambda a: TIPOS.index(a["tipo"]))
