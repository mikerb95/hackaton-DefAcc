"""Recolector de Windows: registro para el software y el sistema, PowerShell para el resto.

Decisiones (docs/plan-agente-local.md, sección 4):
- El software sale de las tres claves `Uninstall` del registro (64 bits, 32 bits y una
  por perfil de usuario). No se usa `Win32_Product`: consultarlo dispara una reparación
  MSI de cada producto.
- Se descartan las entradas con `SystemComponent=1` y las que tienen `ParentKeyName`
  (son actualizaciones de otro producto).
- La versión exacta del sistema es `CurrentBuild` más `UBR` (por ejemplo
  `10.0.22631.4317`), que es contra lo que compara NVD. La lista de KB es informativa.
- Windows 11 dice "Windows 10" en `ProductName`: el nombre se corrige con el build.
- Cada dato de postura es "si", "no" o "desconocido". Sin privilegios de administrador
  varios quedan en "desconocido": nunca se adivinan.

Lo que reporta el registro es texto no confiable: cualquier usuario puede crear una
entrada en `HKCU\\...\\Uninstall` con el `DisplayName` que quiera. Aquí no se limpia
nada: el radar lo limpia al recibirlo y otra vez antes de que un modelo lo vea.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agente_local.comun import (
    DESCONOCIDO,
    NO,
    SI,
    como_lista,
    ejecutar,
    json_o_nada,
    texto,
    tri,
)

RUTA_UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
RUTA_UNINSTALL_32 = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
RUTA_SISTEMA = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

BUILD_WINDOWS_11 = 22000
DIAS_FIRMAS = 7
# Tipos de chasis de Win32_SystemEnclosure que son portátiles.
CHASIS_PORTATIL = {8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32}
CHASIS_FIJO = {3, 4, 5, 6, 7, 13, 15, 16, 17, 23, 24, 35}

POWERSHELL = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]


def _winreg():
    import winreg  # solo existe en Windows

    return winreg


# ---------------------------------------------------------------------------
# Software
# ---------------------------------------------------------------------------


def _valor(clave: Any, nombre: str) -> Any:
    try:
        return _winreg().QueryValueEx(clave, nombre)[0]
    except OSError:
        return None


def entrada_valida(valores: dict[str, Any]) -> bool:
    """True si la entrada de Uninstall es un programa y no un componente o un parche."""
    if not texto(valores.get("DisplayName")):
        return False
    if valores.get("SystemComponent") == 1:
        return False
    return not texto(valores.get("ParentKeyName"))


def programa_de_entrada(valores: dict[str, Any], ambito: str) -> dict[str, Any]:
    return {
        "programa": texto(valores.get("DisplayName")),
        "version": texto(valores.get("DisplayVersion")),
        "proveedor": texto(valores.get("Publisher")),
        "fuente": "registro",
        "ambito": ambito,
    }


def _leer_uninstall(raiz: Any, ruta: str, ambito: str, vista: int = 0) -> list[dict[str, Any]]:
    winreg = _winreg()
    programas: list[dict[str, Any]] = []
    try:
        clave = winreg.OpenKey(raiz, ruta, 0, winreg.KEY_READ | vista)
    except OSError:
        return programas
    with clave:
        indice = 0
        while True:
            try:
                nombre = winreg.EnumKey(clave, indice)
            except OSError:
                break
            indice += 1
            try:
                sub = winreg.OpenKey(clave, nombre)
            except OSError:
                continue
            with sub:
                valores = {
                    n: _valor(sub, n)
                    for n in (
                        "DisplayName",
                        "DisplayVersion",
                        "Publisher",
                        "SystemComponent",
                        "ParentKeyName",
                    )
                }
            if entrada_valida(valores):
                programas.append(programa_de_entrada(valores, ambito))
    return programas


def _perfiles() -> list[str]:
    """SID de los perfiles de usuario cargados en HKEY_USERS (sin las clases)."""
    winreg = _winreg()
    sids: list[str] = []
    indice = 0
    while True:
        try:
            sid = winreg.EnumKey(winreg.HKEY_USERS, indice)
        except OSError:
            break
        indice += 1
        if sid.startswith("S-1-5-21-") and not sid.endswith("_Classes"):
            sids.append(sid)
    return sids


def sin_repetir(programas: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Quita duplicados exactos (el mismo programa aparece en la vista de 32 y de 64 bits)."""
    vistos: set[tuple] = set()
    salida = []
    for p in programas:
        llave = (p["programa"], p["version"], p["proveedor"], p["ambito"])
        if llave not in vistos:
            vistos.add(llave)
            salida.append(p)
    return salida


def software() -> list[dict[str, Any]]:
    winreg = _winreg()
    programas = _leer_uninstall(
        winreg.HKEY_LOCAL_MACHINE, RUTA_UNINSTALL, "maquina", winreg.KEY_WOW64_64KEY
    )
    programas += _leer_uninstall(
        winreg.HKEY_LOCAL_MACHINE, RUTA_UNINSTALL, "maquina", winreg.KEY_WOW64_32KEY
    )
    programas += _leer_uninstall(winreg.HKEY_LOCAL_MACHINE, RUTA_UNINSTALL_32, "maquina")
    for sid in _perfiles():
        programas += _leer_uninstall(winreg.HKEY_USERS, f"{sid}\\{RUTA_UNINSTALL}", "usuario")
    return sorted(sin_repetir(programas), key=lambda p: (p["programa"].lower(), p["version"] or ""))


# ---------------------------------------------------------------------------
# Sistema operativo
# ---------------------------------------------------------------------------


def armar_sistema(valores: dict[str, Any], arquitectura: str | None, parches: list[str]) -> dict:
    """Arma el bloque `so` a partir de los valores de `CurrentVersion` del registro."""
    nombre = texto(valores.get("ProductName")) or "Windows"
    build = texto(valores.get("CurrentBuild")) or texto(valores.get("CurrentBuildNumber"))
    ubr = valores.get("UBR")
    mayor = valores.get("CurrentMajorVersionNumber")
    menor = valores.get("CurrentMinorVersionNumber")
    completo = None
    if build and build.isdigit():
        if int(build) >= BUILD_WINDOWS_11 and "Server" not in nombre:
            nombre = nombre.replace("Windows 10", "Windows 11")
        if isinstance(mayor, int) and isinstance(menor, int) and isinstance(ubr, int):
            completo = f"{mayor}.{menor}.{build}.{ubr}"
    return {
        "familia": "windows",
        "nombre": nombre,
        "version": texto(valores.get("DisplayVersion")) or texto(valores.get("ReleaseId")),
        "build": completo,
        "kernel": None,
        "arquitectura": arquitectura,
        "edicion": texto(valores.get("EditionID")),
        "distro": None,
        "parches": parches,
    }


def _arquitectura() -> str | None:
    import platform

    maquina = platform.machine().lower()
    return {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "x86": "x86"}.get(maquina, maquina)


def sistema(datos_ps: dict[str, Any]) -> dict[str, Any]:
    winreg = _winreg()
    valores: dict[str, Any] = {}
    try:
        clave = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, RUTA_SISTEMA, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        )
    except OSError:
        clave = None
    if clave is not None:
        with clave:
            for nombre in (
                "ProductName",
                "DisplayVersion",
                "ReleaseId",
                "CurrentBuild",
                "CurrentBuildNumber",
                "UBR",
                "EditionID",
                "CurrentMajorVersionNumber",
                "CurrentMinorVersionNumber",
            ):
                valores[nombre] = _valor(clave, nombre)
    parches = sorted({p for p in (texto(x) for x in como_lista(datos_ps.get("parches"))) if p})
    return armar_sistema(valores, _arquitectura(), parches)


# ---------------------------------------------------------------------------
# Hardware y postura (una sola llamada a PowerShell)
# ---------------------------------------------------------------------------

# Cada bloque va en su propio try: lo que falle queda en null y pasa a "desconocido".
GUION_PS = r"""
$ErrorActionPreference = 'Stop'
$r = [ordered]@{}
function Probar($nombre, $bloque) {
  try { $r[$nombre] = & $bloque } catch { $r[$nombre] = $null }
}
Probar 'equipo' { Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory }
Probar 'cpu' { (Get-CimInstance Win32_Processor | Select-Object -First 1).Name }
Probar 'bios' { (Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion }
Probar 'chasis' { @((Get-CimInstance Win32_SystemEnclosure).ChassisTypes) }
Probar 'tpm' { (Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm).SpecVersion }
Probar 'parches' { @((Get-CimInstance Win32_QuickFixEngineering).HotFixID) }
Probar 'defender' { Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, @{n='Firmas';e={$_.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}} }
Probar 'antivirus' { @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState) }
Probar 'firewall' { @(Get-NetFirewallProfile | Select-Object Name, @{n='Activo';e={[bool]$_.Enabled}}) }
Probar 'bitlocker' { @(Get-BitLockerVolume | Select-Object MountPoint, VolumeType, @{n='Proteccion';e={[string]$_.ProtectionStatus}}) }
Probar 'arranque_seguro' { Confirm-SecureBootUEFI }
Probar 'actualizaciones' {
  $p = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
  if ($null -eq $p) { 'sin_politica' } else { [ordered]@{ NoAutoUpdate = $p.NoAutoUpdate; AUOptions = $p.AUOptions } }
}
$r | ConvertTo-Json -Depth 4 -Compress
"""


def consultar_powershell() -> dict[str, Any]:
    salida = ejecutar([*POWERSHELL, "-Command", GUION_PS], tiempo=120)
    datos = json_o_nada(salida)
    return datos if isinstance(datos, dict) else {}


def hardware(datos: dict[str, Any]) -> dict[str, Any]:
    equipo = datos.get("equipo") or {}
    memoria = equipo.get("TotalPhysicalMemory")
    ram = round(memoria / 1024**3, 1) if isinstance(memoria, (int, float)) and memoria else None
    tpm = texto(datos.get("tpm"))
    return {
        "fabricante": texto(equipo.get("Manufacturer")),
        "modelo": texto(equipo.get("Model")),
        "bios": texto(datos.get("bios")),
        "cpu": texto(datos.get("cpu")),
        "ram_gb": ram,
        "tpm": tpm.split(",")[0].strip() if tpm else None,
        "portatil": es_portatil(datos.get("chasis")),
    }


def es_portatil(chasis: Any) -> str:
    tipos = {t for t in como_lista(chasis) if isinstance(t, int)}
    if tipos & CHASIS_PORTATIL:
        return SI
    if tipos & CHASIS_FIJO:
        return NO
    return DESCONOCIDO


def _antivirus(datos: dict[str, Any]) -> str:
    defender = datos.get("defender")
    if isinstance(defender, dict) and defender.get("AntivirusEnabled") is True:
        return tri(defender.get("RealTimeProtectionEnabled"))
    # Antivirus de terceros: el bit 0x1000 de productState indica protección activa.
    productos = [p for p in como_lista(datos.get("antivirus")) if isinstance(p, dict)]
    estados = [p.get("productState") for p in productos if isinstance(p.get("productState"), int)]
    if estados:
        return SI if any(e & 0x1000 for e in estados) else NO
    if isinstance(defender, dict) and defender.get("AntivirusEnabled") is False:
        return NO
    return DESCONOCIDO


def firmas_al_dia(defender: Any, ahora: datetime | None = None) -> str:
    """ "si" si las firmas de Defender tienen 7 días o menos. Con otro antivirus no se sabe."""
    if not isinstance(defender, dict) or defender.get("AntivirusEnabled") is not True:
        return DESCONOCIDO
    marca = texto(defender.get("Firmas"))
    if not marca:
        return DESCONOCIDO
    try:
        fecha = datetime.fromisoformat(marca.replace("Z", "+00:00")[:32])
    except ValueError:
        return DESCONOCIDO
    if fecha.tzinfo is None:
        fecha = fecha.replace(tzinfo=UTC)
    ahora = ahora or datetime.now(UTC)
    return SI if (ahora - fecha).days <= DIAS_FIRMAS else NO


def _firewall(perfiles: Any) -> str:
    """ "no" si algún perfil está apagado (regla de postura: firewall apagado en algún perfil)."""
    estados = [p.get("Activo") for p in como_lista(perfiles) if isinstance(p, dict)]
    estados = [e for e in estados if isinstance(e, bool)]
    if not estados:
        return DESCONOCIDO
    return SI if all(estados) else NO


def _cifrado(volumenes: Any) -> str:
    """Estado de BitLocker del volumen del sistema."""
    for v in como_lista(volumenes):
        if not isinstance(v, dict):
            continue
        tipo = str(v.get("VolumeType"))
        if tipo in ("OperatingSystem", "0"):
            proteccion = str(v.get("Proteccion"))
            if proteccion in ("On", "1"):
                return SI
            if proteccion in ("Off", "0"):
                return NO
    return DESCONOCIDO


def _actualizaciones(politica: Any) -> str:
    # Sin política, Windows Update automático es el comportamiento por defecto.
    if politica == "sin_politica":
        return SI
    if isinstance(politica, dict):
        if politica.get("NoAutoUpdate") == 1 or politica.get("AUOptions") == 1:
            return NO
        return SI
    return DESCONOCIDO


def postura(datos: dict[str, Any], ahora: datetime | None = None) -> dict[str, str]:
    return {
        "firewall": _firewall(datos.get("firewall")),
        "antivirus": _antivirus(datos),
        "firmas_al_dia": firmas_al_dia(datos.get("defender"), ahora),
        "cifrado_disco": _cifrado(datos.get("bitlocker")),
        "secure_boot": tri(datos.get("arranque_seguro")),
        "actualizaciones_automaticas": _actualizaciones(datos.get("actualizaciones")),
    }


def recoger(solo_software: bool = False) -> dict[str, Any]:
    """Todo lo que el agente recoge en Windows. Con `solo_software` no llama a PowerShell."""
    datos = {} if solo_software else consultar_powershell()
    return {
        "so": sistema(datos),
        "hardware": hardware(datos),
        "postura": postura(datos),
        "software": software(),
    }
