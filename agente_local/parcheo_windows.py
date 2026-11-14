"""Ejecutores del catálogo para Windows (docs/plan-parcheo.md, sección 4). Solo librería estándar.

- `winget`: actualiza un paquete de la lista blanca. Verifica en el registro (solo entradas
  de máquina: una entrada de `HKCU` la puede escribir cualquier usuario y haría pasar una
  verificación falsa). Revierte reinstalando la versión previa si el catálogo la tiene.
- `windows_update`: instala las actualizaciones de seguridad y críticas con la API de
  Windows Update. No se puede revertir: el orquestador exige antes un punto de restauración.
- `postura_windows`: firewall, protección en tiempo real y firmas de Defender. Revierte al
  estado medido antes.

Todos los scripts de PowerShell son fijos: las únicas piezas variables salen de conjuntos
cerrados (nombres de perfil, GUID de categoría, True/False) o ya pasaron los patrones del
catálogo. Nada del plan llega a PowerShell como texto libre.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agente_local import plan_parcheo as catalogo
from agente_local.parcheo import (
    OMITIDO,
    YA_AL_DIA,
    Corredor,
    Previo,
    Respaldo,
    Verificacion,
)

POWERSHELL = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
TIEMPO_WINGET = 1800
TIEMPO_BUSQUEDA_WU = 1200
TIEMPO_INSTALACION_WU = 4 * 3600

# Códigos de salida de winget (HRESULT como entero sin signo). Por verificar contra la
# documentación de winget-cli (doc/windows/package-manager/winget/returnCodes.md).
WINGET_SIN_ACTUALIZACION = 0x8A15002B  # UPDATE_NOT_APPLICABLE
WINGET_REINICIO = {0x8A150109, 0x8A15010A, 3010, 1641}  # reinicio para terminar

CATEGORIAS_WU = {
    "seguridad": "0FA1201D-4330-4FA8-8AE9-B877473B6441",  # Security Updates
    "criticas": "E6CF1350-C01B-414D-A61F-263D14D133B4",  # Critical Updates
}
PERFILES_FIREWALL = ("Domain", "Private", "Public")

_ARQUITECTURA = re.compile(r"\((?:x64|x86|64-bit|32-bit|arm64|64 bits|32 bits)\)", re.IGNORECASE)
_TOKEN_VERSION = re.compile(r"^v?\d+(?:[.\-_]\d+)+[a-z0-9.\-]*$|^v?\d+$", re.IGNORECASE)
_SIGNOS = re.compile(r"[^\w+\-]+")


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------


def clave_version(version: str | None) -> tuple:
    """Clave de orden para versiones de programas de Windows (7.13, 24.08, 1.2.3-beta)."""
    if not version:
        return ()
    partes = re.findall(r"\d+|[A-Za-z]+", version)
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower()) for p in partes)


def cumple(version: str | None, minimo: str | None, estricto: bool) -> bool:
    if not version or not minimo:
        return False
    a, b = clave_version(version), clave_version(minimo)
    return a > b if estricto else a >= b


def nombre_base(nombre: str) -> str:
    """'WinRAR 6.22 (64-bit)' y 'WinRAR 7.13 (64-bit)' -> 'winrar'. Sirve para encontrar
    el mismo programa en el registro después de actualizarlo (el nombre trae la versión)."""
    sin_arquitectura = _ARQUITECTURA.sub(" ", nombre or "")
    tokens = [
        t
        for t in (_SIGNOS.sub(" ", p).strip() for p in sin_arquitectura.split())
        if t and not _TOKEN_VERSION.match(t)
    ]
    return " ".join(tokens).lower()


def _json_ps(paso: dict[str, Any]) -> Any:
    """El JSON que imprime un guion de PowerShell: la última línea que se lee como JSON
    (antes pueden salir avisos)."""
    if paso.get("codigo") != 0:
        return None
    for linea in reversed((paso.get("salida") or "").splitlines()):
        linea = linea.strip()
        if linea[:1] in ("{", "["):
            try:
                return json.loads(linea)
            except ValueError:
                continue
    return None


def _powershell(corredor: Corredor, guion: str, tiempo: int = 300, anotar: bool = True) -> dict:
    return corredor.correr([*POWERSHELL, "-Command", guion], tiempo, anotar=anotar)


def localizar_winget() -> str | None:
    """winget.exe. Como SYSTEM no está en el PATH: se busca en WindowsApps la versión más
    nueva de App Installer."""
    ruta = shutil.which("winget")
    if ruta:
        return ruta
    base = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WindowsApps"
    try:
        candidatos = list(base.glob("Microsoft.DesktopAppInstaller_*__8wekyb3d8bbwe/winget.exe"))
    except OSError:
        return None

    def version(ruta: Path) -> tuple:
        partes = ruta.parent.name.split("_")
        return clave_version(partes[1] if len(partes) > 1 else "")

    return str(max(candidatos, key=version)) if candidatos else None


def programas_de_maquina() -> list[dict[str, Any]]:
    from agente_local import windows

    return [p for p in windows.software() if p.get("ambito") == "maquina"]


def programas_de_usuario() -> list[dict[str, Any]]:
    from agente_local import windows

    return [p for p in windows.software() if p.get("ambito") == "usuario"]


# ---------------------------------------------------------------------------
# winget
# ---------------------------------------------------------------------------


def versiones_de_show(salida: str) -> list[str]:
    """Versiones que lista `winget show --versions` (una por línea, después del encabezado)."""
    versiones = []
    for linea in salida.splitlines():
        valor = linea.strip()
        if catalogo.VERSION.match(valor) and valor not in versiones:
            versiones.append(valor)
    return versiones


class Winget:
    def __init__(
        self,
        corredor: Corredor,
        leer_maquina: Any = programas_de_maquina,
        leer_usuario: Any = programas_de_usuario,
        winget: str | None | type = type,
    ):
        self.corredor = corredor
        self.leer_maquina = leer_maquina
        self.leer_usuario = leer_usuario
        self._winget = localizar_winget() if winget is type else winget

    def _comunes(self) -> list[str]:
        return ["--accept-source-agreements", "--disable-interactivity"]

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]:
        objetivo = nombre_base(accion["programa"])
        versiones = [
            p.get("version")
            for p in self.leer_maquina()
            if objetivo and nombre_base(p.get("programa") or "") == objetivo and p.get("version")
        ]
        version = max(versiones, key=clave_version) if versiones else None
        return {"version": version, "entradas": str(len(versiones))}

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo:
        if not self._winget:
            return Previo(OMITIDO, "winget no está disponible en este equipo (App Installer)")
        if not antes.get("version"):
            objetivo = nombre_base(accion["programa"])
            de_usuario = any(
                nombre_base(p.get("programa") or "") == objetivo for p in self.leer_usuario()
            )
            if de_usuario:
                return Previo(
                    OMITIDO,
                    "instalado solo para un usuario: el agente actualiza instalaciones de "
                    "máquina. Actualizar desde la sesión de ese usuario",
                )
            return Previo(OMITIDO, f"no se encontró {accion['programa']} instalado en el equipo")
        if accion.get("minimo") and cumple(antes["version"], accion["minimo"], accion["estricto"]):
            return Previo(YA_AL_DIA, f"la versión {antes['version']} ya cumple el mínimo")
        return Previo()

    def respaldar(self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo) -> Respaldo:
        paso = self.corredor.correr(
            [
                self._winget,
                "show",
                "--id",
                accion["paquete"],
                "--exact",
                "--versions",
                *self._comunes(),
            ],
            300,
        )
        versiones = versiones_de_show(paso["salida"]) if paso["codigo"] == 0 else []
        if antes["version"] in versiones:
            return Respaldo(True, datos={"versiones": versiones[:20]})
        return Respaldo(
            False,
            f"el catálogo de winget ya no ofrece la versión {antes['version']} para volver atrás",
        )

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]:
        # Siempre a la última versión del catálogo: fijar la mínima fallaría si el catálogo
        # ya no la tiene, y la última también cumple. La verificación mide el resultado.
        paso = self.corredor.correr(
            [
                self._winget,
                "upgrade",
                "--id",
                accion["paquete"],
                "--exact",
                "--silent",
                "--accept-package-agreements",
                *self._comunes(),
            ],
            TIEMPO_WINGET,
        )
        codigo = paso["codigo"] & 0xFFFFFFFF if paso["codigo"] is not None else None
        return {"codigo": codigo}

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion:
        nueva, previa = despues.get("version"), antes.get("version")
        reinicio = aplicado.get("codigo") in WINGET_REINICIO
        if not nueva:
            return Verificacion(False, "después de actualizar no se encontró el programa")
        if accion.get("minimo"):
            if cumple(nueva, accion["minimo"], accion["estricto"]):
                return Verificacion(True, f"{previa} -> {nueva}", reinicio, True)
            if aplicado.get("codigo") == WINGET_SIN_ACTUALIZACION:
                return Verificacion(
                    False,
                    f"winget no ofrece una versión que cumpla el mínimo ({accion['minimo']})",
                )
            return Verificacion(False, f"quedó en {nueva}, no cumple el mínimo {accion['minimo']}")
        if clave_version(nueva) > clave_version(previa):
            return Verificacion(True, f"{previa} -> {nueva}", reinicio)
        return Verificacion(False, f"la versión no cambió ({nueva})")

    def revertir(self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo) -> None:
        self.corredor.correr(
            [
                self._winget,
                "install",
                "--id",
                accion["paquete"],
                "--exact",
                "--version",
                antes["version"],
                "--force",
                "--silent",
                "--accept-package-agreements",
                *self._comunes(),
            ],
            TIEMPO_WINGET,
        )

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool:
        return a.get("version") == b.get("version")


# ---------------------------------------------------------------------------
# Windows Update
# ---------------------------------------------------------------------------


def _guion_buscar(guids: list[str]) -> str:
    lista = ",".join(f"'{g}'" for g in guids)
    return (
        "$ErrorActionPreference='Stop';"
        f"$cat=@({lista});"
        "$s=New-Object -ComObject Microsoft.Update.Session;$s.ClientApplicationID='radar-agente';"
        "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\");"
        "$l=@();foreach($u in $r.Updates){foreach($c in $u.Categories){"
        "if($cat -contains $c.CategoryID.ToUpper()){$l+=$u;break}}};"
        "$kb=@($l|ForEach-Object{$_.KBArticleIDs|ForEach-Object{'KB'+$_}});"
        "[pscustomobject]@{pendientes=$l.Count;kbs=($kb -join ',')}|ConvertTo-Json -Compress"
    )


def _guion_instalar(guids: list[str]) -> str:
    lista = ",".join(f"'{g}'" for g in guids)
    return (
        "$ErrorActionPreference='Stop';"
        f"$cat=@({lista});"
        "$s=New-Object -ComObject Microsoft.Update.Session;$s.ClientApplicationID='radar-agente';"
        "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\");"
        "$c=New-Object -ComObject Microsoft.Update.UpdateColl;"
        "foreach($u in $r.Updates){foreach($k in $u.Categories){"
        "if($cat -contains $k.CategoryID.ToUpper()){if(-not $u.EulaAccepted){$u.AcceptEula()};"
        "[void]$c.Add($u);break}}};"
        "if($c.Count -eq 0){[pscustomobject]@{total=0;ok=0;fallidas='';reinicio=$false}"
        "|ConvertTo-Json -Compress;exit 0};"
        "$d=$s.CreateUpdateDownloader();$d.Updates=$c;[void]$d.Download();"
        "$i=$s.CreateUpdateInstaller();$i.Updates=$c;$res=$i.Install();"
        "$ok=0;$f=@();for($n=0;$n -lt $c.Count;$n++){$rc=$res.GetUpdateResult($n).ResultCode;"
        "if($rc -eq 2 -or $rc -eq 3){$ok++}else{$f+=('KB'+($c.Item($n).KBArticleIDs -join '+'))}};"
        "[pscustomobject]@{total=$c.Count;ok=$ok;fallidas=($f -join ',');"
        "reinicio=[bool]$res.RebootRequired}|ConvertTo-Json -Compress"
    )


def build_actual() -> str | None:
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as clave:
            build = winreg.QueryValueEx(clave, "CurrentBuild")[0]
            ubr = winreg.QueryValueEx(clave, "UBR")[0]
        return f"10.0.{build}.{ubr}"
    except (ImportError, OSError):
        return None


class WindowsUpdate:
    def __init__(self, corredor: Corredor, leer_build: Any = build_actual):
        self.corredor = corredor
        self.leer_build = leer_build

    def _guids(self, accion: dict[str, Any]) -> list[str]:
        return [CATEGORIAS_WU[c] for c in sorted(set(accion["categorias"])) if c in CATEGORIAS_WU]

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]:
        paso = _powershell(self.corredor, _guion_buscar(self._guids(accion)), TIEMPO_BUSQUEDA_WU)
        datos = _json_ps(paso)
        if isinstance(datos, dict):
            return {
                "build": self.leer_build(),
                "pendientes": str(datos.get("pendientes", "")),
                "kbs": str(datos.get("kbs") or "")[:160],
            }
        raise RuntimeError("no se pudo consultar Windows Update")

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo:
        if antes.get("pendientes") == "0":
            return Previo(YA_AL_DIA, "no hay actualizaciones de seguridad ni críticas pendientes")
        return Previo()

    def respaldar(self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo) -> Respaldo:
        return Respaldo(
            False,
            "las actualizaciones acumulativas de Windows no se desinstalan de forma segura; "
            "queda el punto de restauración",
        )

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]:
        paso = _powershell(
            self.corredor, _guion_instalar(self._guids(accion)), TIEMPO_INSTALACION_WU
        )
        datos = _json_ps(paso)
        if isinstance(datos, dict):
            return datos
        raise RuntimeError("la instalación de Windows Update no devolvió resultado")

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion:
        total, ok = int(aplicado.get("total") or 0), int(aplicado.get("ok") or 0)
        reinicio = bool(aplicado.get("reinicio"))
        if total and ok == total:
            texto = f"{ok} actualizaciones instaladas"
            if reinicio:
                texto += "; el cambio se completa al reiniciar"
            return Verificacion(True, texto, reinicio)
        fallidas = aplicado.get("fallidas") or ""
        return Verificacion(
            False, f"{ok} de {total} instaladas; fallaron: {fallidas}"[:300], reinicio
        )

    def revertir(self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo) -> None:
        raise RuntimeError("Windows Update no se revierte desde el agente")

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool:
        return a.get("pendientes") == b.get("pendientes") and a.get("build") == b.get("build")


# ---------------------------------------------------------------------------
# Postura
# ---------------------------------------------------------------------------

_GUION_FIREWALL = (
    "Get-NetFirewallProfile -PolicyStore ActiveStore|ForEach-Object{"
    "[pscustomobject]@{n=[string]$_.Name;e=[string]$_.Enabled}}|ConvertTo-Json -Compress"
)
_GUION_DEFENDER = (
    "$m=Get-MpComputerStatus;[pscustomobject]@{modo=[string]$m.AMRunningMode;"
    "tiempo_real=[string]$m.RealTimeProtectionEnabled;"
    "firmas=[string]$m.AntivirusSignatureVersion;"
    "actualizadas=$m.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')}"
    "|ConvertTo-Json -Compress"
)


class PosturaWindows:
    def __init__(self, corredor: Corredor, ahora: Any = None):
        self.corredor = corredor
        self.ahora = ahora or (lambda: datetime.now(UTC))

    def medir(self, accion: dict[str, Any]) -> dict[str, Any]:
        regla = accion["regla"]
        if regla == "firewall":
            datos = _json_ps(_powershell(self.corredor, _GUION_FIREWALL, anotar=False))
            filas = datos if isinstance(datos, list) else [datos] if isinstance(datos, dict) else []
            perfiles = {f.get("n"): f.get("e") for f in filas if f.get("n") in PERFILES_FIREWALL}
            if set(perfiles) != set(PERFILES_FIREWALL):
                raise RuntimeError("no se pudo leer el estado del firewall")
            return perfiles
        datos = _json_ps(_powershell(self.corredor, _GUION_DEFENDER, anotar=False))
        if isinstance(datos, dict):
            return {
                k: str(datos.get(k) or "")
                for k in ("modo", "tiempo_real", "firmas", "actualizadas")
            }
        raise RuntimeError("no se pudo leer el estado de Microsoft Defender")

    def _edad_firmas(self, medido: dict[str, Any]) -> timedelta | None:
        try:
            momento = datetime.fromisoformat(medido.get("actualizadas", "").replace("Z", "+00:00"))  # noqa: FURB162 - Python 3.10
        except ValueError:
            return None
        if momento.tzinfo is None:
            momento = momento.replace(tzinfo=UTC)
        return self.ahora() - momento

    def prechequear(self, accion: dict[str, Any], antes: dict[str, Any]) -> Previo:
        regla = accion["regla"]
        if regla == "firewall":
            if all(v == "True" for v in antes.values()):
                return Previo(YA_AL_DIA, "el firewall ya está activo en los tres perfiles")
            return Previo()
        if antes.get("modo") not in ("Normal", ""):
            return Previo(
                OMITIDO,
                f"Microsoft Defender no es el antivirus activo (modo {antes.get('modo')}): "
                "revisar la consola del otro antivirus",
            )
        if regla == "antivirus" and antes.get("tiempo_real") == "True":
            return Previo(YA_AL_DIA, "la protección en tiempo real ya está activa")
        if regla == "firmas_al_dia":
            edad = self._edad_firmas(antes)
            if edad is not None and edad < timedelta(days=1):
                return Previo(YA_AL_DIA, "las firmas tienen menos de un día")
        return Previo()

    def respaldar(self, accion: dict[str, Any], antes: dict[str, Any], previo: Previo) -> Respaldo:
        if accion["regla"] == "firmas_al_dia":
            return Respaldo(
                False, "una actualización de firmas no se deshace (no cambia la configuración)"
            )
        return Respaldo(True)

    def aplicar(self, accion: dict[str, Any], previo: Previo) -> dict[str, Any]:
        regla = accion["regla"]
        guion = {
            "firewall": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
            "antivirus": "Set-MpPreference -DisableRealtimeMonitoring $false",
            "firmas_al_dia": "Update-MpSignature",
        }[regla]
        paso = _powershell(self.corredor, "$ErrorActionPreference='Stop';" + guion, 900)
        if paso["codigo"] != 0:
            raise RuntimeError(f"PowerShell terminó con código {paso['codigo']}")
        return {}

    def verificar(
        self,
        accion: dict[str, Any],
        antes: dict[str, Any],
        despues: dict[str, Any],
        aplicado: dict[str, Any],
    ) -> Verificacion:
        regla = accion["regla"]
        if regla == "firewall":
            ok = all(despues.get(p) == "True" for p in PERFILES_FIREWALL)
            apagados = [p for p in PERFILES_FIREWALL if despues.get(p) != "True"]
            return Verificacion(
                ok,
                "activo en los tres perfiles"
                if ok
                else f"sigue apagado en: {', '.join(apagados)} (¿directiva de grupo?)",
            )
        if regla == "antivirus":
            ok = despues.get("tiempo_real") == "True"
            return Verificacion(
                ok,
                "protección en tiempo real activa"
                if ok
                else "sigue apagada (¿protección contra alteraciones o directiva?)",
            )
        edad = self._edad_firmas(despues)
        ok = despues.get("firmas") != antes.get("firmas") or (
            edad is not None and edad < timedelta(days=1)
        )
        return Verificacion(ok, f"firmas {antes.get('firmas')} -> {despues.get('firmas')}")

    def revertir(self, accion: dict[str, Any], antes: dict[str, Any], respaldo: Respaldo) -> None:
        regla = accion["regla"]
        if regla == "firewall":
            ordenes = [
                f"Set-NetFirewallProfile -Profile {perfil} -Enabled "
                + ("True" if antes.get(perfil) == "True" else "False")
                for perfil in PERFILES_FIREWALL
            ]
            _powershell(self.corredor, "$ErrorActionPreference='Stop';" + ";".join(ordenes), 300)
        elif regla == "antivirus":
            valor = "$false" if antes.get("tiempo_real") == "True" else "$true"
            _powershell(self.corredor, f"Set-MpPreference -DisableRealtimeMonitoring {valor}", 300)

    def igual(self, accion: dict[str, Any], a: dict[str, Any], b: dict[str, Any]) -> bool:
        if accion["regla"] == "firewall":
            return all(a.get(p) == b.get(p) for p in PERFILES_FIREWALL)
        if accion["regla"] == "antivirus":
            return a.get("tiempo_real") == b.get("tiempo_real")
        return a.get("firmas") == b.get("firmas")


# ---------------------------------------------------------------------------
# Punto de restauración y reinicio pendiente
# ---------------------------------------------------------------------------


def punto_restauracion(corredor: Corredor, descripcion: str) -> dict[str, Any]:
    """Crea un punto de restauración del sistema. Windows no crea más de uno cada 24 horas:
    si ya hay uno reciente, se usa ese y se dice."""
    descripcion = re.sub(r"[^A-Za-z0-9 ]", "", descripcion)[:60]
    paso = _powershell(
        corredor,
        "$ErrorActionPreference='Stop';"
        f"Checkpoint-Computer -Description '{descripcion}' -RestorePointType MODIFY_SETTINGS "
        "-WarningAction SilentlyContinue;"
        "$p=Get-ComputerRestorePoint|Sort-Object SequenceNumber|Select-Object -Last 1;"
        "if($p){[pscustomobject]@{d=[string]$p.Description;"
        "f=([Management.ManagementDateTimeConverter]::ToDateTime($p.CreationTime))"
        ".ToUniversalTime().ToString('o')}|ConvertTo-Json -Compress}else{'{}'}",
        600,
    )
    datos = _json_ps(paso)
    if not isinstance(datos, dict) or not datos.get("f"):
        return {
            "creado": False,
            "detalle": "no se pudo crear (¿Protección del sistema apagada en C:?)",
        }
    try:
        momento = datetime.fromisoformat(datos["f"].replace("Z", "+00:00"))  # noqa: FURB162 - Python 3.10
    except ValueError:
        return {"creado": False, "detalle": "fecha del punto de restauración ilegible"}
    if momento.tzinfo is None:
        momento = momento.replace(tzinfo=UTC)
    if datos.get("d") == descripcion:
        return {"creado": True, "detalle": f"'{descripcion}' creado {datos['f'][:19]}"}
    if datetime.now(UTC) - momento < timedelta(hours=24):
        return {
            "creado": True,
            "detalle": f"se usa el punto '{datos.get('d')}' de {datos['f'][:19]} (Windows crea uno "
            "cada 24 horas como máximo)",
        }
    return {"creado": False, "detalle": "Windows no creó el punto de restauración"}


def reinicio_pendiente(corredor: Corredor) -> bool:
    paso = _powershell(
        corredor,
        "(Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based "
        "Servicing\\RebootPending') -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
        "CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')",
        60,
        anotar=False,
    )
    return paso["codigo"] == 0 and paso["salida"].strip().splitlines()[-1:] == ["True"]


def contexto(corredor: Corredor) -> dict[str, Any]:
    """Ejecutores y ganchos de Windows para `parcheo.Contexto`."""
    return {
        "ejecutores": {
            "winget": Winget(corredor),
            "windows_update": WindowsUpdate(corredor),
            "postura_windows": PosturaWindows(corredor),
        },
        "punto_restauracion": lambda descripcion: punto_restauracion(corredor, descripcion),
        "reinicio_pendiente": lambda: reinicio_pendiente(corredor),
    }
