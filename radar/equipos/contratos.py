"""Contratos del agente local: lo que envía un equipo y lo que el radar concluye de él.

Todo el reporte es texto no confiable (cualquier usuario puede crear una entrada en
`HKCU\\...\\Uninstall` con el nombre que quiera, y un equipo comprometido puede mentir).
Por eso cada cadena se limpia y se recorta al validar, y las listas tienen tope. Los
campos desconocidos se ignoran en vez de rechazar el reporte: un agente más nuevo puede
enviar datos que este servidor todavía no usa.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from radar.contratos import Prioridad
from radar.seguridad.limpieza import LONGITUD_MAXIMA, limpiar_texto

Tri = Literal["si", "no", "desconocido"]
Familia = Literal["windows", "linux"]
FuentePrograma = Literal["registro", "dpkg", "rpm", "snap", "flatpak", "appx"]
Ambito = Literal["maquina", "usuario"]
TipoHallazgoEquipo = Literal["postura", "so_sin_soporte", "paquete"]

MAX_PROGRAMAS = 5000
MAX_PARCHES = 2000
TAMANO_MAXIMO_REPORTE = 1024 * 1024  # bytes
# Fuentes cuya versión es la de la distribución: van a OSV, nunca al cruce por CPE.
FUENTES_DE_DISTRIBUCION = frozenset({"dpkg", "rpm"})

_UUID = r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$"


def _corto(valor: Any) -> Any:
    """Cadena limpia y recortada a 160 caracteres. Lo que no es cadena pasa igual."""
    if isinstance(valor, str):
        return limpiar_texto(valor, LONGITUD_MAXIMA)
    return valor


def _corto_o_nada(valor: Any) -> Any:
    if isinstance(valor, str):
        return limpiar_texto(valor, LONGITUD_MAXIMA) or None
    return valor


def _tri(valor: Any) -> Any:
    """Cualquier valor que no sea "si" o "no" es "desconocido": nunca se adivina."""
    return valor if valor in ("si", "no") else "desconocido"


Texto = Annotated[str, BeforeValidator(_corto)]
TextoOpcional = Annotated[str | None, BeforeValidator(_corto_o_nada)]
TriLimpio = Annotated[Tri, BeforeValidator(_tri)]


class _Reportado(BaseModel):
    model_config = ConfigDict(extra="ignore")


class SistemaReportado(_Reportado):
    familia: Familia
    nombre: Texto = ""
    version: TextoOpcional = None
    build: TextoOpcional = Field(default=None, description="Windows: 10.0.22631.4317")
    kernel: TextoOpcional = None
    arquitectura: TextoOpcional = None
    edicion: TextoOpcional = Field(default=None, description="EditionID o VERSION_CODENAME")
    distro: TextoOpcional = Field(default=None, description="ID de os-release: ubuntu, debian...")
    parches: list[str] = Field(default_factory=list)

    @field_validator("parches", mode="before")
    @classmethod
    def _acotar_parches(cls, valor: Any) -> Any:
        if not isinstance(valor, list):
            return []
        return [limpiar_texto(p, 40) for p in valor[:MAX_PARCHES] if isinstance(p, str)]


class HardwareReportado(_Reportado):
    fabricante: TextoOpcional = None
    modelo: TextoOpcional = None
    bios: TextoOpcional = None
    cpu: TextoOpcional = None
    ram_gb: float | None = Field(default=None, ge=0, le=100_000)
    tpm: TextoOpcional = None
    portatil: TriLimpio = "desconocido"


class PosturaReportada(_Reportado):
    firewall: TriLimpio = "desconocido"
    antivirus: TriLimpio = "desconocido"
    firmas_al_dia: TriLimpio = "desconocido"
    cifrado_disco: TriLimpio = "desconocido"
    secure_boot: TriLimpio = "desconocido"
    actualizaciones_automaticas: TriLimpio = "desconocido"

    def desconocidos(self) -> list[str]:
        return [campo for campo, valor in self.model_dump().items() if valor == "desconocido"]


class ProgramaReportado(_Reportado):
    programa: Texto = Field(min_length=1)
    version: TextoOpcional = None
    proveedor: TextoOpcional = None
    fuente: FuentePrograma
    ambito: Ambito = "maquina"
    origen: TextoOpcional = Field(default=None, description="Paquete fuente (dpkg, rpm)")
    version_origen: TextoOpcional = None


class ReporteEquipo(_Reportado):
    agente_version: Texto
    equipo_id: str = Field(pattern=_UUID)
    nombre_equipo: str = Field(min_length=1, max_length=2000)
    recogido: datetime
    so: SistemaReportado
    hardware: HardwareReportado = Field(default_factory=HardwareReportado)
    postura: PosturaReportada = Field(default_factory=PosturaReportada)
    software: list[ProgramaReportado] = Field(default_factory=list)

    @field_validator("recogido")
    @classmethod
    def _con_zona(cls, valor: datetime) -> datetime:
        return valor if valor.tzinfo else valor.replace(tzinfo=UTC)


class HallazgoEquipo(BaseModel):
    """Algo que está mal en un equipo concreto y no es una CVE de una aplicación: postura,
    sistema operativo sin soporte o un paquete de la distribución con avisos."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="'equipo_id|tipo|clave'")
    equipo_id: str
    tipo: TipoHallazgoEquipo
    clave: str = Field(description="Regla de postura o nombre del paquete")
    titulo: str
    prioridad: Prioridad
    por_que: list[str] = Field(default_factory=list)
    pasos: str = Field(default="", description="Qué hacer, en texto armado por código")
    comandos: list[str] = Field(default_factory=list, description="Solo de plantillas cerradas")
    detalle: dict[str, Any] = Field(default_factory=dict)
    detectado: datetime | None = None


def id_hallazgo(equipo_id: str, tipo: str, clave: str) -> str:
    return f"{equipo_id}|{tipo}|{clave}"
