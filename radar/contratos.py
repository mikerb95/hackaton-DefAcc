"""Contratos de datos compartidos por todos los frentes (PLAN, sección 9).

Un cambio aquí rompe a todos: se anuncia en .coordinacion/nucleo.md antes de hacerlo.

Convenciones:
- `None` significa "no se sabe" y nunca equivale a cero. Un EPSS ausente es `None`,
  no 0.0 (regla 2: fuente caída no es cero).
- Las versiones se guardan como texto tal cual llegan. La comparación vive en
  radar/nucleo/versiones.py.
- Los pares de CPE se escriben "vendor:producto", con el escape de NVD intacto
  (por ejemplo "notepad-plus-plus:notepad\\+\\+").
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# Valores cerrados. Se exportan para que la API, el panel y el agente usen los mismos.
Fuente = Literal["csv", "excel", "mcp", "rmm", "agente"]
Prioridad = Literal["inmediato", "semanal", "informativo", "boletin"]
EstadoHallazgo = Literal["nuevo", "en_curso", "mitigado", "descartado"]
MetodoCpe = Literal["exacto", "difuso", "modelo", "ninguno"]
MotivoCobertura = Literal["sin_version", "no_comparable", "sin_cpe"]
TipoObjetivo = Literal["exacta", "posterior_a", "ninguna"]
OrigenAnalisis = Literal["agente", "respaldo"]
TipoTrabajo = Literal["descargar", "analizar", "cruzar_so"]
EstadoTrabajo = Literal["pendiente", "en_curso", "hecho", "fallido"]

# Orden de la lista de hallazgos: prioridad, luego KEV, luego CVSS (PLAN, sección 8).
ORDEN_PRIORIDAD: dict[str, int] = {"inmediato": 0, "semanal": 1, "informativo": 2, "boletin": 3}


class Contrato(BaseModel):
    """Base común: rechaza campos desconocidos para que un error de nombre falle pronto."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# Inventario
# ---------------------------------------------------------------------------


class FilaInventario(Contrato):
    """Una fila del inventario tal como llega (CSV, Excel, MCP, RMM o agente local).

    Todo texto de aquí es no confiable: antes de llegar al modelo pasa por
    radar/seguridad/limpieza.py.
    """

    equipo: str
    programa: str
    version: str | None = None
    proveedor: str | None = None
    sistema: str | None = None
    fuente: Fuente
    cargado: datetime


class Activo(Contrato):
    """Un producto normalizado en una versión concreta, con los equipos que lo tienen."""

    clave: str = Field(
        description="producto@version con el nombre canónico, por ejemplo 'WinRAR@5.61'"
    )
    producto: str = Field(description="Nombre canónico del producto, por ejemplo 'WinRAR'")
    nombre: str = Field(description="Nombre original del programa en el inventario")
    version: str
    cpes: list[str] = Field(
        default_factory=list,
        description="Pares 'vendor:producto'. Puede haber más de uno (Docker Desktop)",
    )
    equipos: list[str] = Field(default_factory=list)
    confianza_cpe: float | None = Field(default=None, ge=0.0, le=1.0)


class Cobertura(Contrato):
    """Fila que no se pudo comparar. Sin comparación no hay hallazgo (regla 1)."""

    equipo: str
    programa: str
    version: str | None = None
    motivo: MotivoCobertura


# ---------------------------------------------------------------------------
# Fuentes: NVD, KEV, EPSS
# ---------------------------------------------------------------------------


class Rango(Contrato):
    """Un cpeMatch de NVD con `vulnerable: true` (las entradas en false se ignoran).

    Si `version` trae valor, el CPE es de versión fija y no hay límites.
    Si no hay versión ni límites, afecta a todas: el hallazgo es "no preciso".
    """

    cpe: str = Field(description="Criterio completo, 'cpe:2.3:a:vendor:producto:...'")
    vendor: str
    producto: str
    version: str | None = None
    desde: str | None = None
    desde_incluye: bool = False
    hasta: str | None = None
    hasta_incluye: bool = False

    @property
    def par(self) -> str:
        return f"{self.vendor}:{self.producto}"

    @property
    def acotado(self) -> bool:
        """True si el rango dice algo sobre la versión (fija o con algún límite)."""
        return self.version is not None or self.desde is not None or self.hasta is not None


class Referencia(Contrato):
    url: str
    etiquetas: list[str] = Field(default_factory=list)


class CVE(Contrato):
    id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    publicada: datetime | None = None
    modificada: datetime | None = None
    estado: str | None = Field(default=None, description="vulnStatus de NVD: Analyzed, Modified...")
    descripcion: str = ""
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    severidad: str | None = None
    vector: str | None = None
    version_cvss: str | None = Field(default=None, description="'4.0', '3.1', '3.0' o '2.0'")
    cwes: list[str] = Field(default_factory=list)
    referencias: list[Referencia] = Field(default_factory=list)
    rangos: list[Rango] = Field(default_factory=list)
    sin_productos: bool = Field(
        default=False, description="La CVE no trae 'configurations': se cuenta aparte"
    )


class SenalKev(Contrato):
    """Entrada del catálogo KEV. Se empareja por ID de CVE, nunca por fabricante (regla 4)."""

    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    fabricante: str | None = None
    producto: str | None = None
    accion: str | None = None
    agregada: date | None = None
    plazo: date | None = None
    ransomware: bool = Field(default=False, description="knownRansomwareCampaignUse == 'Known'")


class SenalEpss(Contrato):
    """Puntaje EPSS de una CVE. Si la CVE no aparece en EPSS, no hay objeto (no es 0)."""

    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    epss: float = Field(ge=0.0, le=1.0)
    percentil: float = Field(ge=0.0, le=1.0)
    fecha: date


class Senales(Contrato):
    """Señales de explotación indexadas por ID de CVE."""

    kev: dict[str, SenalKev] = Field(default_factory=dict)
    epss: dict[str, SenalEpss] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Resultado del cruce
# ---------------------------------------------------------------------------


class Hallazgo(Contrato):
    """Una CVE que afecta a un activo. El estado solo lo cambia una persona."""

    id: str = Field(description="'CVE|activo', por ejemplo 'CVE-2018-20250|WinRAR@5.61'")
    cve: str
    activo: str = Field(description="Clave del activo (producto@version)")
    producto: str
    version_instalada: str
    equipos: list[str] = Field(default_factory=list)
    prioridad: Prioridad
    por_que: list[str] = Field(default_factory=list, description="Razones en texto legible")
    preciso: bool = Field(default=True, description="False si el rango no acota versión")
    rango: Rango | None = Field(default=None, description="El rango más acotado que emparejó")
    kev: bool = False
    ransomware: bool = False
    epss: float | None = Field(default=None, description="None si EPSS no tiene la CVE")
    cvss: float | None = None
    estado: EstadoHallazgo = "nuevo"
    comentario: str | None = None
    por: str | None = Field(default=None, description="Quién decidió el estado")
    detectado: datetime | None = None
    avisado: bool = Field(default=False, description="Ya comunicado: no se vuelve a avisar")
    propuesto_resuelto: bool = Field(
        default=False,
        description="La última corrida ya no lo encontró: se propone cerrarlo (lo decide una persona)",
    )


class Grupo(Contrato):
    """Hallazgos agrupados por producto: es la unidad que se comunica (una acción por producto)."""

    producto: str
    versiones: list[str] = Field(default_factory=list)
    equipos: list[str] = Field(default_factory=list)
    cves: list[str] = Field(default_factory=list, description="IDs sin repetir")
    en_kev: list[str] = Field(default_factory=list, description="IDs de las CVE que están en KEV")
    ransomware: bool = False
    peor_cvss: float | None = None
    peor_epss: float | None = None
    version_objetivo: str | None = Field(
        default=None,
        description="Valor de la versión de arreglo. Ver tipo_objetivo para cómo leerlo",
    )
    tipo_objetivo: TipoObjetivo = Field(
        default="ninguna",
        description=(
            "'exacta': actualizar a version_objetivo. 'posterior_a': solo se sabe que hay "
            "que pasar de version_objetivo (versionEndIncluding, regla 5). 'ninguna': "
            "alguna CVE no acota versión y no se promete nada"
        ),
    )
    prioridad: Prioridad | None = Field(default=None, description="La más alta del grupo")
    por_que: list[str] = Field(default_factory=list)

    @property
    def n_equipos(self) -> int:
        return len(self.equipos)

    @property
    def n_cves(self) -> int:
        return len(self.cves)

    @model_validator(mode="after")
    def _objetivo_coherente(self) -> Grupo:
        if self.tipo_objetivo == "ninguna" and self.version_objetivo is not None:
            raise ValueError("tipo_objetivo 'ninguna' no lleva version_objetivo")
        if self.tipo_objetivo != "ninguna" and self.version_objetivo is None:
            raise ValueError(f"tipo_objetivo '{self.tipo_objetivo}' requiere version_objetivo")
        return self


class Analisis(Contrato):
    """Salida del analista (o del respaldo armado por código). Se asocia a un hallazgo o a un
    producto; en la práctica, a un producto, porque se comunica por producto."""

    hallazgo: str | None = None
    producto: str | None = None
    resumen: str
    como_se_explota: str = Field(description="Solo lo que diga la fuente")
    remediacion: str
    mitigacion_temporal: str | None = None
    comunicado_ti: str
    comunicado_usuarios: str
    comunicado_gerencia: str | None = Field(
        default=None, description="Resumen para gerencia: riesgo, alcance y decisión que se pide"
    )
    verificado: bool = False
    origen: OrigenAnalisis

    @model_validator(mode="after")
    def _un_destino(self) -> Analisis:
        if (self.hallazgo is None) == (self.producto is None):
            raise ValueError("Analisis lleva 'hallazgo' o 'producto', exactamente uno")
        return self


# ---------------------------------------------------------------------------
# Operación
# ---------------------------------------------------------------------------


class Trabajo(Contrato):
    """Cola de trabajos en Turso que consume el worker."""

    id: int | None = None
    tipo: TipoTrabajo
    estado: EstadoTrabajo = "pendiente"
    creado: datetime | None = None
    terminado: datetime | None = None
    detalle: str | None = None


class Ejecucion(Contrato):
    """Una corrida del worker. `fuentes` dice qué respondió: fuente caída no es cero."""

    id: int | None = None
    inicio: datetime
    fin: datetime | None = None
    tipo: TipoTrabajo
    fuentes: dict[str, bool] = Field(default_factory=dict, description="{'nvd': True, ...}")
    resumen: str | None = None
    error: str | None = None
