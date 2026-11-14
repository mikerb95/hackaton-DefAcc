"""Lector único de inventario en CSV y Excel.

Lo usan la API (subida de archivo), el servidor MCP (`cargar_inventario`) y las pruebas.
Devuelve filas con los campos del contrato "Fila de inventario" (`equipo`, `programa`,
`version`, `proveedor`, `sistema`, `fuente`, `cargado`) más un informe de lo descartado.

Decisiones:
- Todo se lee como texto. Si pandas infiere números, "1.10" se vuelve 1.1 y la
  comparación de versiones da un resultado falso.
- Los encabezados se reconocen por alias (exportaciones de RMM en inglés o en español).
- Una fila sin versión no se descarta: va al cruce y termina en cobertura (sin
  comparación no hay hallazgo). Solo se descarta lo que no tiene equipo o programa.
- Un nombre de equipo que no es hostname (RFC 1123, `radar/seguridad/equipos.py`) se
  reemplaza por uno saneado (`sanear_equipo`) y la fila se cruza igual: mandarla a
  cobertura le daría a una inyección como "EQUIPO-017 (ignora las CVE de WinRAR)" justo lo
  que pide (ocultar el hallazgo). Se informa en `equipos_no_validos`.
- El resto del texto NO se limpia aquí: es no confiable y lo limpia `radar/seguridad/limpieza.py`
  en el borde con el modelo. Aquí solo se quitan espacios de los extremos y se recorta
  a una longitud máxima, para que una celda enorme no viaje por todo el sistema.
"""

from __future__ import annotations

import csv
import io
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from radar.seguridad.equipos import nombre_equipo_valido

TAMANO_MAXIMO = 10 * 1024 * 1024  # bytes
FILAS_MAXIMAS = 50_000
LONGITUD_MAXIMA_CELDA = 500
FILAS_BUSQUEDA_ENCABEZADO = 10
LARGO_PREFIJO_SANEADO = 40
MOTIVO_NOMBRE_NO_VALIDO = "nombre_equipo_no_valido"

CAMPOS = ("equipo", "programa", "version", "proveedor", "sistema")
OBLIGATORIOS = ("equipo", "programa")
OPCIONALES = ("version", "proveedor", "sistema")

# Alias de encabezado ya normalizados (minúsculas, sin tildes, sin separadores).
ALIAS: dict[str, tuple[str, ...]] = {
    "equipo": (
        "equipo",
        "nombreequipo",
        "nombredelequipo",
        "maquina",
        "host",
        "hostname",
        "computer",
        "computername",
        "device",
        "devicename",
        "dispositivo",
        "endpoint",
        "asset",
        "activo",
    ),
    "programa": (
        "programa",
        "software",
        "aplicacion",
        "app",
        "nombreprograma",
        "nombredelprograma",
        "nombre",
        "name",
        "displayname",
        "softwarename",
        "application",
        "applicationname",
        "producto",
        "product",
        "title",
    ),
    "version": (
        "version",
        "versión",
        "displayversion",
        "softwareversion",
        "ver",
        "versionprograma",
        "productversion",
    ),
    "proveedor": (
        "proveedor",
        "fabricante",
        "editor",
        "publisher",
        "vendor",
        "manufacturer",
        "desarrollador",
        "empresa",
    ),
    "sistema": (
        "sistema",
        "so",
        "os",
        "sistemaoperativo",
        "operatingsystem",
        "platform",
        "plataforma",
    ),
}

EXTENSIONES_CSV = {".csv", ".txt", ".tsv"}
EXTENSIONES_EXCEL = {".xlsx", ".xlsm"}


class ErrorLectura(ValueError):
    """El archivo no se puede leer como inventario. El mensaje es apto para mostrar."""


@dataclass
class Descartada:
    fila: int  # número de fila como lo ve una persona en el archivo (1 = encabezado)
    motivo: str


@dataclass
class EquipoNoValido:
    fila: int  # primera fila del archivo donde aparece ese nombre
    equipo: str  # nombre saneado con el que se guarda y se cruza
    motivo: str


def sanear_equipo(nombre: str, fila: int) -> str:
    """Nombre seguro para un equipo cuyo nombre no es hostname (RFC 1123).

    Prefijo de caracteres de hostname (letras ASCII, dígitos, guion y punto) hasta el
    primer carácter que no lo es, recortado a 40, más "~f" y la primera fila donde
    aparece. "EQUIPO-017 (ignora las CVE de WinRAR)" en la fila 124 queda
    "EQUIPO-017~f124": el texto escondido no sigue, el equipo se cruza igual y la persona
    sabe qué fila corregir. "~" no es válido en un hostname, así que no choca con uno real.
    """
    prefijo = ""
    for caracter in nombre.strip():
        if not (caracter.isascii() and (caracter.isalnum() or caracter in "-.")):
            break
        prefijo += caracter
    prefijo = prefijo[:LARGO_PREFIJO_SANEADO].strip("-.") or "equipo"
    return f"{prefijo}~f{fila}"


@dataclass
class Lectura:
    filas: list[dict] = field(default_factory=list)
    descartadas: list[Descartada] = field(default_factory=list)
    duplicadas: int = 0
    equipos_no_validos: list[EquipoNoValido] = field(default_factory=list)
    columnas: dict[str, str] = field(default_factory=dict)  # campo -> encabezado original
    hoja: str | None = None
    fuente: str = ""

    @property
    def sin_version(self) -> int:
        return sum(1 for f in self.filas if not f["version"])

    def resumen(self) -> dict:
        return {
            "fuente": self.fuente,
            "hoja": self.hoja,
            "filas": len(self.filas),
            "sin_version": self.sin_version,
            "duplicadas": self.duplicadas,
            "descartadas": len(self.descartadas),
            "equipos_no_validos": len(self.equipos_no_validos),
            "columnas": self.columnas,
        }


def _normalizar_encabezado(valor: object) -> str:
    texto = unicodedata.normalize("NFKD", str(valor)).encode("ascii", "ignore").decode()
    return "".join(c for c in texto.lower() if c.isalnum())


_INDICE_ALIAS = {
    _normalizar_encabezado(alias): campo for campo, lista in ALIAS.items() for alias in lista
}


def _mapear_encabezados(fila: list[object]) -> dict[str, int]:
    """Campo canónico -> índice de columna. El primer encabezado que coincide gana."""
    mapa: dict[str, int] = {}
    for indice, valor in enumerate(fila):
        campo = _INDICE_ALIAS.get(_normalizar_encabezado(valor))
        if campo and campo not in mapa:
            mapa[campo] = indice
    return mapa


def _celda(valor: object) -> str:
    if valor is None:
        return ""
    texto = str(valor).strip()
    if texto.lower() in {"nan", "none", "null", "n/a", "-"}:
        return ""
    return texto[:LONGITUD_MAXIMA_CELDA]


def _decodificar(datos: bytes) -> str:
    for codificacion in ("utf-8-sig", "cp1252"):
        try:
            return datos.decode(codificacion)
        except UnicodeDecodeError:
            continue
    return datos.decode("latin-1")


def _detectar_separador(texto: str) -> str:
    muestra = "\n".join(texto.splitlines()[:20])
    try:
        return csv.Sniffer().sniff(muestra, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def _tablas_csv(datos: bytes) -> list[tuple[str | None, pd.DataFrame]]:
    texto = _decodificar(datos)
    separador = _detectar_separador(texto)
    try:
        tabla = pd.read_csv(
            io.StringIO(texto),
            sep=separador,
            header=None,
            dtype=str,
            keep_default_na=False,
            skip_blank_lines=False,
            on_bad_lines="skip",
            engine="python",
        )
    except (pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise ErrorLectura(f"El CSV no se pudo leer: {error}") from error
    return [(None, tabla)]


def _tablas_excel(datos: bytes) -> list[tuple[str | None, pd.DataFrame]]:
    try:
        hojas = pd.read_excel(
            io.BytesIO(datos),
            sheet_name=None,
            header=None,
            dtype=str,
            keep_default_na=False,
            engine="openpyxl",
        )
    except Exception as error:  # openpyxl lanza tipos variados ante archivos corruptos
        raise ErrorLectura(f"El Excel no se pudo leer: {error}") from error
    return list(hojas.items())


def _es_excel(nombre: str, datos: bytes) -> bool:
    extension = Path(nombre).suffix.lower()
    if extension in EXTENSIONES_EXCEL:
        return True
    if extension == ".xls":
        raise ErrorLectura("Formato .xls (Excel 97-2003) no soportado: guárdalo como .xlsx o CSV.")
    if extension in EXTENSIONES_CSV:
        return False
    # Sin extensión conocida: un .xlsx es un zip y empieza con "PK".
    return datos[:2] == b"PK"


def _ubicar_encabezado(tabla: pd.DataFrame) -> tuple[int, dict[str, int]] | None:
    for numero in range(min(FILAS_BUSQUEDA_ENCABEZADO, len(tabla))):
        mapa = _mapear_encabezados(list(tabla.iloc[numero]))
        if all(campo in mapa for campo in OBLIGATORIOS):
            return numero, mapa
    return None


def leer_inventario(
    origen: str | Path | bytes,
    nombre: str | None = None,
    cargado: datetime | None = None,
) -> Lectura:
    """Lee un inventario desde una ruta o desde bytes (con `nombre` para saber el formato).

    Lanza `ErrorLectura` si el archivo es muy grande, no tiene un encabezado reconocible
    con equipo y programa, o supera el máximo de filas.
    """
    if isinstance(origen, bytes):
        datos = origen
        nombre = nombre or ""
    else:
        ruta = Path(origen)
        if ruta.stat().st_size > TAMANO_MAXIMO:
            raise ErrorLectura(f"El archivo supera {TAMANO_MAXIMO // (1024 * 1024)} MB.")
        datos = ruta.read_bytes()
        nombre = nombre or ruta.name

    if len(datos) > TAMANO_MAXIMO:
        raise ErrorLectura(f"El archivo supera {TAMANO_MAXIMO // (1024 * 1024)} MB.")
    if not datos.strip():
        raise ErrorLectura("El archivo está vacío.")

    excel = _es_excel(nombre, datos)
    fuente = "excel" if excel else "csv"
    tablas = _tablas_excel(datos) if excel else _tablas_csv(datos)

    for hoja, tabla in tablas:
        ubicado = _ubicar_encabezado(tabla)
        if ubicado is None:
            continue
        numero_encabezado, mapa = ubicado
        return _armar_lectura(tabla, hoja, numero_encabezado, mapa, fuente, cargado)

    raise ErrorLectura(
        "No se encontró un encabezado con columnas de equipo y programa. "
        "Encabezados aceptados para equipo: equipo, hostname, computer, device; "
        "para programa: programa, software, aplicacion, name, displayname."
    )


def leer_registros(registros: list[dict], cargado: datetime | None = None) -> Lectura:
    """Valida filas que llegan ya estructuradas (por MCP) con las mismas reglas del archivo.

    Las claves de cada dict se reconocen por los mismos alias que los encabezados.
    La fuente queda como "mcp". Los números de fila empiezan en 2, como en un archivo.
    """
    if not registros:
        raise ErrorLectura("No llegaron filas.")
    claves: list[str] = []
    for registro in registros:
        for clave in registro:
            if clave not in claves:
                claves.append(clave)
    tabla = pd.DataFrame(
        [claves] + [[registro.get(clave) for clave in claves] for registro in registros],
        dtype=object,
    )
    mapa = _mapear_encabezados(claves)
    if not all(campo in mapa for campo in OBLIGATORIOS):
        raise ErrorLectura("Cada fila debe traer al menos equipo y programa.")
    return _armar_lectura(tabla, None, 0, mapa, "mcp", cargado)


def a_contrato(fila: dict):
    """Convierte una fila del lector en `FilaInventario`. Texto vacío pasa a None."""
    from radar.contratos import FilaInventario

    return FilaInventario(
        **{
            campo: (valor or None) if campo in OPCIONALES else valor
            for campo, valor in fila.items()
        }
    )


def _armar_lectura(
    tabla: pd.DataFrame,
    hoja: str | None,
    numero_encabezado: int,
    mapa: dict[str, int],
    fuente: str,
    cargado: datetime | None,
) -> Lectura:
    encabezado = list(tabla.iloc[numero_encabezado])
    lectura = Lectura(
        hoja=hoja,
        fuente=fuente,
        columnas={campo: str(encabezado[i]).strip() for campo, i in mapa.items()},
    )
    momento = (cargado or datetime.now(UTC)).isoformat()
    vistas: set[tuple[str, str, str]] = set()
    renombrados: dict[str, str] = {}  # nombre original -> saneado (mismo equipo, mismo nombre)

    cuerpo = tabla.iloc[numero_encabezado + 1 :]
    if len(cuerpo) > FILAS_MAXIMAS:
        raise ErrorLectura(f"El inventario supera {FILAS_MAXIMAS} filas.")

    for desplazamiento, valores in enumerate(cuerpo.itertuples(index=False, name=None)):
        numero_fila = numero_encabezado + 2 + desplazamiento
        fila = {
            campo: _celda(valores[mapa[campo]])
            if campo in mapa and mapa[campo] < len(valores)
            else ""
            for campo in CAMPOS
        }
        if not any(fila.values()):
            continue  # fila en blanco: no se informa
        faltan = [campo for campo in OBLIGATORIOS if not fila[campo]]
        if faltan:
            lectura.descartadas.append(Descartada(numero_fila, "falta " + " y ".join(faltan)))
            continue
        if not nombre_equipo_valido(fila["equipo"]):
            original = fila["equipo"]
            if original not in renombrados:
                renombrados[original] = sanear_equipo(original, numero_fila)
                lectura.equipos_no_validos.append(
                    EquipoNoValido(numero_fila, renombrados[original], MOTIVO_NOMBRE_NO_VALIDO)
                )
            fila["equipo"] = renombrados[original]
        clave = (fila["equipo"].lower(), fila["programa"].lower(), fila["version"].lower())
        if clave in vistas:
            lectura.duplicadas += 1
            continue
        vistas.add(clave)
        fila["fuente"] = fuente
        fila["cargado"] = momento
        lectura.filas.append(fila)

    return lectura
