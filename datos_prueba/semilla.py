"""Semilla del inventario de prueba, transcrita a mano de resources/SEMILLA.md.

Es diseño, no cálculo: aquí no se compara ninguna versión contra NVD. Cada caso dice
cómo lo reporta un RMM (nombre, versión del campo, proveedor), qué par o pares de NVD
le tocan, con qué versión se compara y en cuántos equipos aparece.

La respuesta conocida (qué CVE afectan a cada caso) vive en
resources/semilla_respuesta.json y la arma datos_prueba/respuesta.py.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Semilla del generador aleatorio: cualquiera reproduce el mismo inventario.
SEMILLA_ALEATORIA = 20261114

EQUIPOS = [f"EQUIPO-{n:03d}" for n in range(1, 51)]
SERVIDORES = ["SRV-01", "SRV-02"]

# Los primeros 20 equipos son de desarrollo: ahí viven Node.js, Python, Git, Docker,
# Temurin y MongoDB Compass.
EQUIPOS_DESARROLLO = EQUIPOS[:20]


def sistema_de(equipo: str) -> str:
    """Sistema operativo de cada equipo (columna `sistema` de FilaInventario)."""
    if equipo in SERVIDORES:
        return "Windows Server 2022 Standard"
    n = int(equipo.rsplit("-", 1)[1])
    return "Windows 10 Pro" if n % 7 == 0 else "Windows 11 Pro"


# Nombre canónico por producto: Activo.producto, y Activo.clave = "<canónico>@<versión>".
CANONICO: dict[str, str] = {
    "winrar": "WinRAR",
    "7zip": "7-Zip",
    "notepadpp": "Notepad++",
    "chrome": "Google Chrome",
    "firefox": "Mozilla Firefox",
    "nodejs": "Node.js",
    "python": "Python",
    "docker_desktop": "Docker Desktop",
    "teamviewer": "TeamViewer",
    "git": "Git",
    "temurin": "Eclipse Temurin JDK",
    "acrobat": "Adobe Acrobat Reader",
    "vlc": "VLC media player",
    "putty": "PuTTY",
    "compass": "MongoDB Compass",
    "globalprotect": "GlobalProtect",
    "nginx": "nginx",
}


@dataclass(frozen=True)
class Caso:
    """Un programa en una versión, tal como lo siembra el generador."""

    producto: str  # clave estable del producto (agrupa versiones)
    nombre: str  # como lo reporta el RMM
    proveedor: str
    version_campo: str  # lo que trae la columna versión
    version_real: str  # con la que se busca en semilla_respuesta.json
    pares: tuple[str, ...]  # pares NVD "vendor:producto" esperados
    equipos: int  # en cuántos equipos aparece
    prueba: str  # qué mide el caso
    grupo: str = "general"  # "general", "desarrollo" o "servidor"
    equipos_fijos: tuple[str, ...] = field(default_factory=tuple)

    @property
    def canonico(self) -> str:
        return CANONICO[self.producto]

    @property
    def clave(self) -> str:
        """Activo.clave esperada: nombre canónico y versión comparable."""
        return f"{self.canonico}@{self.version_real}"


def _c(
    producto,
    nombre,
    proveedor,
    version_campo,
    pares,
    equipos,
    prueba,
    *,
    version_real=None,
    grupo="general",
    equipos_fijos=(),
):
    if isinstance(pares, str):
        pares = (pares,)
    return Caso(
        producto=producto,
        nombre=nombre,
        proveedor=proveedor,
        version_campo=version_campo,
        version_real=version_real or version_campo,
        pares=tuple(pares),
        equipos=equipos,
        prueba=prueba,
        grupo=grupo,
        equipos_fijos=tuple(equipos_fijos),
    )


WINRAR = "rarlab:winrar"
SIETEZIP = "7-zip:7-zip"
NOTEPAD = "notepad-plus-plus:notepad\\+\\+"  # escape de NVD intacto (contrato)
CHROME = "google:chrome"
FIREFOX = "mozilla:firefox"
NODE = "nodejs:node.js"
PYTHON = "python:python"
DOCKER = ("docker:desktop", "docker:docker_desktop")
TEAMVIEWER = "teamviewer:teamviewer"
GIT = "git-scm:git"
OPENJDK = "oracle:openjdk"
ACROBAT = "adobe:acrobat_reader_dc"
VLC = "videolan:vlc_media_player"
PUTTY = "putty:putty"
COMPASS = "mongodb:compass"
GLOBALPROTECT = "paloaltonetworks:globalprotect"
NGINX = "f5:nginx"

_NODE_VERSIONES = [
    ("18.18.0", 1),
    ("18.20.4", 2),
    ("20.8.0", 1),
    ("20.11.1", 2),
    ("20.18.0", 3),
    ("22.11.0", 2),
    ("22.12.0", 1),
    ("22.20.0", 2),
    ("22.23.4", 2),
    ("24.22.0", 1),
    ("24.22.1", 2),
    ("26.12.1", 1),
]

CASOS: list[Caso] = [
    # WinRAR
    _c(
        "winrar",
        "WinRAR 5.61 (64-bit)",
        "win.rar GmbH",
        "5.61",
        WINRAR,
        2,
        "Frontera inclusiva: CVE-2018-20250 con versionEndIncluding 5.61",
    ),
    _c(
        "winrar",
        "WinRAR 6.22 (32-bit)",
        "win.rar GmbH",
        "6.22",
        WINRAR,
        3,
        "Vulnerable con explotación y ransomware",
    ),
    _c(
        "winrar",
        "WinRAR 6.23 (64-bit)",
        "win.rar GmbH",
        "6.23",
        WINRAR,
        2,
        "Frontera excluyente: ya no tiene CVE-2023-38831",
    ),
    _c(
        "winrar",
        "WinRAR 7.12 (64-bit)",
        "win.rar GmbH",
        "7.12",
        WINRAR,
        4,
        "Una sola CVE, explotada con ransomware",
    ),
    _c(
        "winrar",
        "WinRAR 7.13 (64-bit)",
        "win.rar GmbH",
        "7.13",
        WINRAR,
        6,
        "Sano, justo en el arreglo de CVE-2025-8088",
    ),
    # 7-Zip
    _c("7zip", "7-Zip 24.08 (x64)", "Igor Pavlov", "24.08", SIETEZIP, 10, "Vulnerable con KEV"),
    _c(
        "7zip",
        "7-Zip 24.09 (x64 edition)",
        "Igor Pavlov",
        "24.09",
        SIETEZIP,
        6,
        "Arregla la KEV pero tiene una CVE más que 24.08",
    ),
    _c("7zip", "7-Zip 26.03 (x64)", "Igor Pavlov", "26.03", SIETEZIP, 14, "Sano"),
    # Notepad++ (el CPE lleva \+\+ escapado; el snapshot lo trae sin escapar)
    _c(
        "notepadpp",
        "Notepad++ (64-bit x64)",
        "Notepad++ Team",
        "8.8.8",
        NOTEPAD,
        5,
        "KEV; CPE con \\+\\+ escapado",
    ),
    _c(
        "notepadpp",
        "Notepad++ (64-bit x64)",
        "Notepad++ Team",
        "8.8.9",
        NOTEPAD,
        3,
        "Frontera excluyente de la KEV",
    ),
    _c(
        "notepadpp",
        "Notepad++ (64-bit x64)",
        "Notepad++ Team",
        "8.9.6.4",
        NOTEPAD,
        8,
        "Sano, versión de cuatro componentes",
    ),
    # Chrome
    _c(
        "chrome",
        "Google Chrome",
        "Google LLC",
        "156.0.8079.100",
        CHROME,
        12,
        "KEV de esta semana; volumen alto obliga a agrupar",
    ),
    _c(
        "chrome",
        "Google Chrome",
        "Google LLC",
        "157.0.8103.60",
        CHROME,
        18,
        "Inmediato por CVSS, sin KEV",
    ),
    _c(
        "chrome",
        "Google Chrome",
        "Google LLC",
        "157.0.8103.78",
        CHROME,
        20,
        "Sano en lo preciso, con 13 no precisas",
    ),
    # Firefox (131.0.1 queda fuera por defecto: infla el total)
    _c(
        "firefox",
        "Mozilla Firefox 156.0.1 (x64 es-ES)",
        "Mozilla",
        "156.0.1",
        FIREFOX,
        6,
        "Versión en el nombre y en el campo",
    ),
    _c(
        "firefox",
        "Mozilla Firefox (x64 es-ES)",
        "Mozilla",
        "157.0",
        FIREFOX,
        8,
        "Una CVE crítica reciente",
    ),
    # Node.js: doce versiones en los 20 equipos de desarrollo
    *[
        _c(
            "nodejs",
            "Node.js",
            "Node.js Foundation",
            v,
            NODE,
            n,
            "Doce versiones conviviendo; KEV de Brotli se empareja por ID",
            grupo="desarrollo",
        )
        for v, n in _NODE_VERSIONES
    ],
    # Python: el instalador reporta 3.12.10150.0 para la 3.12.10
    _c(
        "python",
        "Python 3.12.10 (64-bit)",
        "Python Software Foundation",
        "3.12.10150.0",
        PYTHON,
        6,
        "Versión del instalador distinta; la real viene en el nombre",
        version_real="3.12.10",
        grupo="desarrollo",
    ),
    _c(
        "python",
        "Python 3.11.15 (64-bit)",
        "Python Software Foundation",
        "3.11.15",
        PYTHON,
        3,
        "Vulnerable sin KEV",
        grupo="desarrollo",
    ),
    _c(
        "python",
        "Python 3.13.9 (64-bit)",
        "Python Software Foundation",
        "3.13.9",
        PYTHON,
        4,
        "Vulnerable sin KEV",
        grupo="desarrollo",
    ),
    # Docker Desktop: dos pares
    _c(
        "docker_desktop",
        "Docker Desktop",
        "Docker Inc.",
        "4.58.0",
        DOCKER,
        3,
        "Dos pares",
        grupo="desarrollo",
    ),
    _c(
        "docker_desktop",
        "Docker Desktop",
        "Docker Inc.",
        "4.62.0",
        DOCKER,
        4,
        "Solo el segundo par la encuentra",
        grupo="desarrollo",
    ),
    _c(
        "docker_desktop",
        "Docker Desktop",
        "Docker Inc.",
        "4.72.0",
        DOCKER,
        3,
        "Sano",
        grupo="desarrollo",
    ),
    # TeamViewer
    _c(
        "teamviewer",
        "TeamViewer 14",
        "TeamViewer Germany GmbH",
        "14.7.1965",
        TEAMVIEWER,
        1,
        "Frontera inclusiva de una KEV",
    ),
    _c(
        "teamviewer",
        "TeamViewer 14",
        "TeamViewer Germany GmbH",
        "14.7.1966",
        TEAMVIEWER,
        1,
        "Un número después: sale de la KEV",
    ),
    _c("teamviewer", "TeamViewer", "TeamViewer Germany GmbH", "15.70.0", TEAMVIEWER, 12, "Sano"),
    # Git para Windows: sufijo .windows.N
    _c(
        "git",
        "Git",
        "The Git Development Community",
        "2.45.1.windows.1",
        GIT,
        4,
        "Sufijo .windows.N que hay que limpiar",
        version_real="2.45.1",
        grupo="desarrollo",
    ),
    _c(
        "git",
        "Git",
        "The Git Development Community",
        "2.45.4",
        GIT,
        3,
        "Frontera excluyente de la KEV",
        grupo="desarrollo",
    ),
    _c(
        "git", "Git", "The Git Development Community", "2.51.0", GIT, 10, "Sano", grupo="desarrollo"
    ),
    # Eclipse Temurin: sus CVE están en oracle:openjdk
    _c(
        "temurin",
        "Eclipse Temurin JDK with Hotspot 17.0.9+9 (x64)",
        "Eclipse Adoptium",
        "17.0.9+9",
        OPENJDK,
        4,
        "eclipse:temurin no existe; versión con +9",
        version_real="17.0.9",
        grupo="desarrollo",
    ),
    _c(
        "temurin",
        "Eclipse Temurin JDK with Hotspot 17.0.10+7 (x64)",
        "Eclipse Adoptium",
        "17.0.10+7",
        OPENJDK,
        3,
        "Frontera excluyente",
        version_real="17.0.10",
        grupo="desarrollo",
    ),
    _c(
        "temurin",
        "Eclipse Temurin JDK with Hotspot 21.0.5+11 (x64)",
        "Eclipse Adoptium",
        "21.0.5+11",
        OPENJDK,
        5,
        "Sano",
        version_real="21.0.5",
        grupo="desarrollo",
    ),
    # Acrobat Reader: dos nombres del mismo producto
    _c(
        "acrobat",
        "Adobe Acrobat Reader (64-bit)",
        "Adobe Inc.",
        "25.001.20531",
        ACROBAT,
        15,
        "KEV en un lector de PDF",
    ),
    _c(
        "acrobat",
        "Adobe Acrobat Reader DC - Español",
        "Adobe Systems Incorporated",
        "26.002.21901",
        ACROBAT,
        20,
        "Sano, con nombre distinto del mismo producto",
    ),
    # VLC
    _c("vlc", "VLC media player", "VideoLAN", "3.0.18", VLC, 5, "Inmediato por CVSS 9.8"),
    _c("vlc", "VLC media player", "VideoLAN", "3.0.21", VLC, 9, "Sano"),
    # PuTTY
    _c(
        "putty",
        "PuTTY release 0.81 (64-bit)",
        "Simon Tatham",
        "0.81",
        PUTTY,
        3,
        "Vulnerable de baja gravedad: informativo",
    ),
    _c("putty", "PuTTY release 0.84 (64-bit)", "Simon Tatham", "0.84", PUTTY, 4, "Sano"),
    # MongoDB Compass
    _c(
        "compass",
        "MongoDB Compass",
        "MongoDB Inc.",
        "1.36.3",
        COMPASS,
        2,
        "Una CVE con versión exacta, no con rango",
        grupo="desarrollo",
    ),
    _c(
        "compass",
        "MongoDB Compass",
        "MongoDB Inc.",
        "1.49.7",
        COMPASS,
        3,
        "Sano",
        grupo="desarrollo",
    ),
    # GlobalProtect
    _c(
        "globalprotect",
        "GlobalProtect",
        "Palo Alto Networks",
        "6.0.14",
        GLOBALPROTECT,
        10,
        "El par bueno no es globalprotect_app",
    ),
    _c(
        "globalprotect",
        "GlobalProtect",
        "Palo Alto Networks",
        "6.3.5",
        GLOBALPROTECT,
        30,
        "Sano en lo preciso",
    ),
    # nginx: solo en servidores
    _c(
        "nginx",
        "nginx",
        "F5, Inc.",
        "1.24.0",
        NGINX,
        1,
        "Va bajo f5:nginx",
        grupo="servidor",
        equipos_fijos=("SRV-01",),
    ),
    _c(
        "nginx",
        "nginx",
        "F5, Inc.",
        "1.27.4",
        NGINX,
        1,
        "Sano",
        grupo="servidor",
        equipos_fijos=("SRV-02",),
    ),
]

# Disponible pero no sembrado por defecto (756 CVE, KEV CVE-2024-9680 con ransomware).
CASOS_OPCIONALES: list[Caso] = [
    _c(
        "firefox",
        "Mozilla Firefox (x64 es-ES)",
        "Mozilla",
        "131.0.1",
        FIREFOX,
        3,
        "Ransomware en navegador",
    ),
]


@dataclass(frozen=True)
class CasoCobertura:
    """Programa que no debe producir hallazgo: se cuenta como falta de cobertura."""

    nombre: str
    proveedor: str
    version_campo: str
    motivo: str  # MotivoCobertura de radar/contratos.py
    explicacion: str
    equipos: int
    grupo: str = "general"
    par_prohibido: str | None = None  # trampa: este par NO debe asignarse


COBERTURA: list[CasoCobertura] = [
    CasoCobertura(
        "Sistema Contable Interno", "Área de Sistemas", "4.2", "sin_cpe", "No existe en NVD", 4
    ),
    CasoCobertura(
        "Lector PDF Corporativo", "Área de Sistemas", "", "sin_version", "Sin versión", 2
    ),
    CasoCobertura(
        "Docker",
        "Docker Inc.",
        "28.1.1, build 4eba377",
        "no_comparable",
        "Número de compilación como versión",
        2,
        grupo="desarrollo",
    ),
    CasoCobertura(
        "NoSQLBooster for MongoDB",
        "NoSQLBooster",
        "8.1.9",
        "sin_cpe",
        "El cliente no es el servidor",
        1,
        grupo="desarrollo",
        par_prohibido="mongodb:mongodb",
    ),
    CasoCobertura("Agente RMM Ficticio", "RMM Ficticio S.A.", "3.0", "sin_cpe", "Sin CPE", 3),
]

# Relleno: programas que dan tamaño creíble al inventario. Son internos, de marca
# ficticia o componentes que no deberían tener CPE. No entran en la medición de
# detección ni de falsos positivos (si el día del evento el cruce les encuentra algo,
# se reporta aparte). Formato: (nombre, proveedor, versión).
RELLENO: list[tuple[str, str, str]] = [
    ("Portal de Nómina Cliente", "Área de Sistemas", "2.3.1"),
    ("Plantillas Corporativas Office", "Área de Comunicación", "2025.10"),
    ("Firma Electrónica Corporativa", "Área de Sistemas", "1.8.0"),
    ("Cliente de Impresión Segura", "Área de Sistemas", "5.2.4"),
    ("Catálogo de Productos Offline", "Área Comercial", "3.14.2"),
    ("Agenda de Visitas Comercial", "Área Comercial", "1.2.0"),
    ("Control de Asistencia Biométrico", "Recursos Humanos", "4.0.7"),
    ("Visor de Planos Interno", "Área de Ingeniería", "2.1.9"),
    ("Herramienta de Inventario Local", "Área de Sistemas", "0.9.12"),
    ("Paquete de Fuentes Corporativas", "Área de Comunicación", "1.0"),
    ("Fondos de Pantalla Institucionales", "Área de Comunicación", "2026.1"),
    ("Conector de Facturación Electrónica", "Área de Finanzas", "6.3.0"),
    ("Calculadora de Viáticos", "Área de Finanzas", "1.4.2"),
    ("Módulo de Tesorería", "Área de Finanzas", "3.0.5"),
    ("Encuestas de Clima Laboral", "Recursos Humanos", "2.2.0"),
    ("Kit de Bienvenida Digital", "Recursos Humanos", "1.1.3"),
    ("Asistente de Respaldo Local", "Área de Sistemas", "7.0.2"),
    ("Monitor de Disco Interno", "Área de Sistemas", "1.6.0"),
    ("Lanzador de Aplicaciones Corporativas", "Área de Sistemas", "4.5.1"),
    ("Paquete de Idioma Español (México)", "Área de Sistemas", "26.11"),
    ("Paquete de Idioma Inglés (EE. UU.)", "Área de Sistemas", "26.11"),
    ("Controlador de Lector de Credenciales", "Lectores Andinos S.A.", "2.0.14"),
    ("Controlador de Escáner Documental", "Escáneres del Valle S.A.", "11.2.0"),
    ("Utilidad de Teclado Ergonómico", "Periféricos Sur S.A.", "3.3.3"),
    ("Utilidad de Ratón Inalámbrico", "Periféricos Sur S.A.", "1.9.0"),
    ("Panel de Audio del Equipo", "Fabricante del Equipo", "6.0.9600"),
    ("Centro de Ayuda del Fabricante", "Fabricante del Equipo", "2.4.0"),
    ("Actualizador de BIOS del Fabricante", "Fabricante del Equipo", "1.12.0"),
    ("Gestor de Energía del Fabricante", "Fabricante del Equipo", "5.1.2"),
    ("Diccionario Técnico Interno", "Área de Ingeniería", "2.0"),
    ("Manual de Procesos Interactivo", "Área de Calidad", "3.2"),
    ("Formulario de Incidencias", "Área de Sistemas", "1.7.4"),
    ("Tablero de Indicadores Local", "Área de Calidad", "2.9.0"),
    ("Simulador de Cotizaciones", "Área Comercial", "4.1.0"),
    ("Gestor de Contratos Interno", "Área Legal", "1.3.6"),
    ("Archivo Digital de Expedientes", "Área Legal", "2.5.0"),
    ("Cliente de Mensajería Interna", "Área de Sistemas", "8.0.3"),
    ("Visor de Reportes de Calidad", "Área de Calidad", "1.0.8"),
    ("Etiquetadora de Almacén", "Área de Logística", "3.6.1"),
    ("Planificador de Rutas de Reparto", "Área de Logística", "2.2.7"),
]
RELLENO_POR_EQUIPO = (15, 25)

# Nombres sucios que mide el normalizador: (nombre del RMM, versión del campo,
# proveedor, par esperado). Salen de los casos de arriba; se listan aparte para la
# prueba del normalizador.
NOMBRES_SUCIOS: list[tuple[str, str, str, str]] = [
    ("WinRAR 7.12 (64-bit)", "7.12", "win.rar GmbH", WINRAR),
    ("WinRAR 6.22 (32-bit)", "6.22", "win.rar GmbH", WINRAR),
    ("7-Zip 24.08 (x64)", "24.08", "Igor Pavlov", SIETEZIP),
    ("7-Zip 24.09 (x64 edition)", "24.09", "Igor Pavlov", SIETEZIP),
    ("Notepad++ (64-bit x64)", "8.8.8", "Notepad++ Team", NOTEPAD),
    ("Mozilla Firefox (x64 es-ES)", "157.0", "Mozilla", FIREFOX),
    ("Mozilla Firefox 156.0.1 (x64 es-ES)", "156.0.1", "Mozilla", FIREFOX),
    ("Python 3.12.10 (64-bit)", "3.12.10150.0", "Python Software Foundation", PYTHON),
    ("Eclipse Temurin JDK with Hotspot 17.0.9+9 (x64)", "17.0.9+9", "Eclipse Adoptium", OPENJDK),
    ("Adobe Acrobat Reader (64-bit)", "25.001.20531", "Adobe Inc.", ACROBAT),
    ("Adobe Acrobat Reader DC - Español", "26.002.21901", "Adobe Systems Incorporated", ACROBAT),
    ("PuTTY release 0.81 (64-bit)", "0.81", "Simon Tatham", PUTTY),
    ("Git", "2.45.1.windows.1", "The Git Development Community", GIT),
    ("TeamViewer", "15.70.0", "TeamViewer Germany GmbH", TEAMVIEWER),
    ("TeamViewer 14", "14.7.1965", "TeamViewer Germany GmbH", TEAMVIEWER),
]


def validar() -> None:
    """Comprueba que la distribución cabe en los equipos y que todo producto tiene nombre."""
    faltan = {c.producto for c in CASOS + CASOS_OPCIONALES} - set(CANONICO)
    if faltan:
        raise ValueError(f"Productos sin nombre canónico: {sorted(faltan)}")
    por_producto: dict[str, int] = {}
    grupo_de: dict[str, str] = {}
    for c in CASOS:
        por_producto[c.producto] = por_producto.get(c.producto, 0) + c.equipos
        grupo_de[c.producto] = c.grupo
    for prod, n in por_producto.items():
        g = grupo_de[prod]
        cupo = {
            "general": len(EQUIPOS),
            "desarrollo": len(EQUIPOS_DESARROLLO),
            "servidor": len(SERVIDORES),
        }[g]
        if n > cupo:
            raise ValueError(f"{prod}: {n} equipos no caben en el grupo {g} ({cupo})")


validar()
