"""Instancias de ejemplo de cada contrato, para que los frentes trabajen sin esperar al núcleo.

Los datos de CVE, rangos y KEV son reales: salen del snapshot de NVD y del catálogo KEV
2026.11.13 que usa la semilla. EPSS es el del 13 de noviembre de 2026 (api.first.org).
Los nombres de equipo son ilustrativos: la distribución real la arma datos_prueba/generar.py.

Casos elegidos:
- WinRAR 5.61: frontera inclusiva (CVE-2018-20250 con versionEndIncluding 5.61), KEV y
  ransomware. Inmediato.
- Google Chrome 156.0.8079.100: KEV agregada el 10 de noviembre de 2026. Inmediato.
- Docker Desktop 4.62.0: solo el par docker:docker_desktop la encuentra. Semanal.

Uso: `from radar.ejemplos import HALLAZGOS, GRUPOS` o `python -m radar.ejemplos` para
ver todo como JSON.
"""

from __future__ import annotations

import json
from datetime import UTC, date, datetime

from radar.contratos import (
    CVE,
    Activo,
    Analisis,
    Cobertura,
    Ejecucion,
    FilaInventario,
    Grupo,
    Hallazgo,
    Rango,
    Referencia,
    SenalEpss,
    Senales,
    SenalKev,
    Trabajo,
)

CARGADO = datetime(2026, 11, 14, 9, 30, tzinfo=UTC)
DETECTADO = datetime(2026, 11, 14, 9, 45, tzinfo=UTC)

EQUIPOS_WINRAR_561 = ["EQUIPO-007", "EQUIPO-031"]
EQUIPOS_CHROME_156 = [f"EQUIPO-{n:03d}" for n in (1, 4, 9, 12, 15, 18, 22, 26, 33, 38, 41, 47)]
EQUIPOS_DOCKER_462 = ["EQUIPO-011", "EQUIPO-019", "EQUIPO-024", "EQUIPO-036"]

# ---------------------------------------------------------------------------
# Inventario
# ---------------------------------------------------------------------------

FILAS: list[FilaInventario] = [
    FilaInventario(
        equipo="EQUIPO-007",
        programa="WinRAR 5.61 (64-bit)",
        version="5.61",
        proveedor="win.rar GmbH",
        sistema="Windows 11 Pro",
        fuente="csv",
        cargado=CARGADO,
    ),
    FilaInventario(
        equipo="EQUIPO-001",
        programa="Google Chrome",
        version="156.0.8079.100",
        proveedor="Google LLC",
        sistema="Windows 11 Pro",
        fuente="excel",
        cargado=CARGADO,
    ),
    FilaInventario(
        equipo="EQUIPO-011",
        programa="Docker Desktop",
        version="4.62.0",
        proveedor="Docker Inc.",
        sistema="Windows 11 Pro",
        fuente="mcp",
        cargado=CARGADO,
    ),
    # Fila que termina en cobertura: versión no comparable.
    FilaInventario(
        equipo="EQUIPO-011",
        programa="Docker",
        version="28.1.1, build 4eba377",
        proveedor="Docker Inc.",
        sistema="Windows 11 Pro",
        fuente="mcp",
        cargado=CARGADO,
    ),
]

ACTIVOS: list[Activo] = [
    Activo(
        clave="WinRAR@5.61",
        producto="WinRAR",
        nombre="WinRAR 5.61 (64-bit)",
        version="5.61",
        cpes=["rarlab:winrar"],
        equipos=EQUIPOS_WINRAR_561,
        confianza_cpe=1.0,
    ),
    Activo(
        clave="Google Chrome@156.0.8079.100",
        producto="Google Chrome",
        nombre="Google Chrome",
        version="156.0.8079.100",
        cpes=["google:chrome"],
        equipos=EQUIPOS_CHROME_156,
        confianza_cpe=1.0,
    ),
    Activo(
        clave="Docker Desktop@4.62.0",
        producto="Docker Desktop",
        nombre="Docker Desktop",
        version="4.62.0",
        # Dos pares: quedarse con uno solo pierde las dos CVE en silencio.
        cpes=["docker:desktop", "docker:docker_desktop"],
        equipos=EQUIPOS_DOCKER_462,
        confianza_cpe=0.95,
    ),
]

COBERTURA: list[Cobertura] = [
    Cobertura(
        equipo="EQUIPO-011",
        programa="Docker",
        version="28.1.1, build 4eba377",
        motivo="no_comparable",
    ),
    Cobertura(
        equipo="EQUIPO-002", programa="Sistema Contable Interno", version="4.2", motivo="sin_cpe"
    ),
    Cobertura(
        equipo="EQUIPO-005", programa="Lector PDF Corporativo", version=None, motivo="sin_version"
    ),
]

# ---------------------------------------------------------------------------
# Fuentes (datos reales del snapshot)
# ---------------------------------------------------------------------------

RANGO_WINRAR_2018_20250 = Rango(
    cpe="cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
    vendor="rarlab",
    producto="winrar",
    hasta="5.61",
    hasta_incluye=True,  # versionEndIncluding: 5.61 sigue afectada, no se dice "actualizar a 5.61"
)

RANGO_WINRAR_2025_8088 = Rango(
    cpe="cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*",
    vendor="rarlab",
    producto="winrar",
    hasta="7.13",
    hasta_incluye=False,
)

RANGO_CHROME_2026_125350 = Rango(
    cpe="cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    vendor="google",
    producto="chrome",
    hasta="157.0.8103.50",
    hasta_incluye=False,
)

RANGO_DOCKER_2026_5817 = Rango(
    cpe="cpe:2.3:a:docker:docker_desktop:*:*:*:*:*:*:*:*",
    vendor="docker",
    producto="docker_desktop",
    desde="4.62.0",
    desde_incluye=True,
    hasta="4.68.0",
    hasta_incluye=False,
)

RANGO_DOCKER_2026_5843 = Rango(
    cpe="cpe:2.3:a:docker:docker_desktop:*:*:*:*:*:*:*:*",
    vendor="docker",
    producto="docker_desktop",
    desde="4.56.0",
    desde_incluye=True,
    hasta="4.71.0",
    hasta_incluye=False,
)

# Rango de versión fija (CVE-2020-15360, Docker Desktop 2.3.0.3): afecta solo si es igual.
RANGO_DOCKER_FIJO = Rango(
    cpe="cpe:2.3:a:docker:docker_desktop:2.3.0.3:*:*:*:*:*:*:*",
    vendor="docker",
    producto="docker_desktop",
    version="2.3.0.3",
)

CVES: list[CVE] = [
    CVE(
        id="CVE-2018-20250",
        publicada=datetime(2019, 2, 5, 20, 29, 0, 243000, tzinfo=UTC),
        modificada=datetime(2026, 8, 13, 5, 17, 17, 910000, tzinfo=UTC),
        estado="Analyzed",
        descripcion=(
            "In WinRAR versions prior to and including 5.61, There is path traversal "
            "vulnerability when crafting the filename field of the ACE format (in UNACEV2.dll). "
            "When the filename field is manipulated with specific patterns, the destination "
            "(extraction) folder is ignored, thus treating the filename as an absolute path."
        ),
        cvss=7.8,
        severidad="HIGH",
        vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        version_cvss="3.1",
        cwes=["CWE-36", "CWE-22"],
        referencias=[
            Referencia(
                url="http://www.rapid7.com/db/modules/exploit/windows/fileformat/winrar_ace",
                etiquetas=["Third Party Advisory"],
            ),
        ],
        rangos=[RANGO_WINRAR_2018_20250],
    ),
    CVE(
        id="CVE-2026-125350",
        publicada=datetime(2026, 11, 10, 18, 17, 35, 237000, tzinfo=UTC),
        modificada=datetime(2026, 11, 11, 5, 19, 38, 220000, tzinfo=UTC),
        estado="Analyzed",
        descripcion=(
            "Use after free in XML in Google Chrome prior to 157.0.8103.50 allowed a remote "
            "attacker to execute arbitrary code inside the sandbox via a crafted HTML page. "
            "(Chromium security severity: High)"
        ),
        cvss=8.8,
        severidad="HIGH",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        version_cvss="3.1",
        cwes=["CWE-416"],
        referencias=[
            Referencia(
                url="https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop_018223192.html",
                etiquetas=["Release Notes", "Vendor Advisory"],
            ),
        ],
        rangos=[RANGO_CHROME_2026_125350],
    ),
    CVE(
        id="CVE-2026-5817",
        publicada=datetime(2026, 5, 22, 20, 16, 35, 120000, tzinfo=UTC),
        modificada=datetime(2026, 7, 23, 11, 10, 0, 120000, tzinfo=UTC),
        estado="Analyzed",
        descripcion=(
            "The vllm-metal inference backend in Docker Model Runner on macOS unconditionally "
            "sets trust_remote_code=True when loading model tokenizers, and runs without "
            "sandboxing."
        ),
        cvss=8.8,
        severidad="HIGH",
        vector="CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
        version_cvss="4.0",
        cwes=["CWE-829"],
        referencias=[
            Referencia(
                url="https://docs.docker.com/desktop/release-notes/#4680",
                etiquetas=["Release Notes"],
            ),
        ],
        rangos=[RANGO_DOCKER_2026_5817],
    ),
]

SENALES = Senales(
    kev={
        "CVE-2018-20250": SenalKev(
            cve="CVE-2018-20250",
            fabricante="RARLAB",
            producto="WinRAR",
            accion="Apply updates per vendor instructions.",
            agregada=date(2022, 2, 15),
            plazo=date(2022, 8, 15),
            ransomware=True,
        ),
        "CVE-2025-8088": SenalKev(
            cve="CVE-2025-8088",
            fabricante="RARLAB",
            producto="WinRAR",
            accion=(
                "Apply mitigations per vendor instructions, follow applicable BOD 22-01 "
                "guidance for cloud services, or discontinue use of the product if "
                "mitigations are unavailable."
            ),
            agregada=date(2025, 8, 12),
            plazo=date(2025, 9, 2),
            ransomware=True,
        ),
        "CVE-2026-125350": SenalKev(
            cve="CVE-2026-125350",
            fabricante="Google",
            producto="Chromium",  # KEV dice Chromium: por eso se empareja por ID, no por nombre
            accion="Apply mitigations in accordance with vendor instructions (BOD 26-04).",
            agregada=date(2026, 11, 10),
            plazo=date(2026, 11, 24),
            ransomware=False,
        ),
    },
    epss={
        "CVE-2018-20250": SenalEpss(
            cve="CVE-2018-20250", epss=0.96004, percentil=0.99877, fecha=date(2026, 11, 13)
        ),
        "CVE-2025-8088": SenalEpss(
            cve="CVE-2025-8088", epss=0.94287, percentil=0.99853, fecha=date(2026, 11, 13)
        ),
        "CVE-2026-125350": SenalEpss(
            cve="CVE-2026-125350", epss=0.00962, percentil=0.62163, fecha=date(2026, 11, 13)
        ),
        "CVE-2026-5817": SenalEpss(
            cve="CVE-2026-5817", epss=0.00224, percentil=0.13193, fecha=date(2026, 11, 13)
        ),
        "CVE-2026-5843": SenalEpss(
            cve="CVE-2026-5843", epss=0.00224, percentil=0.13193, fecha=date(2026, 11, 13)
        ),
    },
)

# ---------------------------------------------------------------------------
# Resultado del cruce
# ---------------------------------------------------------------------------

HALLAZGOS: list[Hallazgo] = [
    Hallazgo(
        id="CVE-2018-20250|WinRAR@5.61",
        cve="CVE-2018-20250",
        activo="WinRAR@5.61",
        producto="WinRAR",
        version_instalada="5.61",
        equipos=EQUIPOS_WINRAR_561,
        prioridad="inmediato",
        por_que=[
            "Explotación confirmada en el mundo real (CISA KEV)",
            "Usada en campañas de ransomware (CISA KEV)",
            "Probabilidad de explotación del 96% en 30 días (EPSS)",
        ],
        preciso=True,
        rango=RANGO_WINRAR_2018_20250,
        kev=True,
        ransomware=True,
        epss=0.96004,
        cvss=7.8,
        detectado=DETECTADO,
    ),
    Hallazgo(
        id="CVE-2026-125350|Google Chrome@156.0.8079.100",
        cve="CVE-2026-125350",
        activo="Google Chrome@156.0.8079.100",
        producto="Google Chrome",
        version_instalada="156.0.8079.100",
        equipos=EQUIPOS_CHROME_156,
        prioridad="inmediato",
        por_que=[
            "Explotación confirmada en el mundo real (CISA KEV)",
            "Agregada a KEV el 10 de noviembre de 2026, plazo 24 de noviembre de 2026",
        ],
        preciso=True,
        rango=RANGO_CHROME_2026_125350,
        kev=True,
        ransomware=False,
        epss=0.00962,
        cvss=8.8,
        detectado=DETECTADO,
    ),
    Hallazgo(
        id="CVE-2026-5817|Docker Desktop@4.62.0",
        cve="CVE-2026-5817",
        activo="Docker Desktop@4.62.0",
        producto="Docker Desktop",
        version_instalada="4.62.0",
        equipos=EQUIPOS_DOCKER_462,
        prioridad="semanal",
        por_que=["Gravedad alta, CVSS 8.8"],
        preciso=True,
        rango=RANGO_DOCKER_2026_5817,
        kev=False,
        ransomware=False,
        epss=0.00224,
        cvss=8.8,
        estado="en_curso",
        comentario="Actualización programada para el viernes",
        por="ti@empresa.example",
        detectado=DETECTADO,
    ),
]

GRUPOS: list[Grupo] = [
    Grupo(
        producto="WinRAR",
        versiones=["5.61"],
        equipos=EQUIPOS_WINRAR_561,
        # semilla_respuesta.json, rarlab:winrar 5.61
        cves=[
            "CVE-2018-20250",
            "CVE-2018-20251",
            "CVE-2019-25677",
            "CVE-2023-38831",
            "CVE-2023-40477",
            "CVE-2024-33899",
            "CVE-2024-36052",
            "CVE-2025-31334",
            "CVE-2025-6218",
            "CVE-2025-8088",
        ],
        en_kev=["CVE-2018-20250", "CVE-2023-38831", "CVE-2025-6218", "CVE-2025-8088"],
        ransomware=True,
        peor_cvss=8.4,
        peor_epss=0.96004,
        # CVE-2025-8088 se arregla con versionEndExcluding 7.13: es la mayor versión de arreglo.
        version_objetivo="7.13",
        tipo_objetivo="exacta",
        prioridad="inmediato",
        por_que=[
            "4 CVE con explotación confirmada en el mundo real (CISA KEV)",
            "Usada en campañas de ransomware (CISA KEV)",
            "Probabilidad de explotación del 96% en 30 días (EPSS)",
        ],
    ),
    Grupo(
        producto="Docker Desktop",
        versiones=["4.62.0"],
        equipos=EQUIPOS_DOCKER_462,
        # Solo el par docker:docker_desktop las encuentra; docker:desktop da 0.
        cves=["CVE-2026-5817", "CVE-2026-5843"],
        en_kev=[],
        ransomware=False,
        peor_cvss=8.8,
        peor_epss=0.00224,
        # CVE-2026-5817 se arregla en 4.68.0 y CVE-2026-5843 en 4.71.0: manda la mayor.
        version_objetivo="4.71.0",
        tipo_objetivo="exacta",
        prioridad="semanal",
        por_que=["Gravedad alta, CVSS 8.8"],
    ),
]

ANALISIS: list[Analisis] = [
    Analisis(
        producto="WinRAR",
        resumen=(
            "WinRAR 5.61 está instalado en 2 equipos y tiene 10 CVE, 4 de ellas con explotación "
            "confirmada (CISA KEV) y usadas en campañas de ransomware."
        ),
        como_se_explota=(
            "Según NVD, CVE-2018-20250 es un recorrido de rutas en el formato ACE (UNACEV2.dll): "
            "un nombre de archivo manipulado hace que se ignore la carpeta de destino al extraer. "
            "CVE-2025-8088 es un recorrido de rutas que permite ejecutar código con un archivo "
            "comprimido malicioso, y fue explotada en el mundo real."
        ),
        remediacion="Actualizar WinRAR a la versión 7.13 en EQUIPO-007 y EQUIPO-031.",
        mitigacion_temporal=(
            "Mientras se actualiza, no abrir archivos comprimidos recibidos por correo o "
            "descargados de fuentes desconocidas."
        ),
        comunicado_ti=(
            "Prioridad inmediata: WinRAR 5.61 en EQUIPO-007 y EQUIPO-031. 10 CVE, 4 en KEV "
            "(CVE-2018-20250, CVE-2023-38831, CVE-2025-6218, CVE-2025-8088), con ransomware. "
            "Acción: actualizar a 7.13."
        ),
        comunicado_usuarios=(
            "Vamos a actualizar WinRAR en tu equipo. Hasta entonces, no abras archivos "
            "comprimidos (.rar, .zip) que no esperabas."
        ),
        verificado=True,
        origen="agente",
    ),
    Analisis(
        producto="Docker Desktop",
        resumen="Docker Desktop 4.62.0 está instalado en 4 equipos y tiene 2 CVE de gravedad alta.",
        como_se_explota=(
            "Según NVD, CVE-2026-5817 y CVE-2026-5843 afectan a los motores de inferencia de "
            "Docker Model Runner en macOS, que ejecutan código incluido en un modelo descargado."
        ),
        remediacion="Actualizar Docker Desktop a la versión 4.71.0.",
        mitigacion_temporal=None,
        comunicado_ti=(
            "Prioridad semanal: Docker Desktop 4.62.0 en 4 equipos. 2 CVE, ninguna en KEV, "
            "peor CVSS 8.8. Acción: actualizar a 4.71.0."
        ),
        comunicado_usuarios="Vamos a actualizar Docker Desktop en tu equipo esta semana.",
        verificado=True,
        origen="respaldo",
    ),
]

# ---------------------------------------------------------------------------
# Operación
# ---------------------------------------------------------------------------

TRABAJOS: list[Trabajo] = [
    Trabajo(
        id=1,
        tipo="descargar",
        estado="hecho",
        creado=datetime(2026, 11, 14, 9, 31, tzinfo=UTC),
        terminado=datetime(2026, 11, 14, 9, 40, tzinfo=UTC),
        detalle="20 pares desde el snapshot, KEV 2026.11.13, EPSS 2026-11-13",
    ),
    Trabajo(
        id=2,
        tipo="analizar",
        estado="en_curso",
        creado=datetime(2026, 11, 14, 9, 46, tzinfo=UTC),
        detalle="WinRAR",
    ),
    Trabajo(id=3, tipo="analizar", estado="pendiente", creado=DETECTADO, detalle="Google Chrome"),
]

EJECUCIONES: list[Ejecucion] = [
    Ejecucion(
        id=1,
        inicio=datetime(2026, 11, 14, 9, 31, tzinfo=UTC),
        fin=datetime(2026, 11, 14, 9, 40, tzinfo=UTC),
        tipo="descargar",
        fuentes={"nvd": True, "kev": True, "epss": True},
        resumen="20 pares, KEV y EPSS al día",
    ),
]


def todo() -> dict[str, object]:
    """Todos los ejemplos como estructuras JSON (útil para maquetar la API y el panel)."""
    return {
        "filas": [x.model_dump(mode="json") for x in FILAS],
        "activos": [x.model_dump(mode="json") for x in ACTIVOS],
        "cobertura": [x.model_dump(mode="json") for x in COBERTURA],
        "cves": [x.model_dump(mode="json") for x in CVES],
        "senales": SENALES.model_dump(mode="json"),
        "hallazgos": [x.model_dump(mode="json") for x in HALLAZGOS],
        "grupos": [x.model_dump(mode="json") for x in GRUPOS],
        "analisis": [x.model_dump(mode="json") for x in ANALISIS],
        "trabajos": [x.model_dump(mode="json") for x in TRABAJOS],
        "ejecuciones": [x.model_dump(mode="json") for x in EJECUCIONES],
    }


if __name__ == "__main__":
    print(json.dumps(todo(), ensure_ascii=False, indent=2))
