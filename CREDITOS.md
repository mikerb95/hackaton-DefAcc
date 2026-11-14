# Créditos

Qué se usó para construir el radar, de dónde salen los datos y con qué términos. El código
del proyecto se publica con licencia MIT ([LICENSE](LICENSE)).

| Elemento | Cantidad |
|---|---|
| Asistente de IA para desarrollar | 1 (Claude Code, modelo `claude-opus-5-5`) |
| Fuentes de datos públicas | 4 (NVD CVE, diccionario de CPE de NVD, CISA KEV, FIRST EPSS) |
| Librerías principales | 16 |
| Datos de personas o empresas reales en el inventario | 0 (inventario sintético) |

## Asistentes de IA

**Claude Code** (Anthropic), con el modelo `claude-opus-5-5`, se usó para escribir la mayor
parte del código, las pruebas, la documentación, el inventario sintético y los casos de
inyección. Trabajó en varias sesiones paralelas sobre el mismo repositorio, una por frente
de trabajo, coordinadas por archivos de estado compartidos:

| Sesión | Qué hizo |
|---|---|
| Núcleo | Contratos de datos, esquema de la base, descarga de NVD, KEV y EPSS, comparación de versiones, cruce, priorización y agrupación |
| Normalizador | Inventario sintético y su respuesta conocida, diccionario de CPE, normalizador de nombres a CPE y sus mediciones |
| Analista | Agente con Claude Agent SDK que redacta análisis y comunicados |
| Guarda | Limpieza de texto no confiable, verificador, texto de respaldo, hooks, suite de inyección y evals |
| Panel | API, dashboard y documentación consolidada |
| Plugin | Ingesta de CSV y Excel, servidor MCP y plugin de Claude Code |
| Frontend | Landing pública, inicio de sesión con usuarios y roles, panel de administración por secciones, alta de equipos con tokens de inscripción y paquetes del agente (`radar/api/cuentas.py`, `sesion.py`, `paquetes.py`, `public/`) |
| Coordinación e infraestructura | Reparto de tareas, integración y despliegue en Vercel y Turso |

Archivos del analista generados con Claude Code (`claude-opus-5-5`):
`radar/agente/instrucciones.py`, `radar/agente/herramientas.py`, `radar/agente/analista.py`,
`worker/analizar.py`, `worker/principal.py` y `tests/test_analista.py`. El resto del
repositorio se generó de la misma forma, frente por frente (tabla de arriba).

Las personas del equipo definieron el diseño, revisaron el trabajo y decidieron qué se
integra. Ninguna cifra de la documentación se escribió a mano: sale de `evals/reporte.md`
o de pytest.

**En tiempo de ejecución** el radar también usa la API de Claude:

- El analista (Claude Agent SDK, modelo `claude-opus-5-5`) redacta el análisis y los
  comunicados, un producto a la vez. Corre encerrado: solo herramientas de lectura,
  `permission_mode="dontAsk"`, herramientas negadas, sin configuración heredada y con hooks
  de guarda. Tiene un tope de 8 turnos y 0,50 USD por producto. Cada comunicado pasa por el
  verificador; si el modelo falla, se pasa del tope o el verificador lo rechaza, el texto lo
  arma código (respaldo).
- El normalizador puede pedir a Claude que desempate entre cinco candidatos de CPE, solo
  con la bandera `RADAR_DESEMPATE_MODELO=1`. Sin la bandera no se llama al modelo.

## Datos públicos

| Fuente | Uso | Términos |
|---|---|---|
| [NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) (NIST) | CVE, rangos de versiones afectadas (`configurations`) y CVSS | Datos del gobierno de EE. UU., de uso libre. Aviso que pide NVD: *This product uses data from the NVD API but is not endorsed or certified by the NVD.* |
| [Diccionario de CPE de NVD](https://nvd.nist.gov/products/cpe) (feed `nvdcpe-2.0`, 13 nov 2026) | Diccionario de pares `vendor:producto` del normalizador (`radar/datos/cpe_pares.json.gz`, reducido a 50 515 pares de aplicación) | Mismos términos que NVD |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), `catalogVersion` 2026.11.13 | Vulnerabilidades con explotación confirmada; se emparejan por ID de CVE | Datos del gobierno de EE. UU., de uso libre |
| [FIRST EPSS](https://www.first.org/epss/) | Probabilidad de explotación en 30 días, bajada el día del evento | Uso libre; FIRST pide citar la fuente al usarlo |

Los identificadores CVE son del programa CVE®, marca registrada de The MITRE Corporation.

El 14 de noviembre de 2026, antes del evento, se guardó un snapshot de NVD y KEV para 20
pares de productos. Con él, un script auxiliar escrito aparte (nunca el cruce del
proyecto) calculó la respuesta conocida contra la que se mide la detección. La lista de
productos y versiones de prueba se armó ese mismo día con esos datos públicos.

## Inventario sintético

- 50 equipos (`EQUIPO-001` a `EQUIPO-050`) y 2 servidores, todos ficticios.
- Los programas son reales y las versiones elegidas a propósito: vulnerables, sanas,
  fronteras de rangos y nombres sucios como los reporta un RMM. El relleno (15 a 25
  programas por equipo) son nombres internos inventados, sin CPE.
- Semilla fija (`20261114`): dos corridas de `uv run python -m datos_prueba.generar` dan
  los mismos bytes en CSV, Excel y respuesta.
- Los casos de inyección (`datos_prueba/casos_inyeccion.py`) los escribió el equipo como
  pruebas defensivas del propio radar.

## Librerías y servicios

| Librería | Licencia | Uso |
|---|---|---|
| [Pydantic](https://docs.pydantic.dev) | MIT | Contratos de datos |
| [HTTPX](https://www.python-httpx.org) | BSD-3-Clause | Clientes de NVD, KEV y EPSS |
| [RapidFuzz](https://github.com/rapidfuzz/RapidFuzz) | MIT | Búsqueda difusa del normalizador |
| [python-dotenv](https://github.com/theskumar/python-dotenv) | BSD-3-Clause | Secretos desde `.env` |
| turso-serverless | MIT | Cliente de Turso |
| [FastAPI](https://fastapi.tiangolo.com) | MIT | API |
| [Uvicorn](https://www.uvicorn.org) | BSD-3-Clause | Servidor local de la API |
| python-multipart | Apache-2.0 | Subida de archivos en la API |
| [pandas](https://pandas.pydata.org) | BSD-3-Clause | Lectura de CSV y Excel |
| [openpyxl](https://openpyxl.readthedocs.io) | MIT | Excel |
| [Anthropic SDK](https://github.com/anthropics/anthropic-sdk-python) | Apache-2.0 | Desempate opcional del normalizador |
| [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) | MIT | Analista |
| [MCP SDK](https://github.com/modelcontextprotocol/python-sdk) | MIT | Servidor MCP del plugin |
| [Chart.js](https://www.chartjs.org) 4.4.1 | MIT | Gráficos del dashboard |
| [GSAP](https://gsap.com) 3.13.0 (core, SplitText, ScrambleText) | Licencia estándar de GSAP (gratuita, incluye plugins) | Movimiento de la landing |
| [pytest](https://pytest.org) | MIT | Pruebas |
| [Ruff](https://docs.astral.sh/ruff/) | MIT | Formato y lint |

Fuente tipográfica del dashboard: [Inter](https://rsms.me/inter/) (SIL Open Font License),
servida por Google Fonts.

Servicios: [Vercel](https://vercel.com) (API y dashboard) y [Turso](https://turso.tech)
(base de datos). Gestor de entorno: [uv](https://docs.astral.sh/uv/).

## Agente local (rama `agente-local`)

Generado con Claude Code (Anthropic) el 14 de noviembre de 2026 a partir de
`docs/plan-agente-local.md`, y revisado con las pruebas que se listan en `docs/testing.md`:

- Código: `agente_local/`, `radar/equipos/`, `radar/api/agente.py`, `radar/fuentes/osv.py`,
  `radar/fuentes/finsoporte.py`, `radar/nucleo/versiones_paquete.py`, `radar/nucleo/cvss.py`,
  `worker/equipos.py` y la vista por equipo de `public/`.
- Cambios en código existente: `radar/agente/verificador.py` y `respaldo.py` (comandos
  permitidos), `radar/bd.py::guardar_inventario`, `radar/api/rutas.py`, `radar/mcp/servidor.py`,
  `worker/descargar.py`, `radar/contratos.py` (`agente` y `cruzar_so`) y `radar/esquema.sql`.
- Pruebas: `tests/test_agente_local.py`, `test_agente_api.py`, `test_postura.py`, `test_osv.py`
  y `test_versiones_paquete.py`.
- Documentación: `docs/agente-local.md` y las secciones "Agente local" de
  `docs/requerimientos-funcionales.md` y `docs/testing.md`.

Fuentes de datos públicas de esta parte:

- OSV.dev (avisos de seguridad de distribuciones Linux), consultado en línea por el worker.
- endoflife.date (fechas de fin de soporte), copia en `radar/datos/fin_soporte.json`.
- NVD (CPE y rangos de build de Windows), como el resto del radar.
- Algoritmos de comparación de versiones: política de Debian (sección 5.6.12) y `rpmvercmp`.
- Fórmula del puntaje base: especificación de CVSS 3.1 de FIRST.

## Revisi?n del agente local

Codex (OpenAI) corrigi? la recepci?n limitada por bloques, la programaci?n y los reintentos,
la validaci?n del runtime de Windows y la integraci?n con main, con pruebas de regresi?n.

## Parcheo desde el agente local

Claude Code (Claude Opus 5.5, Anthropic) diseñó e implementó el parcheo aprobado: firma
Ed25519 en Python puro, catálogo cerrado, ejecutores de Windows y Linux, rutas, panel e
informe de remediación, con sus pruebas (`docs/plan-parcheo.md`).

## Logo de Lighthouse

Claude Code (Claude Opus 5.5, Anthropic) diseñó el logo: un faro cuyo haz evoca el barrido
del radar, en SVG (`public/lighthouse.svg`, `public/marca.svg` como ícono de pestaña y en
línea en cada página). El nombre está convertido a trazos desde Geist SemiBold (Vercel,
SIL Open Font License 1.1).

## Asistente del panel y de Mi equipo

Claude Code (Claude Opus 5.5, Anthropic) diseñó e implementó el asistente con IA del panel
y de Mi equipo (bucle con pausa para aprobar, herramientas por rol, tarjeta de antes y
después, auditoría, topes de gasto, privacidad, interfaz y pruebas con Playwright), a partir
de la receta `panel-ia` de Mike (`docs/plan-asistente.md`).
