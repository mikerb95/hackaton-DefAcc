# Radar de vulnerabilidades (hackatón def/acc, 14 nov 2026)

Contexto compartido por las sesiones de Claude Code que desarrollan el proyecto en
paralelo, una por frente, todas en este mismo directorio (no son piezas del producto:
el "analista" del producto es otra cosa). Es estable a propósito: no lo edites para
anotar avances (eso invalida la caché de prompt de todos). Los avances van en
`/home/mike/dev/work/github.com/hackaton-DefAcc/.coordinacion/`.

## Qué es

Radar que cruza el inventario de software de una empresa (CSV, Excel, MCP) con NVD,
KEV y EPSS, dice qué equipos están expuestos, prioriza lo explotado y un agente
(Claude Agent SDK) redacta análisis y comunicados. Tesis del pitch: **un agente
defensor que no se deja secuestrar** por un inventario envenenado (inyección indirecta),
demostrado con una suite de inyección medida con defensa y sin defensa. Track 1.

## Fuente de verdad

- Plan completo: `resources/PLAN.md`. Lee solo la sección de tu frente (tabla abajo).
  **No leas desde la línea 1527 (Parte B, privada) ni la cites en código o docs.**
- Semilla y casos de inyección ronda 1: `resources/SEMILLA.md`.
- Respuesta conocida (60 casos): `resources/semilla_respuesta.json`. Nunca se calcula
  con el cruce del proyecto.
- Snapshot crudo de NVD (20 pares, 105 MB) y KEV `2026.11.13`: `resources/nvd_snapshot/`.
  Úsalo como caché local: no vuelvas a pedir a NVD lo que ya está ahí. Son archivos
  grandes: nunca los leas enteros, procésalos con scripts.

| Tema | Líneas de PLAN.md |
|---|---|
| Arquitectura y flujo | 204-233 |
| Stack | 235-283 |
| Fuentes (NVD, KEV, EPSS) | 284-351 |
| Lógica del núcleo (versiones, afectación, prioridad) | 352-423 |
| Contratos | 424-439 |
| Esquema Turso | 440-607 |
| API y dashboard | 608-664 |
| Normalizador | 665-694 |
| Analista Agent SDK (controles, trampas, esqueleto) | 695-849 |
| MCP y plugin | 850-948 |
| Datos de prueba | 949-982 |
| Validación y evals | 983-1032 |
| Seguridad y riesgo dual | 1033-1067 |
| Árbol del repo y dependencias | 1200-1378 |
| Documentación (convenciones) | 1380-1460 |

## Stack

Python 3.12 + `uv`, Pydantic, httpx, Turso (`turso_serverless`), FastAPI en Vercel,
dashboard HTML/JS sin framework con Chart.js en `public/`, pandas + openpyxl,
rapidfuzz, `claude-agent-sdk` (solo worker, nunca en `requirements.txt`), SDK de MCP,
pytest, ruff. Modelo: `claude-opus-5-5`. Desempate del normalizador con `anthropic`
directo y `effort: low`.

## Los frentes y sus carpetas

Cada agente escribe solo en sus carpetas. Si necesitas algo de otro frente, déjalo
pedido en su archivo de coordinación, no lo edites tú.

| Frente | Carpetas y archivos | Piezas |
|---|---|---|
| `nucleo` | `radar/contratos.py`, `config.py`, `bd.py`, `esquema.sql`, `ejemplos.py`, `radar/fuentes/`, `radar/nucleo/`, `worker/descargar.py`, `pyproject.toml`, tests de versiones, cruce y prioridad | 1, 13 |
| `normalizador` | `radar/ingesta/normalizador.py`, `datos_prueba/` (salvo `casos_inyeccion.py`), `tests/test_normalizador.py` | 3, 4 |
| `analista` (contrato en `docs/contrato-analista.md`) | `radar/agente/analista.py`, `herramientas.py`, `instrucciones.py`, `worker/principal.py`, `worker/analizar.py` | 7, 15 |
| `guarda` | `radar/seguridad/`, `radar/agente/hooks.py`, `verificador.py`, `respaldo.py`, `datos_prueba/casos_inyeccion.py`, `evals/`, `plugin/hooks/`, `plugin/scripts/`, `docs/AMENAZAS.md`, `docs/LIMITES.md`, tests de verificador, inyección y plugin, `.github/workflows/pruebas.yml` | 5, 6, 8, 12 |
| `panel` | `app.py`, `requirements.txt`, `radar/api/`, `public/`, `README.md`, `docs/` (consolida), `CREDITOS.md` | 2, 9, 11, 14, 16 |
| `vercel` | Infraestructura: `.vercel/`, `vercel.json`, `.vercelignore`, variables en Vercel, base y tokens de Turso, despliegues. No toca código de la app | 2 |
| `plugin` | `radar/ingesta/archivos.py`, `radar/mcp/`, `plugin/` (salvo hooks y scripts), `.claude-plugin/marketplace.json`, `tests/test_ingesta.py` | 10 |

Las sesiones comparten directorio y `.venv`. Solo `nucleo` toca `pyproject.toml` y
`uv.lock`: si necesitas una dependencia, pídela en `.coordinacion/nucleo.md` en vez de
correr `uv add` (dos `uv add` a la vez corrompen el lock). Un archivo que no es tuyo
no se edita: se pide.

El analista lo construyó la sesión local `analista`. Un dev externo trabaja en otro PC y
entrega por PR (por ejemplo el agente local de inventario); no ve `.coordinacion/` ni
`resources/`. Cualquier cambio en `hooks.py`, `verificador.py`, `respaldo.py`,
`contratos.py`, `bd.py` o en la firma de `analizar` se refleja también en
`docs/contrato-analista.md`.

`radar/contratos.py` y `radar/esquema.sql` son del núcleo. Un cambio ahí se anuncia en
`.coordinacion/nucleo.md` antes de hacerlo, porque rompe a todos.

## Reglas que no se negocian

1. Sin comparación no hay hallazgo: versión ilegible o sin CPE va a cobertura.
2. Fuente caída no es cero. EPSS que no aparece no es 0.
3. Entradas `vulnerable: false` en NVD se ignoran. CVE sin `configurations` se cuenta aparte.
4. KEV se empareja por ID de CVE, nunca por nombre de fabricante.
5. `versionEndIncluding` X: no se puede decir "actualizar a X".
6. El modelo no es punto de falla: siempre hay texto de respaldo armado por código.
7. El agente solo lee. El encierro es `permission_mode="dontAsk"` + `disallowed_tools`
   + `setting_sources=[]` + hooks con `on_failure="block"`. `allowed_tools` solo no encierra.
8. Todo texto del inventario es no confiable: se limpia con `radar/seguridad/limpieza.py`
   (solo librería estándar; `plugin/scripts/limpieza.py` es copia exacta).
9. Las pruebas que llaman a Claude llevan el marcador `agente` y no corren en CI.
10. Toda cifra de docs, ficha y pitch sale de `evals/reporte.md` o de pytest, nunca a mano.

## Convenciones

- Español en código, comentarios, mensajes y docs. Identificadores en español como en el plan.
- Nunca em dash ni en dash como puntuación. Nunca `border-left` de acento en cards.
- Nunca hagas commits ni sugieras hacerlos. Nunca subas `.env` ni `resources/`.
- Secretos solo en `.env` (cárgalo con `python-dotenv`). Nombres en `.env.example`.
- Cita en `CREDITOS.md` lo generado con IA.
- `ruff` antes de dar algo por terminado. Una pieza está terminada cuando tiene prueba,
  su línea en `docs/requerimientos-funcionales.md` y su línea en `docs/testing.md`.

## Coordinación entre sesiones

Al arrancar: lee `.coordinacion/<tu-frente>.md` y `.coordinacion/TABLERO.md`.
Al cerrar una pieza o antes de que se acabe tu sesión: actualiza tu archivo con
Hecho / En curso / Siguiente / Bloqueos / Pedidos a otros frentes, y una línea en
TABLERO.md. Así otra sesión (o la misma con API) retoma sin releer todo.
