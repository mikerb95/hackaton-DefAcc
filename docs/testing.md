## Núcleo

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_versiones.py` | Orden numérico, ceros, prelanzamiento, metadatos `+N`, "no comparable" (RF-101) | nada |
| `tests/test_cruce.py` | Regla de afectación, fronteras, rango más acotado, escape de CPE, dos pares de Docker, cobertura, versión objetivo (RF-102 a RF-104). Detección contra los 60 casos de `semilla_respuesta.json`: CVE precisas, no precisas, KEV y peor CVSS | `resources/` (se salta si falta) |
| `tests/test_prioridad.py` | Umbrales y bordes, umbrales por entorno, razones, EPSS ausente, no precisos, orden, boletín, agrupación, ejemplos coherentes con el núcleo (RF-105, RF-106) | `resources/` para una prueba |
| `tests/test_bd.py` | Ida y vuelta de cada contrato en sqlite, la corrida no pisa el estado humano, cola de trabajos, solo lectura, descarga desde snapshot y fuente caída registrada (RF-108, RF-109) | `resources/` para una prueba |
| `tests/test_corrida.py` | Inventario generado completo contra el snapshot: 735 pares CVE y versión, 6500 por equipo, 1098 no precisos, 518 CVE, 12 KEV, 41 equipos con KEV, cobertura por motivo; grupos y cierre propuesto (RF-107) | `resources/` y `datos_prueba/generados/` |
| `tests/test_estados.py` | Cambio de estado validado, la corrida no pisa el estado, línea base silenciosa con excepción de lo reciente, sin repetir avisos, re-aviso al subir a inmediato, cierre propuesto, aprobación del comunicado, trazas, migración de columnas, barrido de umbrales (RF-110 a RF-113) | nada |
| `tests/test_fuentes.py` | Cliente de NVD con transporte simulado (paginación, `noRejected`, clave, 429, 403, 5xx, ventanas de 120 días), CSV de EPSS, descarga en línea con un par caído | nada |

Córrelo tú mismo: `uv run pytest tests/test_estados.py tests/test_fuentes.py tests/test_versiones.py tests/test_cruce.py tests/test_prioridad.py tests/test_bd.py tests/test_corrida.py`.

## Normalizador y datos de prueba

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_normalizador.py` | Versión comparable, nombre limpio, alias de trampas, nombres fuera de la semilla, producto ausente de NVD, plugins de Jenkins, empate de Python, desempate con modelo sustituido (sin API), agrupación y nombre canónico, nombre enorme (RF-301 a RF-305). Medición contra la respuesta conocida (RF-307) | `resources/` para la medición |
| `tests/test_datos_prueba.py` | Semilla fija, totales de SEMILLA.md (735 y 12 KEV), distribución, fronteras, cobertura con motivos del contrato, inyección aparte, bytes idénticos entre corridas, la ingesta lee CSV y xlsx completos (RF-306) | `resources/` (se salta si falta) |

Córrelo tú mismo: `uv run pytest tests/test_normalizador.py tests/test_datos_prueba.py`. Para las cifras: `uv run python -m datos_prueba.generar && uv run python -m datos_prueba.medir_normalizador`.

## API y panel

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_api.py` | Clave obligatoria y 503 en Vercel sin clave (RF-601); resumen, orden y filtros de hallazgos, EPSS ausente como `null`, productos y análisis (RF-602); "posterior a" y nunca "actualizar a" con `versionEndIncluding` (RF-603); cambio de estado y aprobación (RF-604); inventario ilegible da 400 y cruce real contra una copia de la base local (RF-605, RF-606) | `datos_locales/radar.db` para la prueba de cruce (se salta si falta) |

Córrelo tú mismo: `uv run pytest tests/test_api.py`. El panel en local: `uv run uvicorn app:app --port 8000`.
