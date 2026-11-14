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

## Ingesta

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_ingesta.py` | Campos del contrato, versiones como texto, `;` y cp1252, alias en inglés, encabezado bajo títulos, filas sin versión, descartes con motivo, duplicados, celda enorme y texto hostil intacto, Excel multihoja y sin extensión, errores legibles, límites, inventario generado completo (RF-201 a RF-203); nombres de equipo legítimos intactos, envenenados saneados y cruzados, mismo nombre en varias filas, acentos, guion bajo, saltos, nombre de 2000 caracteres, filas por MCP (RF-206) | `datos_prueba/generados/` para una prueba |

Córrelo tú mismo: `uv run pytest tests/test_ingesta.py`.

## Normalizador y datos de prueba

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_normalizador.py` | Filas envenenadas de las cuatro rondas (`casos_inyeccion.TODOS`): ninguna saca al equipo de los hallazgos, quedan marcadas y sin el texto inyectado en el nombre; versión con instrucción; nombres legítimos sin marca (RF-311). Además: versión comparable, nombre limpio, alias de trampas, nombres fuera de la semilla, producto ausente de NVD, plugins de Jenkins, empate de Python, desempate con modelo sustituido (sin API), agrupación y nombre canónico, nombre enorme (RF-301 a RF-305). Medición contra la respuesta conocida (RF-307) | `resources/` para la medición |
| `tests/test_integracion.py` | Pipeline real de punta a punta: 735 pares CVE y versión, 6500 por equipo, detección y precisión 100 %, 0 falsos positivos, 12 KEV, 1098 no precisos por activo, cobertura por motivo; tabla para el reporte (RF-309, RF-310) | `resources/`; usa `datos_locales/radar.db` en solo lectura o arma una base temporal desde el snapshot |
| `tests/test_datos_prueba.py` | Semilla fija, totales de SEMILLA.md (735 y 12 KEV), distribución, fronteras, cobertura con motivos del contrato, inyección aparte, bytes idénticos entre corridas, la ingesta lee CSV y xlsx completos (RF-306) | `resources/` (se salta si falta) |

Córrelo tú mismo: `uv run pytest tests/test_normalizador.py tests/test_datos_prueba.py tests/test_integracion.py`. La exactitud no ajustada (RF-308) se prueba en `tests/test_normalizador.py::test_conjunto_fuera_de_semilla_no_inventa_cpe` (sin CPE inventados, piso de 80 %). Para las cifras: `uv run python -m datos_prueba.generar && uv run python -m datos_prueba.medir_normalizador`.

## API y panel

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_api.py` | Clave obligatoria y 503 en Vercel sin clave (RF-601); resumen, orden y filtros de hallazgos, EPSS ausente como `null`, productos y análisis (RF-602); "posterior a" y nunca "actualizar a" con `versionEndIncluding` (RF-603); cambio de estado y aprobación (RF-604); inventario ilegible da 400 y cruce real contra una copia de la base local (RF-605, RF-606); detalle sin análisis del agente muestra y aprueba el respaldo (RF-607); aprobación exige quién y queda guardada en la base; barrido de umbrales con piso de KEV y celda vigente (RF-608); trazas desde la base (RF-609) | `datos_locales/radar.db` para la prueba de cruce (se salta si falta) |

Córrelo tú mismo: `uv run pytest tests/test_api.py`. El panel en local: `uv run uvicorn app:app --port 8000`.


## Plugin y servidor MCP

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_mcp.py` | Herramientas y anotaciones de solo lectura; origen `ejemplo`, `local` o `turso` y aviso; base caída como error; orden, filtros, cerrados, acciones por producto, CVE distintas frente a hallazgos; fuente caída y fuente sin dato; equipos expuestos; detalle con y sin grupo y pidiendo solo los pares del producto; `cargar_inventario` con ruta, filas, rutas rechazadas, carga real que guarda, normaliza, cruza y deja trabajo, y función compartida; error por el protocolo MCP con cliente en proceso; `posible_inyeccion` por programa o versión y por equipo saneado, señal débil sola sin marca (RF-204, RF-205, RF-701 a RF-703, RF-705) | `datos_prueba/generados/` para una prueba |

Córrelo tú mismo: `uv run pytest tests/test_mcp.py`. De punta a punta con Claude Code (no corre en CI): `claude plugin validate .` y el guion de `.coordinacion/plugin.md` con `claude --plugin-dir`.


## Agente local

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_agente_local.py` | Recolectores con las salidas de las herramientas como texto (registro, `dpkg-query`, `rpm`, `os-release`, `lsblk`, `ufw`, `mokutil`), build de Windows, postura que nunca adivina, reporte, CSV que lee la ingesta, HTTPS obligatorio, credencial guardada sin el token, respuesta de la que solo se lee el intervalo, reporte pendiente sin red, sin redirecciones (RF-801 a RF-803) | nada |
| `tests/test_agente_api.py` | Inscripción con token y cerrada sin él, credencial como SHA-256, sin reemplazo de credencial, reporte con la credencial del propio equipo, respuesta sin órdenes, reportes mal formados y enormes, revocación por equipo, topes y limpieza, cruce de aplicaciones y de Windows, cierre propuesto al parchar, CSV que no borra a los agentes, nombre de equipo envenenado, paquetes de distribución fuera del cruce por CPE, vista por equipo con comandos, retiro (RF-811 a RF-815); equipo pendiente que no se cruza, aprobar con nombre y cruzar el último reporte, aprobar antes del primer reporte, rechazar, revocado no se aprueba, tope de pendientes, equipos anteriores aprobados al migrar (RF-819) | nada |
| `tests/test_postura.py` | Windows reconocido por build y versión, activos por build, fin de soporte por edición y por distribución, copia de endoflife.date, cada regla de postura con su prioridad, `desconocido` a cobertura, plantillas de `winget`, `apt-get` y `dnf` con nombres hostiles, regla 5 en los comandos, extracción de comandos frente a menciones, verificador con `comando_ajeno`, respaldo con comandos (RF-814, RF-823 a RF-826) | nada |
| `tests/test_osv.py` | Ecosistemas, aviso reducido, lote con paginación, agrupación por paquete fuente o binario, mayor versión de arreglo, KEV y EPSS por ID, caché de avisos, aviso sin detalle, distribución sin fuente, OSV caído que no borra lo guardado, worker y su ejecución (RF-816 a RF-818) | nada: OSV va con transporte simulado |
| `tests/test_versiones_paquete.py` | Orden de dpkg y de rpm en los dos sentidos, mayor de una lista, CVSS 3.x desde el vector y vectores sin puntaje (RF-821, RF-822) | nada |

Córrelo tú mismo: `uv run pytest tests/test_agente_local.py tests/test_agente_api.py tests/test_postura.py tests/test_osv.py tests/test_versiones_paquete.py`. De punta a punta en local, los cinco pasos de [agente-local.md](agente-local.md). RF-804 (instaladores) no tiene prueba automática.

## Seguridad (limpieza, equipos, hooks, verificador, plugin, suite de inyección)

| Prueba | Qué cubre | Requiere |
|---|---|---|
| `tests/test_limpieza.py` | Recorte por campo (160 para el inventario, 2000 para textos largos, claves desconocidas al tope corto), saltos, control e invisibles, `<` `>` neutralizados, marca de datos, forma MCP, los casos de inyección | nada |
| `tests/test_equipos.py` | Nombre de equipo RFC 1123, saneado `prefijo~fNNN` igual al de la ingesta, sin fusionarse con el equipo real | nada |
| `tests/test_hooks.py` | Guarda previa por lista exacta, argumentos con saltos, largo o formato de `cve` inválido, ante error niega; limpieza posterior con la misma forma, ante error retiene; `opciones_encierro` arma un cliente válido | nada |
| `tests/test_verificador.py` | Nada de más (CVE, cifras, versiones, equipos, enlaces y dominios, cuentas en dígitos y palabras), prioridad del origen, KEV no negada, versión instalada no recomendada, equipos fuera de canales abiertos, regla 5, homoglifos, respaldo que siempre pasa, decidir | nada |
| `tests/test_plugin.py` | hooks.json, limpiar_salida que nunca falla y retiene, aprobar_escritura con "ask" y "deny" ante error, copia exacta de limpieza.py | nada |
| `tests/test_inyeccion.py` | Suite de dos brazos y 4 rondas con agentes simulados (peor caso y honesto), entrada forzada y real, equipo oculto, límites declarados, tubería del analista real con un analizar falso; con `-m agente`, el analista real | nada (`-m agente`: clave y `analizar`) |

Las cifras salen de `uv run python -m evals.medir` -> `evals/reporte.md`. Córrelo tú mismo:
`uv run pytest tests/test_limpieza.py tests/test_equipos.py tests/test_hooks.py tests/test_verificador.py tests/test_plugin.py tests/test_inyeccion.py`.
