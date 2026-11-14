# Documentación del Radar de vulnerabilidades

Aquí está todo lo que explica qué hace el radar, cómo está armado y cómo se comprobó. Empieza
por el planteamiento si llegas sin contexto; ve directo a requerimientos o pruebas si buscas
una pieza concreta. Cada requerimiento apunta al archivo que lo implementa y a su prueba.

| Cifra | Valor |
|---|---|
| Páginas con contenido | se completa al cierre |
| Requerimientos funcionales | ver [requerimientos-funcionales.md](requerimientos-funcionales.md) |
| Pruebas automáticas | salen de `uv run pytest`, ver [testing.md](testing.md) |
| Resultados de la suite de inyección | salen de `evals/reporte.md`, ver [reportes-pruebas.md](reportes-pruebas.md) |

Ninguna cifra de esta documentación se escribe a mano: toda sale de `evals/reporte.md` o de la
salida de pytest. Si un número no coincide entre páginas, es un error.

## Mapa

| Página | Qué hay | Cifra clave |
|---|---|---|
| [planteamiento.md](planteamiento.md) | Qué es el radar, para quién, la tesis y las cuatro preguntas de la entrega | Track 1 |
| [requerimientos-funcionales.md](requerimientos-funcionales.md) | Requerimientos `RF-NNN` por módulo, con estado, archivos y pruebas | implementados / total por módulo |
| [requerimientos-no-funcionales.md](requerimientos-no-funcionales.md) | Costo, tiempos, topes de gasto, límites de fuentes, privacidad, reproducibilidad | `RNF-NN` |
| [casos-de-uso.md](casos-de-uso.md) | Casos `CU-NN`: cargar inventario, cruce y priorización, análisis con aprobación, ataque por inventario envenenado | 4 casos del día |
| [diagramas/componentes.md](diagramas/componentes.md) | Piezas del sistema y qué datos pasan entre ellas | 4 lugares de ejecución |
| [diagramas/despliegue.md](diagramas/despliegue.md) | Dónde corre cada pieza: Vercel, Turso, worker, portátil del plugin | 1 base compartida |
| [diagramas/secuencia.md](diagramas/secuencia.md) | Carga y cruce, análisis con verificador, ataque bloqueado | 3 flujos |
| [diagramas/actividades.md](diagramas/actividades.md) | Actividades del responsable de TI | si alcanza |
| [testing.md](testing.md) | Pirámide de pruebas, qué cubre cada archivo y cómo correrlo | total de pytest |
| [reportes-pruebas.md](reportes-pruebas.md) | Resultados de los evals con defensa y sin defensa | tasa de inyección |
| [verificacion-validacion.md](verificacion-validacion.md) | Decisiones que cambian cifras y por qué | decisiones con prueba |
| [contrato-analista.md](contrato-analista.md) | Contrato autocontenido del analista con Agent SDK (frente externo): archivos, funciones disponibles, firma que espera la suite de inyección y reglas | 1 frente externo |
| [escalamiento.md](escalamiento.md) | Escalera de escalamiento: qué pasa con una alerta según su prioridad, de panel a ticket y a teléfono | peldaños |
| [guion-demo.md](guion-demo.md) | Guion de la demo de 3 minutos: preparación, seis pasos con lo que se dice, lámina de números y qué hacer si algo falla | 3 minutos |
| [AMENAZAS.md](AMENAZAS.md) | Modelo de amenazas del agente y del inventario | vectores |
| [LIMITES.md](LIMITES.md) | Lo que el radar no detecta y el riesgo de uso dual | límites conocidos |
| [../CREDITOS.md](../CREDITOS.md) | Lo generado con IA y las fuentes de datos usadas | se completa al cierre |
| [../LICENSE](../LICENSE) | Licencia del proyecto | MIT |
| [roles.md](roles.md) | Roles del equipo y matriz RACI | si alcanza |
| [FICHA_TECNICA.md](FICHA_TECNICA.md) | Ficha de dos páginas para los jueces | 2 páginas |
| [RESUMEN.md](RESUMEN.md) | Resumen de 150 a 250 palabras | se escribe de último |

## Módulos de los requerimientos

| Prefijo | Módulo |
|---|---|
| RF-1NN | Núcleo (fuentes, cruce, priorización, estados) |
| RF-2NN | Ingesta (CSV, Excel, MCP) |
| RF-3NN | Normalizador |
| RF-4NN | Analista |
| RF-5NN | Seguridad (verificador, hooks, guarda, suite de inyección) |
| RF-6NN | API y panel |
| RF-7NN | Plugin de Claude Code |

## Córrelo tú mismo

```bash
uv sync --all-extras --group dev
uv run python -m worker.descargar --en-linea --pares rarlab:winrar google:chrome
# con el snapshot privado en resources/: uv run python -m worker.descargar --desde-snapshot
uv run uvicorn app:app --port 8000   # panel en http://localhost:8000/
uv run pytest
```
