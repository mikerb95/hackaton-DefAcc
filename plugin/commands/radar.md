---
description: Resumen de lo que exige acción hoy según el radar de vulnerabilidades
argument-hint: "[producto o equipo, opcional]"
allowed-tools: mcp__plugin_radar_radar__consultar_hallazgos, mcp__plugin_radar_radar__equipos_expuestos, mcp__plugin_radar_radar__detalle_producto
---

Arma el resumen de exposición de hoy con las herramientas del radar y la skill
`exposicion`. Solo lectura: no cargues inventario.

Filtro pedido (puede venir vacío): $ARGUMENTS

1. Si el filtro parece un producto, llama a `detalle_producto` con él. Si parece un
   equipo (por ejemplo `EQUIPO-007`), llama a `equipos_expuestos` con `equipo`. Si está
   vacío, llama a `consultar_hallazgos` con `prioridad: "inmediato"` y luego a
   `equipos_expuestos` con `prioridad_minima: "inmediato"`.
2. Responde en este orden, breve:
   - Si `datos` contiene `ejemplo`, una primera línea que diga que son datos de ejemplo.
     (`local` es la base sqlite local con datos reales del cruce; `turso`, la compartida.)
   - **Exige acción hoy**: una línea por elemento de `acciones` (versiones, cuántos
     equipos, CVE en KEV y ransomware si aplica, y la acción según `tipo_objetivo` y
     `como_leer_objetivo`). No hace falta llamar a `detalle_producto` para esto.
   - **Equipos más expuestos**: los cinco primeros con su peor prioridad.
   - **Para la semana**: solo el conteo de `semanal` del resumen.
   - **Sin evaluar**: cuántos programas y por qué. Fuentes caídas, si las hay.
3. Si no hay nada `inmediato`, dilo claro y muestra lo `semanal`. No rellenes.
