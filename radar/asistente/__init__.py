"""Asistente con IA del panel y de /mi-equipo/ (docs/plan-asistente.md).

Consulta el radar con herramientas de solo lectura y, cuando hay que cambiar algo, prepara
una tarjeta de antes y después que una persona aprueba. Nunca escribe solo.

Módulos puros (sin red ni base): `bucle`, `costo`, `turnos`, `privacidad`, `guardia`,
`permisos`, `prompt`. Con base: `herramientas`, `escrituras`, `almacen`. Une todo: `motor`.
"""
