"""Equipos que reportan con el agente local (docs/plan-agente-local.md).

- `contratos.py`: el `ReporteEquipo` que envía el agente y el hallazgo por equipo.
- `recepcion.py`: valida, limita y limpia el reporte, y lo reparte.
- `almacen.py`: tablas `equipos`, `paquetes_so` y `hallazgos_equipo`.
- `so.py`: sistema operativo como activo (Windows contra NVD) y fin de soporte.
- `paquetes.py`: paquetes de distribuciones Linux contra OSV.
- `postura.py`: reglas deterministas de postura.
- `remediacion.py`: comandos de remediación desde plantillas cerradas.
- `comandos.py`: extrae del texto lo que parece un comando, para el verificador.
- `cruce.py`: cruce completo del inventario con lo que reportan los agentes.
"""
