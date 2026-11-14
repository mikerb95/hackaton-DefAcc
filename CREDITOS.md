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
