# Radar de vulnerabilidades

Cruza el inventario de software de una empresa (CSV, Excel o MCP) con NVD, CISA KEV y EPSS,
dice qué equipos están expuestos y prioriza lo que ya se está explotando. Un agente hecho con
el Claude Agent SDK redacta el análisis y los comunicados, y está diseñado para no dejarse
secuestrar por un inventario envenenado (inyección indirecta). Proyecto de la hackatón def/acc,
14 de noviembre de 2026.

> Versión corta. La documentación completa vive en [`docs/`](docs/README.md).

## Piezas

| Pieza | Dónde | Qué hace |
|---|---|---|
| Núcleo | `radar/nucleo/`, `radar/fuentes/` | Cruce determinista por versión contra NVD, KEV y EPSS, y priorización |
| Ingesta | `radar/ingesta/` | Lee CSV y Excel y normaliza cada programa a un CPE |
| API y panel | `app.py`, `radar/api/`, `public/` | FastAPI en Vercel y dashboard HTML sin framework |
| Analista | `radar/agente/`, `worker/` | Agente encerrado de solo lectura, con verificador y texto de respaldo |
| Seguridad | `radar/seguridad/`, `evals/` | Limpieza de texto no confiable y suite de inyección con y sin defensa |
| Plugin | `plugin/`, `radar/mcp/` | Plugin de Claude Code con servidor MCP para cargar y consultar |

## Correrlo en local

```bash
uv sync --all-extras --group dev
cp .env.example .env            # completa los valores
uv run python -m worker.descargar --desde-snapshot
uv run uvicorn app:app --port 8000   # panel en http://localhost:8000/
uv run pytest
```

## Plugin de Claude Code

```bash
claude plugin marketplace add mikerb95/hackaton-DefAcc
claude plugin install radar@radar
```

## Licencia

MIT. Lo generado con IA se cita en [`CREDITOS.md`](CREDITOS.md).
