# Lighthouse

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
| Agente local | `agente_local/`, `radar/equipos/` | Recolector para Windows y Linux que envía el inventario de cada PC; vista por equipo en el panel ([estado y cómo probarlo](docs/agente-local.md)) |

## Demo

Enlace a la demo desplegada: se publica aquí cuando esté la preview de Vercel.
El guion de 3 minutos está en [`docs/guion-demo.md`](docs/guion-demo.md).

## Correrlo en local

Requiere Python 3.12 y [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync --all-extras --group dev
cp .env.example .env                    # completa los valores; sin Turso usa un sqlite local

# Fuentes desde la red: NVD por par, KEV y EPSS del día (con NVD_API_KEY va más rápido)
uv run python -m worker.descargar --en-linea --pares rarlab:winrar google:chrome
# Con el snapshot privado del equipo en resources/ (no está en el repositorio):
# uv run python -m worker.descargar --desde-snapshot

# Cruce de un inventario CSV o Excel desde la consola (normaliza, cruza y guarda)
uv run python -m radar.nucleo.corrida ruta/al/inventario.csv

# Panel y API
uv run python -m radar.api.cuentas crear --usuario admin --nombre "Admin" --rol admin
uv run uvicorn app:app --port 8000      # landing en http://localhost:8000/, panel en /panel/
vercel dev                              # o igual que en Vercel (requiere el proyecto linkeado)

# Pruebas (las que llaman a Claude llevan el marcador "agente" y no corren por defecto)
uv run pytest
uv run pytest -m agente                 # solo con ANTHROPIC_API_KEY, gasta créditos
```

Para que el panel lea la base local en vez de los datos de ejemplo: `RADAR_DATOS=base`.

## Analista

El analista con el Claude Agent SDK vive en `radar/agente/` y `worker/` (contrato en
[`docs/contrato-analista.md`](docs/contrato-analista.md)). Corre fuera de Vercel, encerrado en
solo lectura, con tope de turnos y de gasto por producto, y su texto pasa por el verificador;
si algo no coincide, queda el texto armado por código.

```bash
uv run python -m worker.principal --sin-agente  # solo texto de respaldo, sin créditos
uv run python -m worker.principal --una-vez     # un trabajo con Claude (ANTHROPIC_API_KEY)
uv run python -m worker.principal               # bucle: toma los trabajos "analizar" pendientes
```

Contra el Turso compartido pide `--turso` explícito. Mientras ningún worker toma un trabajo, el
panel lo muestra como "Análisis en cola" y el detalle usa el texto armado por código.

## Plugin de Claude Code

```bash
claude plugin marketplace add mikerb95/hackaton-DefAcc
claude plugin install radar@radar
```

## Licencia

MIT. Lo generado con IA se cita en [`CREDITOS.md`](CREDITOS.md).

## Créditos de desarrollo

[![Desarrollado por codebymike](https://img.shields.io/badge/desarrollado%20por-codebymike-0b7285?style=for-the-badge)](https://codebymike.net)
[![GitHub mikerb95](https://img.shields.io/badge/GitHub-mikerb95-181717?style=for-the-badge&logo=github)](https://github.com/mikerb95)
[![GitHub MiguelAriza77](https://img.shields.io/badge/GitHub-MiguelAriza77-181717?style=for-the-badge&logo=github)](https://github.com/MiguelAriza77)
