"""Entrada de la API en Vercel: la variable `app` es la que detecta el runtime de Python.

En Vercel, `public/` lo sirve la red de distribución. En local (`uv run uvicorn app:app`)
se monta aquí para ver el panel en la misma dirección.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from radar.api.agente import router_agente, router_equipos
from radar.api.rutas import router
from radar.api.sesion import router_admin, router_sesion

load_dotenv()

app = FastAPI(title="Radar de vulnerabilidades", docs_url=None, redoc_url=None)
app.include_router(router_sesion)
app.include_router(router_admin)
app.include_router(router)
app.include_router(router_agente)
app.include_router(router_equipos)

PUBLICO = Path(__file__).parent / "public"
if not os.environ.get("VERCEL") and PUBLICO.is_dir():
    app.mount("/", StaticFiles(directory=PUBLICO, html=True), name="publico")
