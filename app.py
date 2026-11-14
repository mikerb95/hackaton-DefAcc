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

from radar.api.rutas import router

load_dotenv()

app = FastAPI(title="Radar de vulnerabilidades", docs_url=None, redoc_url=None)
app.include_router(router)

PUBLICO = Path(__file__).parent / "public"
if not os.environ.get("VERCEL") and PUBLICO.is_dir():
    app.mount("/", StaticFiles(directory=PUBLICO, html=True), name="publico")
