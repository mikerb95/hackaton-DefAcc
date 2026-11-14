"""Clave de acceso compartida para la API (PLAN, sección 11).

La URL es pública y cada carga gasta créditos de Claude, así que en Vercel toda ruta pide
la cabecera `X-Clave-Acceso`. En local, sin `CLAVE_ACCESO` definida, se deja pasar para
poder trabajar; en Vercel (variable `VERCEL` presente) falta de clave es un error, no un
permiso.
"""

from __future__ import annotations

import hmac
import os

from fastapi import Header, HTTPException, status

CABECERA = "X-Clave-Acceso"


def exigir_clave(x_clave_acceso: str | None = Header(default=None)) -> None:
    esperada = os.environ.get("CLAVE_ACCESO", "")
    if not esperada:
        if os.environ.get("VERCEL"):
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "La API no tiene CLAVE_ACCESO configurada.",
            )
        return
    if not x_clave_acceso or not hmac.compare_digest(x_clave_acceso, esperada):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Falta o no coincide {CABECERA}.")
