"""Acceso a la API: sesión de usuario, clave compartida o modo local.

Quién puede llamar a `/api/*` (salvo `/api/sesion` y `/api/agente/*`), en este orden:

1. Una persona con sesión: cookie `radar_sesion` emitida por `POST /api/sesion`
   (`radar/api/cuentas.py`). Su rol decide qué puede cambiar.
2. Un programa con la clave compartida en `X-Clave-Acceso` (`CLAVE_ACCESO`): el agente local
   en `subir-csv`, scripts y pruebas. Cuenta como administrador.
3. En local, sin `CLAVE_ACCESO` y fuera de Vercel, se deja pasar para poder trabajar (como
   administrador "Modo local"). En Vercel (variable `VERCEL`), sin sesión y sin clave
   configurada es un error, no un permiso.

Roles: `lector` solo mira; `analista` además cambia estados, aprueba comunicados y carga
inventarios; `admin` además gestiona usuarios, tokens de inscripción y equipos.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass

from fastapi import HTTPException, Request, status

CABECERA = "X-Clave-Acceso"
COOKIE = "radar_sesion"


@dataclass(frozen=True)
class Identidad:
    usuario: str
    nombre: str
    rol: str
    via: str  # "sesion", "clave" o "local"
    id: int | None = None

    def publico(self) -> dict:
        return {
            "id": self.id,
            "usuario": self.usuario,
            "nombre": self.nombre,
            "rol": self.rol,
            "via": self.via,
        }


def resolver_identidad(peticion: Request) -> Identidad | None:
    from radar.api import cuentas

    galleta = peticion.cookies.get(COOKIE)
    if galleta:
        usuario = cuentas.usuario_de_sesion(galleta)
        if usuario is not None:
            return Identidad(usuario.usuario, usuario.nombre, usuario.rol, "sesion", usuario.id)
    esperada = os.environ.get("CLAVE_ACCESO", "")
    recibida = peticion.headers.get(CABECERA)
    if esperada and recibida and hmac.compare_digest(recibida, esperada):
        return Identidad("clave", "Clave de acceso", "admin", "clave")
    if not esperada and not os.environ.get("VERCEL"):
        return Identidad("local", "Modo local", "admin", "local")
    return None


def exigir_clave(request: Request) -> Identidad:
    """Dependencia de todos los routers del panel. Deja la identidad en `request.state`."""
    identidad = getattr(request.state, "identidad", None) or resolver_identidad(request)
    if identidad is None:
        if (
            os.environ.get("VERCEL")
            and not os.environ.get("CLAVE_ACCESO")
            and not request.cookies.get(COOKIE)
        ):
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "La API no tiene CLAVE_ACCESO configurada.",
            )
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Inicia sesión o envía {CABECERA}.")
    request.state.identidad = identidad
    return identidad


def exigir_rol(minimo: str):
    """Dependencia que exige un rol igual o superior a `minimo`."""
    from radar.api.cuentas import NIVEL

    def dependencia(request: Request) -> Identidad:
        identidad = exigir_clave(request)
        if NIVEL.get(identidad.rol, -1) < NIVEL[minimo]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"Tu rol ({identidad.rol}) no permite esta acción."
            )
        return identidad

    return dependencia


def quien(request: Request, declarado: str | None = None) -> str | None:
    """Nombre a registrar en un cambio: el de la sesión; con clave o en local, el declarado."""
    identidad = getattr(request.state, "identidad", None)
    if identidad is not None and identidad.via == "sesion":
        return identidad.nombre
    return declarado
