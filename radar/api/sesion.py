"""Rutas de sesión, usuarios y tokens de inscripción (`radar/api/cuentas.py`).

- `/api/sesion`: entrar, ver quién soy, cambiar mi contraseña y salir. Entrar no pide clave.
- `/api/usuarios` y `/api/tokens`: solo administradores.

La cookie de sesión es HttpOnly, SameSite=Strict y Secure fuera de localhost, así que ningún
script la lee y otro sitio no la puede usar para mandar peticiones al panel.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from radar.api import cuentas
from radar.api.acceso import COOKIE, exigir_clave, exigir_rol

router_sesion = APIRouter(prefix="/api")
router_admin = APIRouter(prefix="/api", dependencies=[Depends(exigir_rol("admin"))])


def _segura(request: Request) -> bool:
    return bool(os.environ.get("VERCEL")) or request.url.scheme == "https"


def _error_cuenta(error: cuentas.ErrorCuenta) -> HTTPException:
    codigo = status.HTTP_409_CONFLICT if "Ya existe" in str(error) else 422
    return HTTPException(codigo, str(error))


# ---------------------------------------------------------------------------
# Sesión
# ---------------------------------------------------------------------------


class Ingreso(BaseModel):
    usuario: str = Field(min_length=1, max_length=60)
    clave: str = Field(min_length=1, max_length=200)


@router_sesion.post("/sesion")
def entrar(cuerpo: Ingreso, request: Request, respuesta: Response) -> dict:
    conexion = cuentas.conectar()
    try:
        try:
            usuario = cuentas.autenticar(conexion, cuerpo.usuario, cuerpo.clave)
        except cuentas.Bloqueado as error:
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "Demasiados intentos fallidos. Espera unos minutos y vuelve a intentar.",
            ) from error
        if usuario is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Usuario o contraseña incorrectos.")
        valor = cuentas.crear_sesion(conexion, usuario)
    finally:
        conexion.close()
    respuesta.set_cookie(
        COOKIE,
        valor,
        max_age=int(cuentas.DURACION_SESION.total_seconds()),
        httponly=True,
        secure=_segura(request),
        samesite="strict",
        path="/",
    )
    return {"usuario": usuario.publico()}


@router_sesion.get("/sesion")
def quien_soy(request: Request) -> dict:
    """Quién tiene la sesión. Sin sesión responde 200 con `usuario: null` y dice si ya hay
    usuarios creados (si no hay, el login explica cómo crear el primero)."""
    galleta = request.cookies.get(COOKIE)
    usuario = cuentas.usuario_de_sesion(galleta) if galleta else None
    if usuario is not None:
        return {"usuario": usuario.publico()}
    conexion = cuentas.conectar()
    try:
        hay = cuentas.hay_usuarios(conexion)
    finally:
        conexion.close()
    return {"usuario": None, "hay_usuarios": hay}


@router_sesion.delete("/sesion")
def salir(request: Request, respuesta: Response) -> dict:
    galleta = request.cookies.get(COOKIE)
    if galleta:
        cuentas.cerrar_sesion(galleta)
    respuesta.delete_cookie(COOKIE, path="/", httponly=True, samesite="strict")
    return {"cerrada": True}


class CambioClave(BaseModel):
    actual: str = Field(min_length=1, max_length=200)
    nueva: str = Field(min_length=1, max_length=200)


@router_sesion.put("/sesion/clave")
def cambiar_mi_clave(cuerpo: CambioClave, request: Request) -> dict:
    identidad = exigir_clave(request)
    if identidad.via != "sesion" or identidad.id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Solo con una sesión de usuario.")
    conexion = cuentas.conectar()
    try:
        if cuentas.autenticar(conexion, identidad.usuario, cuerpo.actual) is None:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "La contraseña actual no coincide.")
        cuentas.cambiar_usuario(conexion, identidad.id, clave=cuerpo.nueva)
    except cuentas.ErrorCuenta as error:
        raise _error_cuenta(error) from error
    finally:
        conexion.close()
    return {"cambiada": True, "aviso": "Vuelve a entrar con la contraseña nueva."}


# ---------------------------------------------------------------------------
# Usuarios (admin)
# ---------------------------------------------------------------------------


class UsuarioNuevo(BaseModel):
    usuario: str = Field(min_length=1, max_length=60)
    nombre: str = Field(min_length=1, max_length=100)
    rol: str = Field(pattern="^(lector|analista|admin)$")
    clave: str = Field(min_length=1, max_length=200)


class CambioUsuario(BaseModel):
    rol: str | None = Field(default=None, pattern="^(lector|analista|admin)$")
    activo: bool | None = None
    clave: str | None = Field(default=None, min_length=1, max_length=200)


@router_admin.get("/usuarios")
def usuarios() -> dict:
    conexion = cuentas.conectar()
    try:
        lista = [u.publico() for u in cuentas.listar_usuarios(conexion)]
    finally:
        conexion.close()
    return {"usuarios": lista}


@router_admin.post("/usuarios", status_code=status.HTTP_201_CREATED)
def crear_usuario(cuerpo: UsuarioNuevo) -> dict:
    conexion = cuentas.conectar()
    try:
        usuario = cuentas.crear_usuario(
            conexion, cuerpo.usuario, cuerpo.nombre, cuerpo.rol, cuerpo.clave
        )
    except cuentas.ErrorCuenta as error:
        raise _error_cuenta(error) from error
    finally:
        conexion.close()
    return {"usuario": usuario.publico()}


@router_admin.patch("/usuarios/{usuario_id}")
def cambiar_usuario(usuario_id: int, cuerpo: CambioUsuario) -> dict:
    conexion = cuentas.conectar()
    try:
        usuario = cuentas.cambiar_usuario(
            conexion, usuario_id, rol=cuerpo.rol, activo=cuerpo.activo, clave=cuerpo.clave
        )
    except cuentas.ErrorCuenta as error:
        raise _error_cuenta(error) from error
    finally:
        conexion.close()
    if usuario is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Usuario no encontrado.")
    return {"usuario": usuario.publico()}


# ---------------------------------------------------------------------------
# Tokens de inscripción (admin)
# ---------------------------------------------------------------------------


class TokenNuevo(BaseModel):
    horas: int = Field(default=24, ge=1, le=24 * 30)
    usos_max: int = Field(default=1, ge=1, le=1000)
    etiqueta: str | None = Field(default=None, max_length=80)
    sistema: str | None = Field(default=None, pattern="^(windows|linux)$")


@router_admin.get("/tokens")
def tokens() -> dict:
    conexion = cuentas.conectar()
    try:
        lista = cuentas.listar_tokens(conexion)
    finally:
        conexion.close()
    return {"tokens": lista, "token_organizacion": bool(os.environ.get("AGENTE_TOKEN_INSCRIPCION"))}


@router_admin.post("/tokens", status_code=status.HTTP_201_CREATED)
def crear_token(cuerpo: TokenNuevo, request: Request) -> dict:
    identidad = exigir_clave(request)
    conexion = cuentas.conectar()
    try:
        token, ficha = cuentas.crear_token(
            conexion,
            creado_por=identidad.nombre,
            horas=cuerpo.horas,
            usos_max=cuerpo.usos_max,
            etiqueta=cuerpo.etiqueta,
            sistema=cuerpo.sistema,
        )
    except cuentas.ErrorCuenta as error:
        raise _error_cuenta(error) from error
    finally:
        conexion.close()
    # El token en claro solo viaja en esta respuesta: en la base queda su huella.
    return {"token": token, "ficha": ficha}


@router_admin.delete("/tokens/{token_id}")
def revocar_token(token_id: int) -> dict:
    conexion = cuentas.conectar()
    try:
        hecho = cuentas.revocar_token(conexion, token_id)
    finally:
        conexion.close()
    if not hecho:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token no encontrado.")
    return {"revocado": True}
