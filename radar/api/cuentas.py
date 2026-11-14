"""Cuentas del panel: usuarios con contraseña, sesiones y tokens de inscripción de agentes.

Las tablas viven aquí y no en `radar/esquema.sql` para no tocar el esquema del núcleo: se
crean con `CREATE TABLE IF NOT EXISTS` la primera vez que el proceso las necesita, en la
misma base que usa `radar/bd.py` (Turso o el sqlite local).

- Contraseñas con scrypt (librería estándar), sal propia por usuario. Nunca se guardan en claro.
- Sesiones: un valor aleatorio va en una cookie HttpOnly; en la base solo queda su SHA-256.
- Tokens de inscripción: como las sesiones, solo su huella. Tienen vencimiento, tope de usos
  y se revocan desde el panel. El token en claro se muestra una sola vez, al crearlo.

Primer administrador (no hay registro abierto en la web):

    uv run python -m radar.api.cuentas crear --usuario ana --nombre "Ana Pérez" --rol admin
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import os
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

ROLES = ("lector", "analista", "admin")
NIVEL = {rol: i for i, rol in enumerate(ROLES)}

DURACION_SESION = timedelta(hours=12)
LARGO_MINIMO_CLAVE = 10
FALLOS_PERMITIDOS = 5
BLOQUEO = timedelta(minutes=5)
CACHE_SESION_S = 30  # en Vercel ahorra una consulta a Turso por petición

# scrypt: 16 MB de memoria por intento, unos 50 ms. Suficiente para un panel interno.
_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

ESQUEMA_CUENTAS = """
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario TEXT NOT NULL UNIQUE,
  nombre TEXT NOT NULL,
  rol TEXT NOT NULL CHECK (rol IN ('lector', 'analista', 'admin')),
  clave TEXT NOT NULL,
  activo INTEGER NOT NULL DEFAULT 1,
  creado TEXT NOT NULL,
  ultimo_ingreso TEXT,
  fallos INTEGER NOT NULL DEFAULT 0,
  bloqueado_hasta TEXT
);
CREATE TABLE IF NOT EXISTS sesiones (
  huella TEXT PRIMARY KEY,
  usuario_id INTEGER NOT NULL,
  creada TEXT NOT NULL,
  vence TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens_inscripcion (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  huella TEXT NOT NULL UNIQUE,
  pista TEXT NOT NULL,
  etiqueta TEXT,
  sistema TEXT,
  creado_por TEXT NOT NULL,
  creado TEXT NOT NULL,
  vence TEXT NOT NULL,
  usos_max INTEGER NOT NULL,
  usos INTEGER NOT NULL DEFAULT 0,
  revocado INTEGER NOT NULL DEFAULT 0
);
"""


class ErrorCuenta(ValueError):
    """Dato inválido al crear o cambiar una cuenta (se responde 422 o 409)."""


class Bloqueado(Exception):
    """Demasiados intentos fallidos: el usuario queda en espera unos minutos."""


@dataclass(frozen=True)
class Usuario:
    id: int
    usuario: str
    nombre: str
    rol: str
    activo: bool = True
    creado: str | None = None
    ultimo_ingreso: str | None = None

    def publico(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "usuario": self.usuario,
            "nombre": self.nombre,
            "rol": self.rol,
            "activo": self.activo,
            "creado": self.creado,
            "ultimo_ingreso": self.ultimo_ingreso,
        }


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

_listas: set[str] = set()


def _destino() -> str:
    return "|".join(
        os.environ.get(n, "") for n in ("TURSO_DATABASE_URL", "RADAR_SQLITE", "RADAR_DATOS")
    )


def conectar() -> Any:
    """Conexión de escritura a la base del radar con las tablas de cuentas creadas."""
    from radar import bd

    conexion = bd.conectar()
    clave = _destino()
    if clave not in _listas:
        conexion.executescript(ESQUEMA_CUENTAS)
        conexion.commit()
        _listas.add(clave)
    return conexion


def _ahora() -> datetime:
    return datetime.now(UTC)


def _iso(momento: datetime) -> str:
    return momento.isoformat(timespec="seconds")


def _filas(cursor: Any) -> list[dict[str, Any]]:
    nombres = [d[0] for d in cursor.description]
    return [dict(zip(nombres, fila, strict=True)) for fila in cursor.fetchall()]


def _consultar(conexion: Any, sql: str, parametros: list[Any] | None = None) -> list[dict]:
    return _filas(conexion.execute(sql, parametros or []))


def huella(valor: str) -> str:
    return hashlib.sha256(valor.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Contraseñas
# ---------------------------------------------------------------------------


def cifrar_clave(clave: str) -> str:
    sal = secrets.token_bytes(16)
    derivada = hashlib.scrypt(clave.encode(), salt=sal, **_SCRYPT)
    return f"scrypt${_SCRYPT['n']}${_SCRYPT['r']}${_SCRYPT['p']}${sal.hex()}${derivada.hex()}"


def clave_correcta(clave: str, guardada: str) -> bool:
    try:
        tipo, n, r, p, sal, esperada = guardada.split("$")
    except ValueError:
        return False
    if tipo != "scrypt":
        return False
    derivada = hashlib.scrypt(
        clave.encode(), salt=bytes.fromhex(sal), n=int(n), r=int(r), p=int(p),
        dklen=len(esperada) // 2,
    )
    return hmac.compare_digest(derivada.hex(), esperada)


# Para que "usuario inexistente" tarde lo mismo que "contraseña equivocada".
_CLAVE_FALSA = cifrar_clave(secrets.token_hex(8))


def _validar_clave(clave: str) -> None:
    if len(clave) < LARGO_MINIMO_CLAVE:
        raise ErrorCuenta(f"La contraseña necesita al menos {LARGO_MINIMO_CLAVE} caracteres.")
    if len(clave) > 200:
        raise ErrorCuenta("La contraseña es demasiado larga.")


def _normalizar_usuario(usuario: str) -> str:
    valor = usuario.strip().lower()
    if not valor or len(valor) > 60 or not all(c.isalnum() or c in "._-@" for c in valor):
        raise ErrorCuenta("El usuario solo admite letras, números y . _ - @ (hasta 60).")
    return valor


# ---------------------------------------------------------------------------
# Usuarios
# ---------------------------------------------------------------------------

_COLUMNAS = "id, usuario, nombre, rol, activo, creado, ultimo_ingreso"


def _usuario(fila: dict[str, Any]) -> Usuario:
    return Usuario(
        id=int(fila["id"]),
        usuario=fila["usuario"],
        nombre=fila["nombre"],
        rol=fila["rol"],
        activo=bool(fila["activo"]),
        creado=fila.get("creado"),
        ultimo_ingreso=fila.get("ultimo_ingreso"),
    )


def hay_usuarios(conexion: Any) -> bool:
    return bool(_consultar(conexion, "SELECT 1 AS x FROM usuarios LIMIT 1"))


def crear_usuario(conexion: Any, usuario: str, nombre: str, rol: str, clave: str) -> Usuario:
    usuario = _normalizar_usuario(usuario)
    nombre = " ".join(nombre.split())[:100]
    if not nombre:
        raise ErrorCuenta("Falta el nombre.")
    if rol not in ROLES:
        raise ErrorCuenta(f"Rol desconocido: {rol}.")
    _validar_clave(clave)
    if _consultar(conexion, "SELECT 1 AS x FROM usuarios WHERE usuario = ?", [usuario]):
        raise ErrorCuenta("Ya existe un usuario con ese nombre.")
    conexion.execute(
        "INSERT INTO usuarios (usuario, nombre, rol, clave, creado) VALUES (?,?,?,?,?)",
        [usuario, nombre, rol, cifrar_clave(clave), _iso(_ahora())],
    )
    conexion.commit()
    fila = _consultar(conexion, f"SELECT {_COLUMNAS} FROM usuarios WHERE usuario = ?", [usuario])
    return _usuario(fila[0])


def listar_usuarios(conexion: Any) -> list[Usuario]:
    filas = _consultar(conexion, f"SELECT {_COLUMNAS} FROM usuarios ORDER BY usuario")
    return [_usuario(f) for f in filas]


def leer_usuario(conexion: Any, usuario_id: int) -> Usuario | None:
    filas = _consultar(conexion, f"SELECT {_COLUMNAS} FROM usuarios WHERE id = ?", [usuario_id])
    return _usuario(filas[0]) if filas else None


def _admins_activos(conexion: Any) -> int:
    filas = _consultar(
        conexion, "SELECT COUNT(*) AS n FROM usuarios WHERE rol = 'admin' AND activo = 1"
    )
    return int(filas[0]["n"])


def cambiar_usuario(
    conexion: Any,
    usuario_id: int,
    *,
    rol: str | None = None,
    activo: bool | None = None,
    clave: str | None = None,
) -> Usuario | None:
    """Cambia rol, estado o contraseña. Nunca deja la base sin un administrador activo."""
    actual = leer_usuario(conexion, usuario_id)
    if actual is None:
        return None
    if rol is not None and rol not in ROLES:
        raise ErrorCuenta(f"Rol desconocido: {rol}.")
    pierde_admin = actual.rol == "admin" and actual.activo and (
        (rol is not None and rol != "admin") or activo is False
    )
    if pierde_admin and _admins_activos(conexion) <= 1:
        raise ErrorCuenta("Tiene que quedar al menos un administrador activo.")
    cambios: list[tuple[str, Any]] = []
    if rol is not None:
        cambios.append(("rol", rol))
    if activo is not None:
        cambios.append(("activo", 1 if activo else 0))
    if clave is not None:
        _validar_clave(clave)
        cambios += [("clave", cifrar_clave(clave)), ("fallos", 0), ("bloqueado_hasta", None)]
    if cambios:
        sql = ", ".join(f"{c} = ?" for c, _ in cambios)
        conexion.execute(
            f"UPDATE usuarios SET {sql} WHERE id = ?", [v for _, v in cambios] + [usuario_id]
        )
        if activo is False or clave is not None:
            conexion.execute("DELETE FROM sesiones WHERE usuario_id = ?", [usuario_id])
            olvidar_sesiones(usuario_id)
        conexion.commit()
    return leer_usuario(conexion, usuario_id)


def autenticar(conexion: Any, usuario: str, clave: str) -> Usuario | None:
    """El usuario si la contraseña es correcta y está activo. Lleva la cuenta de fallos."""
    try:
        nombre = _normalizar_usuario(usuario)
    except ErrorCuenta:
        clave_correcta(clave, _CLAVE_FALSA)
        return None
    filas = _consultar(
        conexion,
        f"SELECT {_COLUMNAS}, clave, fallos, bloqueado_hasta FROM usuarios WHERE usuario = ?",
        [nombre],
    )
    if not filas:
        clave_correcta(clave, _CLAVE_FALSA)
        return None
    fila = filas[0]
    ahora = _iso(_ahora())
    if fila["bloqueado_hasta"] and fila["bloqueado_hasta"] > ahora:
        raise Bloqueado(fila["bloqueado_hasta"])
    if not clave_correcta(clave, fila["clave"]) or not fila["activo"]:
        fallos = int(fila["fallos"] or 0) + 1
        bloqueo = _iso(_ahora() + BLOQUEO) if fallos >= FALLOS_PERMITIDOS else None
        conexion.execute(
            "UPDATE usuarios SET fallos = ?, bloqueado_hasta = ? WHERE id = ?",
            [0 if bloqueo else fallos, bloqueo, fila["id"]],
        )
        conexion.commit()
        return None
    conexion.execute(
        "UPDATE usuarios SET fallos = 0, bloqueado_hasta = NULL, ultimo_ingreso = ? WHERE id = ?",
        [ahora, fila["id"]],
    )
    conexion.commit()
    return _usuario(fila | {"ultimo_ingreso": ahora})


# ---------------------------------------------------------------------------
# Sesiones
# ---------------------------------------------------------------------------

_cache: dict[str, tuple[float, Usuario]] = {}


def olvidar_sesiones(usuario_id: int | None = None) -> None:
    for clave, (_, usuario) in list(_cache.items()):
        if usuario_id is None or usuario.id == usuario_id:
            _cache.pop(clave, None)


def crear_sesion(conexion: Any, usuario: Usuario) -> str:
    valor = secrets.token_urlsafe(32)
    ahora = _ahora()
    conexion.execute("DELETE FROM sesiones WHERE vence < ?", [_iso(ahora)])
    conexion.execute(
        "INSERT INTO sesiones (huella, usuario_id, creada, vence) VALUES (?,?,?,?)",
        [huella(valor), usuario.id, _iso(ahora), _iso(ahora + DURACION_SESION)],
    )
    conexion.commit()
    return valor


def usuario_de_sesion(valor: str) -> Usuario | None:
    """El usuario dueño de una sesión vigente, o None. Cachea 30 s por proceso."""
    if not valor or len(valor) > 100:
        return None
    clave = huella(valor)
    guardado = _cache.get(clave)
    if guardado and guardado[0] > time.monotonic():
        return guardado[1]
    conexion = conectar()
    try:
        filas = _consultar(
            conexion,
            f"SELECT {', '.join('u.' + c for c in _COLUMNAS.split(', '))} FROM sesiones s "
            "JOIN usuarios u ON u.id = s.usuario_id "
            "WHERE s.huella = ? AND s.vence > ? AND u.activo = 1",
            [clave, _iso(_ahora())],
        )
    finally:
        conexion.close()
    if not filas:
        _cache.pop(clave, None)
        return None
    usuario = _usuario(filas[0])
    _cache[clave] = (time.monotonic() + CACHE_SESION_S, usuario)
    return usuario


def cerrar_sesion(valor: str) -> None:
    clave = huella(valor)
    _cache.pop(clave, None)
    conexion = conectar()
    try:
        conexion.execute("DELETE FROM sesiones WHERE huella = ?", [clave])
        conexion.commit()
    finally:
        conexion.close()


# ---------------------------------------------------------------------------
# Tokens de inscripción de agentes
# ---------------------------------------------------------------------------

PREFIJO_TOKEN = "rdr_"
SISTEMAS = ("windows", "linux")


def _token_publico(fila: dict[str, Any], ahora: str) -> dict[str, Any]:
    if fila["revocado"]:
        estado = "revocado"
    elif fila["vence"] <= ahora:
        estado = "vencido"
    elif fila["usos"] >= fila["usos_max"]:
        estado = "agotado"
    else:
        estado = "vigente"
    return {
        "id": int(fila["id"]),
        "pista": fila["pista"],
        "etiqueta": fila["etiqueta"],
        "sistema": fila["sistema"],
        "creado_por": fila["creado_por"],
        "creado": fila["creado"],
        "vence": fila["vence"],
        "usos": int(fila["usos"]),
        "usos_max": int(fila["usos_max"]),
        "estado": estado,
    }


def crear_token(
    conexion: Any,
    *,
    creado_por: str,
    horas: int,
    usos_max: int,
    etiqueta: str | None = None,
    sistema: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Devuelve el token en claro (única vez) y su ficha."""
    if not 1 <= horas <= 24 * 30:
        raise ErrorCuenta("La validez va de 1 hora a 30 días.")
    if not 1 <= usos_max <= 1000:
        raise ErrorCuenta("Los usos van de 1 a 1000.")
    if sistema is not None and sistema not in SISTEMAS:
        raise ErrorCuenta("Sistema desconocido.")
    token = PREFIJO_TOKEN + secrets.token_urlsafe(24)
    ahora = _ahora()
    etiqueta = " ".join((etiqueta or "").split())[:80] or None
    conexion.execute(
        "INSERT INTO tokens_inscripcion (huella, pista, etiqueta, sistema, creado_por, creado, "
        "vence, usos_max) VALUES (?,?,?,?,?,?,?,?)",
        [
            huella(token),
            token[-4:],
            etiqueta,
            sistema,
            creado_por,
            _iso(ahora),
            _iso(ahora + timedelta(hours=horas)),
            usos_max,
        ],
    )
    conexion.commit()
    fila = _consultar(
        conexion, "SELECT * FROM tokens_inscripcion WHERE huella = ?", [huella(token)]
    )[0]
    return token, _token_publico(fila, _iso(ahora))


def listar_tokens(conexion: Any, limite: int = 50) -> list[dict[str, Any]]:
    ahora = _iso(_ahora())
    filas = _consultar(
        conexion, "SELECT * FROM tokens_inscripcion ORDER BY id DESC LIMIT ?", [limite]
    )
    return [_token_publico(f, ahora) for f in filas]


def hay_tokens_vigentes(conexion: Any) -> bool:
    return bool(
        _consultar(
            conexion,
            "SELECT 1 AS x FROM tokens_inscripcion WHERE revocado = 0 AND vence > ? "
            "AND usos < usos_max LIMIT 1",
            [_iso(_ahora())],
        )
    )


def revocar_token(conexion: Any, token_id: int) -> bool:
    cursor = conexion.execute(
        "UPDATE tokens_inscripcion SET revocado = 1 WHERE id = ?", [token_id]
    )
    conexion.commit()
    return cursor.rowcount != 0


def consumir_token(conexion: Any, token: str) -> int | None:
    """Gasta un uso del token si está vigente y devuelve su id; si no, None.

    La condición va en el mismo UPDATE para que dos inscripciones a la vez no se pasen del
    tope de usos."""
    if not token.startswith(PREFIJO_TOKEN) or len(token) > 100:
        return None
    clave = huella(token)
    filas = _consultar(conexion, "SELECT id FROM tokens_inscripcion WHERE huella = ?", [clave])
    if not filas:
        return None
    cursor = conexion.execute(
        "UPDATE tokens_inscripcion SET usos = usos + 1 WHERE id = ? AND revocado = 0 "
        "AND vence > ? AND usos < usos_max",
        [filas[0]["id"], _iso(_ahora())],
    )
    conexion.commit()
    return int(filas[0]["id"]) if cursor.rowcount > 0 else None


def devolver_uso(conexion: Any, token_id: int) -> None:
    """Si la inscripción falló después de gastar el uso (equipo ya inscrito), lo devuelve."""
    conexion.execute(
        "UPDATE tokens_inscripcion SET usos = usos - 1 WHERE id = ? AND usos > 0", [token_id]
    )
    conexion.commit()


# ---------------------------------------------------------------------------
# Línea de órdenes
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    from dotenv import load_dotenv

    load_dotenv()
    parser = argparse.ArgumentParser(prog="python -m radar.api.cuentas", description=__doc__)
    sub = parser.add_subparsers(dest="orden", required=True)
    crear = sub.add_parser("crear", help="Crea un usuario (pide la contraseña sin mostrarla)")
    crear.add_argument("--usuario", required=True)
    crear.add_argument("--nombre", required=True)
    crear.add_argument("--rol", choices=ROLES, default="admin")
    clave = sub.add_parser("clave", help="Cambia la contraseña de un usuario")
    clave.add_argument("--usuario", required=True)
    sub.add_parser("listar", help="Lista los usuarios")
    args = parser.parse_args(argv)

    conexion = conectar()
    try:
        if args.orden == "listar":
            for u in listar_usuarios(conexion):
                estado = "activo" if u.activo else "inactivo"
                print(f"{u.usuario}\t{u.rol}\t{estado}\t{u.nombre}")
            return 0
        nueva = os.environ.get("RADAR_CLAVE_NUEVA") or getpass.getpass("Contraseña: ")
        if not os.environ.get("RADAR_CLAVE_NUEVA") and nueva != getpass.getpass("Repite: "):
            print("Las contraseñas no coinciden.", file=sys.stderr)
            return 1
        if args.orden == "crear":
            u = crear_usuario(conexion, args.usuario, args.nombre, args.rol, nueva)
            print(f"Usuario {u.usuario} creado con rol {u.rol}.")
            return 0
        filas = _consultar(
            conexion, "SELECT id FROM usuarios WHERE usuario = ?",
            [_normalizar_usuario(args.usuario)],
        )
        if not filas:
            print("No existe ese usuario.", file=sys.stderr)
            return 1
        cambiar_usuario(conexion, int(filas[0]["id"]), clave=nueva)
        print("Contraseña cambiada; sus sesiones abiertas se cerraron.")
        return 0
    except ErrorCuenta as error:
        print(str(error), file=sys.stderr)
        return 1
    finally:
        conexion.close()


if __name__ == "__main__":
    raise SystemExit(main())
