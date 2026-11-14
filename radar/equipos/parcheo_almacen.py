"""Tablas `claves_aprobacion` y `planes_parcheo` (radar/esquema.sql, docs/plan-parcheo.md)."""

from __future__ import annotations

import base64
import json
from typing import Any

from radar import bd
from radar.seguridad import ed25519

# Estados de un plan en el servidor.
APROBADO, ENTREGADO, EJECUTADO, RECHAZADO, CANCELADO = (
    "aprobado",
    "entregado",
    "ejecutado",
    "rechazado",
    "cancelado",
)
ACTIVOS = (APROBADO, ENTREGADO)

_COLUMNAS = (
    "id, equipo_id, estado, canonico, firma, clave, aprobado_por, creado, vence, entregado, "
    "entregas, antes, resultado, recibido, posterior, cancelado_por"
)


# ---------------------------------------------------------------------------
# Claves de aprobación
# ---------------------------------------------------------------------------


class ClaveYaRegistrada(ValueError):
    pass


def registrar_clave(conexion: Any, publica: bytes, nombre: str, por: str) -> str:
    huella = ed25519.huella(publica)
    if conexion.execute("SELECT 1 FROM claves_aprobacion WHERE huella = ?", [huella]).fetchone():
        raise ClaveYaRegistrada(huella)
    conexion.execute(
        "INSERT INTO claves_aprobacion (huella, publica, nombre, registrada, registrada_por) "
        "VALUES (?,?,?,?,?)",
        [huella, base64.b64encode(publica).decode("ascii"), nombre, bd.ahora(), por],
    )
    conexion.commit()
    return huella


def listar_claves(conexion: Any) -> list[dict[str, Any]]:
    return bd._consultar(
        conexion,
        "SELECT huella, publica, nombre, registrada, registrada_por, revocada "
        "FROM claves_aprobacion ORDER BY registrada",
    )


def claves_vigentes(conexion: Any) -> list[dict[str, Any]]:
    return [c for c in listar_claves(conexion) if not c["revocada"]]


def clave(conexion: Any, huella: str) -> dict[str, Any] | None:
    filas = bd._consultar(
        conexion,
        "SELECT huella, publica, nombre, registrada, registrada_por, revocada "
        "FROM claves_aprobacion WHERE huella = ?",
        [huella],
    )
    return filas[0] if filas else None


def revocar_clave(conexion: Any, huella: str) -> bool:
    cursor = conexion.execute(
        "UPDATE claves_aprobacion SET revocada = ? WHERE huella = ? AND revocada IS NULL",
        [bd.ahora(), huella],
    )
    conexion.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------------------
# Planes
# ---------------------------------------------------------------------------


def _plan(fila: dict[str, Any]) -> dict[str, Any]:
    datos = dict(fila)
    for campo in ("antes", "resultado"):
        datos[campo] = json.loads(datos[campo]) if datos.get(campo) else None
    datos["plan"] = json.loads(datos["canonico"])
    return datos


def guardar_plan(
    conexion: Any,
    plan: dict[str, Any],
    canonico: str,
    firma: str,
    huella_clave: str,
    antes: dict[str, Any],
    momento: str,
) -> None:
    conexion.execute(
        "INSERT INTO planes_parcheo (id, equipo_id, estado, canonico, firma, clave, "
        "aprobado_por, creado, vence, antes) VALUES (?,?,?,?,?,?,?,?,?,?)",
        [
            plan["plan_id"],
            plan["equipo_id"],
            APROBADO,
            canonico,
            firma,
            huella_clave,
            plan["aprobado_por"],
            momento,
            plan["vence"],
            json.dumps(antes, ensure_ascii=False),
        ],
    )
    conexion.commit()


def plan_activo(conexion: Any, equipo_id: str) -> bool:
    return (
        conexion.execute(
            "SELECT 1 FROM planes_parcheo WHERE equipo_id = ? AND estado IN (?, ?) LIMIT 1",
            [equipo_id, *ACTIVOS],
        ).fetchone()
        is not None
    )


def siguiente_para_agente(conexion: Any, equipo_id: str, ahora: str) -> dict[str, Any] | None:
    filas = bd._consultar(
        conexion,
        f"SELECT {_COLUMNAS} FROM planes_parcheo WHERE equipo_id = ? AND estado IN (?, ?) "
        "AND vence > ? ORDER BY creado LIMIT 1",
        [equipo_id, *ACTIVOS, ahora],
    )
    return filas[0] if filas else None


def marcar_entregado(conexion: Any, plan_id: str, momento: str) -> None:
    conexion.execute(
        "UPDATE planes_parcheo SET estado = ?, entregas = coalesce(entregas, 0) + 1, "
        "entregado = coalesce(entregado, ?) WHERE id = ? AND estado IN (?, ?)",
        [ENTREGADO, momento, plan_id, *ACTIVOS],
    )
    conexion.commit()


def leer_plan(conexion: Any, plan_id: str) -> dict[str, Any] | None:
    filas = bd._consultar(
        conexion, f"SELECT {_COLUMNAS} FROM planes_parcheo WHERE id = ?", [plan_id]
    )
    return _plan(filas[0]) if filas else None


def planes_de_equipo(conexion: Any, equipo_id: str, limite: int = 20) -> list[dict[str, Any]]:
    filas = bd._consultar(
        conexion,
        f"SELECT {_COLUMNAS} FROM planes_parcheo WHERE equipo_id = ? ORDER BY creado DESC LIMIT ?",
        [equipo_id, limite],
    )
    return [_plan(f) for f in filas]


def guardar_resultado(
    conexion: Any, plan_id: str, estado: str, resultado: dict[str, Any], momento: str
) -> bool:
    """Guarda el resultado una sola vez. False si el plan ya tenía resultado."""
    cursor = conexion.execute(
        "UPDATE planes_parcheo SET estado = ?, resultado = ?, recibido = ? "
        "WHERE id = ? AND resultado IS NULL",
        [estado, json.dumps(resultado, ensure_ascii=False), momento, plan_id],
    )
    conexion.commit()
    return cursor.rowcount > 0


def cancelar(conexion: Any, plan_id: str, por: str) -> bool:
    cursor = conexion.execute(
        "UPDATE planes_parcheo SET estado = ?, cancelado_por = ? WHERE id = ? AND estado IN (?, ?)",
        [CANCELADO, por, plan_id, *ACTIVOS],
    )
    conexion.commit()
    return cursor.rowcount > 0


def marcar_inventario_posterior(conexion: Any, equipo_id: str, momento: str) -> int:
    """Llegó un inventario del equipo después del resultado: desde ahora el cruce sirve de
    verificación independiente de lo que dijo el agente."""
    cursor = conexion.execute(
        "UPDATE planes_parcheo SET posterior = ? "
        "WHERE equipo_id = ? AND resultado IS NOT NULL AND posterior IS NULL",
        [momento, equipo_id],
    )
    conexion.commit()
    return cursor.rowcount
