"""Tablas del asistente: conversaciones, consumo, auditoría y topes.

Viven aquí y no en `radar/esquema.sql` (mismo criterio que `radar/api/cuentas.py` y
`radar/ajustes.py`): se crean con `CREATE TABLE IF NOT EXISTS` la primera vez que el proceso
las necesita. Los topes van en la tabla `ajustes` que ya existe.

- `asistente_conversaciones`: una fila = estado del bucle. `mensajes` es el historial de la
  API, solo por anexión. Se purga a los 30 días.
- `asistente_consumo`: una fila por llamada al modelo. De ahí salen el gasto del día y el
  reporte. No se purga.
- `asistente_auditoria`: cada decisión sobre una propuesta. No se purga.

El día es el de Colombia (UTC-5 todo el año, sin horario de verano).
"""

from __future__ import annotations

import contextlib
import json
import os
from dataclasses import asdict
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from radar.asistente.bucle import Ejecucion, Propuesta
from radar.asistente.contexto import Contexto
from radar.asistente.costo import Uso

COLOMBIA = timezone(timedelta(hours=-5))
RETENCION_DIAS = 30
MAX_TURNOS = 12
# Una conversación "corriendo" sin actualizarse en este tiempo murió con la función.
CORRIENDO_VENCE = timedelta(minutes=10)

TOPES_POR_DEFECTO = {"dia": 3.0, "usuario": 1.0, "equipo": 0.20}
TOPE_MAXIMO = 100.0

ESQUEMA = """
CREATE TABLE IF NOT EXISTS asistente_conversaciones (
  id TEXT PRIMARY KEY,
  usuario_id TEXT NOT NULL,
  usuario_nombre TEXT NOT NULL,
  usuario_rol TEXT NOT NULL,
  estado TEXT NOT NULL,
  pregunta TEXT NOT NULL,
  mensajes TEXT NOT NULL,
  propuesta TEXT,
  respuesta TEXT,
  error TEXT,
  iteraciones INTEGER NOT NULL DEFAULT 0,
  uso TEXT,
  costo_usd REAL NOT NULL DEFAULT 0,
  creada TEXT NOT NULL,
  actualizada TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS asistente_conv_usuario ON asistente_conversaciones(usuario_id, actualizada);
CREATE TABLE IF NOT EXISTS asistente_consumo (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fecha TEXT NOT NULL,
  dia TEXT NOT NULL,
  usuario_id TEXT NOT NULL,
  usuario_nombre TEXT,
  conversacion_id TEXT NOT NULL,
  modelo TEXT NOT NULL,
  tokens_entrada INTEGER NOT NULL,
  tokens_salida INTEGER NOT NULL,
  tokens_cache_lectura INTEGER NOT NULL,
  tokens_cache_escritura INTEGER NOT NULL,
  costo_usd REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS asistente_consumo_dia ON asistente_consumo(dia, usuario_id);
CREATE TABLE IF NOT EXISTS asistente_auditoria (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  fecha TEXT NOT NULL,
  conversacion_id TEXT NOT NULL,
  herramienta TEXT NOT NULL,
  pidio TEXT NOT NULL,
  decidio TEXT NOT NULL,
  decision TEXT NOT NULL,
  entrada TEXT NOT NULL,
  vista TEXT,
  resultado TEXT,
  ok INTEGER NOT NULL
);
"""

_listas: set[str] = set()


def _destino() -> str:
    return "|".join(
        os.environ.get(n, "") for n in ("TURSO_DATABASE_URL", "RADAR_SQLITE", "RADAR_DATOS")
    )


def conectar() -> Any:
    from radar import bd
    from radar.ajustes import ESQUEMA_AJUSTES

    conexion = bd.conectar()
    clave = _destino()
    if clave not in _listas:
        conexion.executescript(ESQUEMA + ESQUEMA_AJUSTES)
        conexion.commit()
        _listas.add(clave)
    return conexion


def ahora() -> datetime:
    return datetime.now(UTC)


def _iso(momento: datetime) -> str:
    return momento.isoformat(timespec="seconds")


def dia_colombia(momento: datetime | None = None) -> str:
    return (momento or ahora()).astimezone(COLOMBIA).strftime("%Y-%m-%d")


def _filas(cursor: Any) -> list[dict[str, Any]]:
    nombres = [d[0] for d in cursor.description]
    return [dict(zip(nombres, f, strict=True)) for f in cursor.fetchall()]


# ---------------------------------------------------------------------------
# Conversaciones
# ---------------------------------------------------------------------------


def _a_fila(e: Ejecucion) -> dict[str, Any]:
    return {
        "estado": e.estado,
        "mensajes": json.dumps(e.mensajes, ensure_ascii=False, default=str),
        "propuesta": json.dumps(asdict(e.propuesta), ensure_ascii=False, default=str)
        if e.propuesta
        else None,
        "respuesta": e.respuesta,
        "error": e.error,
        "iteraciones": e.iteraciones,
        "uso": json.dumps(e.uso.a_dict()),
        "costo_usd": e.costo_usd,
    }


def _de_fila(f: dict[str, Any]) -> Ejecucion:
    propuesta = json.loads(f["propuesta"]) if f.get("propuesta") else None
    return Ejecucion(
        id=f["id"],
        pregunta=f["pregunta"],
        mensajes=json.loads(f["mensajes"]),
        estado=f["estado"],
        propuesta=Propuesta(**propuesta) if propuesta else None,
        respuesta=f.get("respuesta"),
        error=f.get("error"),
        iteraciones=int(f.get("iteraciones") or 0),
        uso=Uso.de_dict(json.loads(f["uso"]) if f.get("uso") else None),
        costo_usd=float(f.get("costo_usd") or 0),
    )


def crear(conexion: Any, e: Ejecucion, ctx: Contexto) -> None:
    momento = _iso(ahora())
    fila = _a_fila(e)
    conexion.execute(
        "INSERT INTO asistente_conversaciones (id, usuario_id, usuario_nombre, usuario_rol, estado, "
        "pregunta, mensajes, propuesta, respuesta, error, iteraciones, uso, costo_usd, creada, actualizada) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            e.id,
            ctx.usuario_id,
            ctx.nombre,
            ctx.rol,
            fila["estado"],
            e.pregunta[:2000],
            fila["mensajes"],
            fila["propuesta"],
            fila["respuesta"],
            fila["error"],
            fila["iteraciones"],
            fila["uso"],
            fila["costo_usd"],
            momento,
            momento,
        ],
    )
    conexion.commit()


def guardar(conexion: Any, e: Ejecucion) -> None:
    fila = _a_fila(e)
    conexion.execute(
        "UPDATE asistente_conversaciones SET estado = ?, mensajes = ?, propuesta = ?, respuesta = ?, "
        "error = ?, iteraciones = ?, uso = ?, costo_usd = ?, actualizada = ? WHERE id = ?",
        [
            fila["estado"],
            fila["mensajes"],
            fila["propuesta"],
            fila["respuesta"],
            fila["error"],
            fila["iteraciones"],
            fila["uso"],
            fila["costo_usd"],
            _iso(ahora()),
            e.id,
        ],
    )
    conexion.commit()


def obtener(conexion: Any, id_: str) -> tuple[Ejecucion, dict[str, Any]] | None:
    """(ejecución, metadatos de la fila) o None."""
    cursor = conexion.execute("SELECT * FROM asistente_conversaciones WHERE id = ?", [id_])
    filas = _filas(cursor)
    if not filas:
        return None
    f = filas[0]
    e = _de_fila(f)
    if (
        e.estado == "corriendo"
        and datetime.fromisoformat(f["actualizada"]) < ahora() - CORRIENDO_VENCE
    ):
        e.estado = "fallida"
        e.error = e.error or "La conversación se interrumpió."
    meta = {
        k: f[k] for k in ("usuario_id", "usuario_nombre", "usuario_rol", "creada", "actualizada")
    }
    return e, meta


def reclamar(conexion: Any, id_: str, desde: list[str], usuario_id: str) -> Ejecucion | None:
    """Pasa a `corriendo` solo si está en uno de `desde` y es de `usuario_id`. Atómico: dos
    clics o dos pestañas no avanzan la misma conversación. Solo el dueño la sigue o decide."""
    marcas = ", ".join("?" for _ in desde)
    cursor = conexion.execute(
        f"UPDATE asistente_conversaciones SET estado = 'corriendo', actualizada = ? "
        f"WHERE id = ? AND usuario_id = ? AND estado IN ({marcas})",
        [_iso(ahora()), id_, usuario_id, *desde],
    )
    conexion.commit()
    if cursor.rowcount != 1:
        return None
    leida = obtener(conexion, id_)
    return leida[0] if leida else None


def soltar(conexion: Any, id_: str, estado: str) -> None:
    """Devuelve una conversación reclamada a su estado anterior (si no se pudo seguir)."""
    conexion.execute(
        "UPDATE asistente_conversaciones SET estado = ?, actualizada = ? WHERE id = ?",
        [estado, _iso(ahora()), id_],
    )
    conexion.commit()


def recientes(conexion: Any, usuario_id: str | None, limite: int = 8) -> list[dict[str, Any]]:
    """Las del usuario, o todas (usuario_id None, solo admin). Nunca las de /mi-equipo/."""
    sql = (
        "SELECT id, usuario_nombre, pregunta, estado, actualizada, costo_usd FROM asistente_conversaciones "
        "WHERE usuario_id NOT LIKE 'equipo:%'"
    )
    parametros: list[Any] = []
    if usuario_id is not None:
        sql += " AND usuario_id = ?"
        parametros.append(usuario_id)
    sql += " ORDER BY actualizada DESC LIMIT ?"
    parametros.append(limite)
    return _filas(conexion.execute(sql, parametros))


def purgar(conexion: Any, dias: int = RETENCION_DIAS) -> int:
    limite = _iso(ahora() - timedelta(days=dias))
    cursor = conexion.execute(
        "DELETE FROM asistente_conversaciones WHERE actualizada < ?", [limite]
    )
    conexion.commit()
    return max(cursor.rowcount, 0)


# ---------------------------------------------------------------------------
# Consumo y topes
# ---------------------------------------------------------------------------


def registrar_consumo(
    conexion: Any, ctx: Contexto, conversacion_id: str, modelo: str, uso: Uso, costo: float
) -> None:
    momento = ahora()
    conexion.execute(
        "INSERT INTO asistente_consumo (fecha, dia, usuario_id, usuario_nombre, conversacion_id, modelo, "
        "tokens_entrada, tokens_salida, tokens_cache_lectura, tokens_cache_escritura, costo_usd) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            _iso(momento),
            dia_colombia(momento),
            ctx.usuario_id,
            ctx.nombre,
            conversacion_id,
            modelo,
            uso.entrada,
            uso.salida,
            uso.cache_lectura,
            uso.cache_escritura,
            costo,
        ],
    )
    conexion.commit()


def gasto(conexion: Any, dia: str, usuario_id: str | None = None) -> float:
    sql = "SELECT COALESCE(SUM(costo_usd), 0) FROM asistente_consumo WHERE dia = ?"
    parametros: list[Any] = [dia]
    if usuario_id is not None:
        sql += " AND usuario_id = ?"
        parametros.append(usuario_id)
    return float(conexion.execute(sql, parametros).fetchone()[0] or 0)


def topes(conexion: Any) -> dict[str, float]:
    valores = dict(TOPES_POR_DEFECTO)
    cursor = conexion.execute(
        "SELECT clave, valor FROM ajustes WHERE clave LIKE 'asistente.tope_%'"
    )
    for clave, valor in cursor.fetchall():
        nombre = clave.removeprefix("asistente.tope_")
        if nombre in valores:
            with contextlib.suppress(TypeError, ValueError):
                valores[nombre] = float(valor)
    return valores


def guardar_tope(conexion: Any, nombre: str, valor: float, por: str) -> None:
    if nombre not in TOPES_POR_DEFECTO:
        raise ValueError(f"Tope desconocido: {nombre!r}.")
    if not (0 <= valor <= TOPE_MAXIMO):
        raise ValueError(f"El tope va de 0 a {TOPE_MAXIMO:g} USD.")
    conexion.execute(
        "INSERT INTO ajustes (clave, valor, por, cambiado) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor, por = excluded.por, cambiado = excluded.cambiado",
        [f"asistente.tope_{nombre}", str(round(valor, 2)), por, _iso(ahora())],
    )
    conexion.commit()


def restante(conexion: Any, ctx: Contexto) -> float:
    """USD que quedan hoy para `ctx`: el mínimo entre el tope general y el suyo. Si la base no
    responde, lanza (el bucle falla cerrado)."""
    t = topes(conexion)
    dia = dia_colombia()
    propio = t["equipo"] if ctx.rol == "equipo" else t["usuario"]
    return min(t["dia"] - gasto(conexion, dia), propio - gasto(conexion, dia, ctx.usuario_id))


def reporte(conexion: Any, mes: str) -> dict[str, Any]:
    """Consumo del mes (AAAA-MM) por usuario y por día. Estimado con la tarifa vigente."""
    from radar.asistente.costo import TARIFA_VIGENTE_DESDE

    por_usuario = _filas(
        conexion.execute(
            "SELECT usuario_id, MAX(usuario_nombre) AS nombre, COUNT(DISTINCT conversacion_id) AS conversaciones, "
            "COUNT(*) AS llamadas, ROUND(SUM(costo_usd), 4) AS usd FROM asistente_consumo "
            "WHERE dia LIKE ? GROUP BY usuario_id ORDER BY usd DESC",
            [f"{mes}%"],
        )
    )
    por_dia = _filas(
        conexion.execute(
            "SELECT dia, COUNT(*) AS llamadas, ROUND(SUM(costo_usd), 4) AS usd FROM asistente_consumo "
            "WHERE dia LIKE ? GROUP BY dia ORDER BY dia",
            [f"{mes}%"],
        )
    )
    return {
        "mes": mes,
        "total_usd": round(sum(f["usd"] or 0 for f in por_usuario), 4),
        "por_usuario": por_usuario,
        "por_dia": por_dia,
        "nota": f"Estimado con la tarifa vigente desde {TARIFA_VIGENTE_DESDE}. La cifra que manda es la de la consola de Claude.",
    }


# ---------------------------------------------------------------------------
# Auditoría
# ---------------------------------------------------------------------------


def auditar(
    conexion: Any,
    conversacion_id: str,
    propuesta: Propuesta,
    pidio: str,
    decidio: str,
    aprobado: bool,
    resultado: Any,
    ok: bool,
) -> None:
    conexion.execute(
        "INSERT INTO asistente_auditoria (fecha, conversacion_id, herramienta, pidio, decidio, decision, "
        "entrada, vista, resultado, ok) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            _iso(ahora()),
            conversacion_id,
            propuesta.herramienta,
            pidio,
            decidio,
            "aprobada" if aprobado else "rechazada",
            json.dumps(propuesta.entrada, ensure_ascii=False, default=str),
            json.dumps(propuesta.vista, ensure_ascii=False, default=str),
            json.dumps(resultado, ensure_ascii=False, default=str),
            1 if ok else 0,
        ],
    )
    conexion.commit()


def auditoria(conexion: Any, limite: int = 50) -> list[dict[str, Any]]:
    return _filas(
        conexion.execute(
            "SELECT fecha, conversacion_id, herramienta, pidio, decidio, decision, resultado, ok "
            "FROM asistente_auditoria ORDER BY id DESC LIMIT ?",
            [limite],
        )
    )
