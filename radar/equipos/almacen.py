"""Lectura y escritura de las tablas del agente local: `equipos`, `paquetes_so`,
`hallazgos_equipo` y `osv_avisos`. Usa las mismas conexiones DB-API que `radar/bd.py`.

La credencial de un equipo nunca se guarda: se guarda su SHA-256. Quien lea la base no
puede hacerse pasar por un equipo.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from radar import bd
from radar.contratos import FilaInventario
from radar.equipos.contratos import (
    HallazgoEquipo,
    HardwareReportado,
    PosturaReportada,
    ProgramaReportado,
    SistemaReportado,
)

BYTES_CREDENCIAL = 32


class EquipoYaInscrito(ValueError):
    """Ese identificador ya tiene credencial. No se reemplaza: primero se revoca o se retira."""


@dataclass
class Equipo:
    id: str
    nombre: str
    inscrito: str
    ultimo_reporte: str | None = None
    agente_version: str | None = None
    revocado: bool = False
    so: SistemaReportado | None = None
    hardware: HardwareReportado | None = None
    postura: PosturaReportada | None = None
    recortes: dict[str, int] = field(default_factory=dict)
    # Aprobación en la consola: un equipo pendiente reporta, se ve en el panel y no entra
    # al cruce hasta que una persona lo aprueba.
    pendiente: bool = False
    aprobado: str | None = None
    aprobado_por: str | None = None

    def resumen(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "nombre": self.nombre,
            "inscrito": self.inscrito,
            "ultimo_reporte": self.ultimo_reporte,
            "agente_version": self.agente_version,
            "revocado": self.revocado,
            "pendiente": self.pendiente,
            "aprobado": self.aprobado,
            "aprobado_por": self.aprobado_por,
            "so": self.so.model_dump() if self.so else None,
            "hardware": self.hardware.model_dump() if self.hardware else None,
            "postura": self.postura.model_dump() if self.postura else None,
            "recortes": self.recortes,
        }


def huella(credencial: str) -> str:
    return hashlib.sha256(credencial.encode("utf-8")).hexdigest()


def _equipo(f: dict[str, Any]) -> Equipo:
    def modelo(clase: Any, texto: str | None) -> Any:
        return clase.model_validate_json(texto) if texto else None

    return Equipo(
        id=f["id"],
        nombre=f["nombre"],
        inscrito=f["inscrito"],
        ultimo_reporte=f["ultimo_reporte"],
        agente_version=f["agente_version"],
        revocado=bool(f["revocado"]),
        so=modelo(SistemaReportado, f["so"]),
        hardware=modelo(HardwareReportado, f["hardware"]),
        postura=modelo(PosturaReportada, f["postura"]),
        recortes=json.loads(f["recortes"]) if f["recortes"] else {},
        pendiente=f["aprobado"] is None,
        aprobado=f["aprobado"],
        aprobado_por=f["aprobado_por"],
    )


_COLUMNAS = (
    "id, nombre, inscrito, ultimo_reporte, agente_version, revocado, so, hardware, postura, "
    "recortes, aprobado, aprobado_por"
)
APROBACION_AUTOMATICA = "aprobación automática"


# ---------------------------------------------------------------------------
# Inscripción y credenciales
# ---------------------------------------------------------------------------


def nombre_libre(conexion: Any, nombre: str, equipo_id: str) -> str:
    """El nombre saneado, o con un sufijo del identificador si otro equipo ya lo usa.

    Dos equipos con el mismo nombre se mezclarían en el inventario (la columna `equipo` es
    el nombre). El sufijo sale del uuid, no del texto que envió el equipo.
    """
    ocupado = conexion.execute(
        "SELECT 1 FROM equipos WHERE lower(nombre) = lower(?) AND id <> ? LIMIT 1",
        [nombre, equipo_id],
    ).fetchone()
    if ocupado is None:
        return nombre
    return f"{nombre[:240]}-{equipo_id[:8]}"


_CODIGO = re.compile(r"^[A-Z0-9]{8}$")
DIAS_PENDIENTE = 7


def normalizar_codigo(codigo: str | None) -> str | None:
    """`k7pq 4mxr`, `K7PQ-4MXR` y `k7pq4mxr` son el mismo código. None si no tiene forma."""
    if not codigo:
        return None
    limpio = re.sub(r"[\s-]", "", codigo).upper()
    return f"{limpio[:4]}-{limpio[4:]}" if _CODIGO.match(limpio) else None


def inscribir(
    conexion: Any,
    equipo_id: str,
    nombre: str,
    agente_version: str | None,
    credencial: str,
    codigo: str,
    aprobar: bool = False,
) -> None:
    """Crea el equipo con la credencial y el código que generó el propio agente.

    Del lado del radar solo quedan sus huellas (SHA-256): quien lea la base no puede
    hacerse pasar por el equipo ni activarlo. Por defecto queda pendiente hasta que TI
    escribe el código en el panel; con `aprobar` (modo automático) entra aprobado. Un
    equipo retirado puede volver a inscribirse; uno vigente o revocado, no.
    """
    existente = conexion.execute("SELECT 1 FROM equipos WHERE id = ?", [equipo_id]).fetchone()
    if existente is not None:
        raise EquipoYaInscrito(equipo_id)
    normal = normalizar_codigo(codigo)
    if normal is None:
        raise ValueError("Código de activación sin forma válida")
    momento = bd.ahora()
    conexion.execute(
        "INSERT INTO equipos (id, nombre, credencial, inscrito, agente_version, aprobado, "
        "aprobado_por, codigo) VALUES (?,?,?,?,?,?,?,?)",
        [
            equipo_id,
            nombre_libre(conexion, nombre, equipo_id),
            huella(credencial),
            momento,
            agente_version,
            momento if aprobar else None,
            APROBACION_AUTOMATICA if aprobar else None,
            huella(normal),
        ],
    )
    conexion.commit()


def equipo_de_codigo(conexion: Any, codigo: str) -> str | None:
    """Id del equipo pendiente con ese código de activación, o None."""
    normal = normalizar_codigo(codigo)
    if normal is None:
        return None
    fila = conexion.execute(
        "SELECT id FROM equipos WHERE codigo = ? AND aprobado IS NULL AND revocado = 0",
        [huella(normal)],
    ).fetchone()
    return fila[0] if fila else None


def borrar_pendientes_viejos(conexion: Any, dias: int = DIAS_PENDIENTE) -> int:
    """Borra las inscripciones que nadie activó en `dias` días (nunca llegaron al cruce)."""
    limite = (datetime.now(UTC) - timedelta(days=dias)).isoformat(timespec="seconds")
    cursor = conexion.execute(
        "DELETE FROM equipos WHERE aprobado IS NULL AND revocado = 0 AND inscrito < ?", [limite]
    )
    conexion.commit()
    return cursor.rowcount


def contar_pendientes(conexion: Any) -> int:
    return conexion.execute(
        "SELECT count(*) FROM equipos WHERE aprobado IS NULL AND revocado = 0"
    ).fetchone()[0]


def guardar_reporte_pendiente(conexion: Any, equipo_id: str, reporte_json: str) -> None:
    """Guarda el último reporte de un equipo pendiente, para cruzarlo cuando se apruebe."""
    conexion.execute(
        "UPDATE equipos SET reporte_pendiente = ? WHERE id = ?", [reporte_json, equipo_id]
    )
    conexion.commit()


def leer_reporte_pendiente(conexion: Any, equipo_id: str) -> str | None:
    fila = conexion.execute(
        "SELECT reporte_pendiente FROM equipos WHERE id = ?", [equipo_id]
    ).fetchone()
    return fila[0] if fila else None


def marcar_aprobado(conexion: Any, equipo_id: str, por: str) -> bool:
    """Aprueba un equipo pendiente. False si no existe, está revocado o ya estaba aprobado."""
    cursor = conexion.execute(
        "UPDATE equipos SET aprobado = ?, aprobado_por = ?, reporte_pendiente = NULL "
        "WHERE id = ? AND aprobado IS NULL AND revocado = 0",
        [bd.ahora(), por, equipo_id],
    )
    conexion.commit()
    return cursor.rowcount > 0


def equipo_de_credencial(conexion: Any, credencial: str) -> Equipo | None:
    """El equipo dueño de la credencial, o None. Un equipo revocado también se devuelve
    (con `revocado`), para responder distinto a "credencial desconocida"."""
    if not credencial:
        return None
    esperada = huella(credencial)
    filas = bd._consultar(
        conexion, f"SELECT {_COLUMNAS}, credencial FROM equipos WHERE credencial = ?", [esperada]
    )
    if not filas or not hmac.compare_digest(filas[0]["credencial"], esperada):
        return None
    return _equipo(filas[0])


def revocar(conexion: Any, equipo_id: str) -> bool:
    """Deja de aceptar reportes del equipo. Sus datos quedan para la auditoría."""
    cursor = conexion.execute("UPDATE equipos SET revocado = 1 WHERE id = ?", [equipo_id])
    conexion.commit()
    return cursor.rowcount > 0


def retirar(conexion: Any, equipo_id: str) -> bool:
    """Borra el equipo y todo lo que reportó (desinstalación)."""
    equipo = leer_equipo(conexion, equipo_id)
    if equipo is None:
        return False
    conexion.execute(
        "DELETE FROM inventario WHERE fuente = 'agente' AND equipo = ?", [equipo.nombre]
    )
    for tabla in ("paquetes_so", "hallazgos_equipo"):
        conexion.execute(f"DELETE FROM {tabla} WHERE equipo_id = ?", [equipo_id])
    conexion.execute("DELETE FROM equipos WHERE id = ?", [equipo_id])
    conexion.commit()
    return True


# ---------------------------------------------------------------------------
# Lectura
# ---------------------------------------------------------------------------


@bd.conexion_opcional()
def leer_equipos(conexion: Any) -> list[Equipo]:
    filas = bd._consultar(conexion, f"SELECT {_COLUMNAS} FROM equipos ORDER BY lower(nombre)")
    return [_equipo(f) for f in filas]


@bd.conexion_opcional()
def leer_equipo(conexion: Any, equipo_id: str) -> Equipo | None:
    filas = bd._consultar(conexion, f"SELECT {_COLUMNAS} FROM equipos WHERE id = ?", [equipo_id])
    return _equipo(filas[0]) if filas else None


@bd.conexion_opcional()
def hay_equipos(conexion: Any) -> bool:
    """True si hay algún equipo inscrito. False si la tabla `equipos` todavía no existe (base
    creada antes del agente local, o conexión de solo lectura que no puede crear el esquema)."""
    tabla = conexion.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'equipos'"
    ).fetchone()
    if tabla is None:
        return False
    return conexion.execute("SELECT 1 FROM equipos LIMIT 1").fetchone() is not None


# ---------------------------------------------------------------------------
# Reporte
# ---------------------------------------------------------------------------


def guardar_reporte(
    conexion: Any,
    equipo: Equipo,
    nombre: str,
    agente_version: str,
    so: SistemaReportado,
    hardware: HardwareReportado,
    postura: PosturaReportada,
    recortes: dict[str, int],
    recogido: datetime,
) -> None:
    conexion.execute(
        "UPDATE equipos SET nombre = ?, ultimo_reporte = ?, agente_version = ?, so = ?, "
        "hardware = ?, postura = ?, recortes = ? WHERE id = ?",
        [
            nombre,
            recogido.isoformat(timespec="seconds"),
            agente_version,
            so.model_dump_json(),
            hardware.model_dump_json(),
            postura.model_dump_json(),
            json.dumps(recortes),
            equipo.id,
        ],
    )
    conexion.commit()


def reemplazar_inventario(
    conexion: Any, nombre_anterior: str, filas: Iterable[FilaInventario]
) -> int:
    """Reemplaza en `inventario` las filas que reportó este equipo. No toca lo cargado por
    archivo ni lo de otros equipos."""
    lista = list(filas)
    nombres = {nombre_anterior} | {f.equipo for f in lista}
    for nombre in nombres:
        conexion.execute("DELETE FROM inventario WHERE fuente = 'agente' AND equipo = ?", [nombre])
    bd.guardar_inventario(conexion, lista, reemplazar=False)
    return len(lista)


def reemplazar_paquetes(
    conexion: Any, equipo_id: str, paquetes: Iterable[ProgramaReportado]
) -> int:
    lista = list(paquetes)
    conexion.execute("DELETE FROM paquetes_so WHERE equipo_id = ?", [equipo_id])
    bd._en_lotes(
        conexion,
        "INSERT INTO paquetes_so (equipo_id, nombre, version, fuente, origen, version_origen) "
        "VALUES (?,?,?,?,?,?)",
        [
            (equipo_id, p.programa, p.version, p.fuente, p.origen, p.version_origen)
            for p in lista
            if p.version
        ],
    )
    conexion.commit()
    return len(lista)


@bd.conexion_opcional()
def leer_paquetes(conexion: Any, equipo_id: str) -> list[dict[str, Any]]:
    return bd._consultar(
        conexion,
        "SELECT nombre, version, fuente, origen, version_origen FROM paquetes_so "
        "WHERE equipo_id = ? ORDER BY nombre",
        [equipo_id],
    )


# ---------------------------------------------------------------------------
# Hallazgos por equipo
# ---------------------------------------------------------------------------


def reemplazar_hallazgos(
    conexion: Any, equipo_id: str, tipos: Iterable[str], hallazgos: Iterable[HallazgoEquipo]
) -> int:
    """Reemplaza los hallazgos de esos tipos para el equipo por los de la última revisión.

    Lo que ya no aparece se borra: una postura corregida deja de ser hallazgo.
    """
    lista = list(hallazgos)
    for tipo in set(tipos):
        conexion.execute(
            "DELETE FROM hallazgos_equipo WHERE equipo_id = ? AND tipo = ?", [equipo_id, tipo]
        )
    bd._en_lotes(
        conexion,
        "INSERT OR REPLACE INTO hallazgos_equipo (id, equipo_id, tipo, clave, titulo, prioridad, "
        "por_que, pasos, comandos, detalle, detectado) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                h.id,
                h.equipo_id,
                h.tipo,
                h.clave,
                h.titulo,
                h.prioridad,
                json.dumps(h.por_que, ensure_ascii=False),
                h.pasos,
                json.dumps(h.comandos, ensure_ascii=False),
                json.dumps(h.detalle, ensure_ascii=False),
                (h.detectado.isoformat(timespec="seconds") if h.detectado else bd.ahora()),
            )
            for h in lista
        ],
    )
    conexion.commit()
    return len(lista)


@bd.conexion_opcional()
def leer_hallazgos(conexion: Any, equipo_id: str | None = None) -> list[HallazgoEquipo]:
    sql = (
        "SELECT id, equipo_id, tipo, clave, titulo, prioridad, por_que, pasos, comandos, "
        "detalle, detectado FROM hallazgos_equipo"
    )
    filas = (
        bd._consultar(conexion, sql)
        if equipo_id is None
        else bd._consultar(conexion, sql + " WHERE equipo_id = ?", [equipo_id])
    )
    return [
        HallazgoEquipo(
            **{
                **f,
                "por_que": json.loads(f["por_que"] or "[]"),
                "comandos": json.loads(f["comandos"] or "[]"),
                "detalle": json.loads(f["detalle"] or "{}"),
            }
        )
        for f in filas
    ]


# ---------------------------------------------------------------------------
# Caché de avisos de OSV
# ---------------------------------------------------------------------------


@bd.conexion_opcional()
def leer_avisos(conexion: Any, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Avisos guardados, por id, con su fecha de modificación en la clave `modified`."""
    lista = sorted(set(ids))
    salida: dict[str, dict[str, Any]] = {}
    for i in range(0, len(lista), bd.LOTE):
        lote = lista[i : i + bd.LOTE]
        for f in bd._consultar(
            conexion,
            f"SELECT id, contenido FROM osv_avisos WHERE id IN ({bd._marcadores(len(lote))})",
            lote,
        ):
            salida[f["id"]] = json.loads(f["contenido"])
    return salida


def guardar_avisos(conexion: Any, avisos: Iterable[dict[str, Any]]) -> int:
    lista = list(avisos)
    bd._en_lotes(
        conexion,
        "INSERT OR REPLACE INTO osv_avisos (id, modificado, contenido) VALUES (?,?,?)",
        [(a["id"], a.get("modified"), json.dumps(a, ensure_ascii=False)) for a in lista],
    )
    conexion.commit()
    return len(lista)


def trabajo_pendiente(conexion: Any, tipo: str, detalle: str) -> bool:
    return (
        conexion.execute(
            "SELECT 1 FROM trabajos WHERE tipo = ? AND detalle = ? AND estado = 'pendiente' "
            "LIMIT 1",
            [tipo, detalle],
        ).fetchone()
        is not None
    )
