"""Conexión a la base y funciones de lectura y escritura.

Mientras no haya Turso se usa un sqlite local con el mismo esquema (radar/esquema.sql). Las dos
conexiones son DB-API con `?` como marcador, así que el cambio a Turso es solo de conexión:
basta con poner TURSO_DATABASE_URL y TURSO_AUTH_TOKEN en `.env`.

Reglas que se cumplen aquí:
- La corrida automática actualiza los datos de un hallazgo pero nunca pisa `estado`,
  `comentario`, `por`, `avisado` ni `detectado` (la decisión humana manda).
- `conectar(solo_lectura=True)` es para las herramientas del agente: rechaza toda sentencia
  que no sea de lectura, además del token de solo lectura de Turso cuando exista.
"""

from __future__ import annotations

import functools
import json
import re
import sqlite3
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from radar import config
from radar.contratos import (
    CVE,
    Analisis,
    Cobertura,
    Ejecucion,
    FilaInventario,
    Grupo,
    Hallazgo,
    Rango,
    Referencia,
    SenalEpss,
    Senales,
    SenalKev,
    Trabajo,
)

ESQUEMA = Path(__file__).with_name("esquema.sql")
_LECTURA = re.compile(r"^\s*(select|with|explain)\b", re.IGNORECASE)
LOTE = 500
# Tope de parámetros por sentencia (el mínimo histórico de SQLite es 999).
MAX_PARAMETROS = 900
_VALORES = re.compile(r"VALUES\s*(\((?:\s*\?\s*,)*\s*\?\s*\))", re.IGNORECASE)


class EscrituraNoPermitida(PermissionError):
    """Se intentó escribir con una conexión de solo lectura."""


class ConexionSoloLectura:
    """Envuelve una conexión DB-API y deja pasar solo sentencias de lectura."""

    def __init__(self, conexion: Any):
        self._c = conexion

    def execute(self, sql: str, parametros: Sequence[Any] = ()) -> Any:
        if not _LECTURA.match(sql) or ";" in sql.strip().rstrip(";"):
            raise EscrituraNoPermitida("Conexión de solo lectura: solo se permite SELECT")
        return self._c.execute(sql, parametros)

    def close(self) -> None:
        self._c.close()


def ahora() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def conectar(solo_lectura: bool = False, ruta_sqlite: Path | None = None) -> Any:
    """Abre Turso si está configurado; si no, el sqlite local.

    Con `solo_lectura`, en Turso usa TURSO_AUTH_TOKEN_LECTURA si existe, y en todo caso
    envuelve la conexión para rechazar escrituras.
    """
    if ruta_sqlite is None:
        datos = config.turso(solo_lectura=True) if solo_lectura else None
        datos = datos or config.turso()
        if datos:
            import turso_serverless

            url, token = datos
            conexion = turso_serverless.connect(url, auth_token=token)
            return ConexionSoloLectura(conexion) if solo_lectura else conexion
    ruta = ruta_sqlite or config.ruta_sqlite_local()
    if solo_lectura:
        conexion = sqlite3.connect(f"file:{ruta}?mode=ro", uri=True)
        return ConexionSoloLectura(conexion)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(ruta)


def conexion_opcional(solo_lectura: bool = True):
    """Permite llamar a una función de lectura sin conexión: abre una, la usa y la cierra.

    `leer_hallazgos()` y `leer_hallazgos(conexion)` hacen lo mismo. Sin conexión se usa la de
    solo lectura (Turso si está configurado, si no el sqlite local).
    """

    def decorador(funcion):
        @functools.wraps(funcion)
        def envoltura(conexion: Any = None, *args: Any, **kwargs: Any) -> Any:
            if conexion is not None:
                return funcion(conexion, *args, **kwargs)
            propia = conectar(solo_lectura=solo_lectura)
            try:
                return funcion(propia, *args, **kwargs)
            finally:
                propia.close()

        return envoltura

    return decorador


def crear_esquema(conexion: Any) -> None:
    conexion.executescript(ESQUEMA.read_text(encoding="utf-8"))
    conexion.commit()


def _filas(cursor: Any) -> list[dict[str, Any]]:
    nombres = [d[0] for d in cursor.description]
    return [dict(zip(nombres, fila, strict=True)) for fila in cursor.fetchall()]


def _consultar(conexion: Any, sql: str, parametros: Sequence[Any] = ()) -> list[dict[str, Any]]:
    return _filas(conexion.execute(sql, list(parametros)))


def _json(valor: Any) -> str | None:
    return None if valor is None else json.dumps(valor, ensure_ascii=False)


def _de_json(texto: str | None, defecto: Any = None) -> Any:
    return defecto if texto is None else json.loads(texto)


def _en_lotes(conexion: Any, sql: str, filas: list[Sequence[Any]]) -> None:
    """Inserta muchas filas con INSERT de varias filas: `VALUES (?,?),(?,?),...`.

    En turso_serverless, `executemany` hace una petición HTTP por fila (125 000 peticiones
    para el snapshot). Con varias filas por sentencia son unas 100 filas por petición, y el
    SQL es el mismo en sqlite y en Turso.
    """
    if not filas:
        return
    m = _VALORES.search(sql)
    if m is None:
        raise ValueError("_en_lotes espera una sentencia INSERT ... VALUES (?, ...)")
    fila = m.group(1)
    columnas = fila.count("?")
    por_sentencia = max(1, MAX_PARAMETROS // columnas)
    prefijo, sufijo = sql[: m.start(1)], sql[m.end(1) :]
    for i in range(0, len(filas), por_sentencia):
        lote = filas[i : i + por_sentencia]
        conexion.execute(
            prefijo + ",".join([fila] * len(lote)) + sufijo,
            [valor for f in lote for valor in f],
        )


def _marcadores(n: int) -> str:
    return ",".join("?" * n)


# ---------------------------------------------------------------------------
# CVE y rangos
# ---------------------------------------------------------------------------


def guardar_cves(conexion: Any, cves: Iterable[CVE]) -> int:
    """Inserta o reemplaza CVE con sus rangos. Devuelve cuántas guardó."""
    lista = list(cves)
    if not lista:
        return 0
    _en_lotes(
        conexion,
        "INSERT OR REPLACE INTO cves (id, publicada, modificada, estado, descripcion, cvss, "
        "severidad, vector, version_cvss, cwes, referencias, sin_productos) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        [
            (
                c.id,
                c.publicada.isoformat() if c.publicada else None,
                c.modificada.isoformat() if c.modificada else None,
                c.estado,
                c.descripcion,
                c.cvss,
                c.severidad,
                c.vector,
                c.version_cvss,
                _json(c.cwes),
                _json([r.model_dump() for r in c.referencias]),
                int(c.sin_productos),
            )
            for c in lista
        ],
    )
    ids = [c.id for c in lista]
    for i in range(0, len(ids), LOTE):
        lote = ids[i : i + LOTE]
        conexion.execute(f"DELETE FROM cve_rangos WHERE cve IN ({_marcadores(len(lote))})", lote)
    _en_lotes(
        conexion,
        "INSERT INTO cve_rangos (cve, cpe, vendor, producto, version, desde, desde_incluye, "
        "hasta, hasta_incluye) VALUES (?,?,?,?,?,?,?,?,?)",
        [
            (
                c.id,
                r.cpe,
                r.vendor,
                r.producto,
                r.version,
                r.desde,
                int(r.desde_incluye),
                r.hasta,
                int(r.hasta_incluye),
            )
            for c in lista
            for r in c.rangos
        ],
    )
    conexion.commit()
    return len(lista)


def _fecha(texto: str | None) -> datetime | None:
    return datetime.fromisoformat(texto) if texto else None


@conexion_opcional()
def leer_cves(conexion: Any, pares: Iterable[str] | None = None) -> list[CVE]:
    """CVE con sus rangos. Con `pares` ('vendor:producto'), solo las que tocan esos pares.

    Los pares se comparan sin los escapes de CPE (notepad++ == notepad\\+\\+).
    """
    if pares is None:
        filas = _consultar(conexion, "SELECT * FROM cves")
    else:
        lista = sorted({p.replace("\\", "").lower() for p in pares})
        if not lista:
            return []
        filas = _consultar(
            conexion,
            "SELECT * FROM cves WHERE id IN (SELECT DISTINCT cve FROM cve_rangos WHERE "
            f"lower(vendor) || ':' || replace(lower(producto), '\\', '') IN "
            f"({_marcadores(len(lista))}))",
            lista,
        )
    if not filas:
        return []
    rangos: dict[str, list[Rango]] = {}
    ids = [f["id"] for f in filas]
    for i in range(0, len(ids), LOTE):
        lote = ids[i : i + LOTE]
        for r in _consultar(
            conexion,
            f"SELECT * FROM cve_rangos WHERE cve IN ({_marcadores(len(lote))})",
            lote,
        ):
            rangos.setdefault(r["cve"], []).append(
                Rango(
                    cpe=r["cpe"],
                    vendor=r["vendor"],
                    producto=r["producto"],
                    version=r["version"],
                    desde=r["desde"],
                    desde_incluye=bool(r["desde_incluye"]),
                    hasta=r["hasta"],
                    hasta_incluye=bool(r["hasta_incluye"]),
                )
            )
    return [
        CVE(
            id=f["id"],
            publicada=_fecha(f["publicada"]),
            modificada=_fecha(f["modificada"]),
            estado=f["estado"],
            descripcion=f["descripcion"] or "",
            cvss=f["cvss"],
            severidad=f["severidad"],
            vector=f["vector"],
            version_cvss=f["version_cvss"],
            cwes=_de_json(f["cwes"], []),
            referencias=[Referencia(**r) for r in _de_json(f["referencias"], [])],
            rangos=rangos.get(f["id"], []),
            sin_productos=bool(f["sin_productos"]),
        )
        for f in filas
    ]


def contar(conexion: Any, tabla: str) -> int:
    if not re.fullmatch(r"[a-z_]+", tabla):
        raise ValueError(f"Nombre de tabla no válido: {tabla!r}")
    return conexion.execute(f"SELECT count(*) FROM {tabla}").fetchone()[0]


# ---------------------------------------------------------------------------
# Señales
# ---------------------------------------------------------------------------


def guardar_kev(conexion: Any, kev: dict[str, SenalKev]) -> int:
    """Reemplaza el catálogo KEV completo (no hay consulta incremental)."""
    conexion.execute("DELETE FROM kev")
    _en_lotes(
        conexion,
        "INSERT INTO kev (cve, fabricante, producto, accion, agregada, plazo, ransomware) "
        "VALUES (?,?,?,?,?,?,?)",
        [
            (
                k.cve,
                k.fabricante,
                k.producto,
                k.accion,
                k.agregada.isoformat() if k.agregada else None,
                k.plazo.isoformat() if k.plazo else None,
                int(k.ransomware),
            )
            for k in kev.values()
        ],
    )
    conexion.commit()
    return len(kev)


def guardar_epss(conexion: Any, epss: dict[str, SenalEpss]) -> int:
    _en_lotes(
        conexion,
        "INSERT OR REPLACE INTO epss (cve, epss, percentil, fecha) VALUES (?,?,?,?)",
        [(e.cve, e.epss, e.percentil, e.fecha.isoformat()) for e in epss.values()],
    )
    conexion.commit()
    return len(epss)


@conexion_opcional()
def leer_senales(conexion: Any, cves: Iterable[str] | None = None) -> Senales:
    """KEV y EPSS indexados por CVE. Con `cves`, solo esas."""
    if cves is None:
        filas_kev = _consultar(conexion, "SELECT * FROM kev")
        filas_epss = _consultar(conexion, "SELECT * FROM epss")
    else:
        ids = sorted(set(cves))
        filas_kev, filas_epss = [], []
        for i in range(0, len(ids), LOTE):
            lote = ids[i : i + LOTE]
            m = _marcadores(len(lote))
            filas_kev += _consultar(conexion, f"SELECT * FROM kev WHERE cve IN ({m})", lote)
            filas_epss += _consultar(conexion, f"SELECT * FROM epss WHERE cve IN ({m})", lote)
    return Senales(
        kev={
            f["cve"]: SenalKev(
                cve=f["cve"],
                fabricante=f["fabricante"],
                producto=f["producto"],
                accion=f["accion"],
                agregada=f["agregada"],
                plazo=f["plazo"],
                ransomware=bool(f["ransomware"]),
            )
            for f in filas_kev
        },
        epss={
            f["cve"]: SenalEpss(
                cve=f["cve"], epss=f["epss"], percentil=f["percentil"], fecha=f["fecha"]
            )
            for f in filas_epss
        },
    )


# ---------------------------------------------------------------------------
# Inventario y cobertura
# ---------------------------------------------------------------------------


def guardar_inventario(
    conexion: Any, filas: Iterable[FilaInventario], reemplazar: bool = True
) -> int:
    lista = list(filas)
    if reemplazar:
        conexion.execute("DELETE FROM inventario")
    _en_lotes(
        conexion,
        "INSERT INTO inventario (equipo, programa, version, proveedor, sistema, fuente, cargado) "
        "VALUES (?,?,?,?,?,?,?)",
        [
            (
                f.equipo,
                f.programa,
                f.version,
                f.proveedor,
                f.sistema,
                f.fuente,
                f.cargado.isoformat(),
            )
            for f in lista
        ],
    )
    conexion.commit()
    return len(lista)


@conexion_opcional()
def leer_inventario(conexion: Any) -> list[FilaInventario]:
    return [
        FilaInventario(**{k: v for k, v in f.items() if k != "id"})
        for f in _consultar(conexion, "SELECT * FROM inventario ORDER BY id")
    ]


def guardar_cobertura(conexion: Any, cobertura: Iterable[Cobertura]) -> int:
    """Reemplaza la tabla de cobertura con la del último cruce."""
    lista = list(cobertura)
    conexion.execute("DELETE FROM cobertura")
    _en_lotes(
        conexion,
        "INSERT INTO cobertura (equipo, programa, version, motivo) VALUES (?,?,?,?)",
        [(c.equipo, c.programa, c.version, c.motivo) for c in lista],
    )
    conexion.commit()
    return len(lista)


@conexion_opcional()
def leer_cobertura(conexion: Any) -> list[Cobertura]:
    return [Cobertura(**f) for f in _consultar(conexion, "SELECT * FROM cobertura")]


# ---------------------------------------------------------------------------
# Hallazgos
# ---------------------------------------------------------------------------

_COLUMNAS_DATOS = (
    "cve",
    "activo",
    "producto",
    "version_instalada",
    "equipos",
    "prioridad",
    "por_que",
    "preciso",
    "rango",
    "kev",
    "ransomware",
    "epss",
    "cvss",
)


def guardar_hallazgos(conexion: Any, hallazgos: Iterable[Hallazgo]) -> int:
    """Inserta hallazgos nuevos y actualiza los datos de los existentes.

    Nunca pisa `estado`, `comentario`, `por`, `avisado` ni `detectado` de uno que ya existe.
    """
    lista = list(hallazgos)
    asignar = ", ".join(f"{c} = excluded.{c}" for c in _COLUMNAS_DATOS)
    _en_lotes(
        conexion,
        f"INSERT INTO hallazgos (id, {', '.join(_COLUMNAS_DATOS)}, estado, comentario, por, "
        f"detectado, avisado) VALUES ({_marcadores(len(_COLUMNAS_DATOS) + 6)}) "
        f"ON CONFLICT(id) DO UPDATE SET {asignar}",
        [
            (
                h.id,
                h.cve,
                h.activo,
                h.producto,
                h.version_instalada,
                _json(h.equipos),
                h.prioridad,
                _json(h.por_que),
                int(h.preciso),
                _json(h.rango.model_dump()) if h.rango else None,
                int(h.kev),
                int(h.ransomware),
                h.epss,
                h.cvss,
                h.estado,
                h.comentario,
                h.por,
                (h.detectado or datetime.now(UTC)).isoformat(),
                int(h.avisado),
            )
            for h in lista
        ],
    )
    conexion.commit()
    return len(lista)


def _hallazgo(f: dict[str, Any]) -> Hallazgo:
    rango = _de_json(f["rango"])
    return Hallazgo(
        id=f["id"],
        cve=f["cve"],
        activo=f["activo"],
        producto=f["producto"],
        version_instalada=f["version_instalada"] or "",
        equipos=_de_json(f["equipos"], []),
        prioridad=f["prioridad"],
        por_que=_de_json(f["por_que"], []),
        preciso=bool(f["preciso"]),
        rango=Rango(**rango) if rango else None,
        kev=bool(f["kev"]),
        ransomware=bool(f["ransomware"]),
        epss=f["epss"],
        cvss=f["cvss"],
        estado=f["estado"],
        comentario=f["comentario"],
        por=f["por"],
        detectado=_fecha(f["detectado"]),
        avisado=bool(f["avisado"]),
    )


@conexion_opcional()
def leer_hallazgos(conexion: Any, producto: str | None = None) -> list[Hallazgo]:
    if producto is None:
        filas = _consultar(conexion, "SELECT * FROM hallazgos")
    else:
        filas = _consultar(conexion, "SELECT * FROM hallazgos WHERE producto = ?", [producto])
    return [_hallazgo(f) for f in filas]


def cambiar_estado(
    conexion: Any, hallazgo_id: str, estado: str, por: str, comentario: str | None = None
) -> bool:
    """Lo usa una persona (API o panel). Devuelve False si el hallazgo no existe."""
    cursor = conexion.execute(
        "UPDATE hallazgos SET estado = ?, comentario = ?, por = ? WHERE id = ?",
        [estado, comentario, por, hallazgo_id],
    )
    conexion.commit()
    return cursor.rowcount > 0


def marcar_avisados(conexion: Any, ids: Iterable[str]) -> None:
    lista = list(ids)
    for i in range(0, len(lista), LOTE):
        lote = lista[i : i + LOTE]
        conexion.execute(
            f"UPDATE hallazgos SET avisado = 1 WHERE id IN ({_marcadores(len(lote))})", lote
        )
    conexion.commit()


# ---------------------------------------------------------------------------
# Análisis
# ---------------------------------------------------------------------------


def guardar_analisis(conexion: Any, analisis: Analisis) -> None:
    clave = analisis.producto or analisis.hallazgo
    conexion.execute(
        "INSERT OR REPLACE INTO analisis (producto, contenido, verificado, origen, creado) "
        "VALUES (?,?,?,?,?)",
        [clave, analisis.model_dump_json(), int(analisis.verificado), analisis.origen, ahora()],
    )
    conexion.commit()


@conexion_opcional()
def leer_analisis(conexion: Any, producto: str | None = None) -> list[Analisis]:
    """Análisis guardados (uno por producto). Con `producto`, solo ese (lista de 0 o 1)."""
    if producto is None:
        filas = _consultar(conexion, "SELECT contenido FROM analisis ORDER BY producto")
    else:
        filas = _consultar(
            conexion, "SELECT contenido FROM analisis WHERE producto = ?", [producto]
        )
    return [Analisis.model_validate_json(f["contenido"]) for f in filas]


# ---------------------------------------------------------------------------
# Trabajos, ejecuciones y trazas
# ---------------------------------------------------------------------------


def crear_trabajo(conexion: Any, tipo: str, detalle: str | None = None) -> int:
    cursor = conexion.execute(
        "INSERT INTO trabajos (tipo, estado, creado, detalle) VALUES (?, 'pendiente', ?, ?)",
        [tipo, ahora(), detalle],
    )
    conexion.commit()
    return cursor.lastrowid


def tomar_trabajo(conexion: Any, tipo: str | None = None) -> Trabajo | None:
    """Toma el trabajo pendiente más antiguo y lo pasa a `en_curso`."""
    sql = "SELECT * FROM trabajos WHERE estado = 'pendiente'"
    parametros: list[Any] = []
    if tipo:
        sql += " AND tipo = ?"
        parametros.append(tipo)
    filas = _consultar(conexion, sql + " ORDER BY id LIMIT 1", parametros)
    if not filas:
        return None
    f = filas[0]
    cursor = conexion.execute(
        "UPDATE trabajos SET estado = 'en_curso' WHERE id = ? AND estado = 'pendiente'", [f["id"]]
    )
    conexion.commit()
    if cursor.rowcount == 0:  # otro worker lo tomó primero
        return None
    f["estado"] = "en_curso"
    return Trabajo(**f)


def terminar_trabajo(conexion: Any, trabajo_id: int, ok: bool, detalle: str | None = None) -> None:
    conexion.execute(
        "UPDATE trabajos SET estado = ?, terminado = ?, detalle = coalesce(?, detalle) "
        "WHERE id = ?",
        ["hecho" if ok else "fallido", ahora(), detalle, trabajo_id],
    )
    conexion.commit()


@conexion_opcional()
def leer_trabajos(conexion: Any, limite: int = 50) -> list[Trabajo]:
    return [
        Trabajo(**f)
        for f in _consultar(conexion, "SELECT * FROM trabajos ORDER BY id DESC LIMIT ?", [limite])
    ]


def guardar_ejecucion(conexion: Any, ejecucion: Ejecucion) -> int:
    cursor = conexion.execute(
        "INSERT INTO ejecuciones (inicio, fin, tipo, fuentes, resumen, error) VALUES (?,?,?,?,?,?)",
        [
            ejecucion.inicio.isoformat(),
            ejecucion.fin.isoformat() if ejecucion.fin else None,
            ejecucion.tipo,
            _json(ejecucion.fuentes),
            ejecucion.resumen,
            ejecucion.error,
        ],
    )
    conexion.commit()
    return cursor.lastrowid


@conexion_opcional()
def ultima_ejecucion(conexion: Any, tipo: str | None = None) -> Ejecucion | None:
    sql = "SELECT * FROM ejecuciones"
    parametros: list[Any] = []
    if tipo:
        sql += " WHERE tipo = ?"
        parametros.append(tipo)
    filas = _consultar(conexion, sql + " ORDER BY id DESC LIMIT 1", parametros)
    if not filas:
        return None
    f = filas[0]
    f["fuentes"] = _de_json(f["fuentes"], {})
    return Ejecucion(**f)


def guardar_traza(conexion: Any, herramienta: str, entrada: str, decision: str) -> None:
    """Registro de cada llamada del agente a una herramienta (permitida, negada, limpiada)."""
    conexion.execute(
        "INSERT INTO trazas (momento, herramienta, entrada, decision) VALUES (?,?,?,?)",
        [ahora(), herramienta, entrada, decision],
    )
    conexion.commit()


@conexion_opcional()
def leer_ejecuciones(conexion: Any, limite: int = 20) -> list[Ejecucion]:
    filas = _consultar(conexion, "SELECT * FROM ejecuciones ORDER BY id DESC LIMIT ?", [limite])
    for f in filas:
        f["fuentes"] = _de_json(f["fuentes"], {})
    return [Ejecucion(**f) for f in filas]


# ---------------------------------------------------------------------------
# Atajos que pidió el frente plugin (servidor MCP)
# ---------------------------------------------------------------------------


@conexion_opcional()
def leer_grupos(conexion: Any, umbrales: Any = None) -> list[Grupo]:
    """Grupos por producto calculados desde los hallazgos guardados (no hay tabla de grupos)."""
    from radar.nucleo.agrupar import agrupar

    return agrupar(leer_hallazgos(conexion), umbrales)


def insertar_inventario(
    filas: Iterable[FilaInventario], reemplazar: bool = True, conexion: Any = None
) -> int:
    """Guarda filas de inventario. Sin conexión abre una de escritura y la cierra."""
    if conexion is not None:
        return guardar_inventario(conexion, filas, reemplazar)
    propia = conectar()
    try:
        crear_esquema(propia)
        return guardar_inventario(propia, filas, reemplazar)
    finally:
        propia.close()
