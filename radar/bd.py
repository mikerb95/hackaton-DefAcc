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
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, get_args

from radar import config
from radar.contratos import (
    CVE,
    Analisis,
    Cobertura,
    Ejecucion,
    EstadoHallazgo,
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
# Tope de parámetros por sentencia. En sqlite local, 900 (el mínimo histórico de SQLite es 999).
# En Turso cada sentencia es una petición HTTP (~0,65 s medidos): conviene meter muchas filas,
# hasta 30 000 parámetros (libSQL acepta 32 766) y 500 filas para no mandar cuerpos enormes.
MAX_PARAMETROS = 900
MAX_PARAMETROS_REMOTO = 30_000
MAX_FILAS_REMOTO = 500
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


def destino() -> str:
    """A dónde iría `conectar()` sin ruta: 'turso' o 'local <ruta>'.

    Precedencia: RADAR_SQLITE explícito > Turso (TURSO_DATABASE_URL y TURSO_AUTH_TOKEN) >
    datos_locales/radar.db. Así una copia local nunca termina escribiendo en Turso sin querer.
    """
    explicito = config.sqlite_explicito()
    if explicito is None and config.turso():
        return "turso"
    return f"local {explicito or config.ruta_sqlite_local()}"


def _anunciar(texto: str) -> None:
    print(f"[radar] datos: {texto}", file=sys.stderr, flush=True)


def conectar(solo_lectura: bool = False, ruta_sqlite: Path | None = None) -> Any:
    """Abre la base según la precedencia de `destino()` y lo dice en stderr.

    Con `ruta_sqlite` abre ese sqlite sin mirar el entorno. Con `solo_lectura`, en Turso usa
    TURSO_AUTH_TOKEN_LECTURA si existe, y en todo caso envuelve la conexión para rechazar
    escrituras.
    """
    if ruta_sqlite is None and config.sqlite_explicito() is None:
        datos = config.turso(solo_lectura=True) if solo_lectura else None
        datos = datos or config.turso()
        if datos:
            import turso_serverless

            url, token = datos
            _anunciar("turso" + (" (solo lectura)" if solo_lectura else ""))
            conexion = turso_serverless.connect(url, auth_token=token)
            return ConexionSoloLectura(conexion) if solo_lectura else conexion
    ruta = ruta_sqlite or config.ruta_sqlite_local()
    _anunciar(f"local {ruta}" + (" (solo lectura)" if solo_lectura else ""))
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


# Columnas agregadas después de crear el esquema: (tabla, columna, definición).
# `CREATE TABLE IF NOT EXISTS` no toca una tabla que ya existe, así que se agregan aquí.
_MIGRACIONES = (
    ("hallazgos", "propuesto_resuelto", "INTEGER DEFAULT 0"),
    ("analisis", "aprobado", "TEXT"),
    ("analisis", "aprobado_por", "TEXT"),
    ("equipos", "aprobado", "TEXT"),
    ("equipos", "aprobado_por", "TEXT"),
    ("equipos", "reporte_pendiente", "TEXT"),
)


def crear_esquema(conexion: Any) -> None:
    """Crea las tablas que falten y agrega las columnas nuevas a las que ya existen."""
    conexion.executescript(ESQUEMA.read_text(encoding="utf-8"))
    agregadas: set[tuple[str, str]] = set()
    for tabla, columna, definicion in _MIGRACIONES:
        existentes = {
            f[0]
            for f in conexion.execute("SELECT name FROM pragma_table_info(?)", [tabla]).fetchall()
        }
        if columna not in existentes:
            conexion.execute(f"ALTER TABLE {tabla} ADD COLUMN {columna} {definicion}")
            agregadas.add((tabla, columna))
    if ("equipos", "aprobado") in agregadas:
        # Los equipos inscritos antes de que existiera la aprobación ya se cruzaban: quedan
        # aprobados para no esconderlos de golpe.
        conexion.execute(
            "UPDATE equipos SET aprobado = inscrito, "
            "aprobado_por = 'inscrito antes de la aprobación'"
        )
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


def es_local(conexion: Any) -> bool:
    """True si la conexión es sqlite local (directa o envuelta para pruebas o solo lectura)."""
    while not isinstance(conexion, sqlite3.Connection):
        interna = getattr(conexion, "_c", None) or getattr(conexion, "c", None)
        if interna is None:
            return False
        conexion = interna
    return True


def filas_por_sentencia(conexion: Any, columnas: int) -> int:
    if es_local(conexion):
        return max(1, MAX_PARAMETROS // columnas)
    return max(1, min(MAX_FILAS_REMOTO, MAX_PARAMETROS_REMOTO // columnas))


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
    por_sentencia = filas_por_sentencia(conexion, fila.count("?"))
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
        # Una carga de archivo reemplaza lo cargado por archivo. Lo que reportan los agentes
        # locales lo reemplaza cada equipo con su propio reporte (radar/equipos/almacen.py).
        conexion.execute("DELETE FROM inventario WHERE fuente <> 'agente'")
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

    Nunca pisa `estado`, `comentario`, `por` ni `detectado` de uno que ya existe (la decisión
    humana manda). `avisado` se conserva (sin repetir avisos) salvo que el hallazgo suba a
    "inmediato" en esta corrida (por ejemplo, entró a KEV): eso es información nueva y se vuelve
    a avisar. Un hallazgo que la corrida encontró deja de estar `propuesto_resuelto`.
    """
    lista = list(hallazgos)
    asignar = ", ".join(f"{c} = excluded.{c}" for c in _COLUMNAS_DATOS)
    asignar += (
        ", propuesto_resuelto = 0"
        ", avisado = CASE WHEN excluded.prioridad = 'inmediato' "
        "AND hallazgos.prioridad <> 'inmediato' THEN 0 ELSE hallazgos.avisado END"
    )
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
        propuesto_resuelto=bool(f.get("propuesto_resuelto") or 0),
    )


@conexion_opcional()
def leer_hallazgos(conexion: Any, producto: str | None = None) -> list[Hallazgo]:
    if producto is None:
        filas = _consultar(conexion, "SELECT * FROM hallazgos")
    else:
        filas = _consultar(conexion, "SELECT * FROM hallazgos WHERE producto = ?", [producto])
    return [_hallazgo(f) for f in filas]


ESTADOS = get_args(EstadoHallazgo)
# Cerrar un hallazgo exige decir por qué.
ESTADOS_CON_COMENTARIO = frozenset({"mitigado", "descartado"})


def cambiar_estado(
    conexion: Any, hallazgo_id: str, estado: str, por: str, comentario: str | None = None
) -> bool:
    """Cambio de estado por una persona (API o panel). Es la única vía para cambiarlo.

    Exige quién decide (`por`) y, para cerrar (mitigado o descartado), un comentario.
    Devuelve False si el hallazgo no existe; lanza ValueError si faltan datos.
    """
    if estado not in ESTADOS:
        raise ValueError(f"Estado no válido: {estado!r}. Válidos: {', '.join(ESTADOS)}")
    if not por or not por.strip():
        raise ValueError("El cambio de estado lo hace una persona: falta quién decide ('por')")
    comentario = comentario.strip() if comentario else None
    if estado in ESTADOS_CON_COMENTARIO and not comentario:
        raise ValueError(f"Marcar como '{estado}' exige un comentario")
    cursor = conexion.execute(
        "UPDATE hallazgos SET estado = ?, comentario = ?, por = ? WHERE id = ?",
        [estado, comentario, por.strip(), hallazgo_id],
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


def marcar_propuestos(conexion: Any, ids: Iterable[str]) -> None:
    """Marca hallazgos que la última corrida ya no encontró (cierre propuesto)."""
    lista = list(ids)
    for i in range(0, len(lista), LOTE):
        lote = lista[i : i + LOTE]
        conexion.execute(
            f"UPDATE hallazgos SET propuesto_resuelto = 1 WHERE id IN ({_marcadores(len(lote))})",
            lote,
        )
    conexion.commit()


# ---------------------------------------------------------------------------
# Análisis
# ---------------------------------------------------------------------------


def guardar_analisis(conexion: Any, analisis: Analisis) -> None:
    """Guarda el análisis de un producto. Reemplaza el anterior y borra su aprobación: lo que
    se aprobó fue otro texto."""
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


# ---------------------------------------------------------------------------
# Aprobación del comunicado (pedido de panel) y trazas
# ---------------------------------------------------------------------------


def aprobar_comunicado(conexion: Any, producto: str, por: str) -> bool:
    """Una persona aprueba el comunicado de un producto.

    Los hallazgos abiertos del producto quedan como avisados (sin repetir avisos). Devuelve
    False si el producto no tiene análisis guardado.
    """
    if not por or not por.strip():
        raise ValueError("La aprobación la hace una persona: falta quién aprueba ('por')")
    cursor = conexion.execute(
        "UPDATE analisis SET aprobado = ?, aprobado_por = ? WHERE producto = ?",
        [ahora(), por.strip(), producto],
    )
    if cursor.rowcount == 0:
        conexion.commit()
        return False
    conexion.execute(
        "UPDATE hallazgos SET avisado = 1 WHERE producto = ? "
        "AND estado NOT IN ('mitigado', 'descartado')",
        [producto],
    )
    conexion.commit()
    return True


@conexion_opcional()
def leer_aprobacion(conexion: Any, producto: str) -> dict[str, str] | None:
    """{'aprobado': fecha, 'aprobado_por': quién} o None si no está aprobado."""
    filas = _consultar(
        conexion,
        "SELECT aprobado, aprobado_por FROM analisis WHERE producto = ? AND aprobado IS NOT NULL",
        [producto],
    )
    return filas[0] if filas else None


@conexion_opcional()
def leer_trazas(conexion: Any, limite: int = 100) -> list[dict[str, Any]]:
    """Últimas llamadas del agente a herramientas: momento, herramienta, entrada, decisión."""
    return _consultar(
        conexion,
        "SELECT momento, herramienta, entrada, decision FROM trazas ORDER BY id DESC LIMIT ?",
        [limite],
    )


@conexion_opcional()
def hay_hallazgos(conexion: Any) -> bool:
    return conexion.execute("SELECT 1 FROM hallazgos LIMIT 1").fetchone() is not None


def guardar_decisiones_cpe(conexion: Any, decisiones: Iterable[Any]) -> int:
    """Guarda las decisiones del normalizador en `programa_cpe` (una fila por nombre limpio).

    `vendor` y `producto` llevan el primer par; la lista completa de pares (Docker Desktop
    tiene dos) va en el JSON de `candidatos`, bajo "pares".
    """
    filas = []
    for d in decisiones:
        primero = d.pares[0].split(":", 1) if d.pares else (None, None)
        filas.append(
            (
                d.nombre_limpio,
                primero[0],
                primero[1],
                d.confianza,
                d.metodo,
                _json(
                    {
                        "pares": list(d.pares),
                        "producto": d.producto,
                        "candidatos": [
                            {"par": c.par, "puntaje": c.puntaje, "titulo": c.titulo}
                            for c in d.candidatos[:5]
                        ],
                    }
                ),
            )
        )
    conexion.execute("DELETE FROM programa_cpe")
    _en_lotes(
        conexion,
        "INSERT OR REPLACE INTO programa_cpe (programa, vendor, producto, confianza, metodo, "
        "candidatos) VALUES (?,?,?,?,?,?)",
        filas,
    )
    conexion.commit()
    return len(filas)


@conexion_opcional()
def pares_asignados(conexion: Any) -> list[str]:
    """Todos los pares que el normalizador asignó (incluye los segundos pares)."""
    pares: set[str] = set()
    for vendor, producto, candidatos in conexion.execute(
        "SELECT vendor, producto, candidatos FROM programa_cpe"
    ).fetchall():
        if vendor and producto:
            pares.add(f"{vendor}:{producto}")
        pares.update((_de_json(candidatos, {}) or {}).get("pares", []))
    return sorted(pares)


# ---------------------------------------------------------------------------
# Trazas de la guarda del plugin (traza.jsonl en ${CLAUDE_PLUGIN_DATA})
# ---------------------------------------------------------------------------

LARGO_ENTRADA_TRAZA = 300
_CLAVES_FIJAS = {"hora", "evento", "herramienta", "decision"}


def decision_de_traza(registro: dict[str, Any]) -> str:
    """Traduce una línea de traza.jsonl a la decisión de la tabla `trazas`.

    PreToolUse: deny -> negada, ask -> aprobacion_pedida, allow -> permitida.
    PostToolUse: retenido -> negada, con señales -> limpiada, sin señales -> permitida.
    """
    if registro.get("evento") == "PreToolUse":
        return {"deny": "negada", "ask": "aprobacion_pedida", "allow": "permitida"}.get(
            str(registro.get("decision")), "negada"
        )
    if registro.get("retenido"):
        return "negada"
    return "limpiada" if registro.get("senales") else "permitida"


def importar_trazas(conexion: Any, ruta: Path | str) -> int:
    """Carga las trazas de la guarda del plugin en la tabla `trazas`. Devuelve cuántas agregó.

    Cada línea es JSON con `hora`, `evento`, `herramienta` y, según el evento, `decision` o
    `largo`, `sha256`, `senales`, `retenido`, `error`. La entrada guardada es el evento y esos
    datos (nunca el texto crudo de la herramienta), limpia y recortada. Las líneas ilegibles se
    saltan, y reimportar el mismo archivo no duplica filas.
    """
    from radar.seguridad.limpieza import limpiar_texto

    crear_esquema(conexion)
    existentes = {
        tuple(f)
        for f in conexion.execute("SELECT momento, herramienta, entrada FROM trazas").fetchall()
    }
    nuevas = []
    with open(ruta, encoding="utf-8") as archivo:
        for linea in archivo:
            try:
                registro = json.loads(linea)
            except ValueError:
                continue
            if not isinstance(registro, dict):
                continue
            extra = {k: v for k, v in registro.items() if k not in _CLAVES_FIJAS}
            entrada = limpiar_texto(
                f"{registro.get('evento', '?')} {json.dumps(extra, ensure_ascii=False)}",
                LARGO_ENTRADA_TRAZA,
            )
            fila = (
                limpiar_texto(str(registro.get("hora") or ""), 40),
                limpiar_texto(str(registro.get("herramienta") or "(desconocida)"), 120),
                entrada,
            )
            if fila in existentes:
                continue
            existentes.add(fila)
            nuevas.append((*fila, decision_de_traza(registro)))
    if nuevas:
        _en_lotes(
            conexion,
            "INSERT INTO trazas (momento, herramienta, entrada, decision) VALUES (?,?,?,?)",
            nuevas,
        )
    conexion.commit()
    return len(nuevas)


def principal(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="python -m radar.bd", description="Utilidades de la base")
    sub = p.add_subparsers(dest="orden", required=True)
    trazas = sub.add_parser("importar-trazas", help="Carga traza.jsonl de la guarda del plugin")
    trazas.add_argument("ruta", type=Path)
    trazas.add_argument("--sqlite", type=Path, help="Fuerza un sqlite local en esta ruta")
    args = p.parse_args(argv)

    conexion = conectar(ruta_sqlite=args.sqlite)
    try:
        n = importar_trazas(conexion, args.ruta)
        total = contar(conexion, "trazas")
    finally:
        conexion.close()
    print(f"[bd] {n} trazas nuevas importadas de {args.ruta} ({total} en la tabla)", flush=True)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(principal())
