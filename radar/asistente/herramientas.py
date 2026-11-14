"""Herramientas de LECTURA del asistente. Ninguna escribe (tests/test_asistente.py lo vigila
comparando la base antes y después).

Reutilizan las mismas funciones que sirven al panel (`obtener_datos()`, `radar/equipos/vista.py`,
`vista_simple` de /mi-equipo/), así el asistente y la pantalla nunca dicen cosas distintas.

Reglas (skill `panel-ia`):

- Campos nombrados, nunca el objeto entero: lo que no está en la lista no sale hacia la API.
- Límite de filas en cada lista y conteos ya hechos: el modelo no cuenta ni suma.
- Cada resultado trae `enlace` a su sección del panel, para que el modelo no invente rutas.
- Nunca lanza: un error vuelve como `fallo(...)` y el modelo lo explica.
- `motor.py` pasa todo resultado por `privacidad.proteger` y lo marca como dato no confiable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from radar.asistente.bucle import Resultado, exito, fallo
from radar.asistente.contexto import Contexto

TODOS = ("lector", "analista", "admin")
MAX_FILAS = 30


class _Entrada(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class Herramienta:
    nombre: str
    descripcion: str
    entrada: type[_Entrada]
    roles: tuple[str, ...]
    paso: str  # lo que ve la persona mientras corre ("Revisando los hallazgos")
    ejecutar: Callable[[Any, Contexto], Any]


# ---------------------------------------------------------------------------
# Acceso a datos
# ---------------------------------------------------------------------------


def _datos():
    from radar.api.datos import obtener_datos

    return obtener_datos()


def _hay_base() -> bool:
    return _datos().origen == "base"


def _con_base(funcion: Callable[[Any], Any]) -> Any:
    from radar import bd

    conexion = bd.conectar(solo_lectura=True)
    try:
        return funcion(conexion)
    finally:
        conexion.close()


def _texto_objetivo(grupo: Any) -> str:
    from radar.api.rutas import texto_objetivo

    return texto_objetivo(grupo)


def _hallazgo(h: Any) -> dict[str, Any]:
    return {
        "id": h.id,
        "cve": h.cve,
        "producto": h.producto,
        "version_instalada": h.version_instalada,
        "n_equipos": len(h.equipos),
        "equipos": h.equipos[:5],
        "prioridad": h.prioridad,
        "kev": h.kev,
        "ransomware": h.ransomware,
        "epss": h.epss,
        "cvss": h.cvss,
        "estado": h.estado,
        "por_que": h.por_que[:3],
        "propuesto_resuelto": h.propuesto_resuelto,
    }


def _grupo(g: Any) -> dict[str, Any]:
    return {
        "producto": g.producto,
        "prioridad": g.prioridad,
        "versiones": g.versiones[:10],
        "n_equipos": len(g.equipos),
        "n_cves": len(g.cves),
        "en_kev": g.en_kev[:10],
        "ransomware": g.ransomware,
        "peor_cvss": g.peor_cvss,
        "peor_epss": g.peor_epss,
        "objetivo": _texto_objetivo(g),
        "por_que": g.por_que[:3],
    }


# ---------------------------------------------------------------------------
# Herramientas
# ---------------------------------------------------------------------------


class SinEntrada(_Entrada):
    pass


def resumen_radar(_e: SinEntrada, _ctx: Contexto) -> dict[str, Any]:
    r = _datos().resumen()
    return {
        "cifras": r["cifras"],
        "revision": {k: r["revision"][k] for k in ("inicio", "fin", "caidas", "error")},
        "cobertura": {k: r["cobertura"][k] for k in ("cruzados", "sin_evaluar", "por_motivo")},
        "trabajos_en_cola": r["trabajos"],
        "datos_de_ejemplo": not r["persistente"],
        "enlace": "/panel/#resumen",
    }


class EntradaHallazgos(_Entrada):
    prioridad: Literal["inmediato", "semanal", "informativo", "boletin"] | None = Field(
        default=None, description="Filtra por prioridad del radar."
    )
    kev: bool | None = Field(
        default=None, description="true: solo las que están en KEV (explotadas)."
    )
    texto: str | None = Field(
        default=None, max_length=100, description="Busca en CVE, producto o nombre de equipo."
    )
    estado: Literal["nuevo", "en_curso", "mitigado", "descartado"] | None = None
    limite: int = Field(default=15, ge=1, le=MAX_FILAS)


def buscar_hallazgos(e: EntradaHallazgos, _ctx: Contexto) -> dict[str, Any]:
    lista = _datos().hallazgos(prioridad=e.prioridad, kev=e.kev, texto=e.texto)
    if e.estado:
        lista = [h for h in lista if h.estado == e.estado]
    return {
        "total": len(lista),
        "mostrados": min(len(lista), e.limite),
        "por_estado": _contar(h.estado for h in lista),
        "hallazgos": [_hallazgo(h) for h in lista[: e.limite]],
        "enlace": "/panel/#hallazgos",
    }


def _contar(valores: Any) -> dict[str, int]:
    conteo: dict[str, int] = {}
    for v in valores:
        conteo[v] = conteo.get(v, 0) + 1
    return conteo


class EntradaProductos(_Entrada):
    limite: int = Field(default=15, ge=1, le=MAX_FILAS)


def productos_expuestos(e: EntradaProductos, _ctx: Contexto) -> dict[str, Any]:
    grupos = _datos().productos()
    return {
        "total": len(grupos),
        "productos": [_grupo(g) for g in grupos[: e.limite]],
        "enlace": "/panel/#resumen",
    }


class EntradaProducto(_Entrada):
    producto: str = Field(
        min_length=1,
        max_length=200,
        description="Nombre exacto del producto, sale de productos_expuestos.",
    )


def detalle_producto(e: EntradaProducto, _ctx: Contexto) -> Any:
    datos = _datos()
    grupo = datos.grupo(e.producto)
    if grupo is None:
        return fallo(
            f"No hay hallazgos para el producto {e.producto!r}. Búscalo con productos_expuestos."
        )
    analisis = datos.analisis(e.producto)
    return {
        "producto": _grupo(grupo),
        "cves": grupo.cves[:20],
        "analisis": (
            {
                "origen": analisis.origen,
                "verificado": analisis.verificado,
                "resumen": analisis.resumen,
                "remediacion": analisis.remediacion,
                "mitigacion_temporal": analisis.mitigacion_temporal,
                "comunicado_ti": analisis.comunicado_ti,
                "comunicado_usuarios": analisis.comunicado_usuarios,
            }
            if analisis
            else None
        ),
        "comunicado_aprobado": datos.aprobacion(e.producto),
        "enlace": "/panel/#hallazgos",
    }


def _equipo_fila(f: dict[str, Any]) -> dict[str, Any]:
    from radar.api.termometro import termometro

    so = f.get("so") or {}
    return {
        "equipo_id": f["id"],
        "nombre": f["nombre"],
        "pendiente_de_aprobar": bool(f.get("pendiente")) and not f.get("revocado"),
        "revocado": bool(f.get("revocado")),
        "ultimo_reporte": f.get("ultimo_reporte"),
        "sistema": " ".join(str(so.get(k)) for k in ("nombre", "version") if so.get(k)) or None,
        "peor_prioridad": f.get("peor_prioridad"),
        "acciones": f.get("acciones"),
        "termometro": termometro(f),
    }


class EntradaEquipos(_Entrada):
    solo_pendientes: bool = Field(
        default=False, description="true: solo los que esperan aprobación."
    )
    limite: int = Field(default=20, ge=1, le=MAX_FILAS)


def equipos(e: EntradaEquipos, _ctx: Contexto) -> Any:
    if not _hay_base():
        return fallo(
            "Los equipos con agente necesitan una base conectada; ahora el radar usa datos de ejemplo."
        )
    from radar.equipos import vista

    filas = [_equipo_fila(f) for f in _con_base(vista.lista)]
    if e.solo_pendientes:
        filas = [f for f in filas if f["pendiente_de_aprobar"]]
    return {
        "total": len(filas),
        "pendientes_de_aprobar": sum(1 for f in filas if f["pendiente_de_aprobar"]),
        "equipos": filas[: e.limite],
        "enlace": "/panel/#equipos",
    }


class EntradaEquipo(_Entrada):
    equipo: str = Field(
        min_length=1,
        max_length=200,
        description="equipo_id o nombre exacto, sale de la herramienta equipos.",
    )


def _resolver_equipo(conexion: Any, clave: str) -> str | None:
    from radar.equipos import almacen

    if almacen.leer_equipo(conexion, clave):
        return clave
    coinciden = [
        eq.id for eq in almacen.leer_equipos(conexion) if eq.nombre.casefold() == clave.casefold()
    ]
    return coinciden[0] if len(coinciden) == 1 else None


def detalle_equipo(e: EntradaEquipo, _ctx: Contexto) -> Any:
    if not _hay_base():
        return fallo("Los equipos con agente necesitan una base conectada.")
    from radar.api.mi_equipo import _parcheo
    from radar.equipos import vista

    def leer(conexion: Any) -> Any:
        equipo_id = _resolver_equipo(conexion, e.equipo)
        if equipo_id is None:
            return None
        return equipo_id, vista.detalle(conexion, equipo_id), _parcheo(conexion, equipo_id)

    leido = _con_base(leer)
    if leido is None or leido[1] is None:
        return fallo(f"No encontré el equipo {e.equipo!r}. Búscalo con la herramienta equipos.")
    _id, datos, parcheo = leido
    return {
        "equipo": _equipo_fila(datos["equipo"]),
        "postura": (datos["equipo"].get("postura") or None),
        "productos": [
            {
                k: p.get(k)
                for k in ("producto", "prioridad", "versiones", "en_kev", "n_cves", "pasos")
            }
            for p in datos["productos"][:MAX_FILAS]
        ],
        "hallazgos_del_sistema": [
            {k: h.get(k) for k in ("tipo", "clave", "prioridad", "titulo", "pasos")}
            for h in datos["hallazgos_equipo"][:MAX_FILAS]
        ],
        "sin_revisar": datos["sin_revisar"][:10],
        "cobertura": {k: datos["cobertura"][k] for k in ("sin_evaluar", "por_motivo")},
        "parcheo": parcheo,
        "enlace": "/panel/#equipos",
    }


class EntradaCobertura(_Entrada):
    motivo: Literal["sin_version", "no_comparable", "sin_cpe"] | None = None
    limite: int = Field(default=15, ge=1, le=MAX_FILAS)


def cobertura(e: EntradaCobertura, _ctx: Contexto) -> dict[str, Any]:
    r = _datos().resumen()["cobertura"]
    detalle = [c for c in r["detalle"] if not e.motivo or c["motivo"] == e.motivo]
    return {
        "cruzados": r["cruzados"],
        "sin_evaluar": r["sin_evaluar"],
        "por_motivo": r["por_motivo"],
        "explicacion_motivos": {
            "sin_version": "el inventario no trae versión legible",
            "no_comparable": "la versión no se puede comparar con los rangos de NVD",
            "sin_cpe": "no se encontró el producto en el diccionario de NVD",
        },
        "filas": [
            {k: c.get(k) for k in ("equipo", "programa", "version", "motivo")}
            for c in detalle[: e.limite]
        ],
        "enlace": "/panel/#resumen",
    }


class EntradaTrazas(_Entrada):
    limite: int = Field(default=15, ge=1, le=MAX_FILAS)


def trazas_agente(e: EntradaTrazas, _ctx: Contexto) -> dict[str, Any]:
    filas = _datos().trazas() or []
    return {
        "total": len(filas),
        "trazas": [
            {k: t.get(k) for k in ("momento", "herramienta", "decision")} for t in filas[: e.limite]
        ],
        "enlace": "/panel/#actividad",
    }


def usuarios_y_tokens(_e: SinEntrada, _ctx: Contexto) -> Any:
    from radar.api import cuentas

    if not _hay_base():
        return fallo("Las cuentas viven en la base y ahora no hay base conectada.")
    conexion = cuentas.conectar()
    try:
        usuarios = cuentas.listar_usuarios(conexion)
        tokens = cuentas.listar_tokens(conexion, limite=20)
    finally:
        conexion.close()
    return {
        "usuarios": [
            {"usuario": u.usuario, "nombre": u.nombre, "rol": u.rol, "activo": u.activo}
            for u in usuarios
        ],
        "tokens_de_inscripcion": [
            {k: t.get(k) for k in ("etiqueta", "sistema", "estado", "vence", "usos", "usos_max")}
            for t in tokens
        ],
        "enlace": "/panel/#usuarios",
    }


# Secciones del panel: lo que responde "¿dónde veo...?" sin IA (también lo usa la caja).
SECCIONES: tuple[dict[str, Any], ...] = (
    {
        "titulo": "Resumen",
        "enlace": "/panel/#resumen",
        "claves": "resumen cifras cobertura productos inicio",
    },
    {
        "titulo": "Hallazgos",
        "enlace": "/panel/#hallazgos",
        "claves": "hallazgos cve estado kev prioridad comunicado",
    },
    {
        "titulo": "Equipos",
        "enlace": "/panel/#equipos",
        "claves": "equipos agente aprobar pendientes parcheo termómetro",
    },
    {
        "titulo": "Agregar equipo",
        "enlace": "/panel/#equipos",
        "claves": "agregar equipo token instalar agente",
    },
    {
        "titulo": "Cargar inventario",
        "enlace": "/panel/#inventario",
        "claves": "cargar inventario csv excel archivo",
        "rol": "analista",
    },
    {"titulo": "Umbrales", "enlace": "/panel/#umbrales", "claves": "umbrales epss cvss prioridad"},
    {
        "titulo": "Actividad del agente",
        "enlace": "/panel/#actividad",
        "claves": "actividad trazas analista agente",
    },
    {
        "titulo": "Usuarios",
        "enlace": "/panel/#usuarios",
        "claves": "usuarios roles contraseña cuentas",
        "rol": "admin",
    },
    {
        "titulo": "Configuración",
        "enlace": "/panel/#configuracion",
        "claves": "configuración modelo topes gasto asistente",
        "rol": "admin",
    },
)

NIVEL = {"lector": 0, "analista": 1, "admin": 2}


def secciones_para(rol: str, texto: str = "") -> list[dict[str, str]]:
    t = texto.casefold().strip()
    salida = []
    for s in SECCIONES:
        if NIVEL.get(rol, -1) < NIVEL.get(s.get("rol", "lector"), 0):
            continue
        if not t or any(p in s["claves"] or p in s["titulo"].casefold() for p in t.split()):
            salida.append({"titulo": s["titulo"], "enlace": s["enlace"]})
    return salida


class EntradaBuscar(_Entrada):
    texto: str = Field(
        min_length=1, max_length=100, description="Qué busca la persona, en sus palabras."
    )


def buscar_en_panel(e: EntradaBuscar, ctx: Contexto) -> dict[str, Any]:
    return {"secciones": secciones_para(ctx.rol, e.texto) or secciones_para(ctx.rol)}


def mi_equipo(_e: SinEntrada, ctx: Contexto) -> Any:
    """Solo el equipo del enlace firmado: el id sale del contexto, nunca del modelo."""
    from radar.api.mi_equipo import vista_simple

    if not ctx.equipo_id:
        return fallo("Sin equipo.")
    datos = _con_base(lambda c: vista_simple(c, ctx.equipo_id))
    if datos is None:
        return fallo("Este equipo ya no está en el radar.")
    return {
        "equipo": datos["equipo"],
        "termometro": datos["termometro"],
        "tareas": datos["tareas"][:MAX_FILAS],
        "parcheo": datos["parcheo"],
        "sin_revisar": datos["sin_revisar"][:10],
    }


HERRAMIENTAS: tuple[Herramienta, ...] = (
    Herramienta(
        "resumen_radar",
        "Cifras del día: cuántos hallazgos exigen acción, cuántas CVE están explotadas (KEV), "
        "equipos afectados, fuentes caídas y cobertura. Úsala para '¿cómo estamos hoy?'.",
        SinEntrada,
        TODOS,
        "Revisando el resumen del radar",
        resumen_radar,
    ),
    Herramienta(
        "buscar_hallazgos",
        "Hallazgos (una CVE en un producto instalado) filtrados por prioridad, KEV, estado o texto. "
        "Úsala para '¿qué es inmediato?', '¿qué está en KEV y sigue nuevo?' o para encontrar el id "
        "de un hallazgo antes de proponer un cambio de estado.",
        EntradaHallazgos,
        TODOS,
        "Buscando hallazgos",
        buscar_hallazgos,
    ),
    Herramienta(
        "productos_expuestos",
        "Productos con hallazgos, del más urgente al menos, con versión objetivo, KEV y equipos. "
        "Úsala para '¿qué hay que actualizar primero?'.",
        EntradaProductos,
        TODOS,
        "Revisando los productos expuestos",
        productos_expuestos,
    ),
    Herramienta(
        "detalle_producto",
        "Detalle de un producto: CVE, análisis, comunicados redactados y si el comunicado ya está "
        "aprobado. Úsala para '¿qué dice el comunicado de X?'.",
        EntradaProducto,
        TODOS,
        "Leyendo el análisis del producto",
        detalle_producto,
    ),
    Herramienta(
        "equipos",
        "Equipos con agente local, del más expuesto al menos, con termómetro y si esperan "
        "aprobación. Úsala para '¿qué equipos están peor?' o '¿hay equipos por aprobar?'.",
        EntradaEquipos,
        TODOS,
        "Revisando los equipos",
        equipos,
    ),
    Herramienta(
        "detalle_equipo",
        "Lo que le falta a un equipo: productos a actualizar, hallazgos del sistema, postura y "
        "estado del parcheo. Úsala para '¿qué le falta a PC-X?'.",
        EntradaEquipo,
        TODOS,
        "Revisando el equipo",
        detalle_equipo,
    ),
    Herramienta(
        "cobertura",
        "Lo que el radar no pudo comparar (sin versión, sin CPE, no comparable) y por qué. "
        "Sin comparación no hay hallazgo: úsala para '¿qué quedó sin revisar?'.",
        EntradaCobertura,
        TODOS,
        "Revisando la cobertura",
        cobertura,
    ),
    Herramienta(
        "trazas_agente",
        "Últimas decisiones del agente analista sobre sus herramientas (permitidas o negadas). "
        "Úsala para '¿qué hizo el analista?'.",
        EntradaTrazas,
        TODOS,
        "Revisando la actividad del analista",
        trazas_agente,
    ),
    Herramienta(
        "usuarios_y_tokens",
        "Usuarios del panel con su rol y si están activos, y tokens de inscripción con su vigencia. "
        "Nunca contraseñas ni sesiones. Úsala para '¿quién es admin?'.",
        SinEntrada,
        ("admin",),
        "Revisando usuarios y tokens",
        usuarios_y_tokens,
    ),
    Herramienta(
        "buscar_en_panel",
        "Secciones del panel con su enlace. Úsala cuando pregunten dónde se hace o se ve algo.",
        EntradaBuscar,
        TODOS,
        "Buscando en el panel",
        buscar_en_panel,
    ),
    Herramienta(
        "mi_equipo",
        "Lo que tiene que hacer la persona en SU equipo: tareas por urgencia, si debe reiniciar y "
        "el último parcheo. Úsala para cualquier pregunta sobre su equipo.",
        SinEntrada,
        ("equipo",),
        "Revisando tu equipo",
        mi_equipo,
    ),
)

POR_NOMBRE = {h.nombre: h for h in HERRAMIENTAS}


def ejecutar(nombre: str, entrada: Any, ctx: Contexto) -> Resultado:
    """Ejecuta una lectura. Nunca lanza."""
    h = POR_NOMBRE.get(nombre)
    if h is None:
        return fallo(f"Herramienta desconocida: {nombre}.")
    try:
        datos = h.ejecutar(h.entrada.model_validate(entrada or {}), ctx)
    except Exception as error:  # noqa: BLE001 - el modelo recibe el error y lo explica
        return fallo(f"No se pudo consultar ({type(error).__name__}).")
    return datos if isinstance(datos, Resultado) else exito(datos)
