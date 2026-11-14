"""Motor del asistente: une bucle, herramientas, escrituras, permisos, prompt, consumo y topes.

Llama a la API de Claude con el SDK `anthropic` (no el Agent SDK: este bucle tiene que poder
pausarse horas esperando un clic, y vive en una función de Vercel).

- Modelo: `radar.ajustes.modelo("asistente")` (Configuración del panel; Sonnet 5.5 por defecto).
- Caché: system prompt con la fecha (no la hora) y `cache_control` en la última herramienta.
- Consumo: se registra POR LLAMADA, no al final: si la función muere, lo pagado cuenta.
- Topes: antes de cada llamada; si no se pueden leer, no se llama (falla cerrado).
- Modelo simulado: `RADAR_ASISTENTE_FALSO=1` responde con reglas fijas y costo cero, para las
  pruebas y Playwright. Se ignora en Vercel.

Cada operación de base abre su propia conexión: en Turso una conexión larga puede caducar
mientras el modelo piensa.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import uuid
from collections.abc import Callable, Iterator
from typing import Any

from radar.asistente import almacen, escrituras, guardia, herramientas, permisos, prompt
from radar.asistente.bucle import (
    Dependencias,
    Ejecucion,
    Preparada,
    Resultado,
    avanzar,
    decidir,
    exito,
    fallo,
    nueva_ejecucion,
)
from radar.asistente.contexto import Contexto
from radar.asistente.costo import costo_usd, uso_de_api
from radar.asistente.privacidad import proteger
from radar.asistente.turnos import contar_turnos, texto_rechazo, turnos_de
from radar.seguridad.limpieza import AVISO_DATOS

MAX_TOKENS = 16_000
ESFUERZO = "medium"
MODELO_FALSO = "falso"
# Modelos con respaldo del servidor ante un rechazo (skill claude-api). Haiku no tiene.
CON_RESPALDO = {"claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2"}

Emitir = Callable[[dict[str, Any]], None]


class NoDisponible(RuntimeError):
    """Sin clave de API: la caja solo busca."""


def modo_falso() -> bool:
    return os.environ.get("RADAR_ASISTENTE_FALSO") == "1" and not os.environ.get("VERCEL")


def disponible() -> bool:
    return modo_falso() or bool(
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    )


def modelo() -> str:
    if modo_falso():
        return MODELO_FALSO
    from radar.ajustes import modelo as modelo_de

    return modelo_de("asistente")


@contextlib.contextmanager
def base() -> Iterator[Any]:
    conexion = almacen.conectar()
    try:
        yield conexion
    finally:
        with contextlib.suppress(Exception):
            conexion.close()


def hoy() -> str:
    return almacen.dia_colombia()


def _registrar(texto: str) -> None:
    print(f"[asistente] {texto}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------


def _llamar_api(
    system: str, tools: list[dict[str, Any]], mensajes: list[dict[str, Any]], id_modelo: str
) -> dict:
    import anthropic

    cliente = anthropic.Anthropic()
    extra: dict[str, Any] = {}
    if id_modelo in CON_RESPALDO:
        extra = {"betas": ["server-side-fallback-2026-07-01"], "fallbacks": "default"}
    with cliente.beta.messages.stream(
        model=id_modelo,
        max_tokens=MAX_TOKENS,
        system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        tools=tools,
        messages=mensajes,
        thinking={"type": "adaptive"},
        output_config={"effort": ESFUERZO},
        **extra,
    ) as flujo:
        mensaje = flujo.get_final_message()
    datos = mensaje.to_dict()
    return {
        "content": datos.get("content") or [],
        "stop_reason": datos.get("stop_reason"),
        "usage": datos.get("usage") or {},
        "model": datos.get("model") or id_modelo,
    }


def _ultima_pregunta(mensajes: list[dict[str, Any]]) -> str:
    for m in reversed(mensajes):
        if m["role"] == "user" and isinstance(m["content"], str):
            return m["content"]
    return ""


def _usos_previos(mensajes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for m in reversed(mensajes):
        if m["role"] == "assistant" and isinstance(m["content"], list):
            return [b for b in m["content"] if b.get("type") == "tool_use"]
    return []


def modelo_simulado(mensajes: list[dict[str, Any]], ctx: Contexto) -> dict[str, Any]:
    """Reglas fijas para pruebas: consulta, propone un cambio de estado o termina."""
    n = sum(1 for m in mensajes if m["role"] == "assistant")

    def usar(nombre: str, entrada: dict[str, Any]) -> dict[str, Any]:
        bloque = {"type": "tool_use", "id": f"toolu_falso_{n}", "name": nombre, "input": entrada}
        return {"content": [bloque], "stop_reason": "tool_use", "usage": {}, "model": MODELO_FALSO}

    def decir(texto: str) -> dict[str, Any]:
        return {
            "content": [{"type": "text", "text": texto}],
            "stop_reason": "end_turn",
            "usage": {},
            "model": MODELO_FALSO,
        }

    ultimo = mensajes[-1]
    pregunta = _ultima_pregunta(mensajes).casefold()
    quiere_cambio = any(p in pregunta for p in ("marca", "pasa ", "cambia", "aprueba"))

    if isinstance(ultimo["content"], str):
        if ctx.rol == "equipo":
            return usar("mi_equipo", {})
        if quiere_cambio and permisos.puede(ctx.rol, "proponer_estado_hallazgo"):
            return usar("buscar_hallazgos", {"limite": 1, "estado": "nuevo"})
        if quiere_cambio:
            return decir(
                "Con tu rol solo puedes consultar. Ese cambio lo hace alguien con rol analista en [Hallazgos](/panel/#hallazgos)."
            )
        return usar("resumen_radar", {})

    resultados = [b for b in ultimo["content"] if b.get("type") == "tool_result"]
    previos = {u["id"]: u["name"] for u in _usos_previos(mensajes)}
    for r in resultados:
        nombre = previos.get(r["tool_use_id"])
        contenido = r.get("content") or ""
        if nombre == "proponer_estado_hallazgo":
            if r.get("is_error"):
                return decir("Entendido, no cambio nada. ¿Qué quieres ajustar?")
            return decir("Listo, el hallazgo quedó en curso. [Ver hallazgos](/panel/#hallazgos)")
        if nombre == "buscar_hallazgos" and quiere_cambio:
            try:
                datos = json.loads(contenido)["datos"]["hallazgos"]
            except (ValueError, KeyError, TypeError):
                datos = []
            if not datos:
                return decir("No encontré hallazgos nuevos para cambiar.")
            return usar(
                "proponer_estado_hallazgo", {"id_hallazgo": datos[0]["id"], "estado": "en_curso"}
            )
        if nombre == "mi_equipo":
            return decir(
                "Respuesta simulada: revisé tu equipo en el radar. Mira las tareas de hoy arriba."
            )
    return decir(
        "Respuesta simulada con datos del radar: revisé el resumen. [Ver resumen](/panel/#resumen)"
    )


# ---------------------------------------------------------------------------
# Dependencias del bucle
# ---------------------------------------------------------------------------


def _con_aviso(r: Resultado) -> Resultado:
    """Todo dato hacia el modelo: sin datos personales, limpio y marcado como no confiable."""
    if not r.ok:
        return r
    return exito({"aviso": AVISO_DATOS, "datos": proteger(r.datos)})


def dependencias(ctx: Contexto, emitir: Emitir, decide: Contexto | None = None) -> Dependencias:
    """`decide` es quien hace clic al aprobar (con su rol ACTUAL); por defecto, quien pregunta."""
    id_modelo = modelo()
    lecturas = permisos.herramientas_de(ctx.rol)
    acciones = permisos.escrituras_de(ctx.rol)
    tools = permisos.definiciones(ctx.rol)
    system = prompt.prompt_equipo(hoy()) if ctx.rol == "equipo" else prompt.prompt_panel(hoy(), ctx)
    pasos = {h.nombre: h.paso for h in lecturas}
    nombres_escritura = {a.nombre for a in acciones}
    conversacion: dict[str, Ejecucion | None] = {"e": None}

    def llamar(mensajes: list[dict[str, Any]]) -> dict[str, Any]:
        if id_modelo == MODELO_FALSO:
            return modelo_simulado(mensajes, ctx)
        msg = _llamar_api(system, tools, mensajes, id_modelo)
        uso = uso_de_api(msg["usage"])
        try:
            with base() as c:
                e = conversacion["e"]
                almacen.registrar_consumo(
                    c, ctx, e.id if e else "", msg["model"], uso, costo_usd(uso, msg["model"])
                )
        except Exception as error:  # noqa: BLE001 - se registra en stderr; el tope usa lo que haya
            _registrar(f"no se pudo registrar el consumo: {error}")
        return msg

    def ejecutar(nombre: str, entrada: Any, _uid: str) -> Resultado:
        if nombre in nombres_escritura:
            quien = decide or ctx
            return _con_aviso(escrituras.ejecutar(nombre, entrada, quien))
        if not permisos.puede(ctx.rol, nombre):
            return fallo("Sin permiso para esa herramienta con tu rol.")
        return _con_aviso(herramientas.ejecutar(nombre, entrada, ctx))

    def preparar(nombre: str, entrada: Any) -> Preparada:
        return escrituras.preparar(nombre, entrada, ctx)

    def guardar(e: Ejecucion) -> None:
        conversacion["e"] = e
        with base() as c:
            almacen.guardar(c, e)

    def restante() -> float:
        if id_modelo == MODELO_FALSO:
            return 1.0
        with base() as c:
            return almacen.restante(c, ctx)

    def emitir_limpio(evento: dict[str, Any]) -> None:
        if evento.get("tipo") == "texto":
            e = conversacion["e"]
            evento = {
                **evento,
                "texto": guardia.revisar(
                    evento["texto"], guardia.vistos_de(e.mensajes) if e else []
                ),
            }
        elif evento.get("tipo") == "paso":
            evento = {**evento, "texto": pasos.get(evento["herramienta"], "Consultando el radar")}
        emitir(evento)

    deps = Dependencias(
        llamar_modelo=llamar,
        validar=lambda nombre, entrada: permisos.validar(ctx.rol, nombre, entrada),
        ejecutar=ejecutar,
        guardar=guardar,
        emitir=emitir_limpio,
        presupuesto_restante=restante,
        herramientas_aprobacion=sorted(nombres_escritura),
        preparar_propuesta=preparar,
        rechazo=texto_rechazo,
    )
    deps.conversacion = conversacion  # type: ignore[attr-defined]
    return deps


# ---------------------------------------------------------------------------
# Lo que llaman los endpoints
# ---------------------------------------------------------------------------


class Conflicto(RuntimeError):
    """La conversación no se puede seguir (ya corre, ya se decidió, es ajena o está llena)."""

    def __init__(self, mensaje: str, nueva: bool = False) -> None:
        super().__init__(mensaje)
        self.nueva = nueva


def presupuesto(ctx: Contexto) -> float:
    if modo_falso():
        return 1.0
    with base() as c:
        return almacen.restante(c, ctx)


def preguntar(ctx: Contexto, pregunta: str, id_: str | None, emitir: Emitir) -> Ejecucion:
    """Nueva conversación, o sigue una del usuario. Con una propuesta abierta, escribir otra
    cosa es "pedir cambios": cuenta como rechazo con indicación."""
    deps = dependencias(ctx, emitir)
    if id_ is None:
        e = nueva_ejecucion(str(uuid.uuid4()), pregunta)
        with base() as c:
            almacen.crear(c, e, ctx)
            with contextlib.suppress(Exception):
                almacen.purgar(c)
        deps.conversacion["e"] = e  # type: ignore[attr-defined]
        emitir({"tipo": "conversacion", "id": e.id})
        return avanzar(e, deps)

    with base() as c:
        leida = almacen.obtener(c, id_)
        if leida is None or leida[1]["usuario_id"] != ctx.usuario_id:
            raise Conflicto("Esa conversación no existe o no es tuya.", nueva=True)
        previa = leida[0]
        if previa.estado == "fallida":
            raise Conflicto("Esa conversación se cortó. Empieza otra.", nueva=True)
        if previa.estado == "terminada" and contar_turnos(previa.mensajes) >= almacen.MAX_TURNOS:
            raise Conflicto("Esta conversación ya es muy larga. Empieza otra.", nueva=True)
        e = (
            almacen.reclamar(c, id_, [previa.estado], ctx.usuario_id)
            if previa.estado != "corriendo"
            else None
        )
    if e is None:
        raise Conflicto("La conversación está ocupada o ya cambió. Recarga para verla.")
    deps.conversacion["e"] = e  # type: ignore[attr-defined]
    emitir({"tipo": "conversacion", "id": e.id})
    if previa.estado == "esperando_aprobacion":
        e.estado = "esperando_aprobacion"
        e.propuesta = previa.propuesta
        with base() as c:
            almacen.auditar(
                c,
                e.id,
                e.propuesta,
                ctx.usuario_id,
                ctx.usuario_id,
                False,
                {"comentario": pregunta},
                True,
            )
        return decidir(e, False, deps, comentario=pregunta)
    e.mensajes.append({"role": "user", "content": pregunta})
    e.estado = "corriendo"
    return avanzar(e, deps)


def rol_actual(ctx: Contexto) -> str | None:
    """Rol de quien decide, leído de la base AHORA (pudo cambiar desde que se propuso)."""
    if ctx.via != "sesion" or ctx.cuenta_id is None:
        return ctx.rol
    from radar.api import cuentas

    conexion = cuentas.conectar()
    try:
        usuario = cuentas.leer_usuario(conexion, ctx.cuenta_id)
    finally:
        conexion.close()
    if usuario is None or not usuario.activo:
        return None
    return usuario.rol


def decidir_propuesta(ctx: Contexto, id_: str, aprobado: bool, emitir: Emitir) -> Ejecucion:
    """Aprobar o descartar la propuesta pendiente. Solo el dueño de la conversación decide, y
    con el rol que tiene HOY."""
    rol = rol_actual(ctx)
    if rol is None:
        raise Conflicto("Tu cuenta ya no está activa.")
    quien = Contexto(ctx.usuario_id, ctx.nombre, rol, ctx.via, ctx.cuenta_id, ctx.equipo_id)
    with base() as c:
        leida = almacen.obtener(c, id_)
        if leida is None or leida[1]["usuario_id"] != ctx.usuario_id:
            raise Conflicto("Esa conversación no existe o no es tuya.")
        e = almacen.reclamar(c, id_, ["esperando_aprobacion"], ctx.usuario_id)
    if e is None or e.propuesta is None:
        raise Conflicto("Esta propuesta ya se decidió en otra pestaña.")
    propuesta = e.propuesta
    if aprobado and not permisos.puede(rol, propuesta.herramienta):
        with base() as c:
            almacen.soltar(c, id_, "esperando_aprobacion")
        raise Conflicto("Tu rol actual no permite aprobar este cambio.")

    capturado: dict[str, Any] = {}
    deps = dependencias(quien, emitir, decide=quien)
    original = deps.ejecutar

    def ejecutar_y_capturar(nombre: str, entrada: Any, uid: str) -> Resultado:
        r = original(nombre, entrada, uid)
        if uid == propuesta.tool_use_id:
            capturado["r"] = r
        return r

    deps.ejecutar = ejecutar_y_capturar
    deps.conversacion["e"] = e  # type: ignore[attr-defined]
    e.estado = "esperando_aprobacion"
    emitir({"tipo": "conversacion", "id": e.id})

    def auditar_al_guardar(
        original_guardar: Callable[[Ejecucion], None],
    ) -> Callable[[Ejecucion], None]:
        hecho = {"si": False}

        def guardar(ej: Ejecucion) -> None:
            original_guardar(ej)
            if not hecho["si"]:
                hecho["si"] = True
                r = capturado.get("r")
                with base() as c:
                    almacen.auditar(
                        c,
                        ej.id,
                        propuesta,
                        leida[1]["usuario_id"],
                        quien.usuario_id,
                        aprobado,
                        (r.datos if r and r.ok else (r.error if r else None)),
                        bool(r.ok) if r else True,
                    )

        return guardar

    deps.guardar = auditar_al_guardar(deps.guardar)
    return decidir(e, aprobado, deps)


def ver(ctx: Contexto, id_: str) -> dict[str, Any] | None:
    """La conversación para pintarla. El admin puede ver las ajenas, en solo lectura."""
    with base() as c:
        leida = almacen.obtener(c, id_)
    if leida is None:
        return None
    e, meta = leida
    propia = meta["usuario_id"] == ctx.usuario_id
    if not propia and not ctx.es_admin:
        return None
    vistos = guardia.vistos_de(e.mensajes)
    turnos = []
    for t in turnos_de(e.mensajes):
        datos = t.a_dict()
        datos["respuesta"] = (
            guardia.revisar(datos["respuesta"], vistos) if datos["respuesta"] else ""
        )
        datos["pasos"] = [_paso_legible(p) for p in datos["pasos"]]
        turnos.append(datos)
    return {
        "id": e.id,
        "estado": e.estado,
        "error": e.error,
        "solo_lectura": not propia,
        "dueno": meta["usuario_nombre"],
        "turnos": turnos,
        "propuesta": (
            {"origen": e.propuesta.origen, "motivo": e.propuesta.motivo, "vista": e.propuesta.vista}
            if e.propuesta and e.estado == "esperando_aprobacion"
            else None
        ),
        "costo_usd": round(e.costo_usd, 4),
    }


def _paso_legible(nombre: str) -> str:
    h = herramientas.POR_NOMBRE.get(nombre)
    if h:
        return h.paso
    return "Preparando una propuesta" if nombre in escrituras.POR_NOMBRE else "Consultando el radar"
