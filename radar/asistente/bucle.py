"""Bucle del asistente: habla con Claude, ejecuta lecturas y SE PAUSA ante una escritura.

Por qué un bucle propio y no el Tool Runner ni el Agent SDK: una propuesta puede esperar el
clic de una persona durante horas, y una función de Vercel no se queda esperando. La
conversación se guarda en `esperando_aprobacion`, la función termina y `decidir()` la
retoma en otra petición con el `tool_result` que falta.

Reglas de la API que respeta:

- Historial solo por anexión: el `content` de cada respuesta se guarda tal cual (con los
  bloques de thinking). Editar turnos previos invalida el thinking.
- Nunca ejecuta herramientas de un turno cortado (`max_tokens`, `refusal`).
- Los `tool_result` vuelven en el orden de los `tool_use` del turno.

Sin base ni red: todo lo externo llega por `Dependencias`, para probar cada rama con un
modelo falso. Portado de la skill `panel-ia` (assets/bucle.ts).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Literal

from radar.asistente.costo import USO_CERO, Uso, costo_usd, sumar, uso_de_api

MAX_ITERACIONES = 15

Estado = Literal["corriendo", "esperando_aprobacion", "terminada", "fallida"]


@dataclass
class Resultado:
    ok: bool
    datos: Any = None
    error: str | None = None


def exito(datos: Any) -> Resultado:
    return Resultado(True, datos=datos)


def fallo(error: str) -> Resultado:
    return Resultado(False, error=error)


@dataclass
class Preparada:
    """Lo que la pantalla enseña para decidir. Lo arma el servidor, nunca el modelo."""

    ok: bool
    origen: str = ""
    motivo: str = ""
    vista: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class Propuesta:
    tool_use_id: str
    herramienta: str
    origen: str
    motivo: str
    vista: dict[str, Any] | None
    entrada: Any
    resultados_previos: list[dict[str, Any]]
    orden: list[str]


@dataclass
class Ejecucion:
    id: str
    pregunta: str
    mensajes: list[dict[str, Any]]
    estado: Estado = "corriendo"
    propuesta: Propuesta | None = None
    respuesta: str | None = None
    error: str | None = None
    iteraciones: int = 0
    uso: Uso = USO_CERO
    costo_usd: float = 0.0
    # Datos que devolvieron las herramientas en esta ejecución (para la guardia).
    vistos: list[str] = field(default_factory=list)


def nueva_ejecucion(id_: str, pregunta: str) -> Ejecucion:
    return Ejecucion(id=id_, pregunta=pregunta, mensajes=[{"role": "user", "content": pregunta}])


@dataclass
class Dependencias:
    # -> {"content": [...], "stop_reason": str, "usage": {...}, "model": str}
    llamar_modelo: Callable[[list[dict[str, Any]]], dict[str, Any]]
    # Valida entrada Y permiso sin ejecutar. Devuelve el error o None.
    validar: Callable[[str, Any], str | None]
    # Ejecuta una lectura, o una escritura ya aprobada.
    ejecutar: Callable[[str, Any, str], Resultado]
    guardar: Callable[[Ejecucion], None]
    emitir: Callable[[dict[str, Any]], None]
    # USD que quedan hoy. Si no se puede saber, debe lanzar.
    presupuesto_restante: Callable[[], float]
    herramientas_aprobacion: list[str]
    preparar_propuesta: Callable[[str, Any], Preparada]
    rechazo: Callable[[str | None], str]


def _a_resultado(tool_use_id: str, r: Resultado) -> dict[str, Any]:
    if r.ok:
        return {
            "type": "tool_result",
            "tool_use_id": tool_use_id,
            "content": json.dumps(r.datos, ensure_ascii=False, default=str),
        }
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": r.error or "Error.", "is_error": True}


def _en_orden(orden: list[str], resultados: list[dict[str, Any]]) -> list[dict[str, Any]]:
    por_id = {r["tool_use_id"]: r for r in resultados}
    return [por_id[i] for i in orden if i in por_id]


def _terminar(e: Ejecucion, deps: Dependencias, estado: Estado, error: str | None) -> Ejecucion:
    e.estado = estado
    e.error = error
    e.propuesta = None
    deps.guardar(e)
    deps.emitir(
        {"tipo": "fin", "estado": estado, "iteraciones": e.iteraciones, "costo_usd": round(e.costo_usd, 4), "error": error}
    )
    return e


def avanzar(e: Ejecucion, deps: Dependencias) -> Ejecucion:
    """Hace avanzar una ejecución `corriendo` hasta que termina, falla o se pausa. No lanza."""
    while True:
        if e.iteraciones >= MAX_ITERACIONES:
            return _terminar(e, deps, "fallida", f"Se superó el máximo de {MAX_ITERACIONES} pasos.")
        try:
            restante = deps.presupuesto_restante()
        except Exception:  # noqa: BLE001 - falla cerrado
            return _terminar(
                e, deps, "fallida", "No se pudo comprobar el gasto del día; por seguridad no se sigue gastando."
            )
        if restante <= 0:
            return _terminar(e, deps, "fallida", "Se alcanzó el tope de gasto de hoy. Mañana vuelve a estar disponible.")

        try:
            msg = deps.llamar_modelo(e.mensajes)
        except Exception as error:  # noqa: BLE001
            return _terminar(e, deps, "fallida", f"La API de Claude falló: {error}")
        e.iteraciones += 1
        uso = uso_de_api(msg.get("usage"))
        e.uso = sumar(e.uso, uso)
        e.costo_usd += costo_usd(uso, msg.get("model") or "")
        contenido = list(msg.get("content") or [])
        e.mensajes.append({"role": "assistant", "content": contenido})

        textos = [b["text"].strip() for b in contenido if b.get("type") == "text" and (b.get("text") or "").strip()]
        for t in textos:
            deps.emitir({"tipo": "texto", "texto": t})

        motivo = msg.get("stop_reason")
        if motivo in ("end_turn", "stop_sequence"):
            e.respuesta = "\n\n".join(textos) or None
            return _terminar(e, deps, "terminada", None)
        if motivo == "pause_turn":
            deps.guardar(e)
            continue
        if motivo == "refusal":
            return _terminar(e, deps, "fallida", "El modelo declinó continuar.")
        if motivo == "max_tokens":
            return _terminar(e, deps, "fallida", "La respuesta del modelo se cortó por longitud.")
        if motivo != "tool_use":
            return _terminar(e, deps, "fallida", f"El modelo se detuvo de forma inesperada ({motivo}).")

        usos = [b for b in contenido if b.get("type") == "tool_use"]
        if not usos:
            return _terminar(e, deps, "fallida", "El modelo pidió herramientas sin nombrar ninguna.")

        aprobacion = set(deps.herramientas_aprobacion)
        resultados: list[dict[str, Any]] = []
        propuesta: Propuesta | None = None
        for uso_h in usos:
            nombre, entrada, uid = uso_h.get("name", ""), uso_h.get("input"), uso_h.get("id", "")
            invalida = deps.validar(nombre, entrada)
            if invalida:
                resultados.append(_a_resultado(uid, fallo(invalida)))
                continue
            if nombre in aprobacion:
                if propuesta is not None:
                    resultados.append(_a_resultado(uid, fallo("Propón un cambio a la vez y espera la decisión.")))
                    continue
                try:
                    preparada = deps.preparar_propuesta(nombre, entrada)
                except Exception as error:  # noqa: BLE001
                    preparada = Preparada(False, error=f"No se pudo preparar la propuesta: {error}")
                if not preparada.ok:
                    resultados.append(_a_resultado(uid, fallo(preparada.error or "No se pudo preparar.")))
                    continue
                propuesta = Propuesta(
                    tool_use_id=uid,
                    herramienta=nombre,
                    origen=preparada.origen,
                    motivo=preparada.motivo,
                    vista=preparada.vista,
                    entrada=entrada,
                    resultados_previos=[],
                    orden=[u.get("id", "") for u in usos],
                )
                continue
            deps.emitir({"tipo": "paso", "id": uid, "herramienta": nombre})
            r = deps.ejecutar(nombre, entrada, uid)
            if r.ok:
                e.vistos.append(json.dumps(r.datos, ensure_ascii=False, default=str))
            resultados.append(_a_resultado(uid, r))

        if propuesta is not None:
            propuesta.resultados_previos = resultados
            e.propuesta = propuesta
            e.estado = "esperando_aprobacion"
            deps.guardar(e)
            deps.emitir(
                {
                    "tipo": "aprobacion",
                    "origen": propuesta.origen,
                    "motivo": propuesta.motivo,
                    "herramienta": propuesta.herramienta,
                    "vista": propuesta.vista,
                }
            )
            return e

        e.mensajes.append({"role": "user", "content": _en_orden([u.get("id", "") for u in usos], resultados)})
        deps.guardar(e)


def decidir(e: Ejecucion, aprobado: bool, deps: Dependencias, comentario: str | None = None) -> Ejecucion:
    """Aplica la decisión sobre la propuesta pendiente y retoma.

    Quien llama debe haber reclamado la conversación de forma atómica (dos clics no la
    deciden dos veces) y comprobado el rol ACTUAL de quien decide. `comentario` = la
    persona escribió otra cosa con la tarjeta abierta.
    """
    p = e.propuesta
    if p is None:
        raise ValueError("La conversación no tiene ninguna propuesta pendiente.")
    if aprobado:
        r = deps.ejecutar(p.herramienta, p.entrada, p.tool_use_id)
        if r.ok:
            e.vistos.append(json.dumps(r.datos, ensure_ascii=False, default=str))
        resultado = _a_resultado(p.tool_use_id, r)
    else:
        resultado = _a_resultado(p.tool_use_id, fallo(deps.rechazo(comentario)))
    deps.emitir({"tipo": "decision", "origen": p.origen, "aprobado": aprobado, "herramienta": p.herramienta})
    e.mensajes.append({"role": "user", "content": _en_orden(p.orden, [*p.resultados_previos, resultado])})
    e.propuesta = None
    e.estado = "corriendo"
    deps.guardar(e)
    return avanzar(e, deps)
