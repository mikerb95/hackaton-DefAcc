"""Resultado del parcheo que envía el agente y el informe de remediación (docs/plan-parcheo.md).

El resultado es texto no confiable como todo lo que viene del equipo: cada cadena se limpia y
se recorta al validar, y las listas tienen tope. El informe junta el plan firmado, lo que el
agente dice que pasó y lo que el radar ve después en el cruce, que es la verificación
independiente: una acción solo cuenta como confirmada si el inventario nuevo del equipo ya no
tiene sus CVE abiertas (o la regla de postura ya está en "sí").
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from radar import bd
from radar.equipos import almacen
from radar.equipos import parcheo_almacen as tablas
from radar.seguridad import plan_parcheo as catalogo
from radar.seguridad.limpieza import limpiar_texto

TAMANO_MAXIMO_RESULTADO = 512 * 1024
LARGO_SALIDA = 2_000

EstadoAccion = Literal[
    "aplicado",
    "ya_al_dia",
    "revertido",
    "sin_cambios",
    "omitido",
    "fallido_sin_revertir",
    "interrumpido",
    "rechazado",
]
EstadoResultado = Literal["ejecutado", "rechazado", "interrumpido"]

# Qué significa cada estado para quien lee el informe.
ETIQUETAS = {
    "aplicado": "Aplicado y verificado en el equipo",
    "ya_al_dia": "Ya estaba al día",
    "revertido": "Falló y se revirtió al estado anterior",
    "sin_cambios": "Falló sin cambiar nada",
    "omitido": "Omitido por una condición de seguridad",
    "fallido_sin_revertir": "Falló y no se pudo revertir: requiere intervención",
    "interrumpido": "Interrumpido: requiere revisión",
    "rechazado": "Rechazado por el agente",
}
ATENCION = {"fallido_sin_revertir", "interrumpido"}
NO_LOGRADO = {"revertido", "sin_cambios", "omitido", "rechazado"}


def _corto(valor: Any) -> Any:
    return limpiar_texto(valor, 160) if isinstance(valor, str) else valor


def _largo(valor: Any) -> Any:
    return limpiar_texto(valor, 500) if isinstance(valor, str) else valor


def _salida(valor: Any) -> Any:
    return limpiar_texto(valor, LARGO_SALIDA) if isinstance(valor, str) else valor


def _estado_medido(valor: Any) -> dict[str, str | None]:
    """Mapa pequeño de lo medido (versión, estado del firewall...): claves y valores cortos."""
    if not isinstance(valor, dict):
        return {}
    limpio: dict[str, str | None] = {}
    for clave, dato in list(valor.items())[:20]:
        nombre = limpiar_texto(clave, 40)
        if nombre:
            limpio[nombre] = None if dato is None else limpiar_texto(dato, 160)
    return limpio


Corto = Annotated[str, BeforeValidator(_corto)]
Largo = Annotated[str, BeforeValidator(_largo)]
Medido = Annotated[dict[str, str | None], BeforeValidator(_estado_medido)]


class Paso(BaseModel):
    model_config = ConfigDict(extra="ignore")

    orden: list[Corto] = Field(default_factory=list)
    codigo: int | None = None
    salida: Annotated[str, BeforeValidator(_salida)] = ""
    duracion: float | None = Field(default=None, ge=0, le=86_400)

    @field_validator("orden", mode="before")
    @classmethod
    def _tope(cls, valor: Any) -> Any:
        return valor[:30] if isinstance(valor, list) else []


class ResultadoAccion(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: str = Field(pattern=catalogo.ID_ACCION.pattern)
    estado: EstadoAccion
    motivo: Largo = ""
    antes: Medido = Field(default_factory=dict)
    despues: Medido = Field(default_factory=dict)
    reversible: bool | None = None
    reinicio_pendiente: bool = False
    cumple_minimo: bool | None = None
    inicio: datetime | None = None
    fin: datetime | None = None
    pasos: list[Paso] = Field(default_factory=list)

    @field_validator("pasos", mode="before")
    @classmethod
    def _tope(cls, valor: Any) -> Any:
        return valor[:25] if isinstance(valor, list) else []


class PuntoRestauracion(BaseModel):
    model_config = ConfigDict(extra="ignore")

    creado: bool | None = None
    detalle: Largo = ""


class ResultadoPlan(BaseModel):
    model_config = ConfigDict(extra="ignore")

    plan_id: str = Field(pattern=catalogo.UUID.pattern)
    equipo_id: str = Field(pattern=catalogo.UUID.pattern)
    agente_version: Corto = ""
    estado: EstadoResultado
    motivo: Largo = ""
    huella_plan: str = Field(pattern=r"^[0-9a-f]{64}$")
    inicio: datetime | None = None
    fin: datetime | None = None
    punto_restauracion: PuntoRestauracion | None = None
    reinicio_pendiente: bool = False
    acciones: list[ResultadoAccion] = Field(default_factory=list, max_length=catalogo.MAX_ACCIONES)


class ErrorResultado(ValueError):
    def __init__(self, mensaje: str, codigo: int = 400):
        super().__init__(mensaje)
        self.codigo = codigo


def recibir_resultado(conexion: Any, equipo: almacen.Equipo, cuerpo: bytes) -> dict[str, Any]:
    """Valida y guarda el resultado de un plan. Una sola vez por plan."""
    if len(cuerpo) > TAMANO_MAXIMO_RESULTADO:
        raise ErrorResultado("Resultado muy grande.", 413)
    try:
        datos = ResultadoPlan.model_validate_json(cuerpo)
    except ValueError as error:
        raise ErrorResultado("Resultado mal formado.", 422) from error
    if datos.equipo_id != equipo.id:
        raise ErrorResultado("El resultado es de otro equipo.", 403)
    plan = tablas.leer_plan(conexion, datos.plan_id)
    if plan is None or plan["equipo_id"] != equipo.id:
        raise ErrorResultado("Plan desconocido para este equipo.", 404)
    esperada = catalogo.huella_plan(plan["canonico"].encode("ascii"))
    if datos.huella_plan != esperada:
        raise ErrorResultado("La huella del plan no coincide con el plan firmado.", 409)
    ids_plan = {a["id"] for a in plan["plan"]["acciones"]}
    if any(a.id not in ids_plan for a in datos.acciones):
        raise ErrorResultado("El resultado trae acciones que no están en el plan.", 422)
    if len({a.id for a in datos.acciones}) != len(datos.acciones):
        raise ErrorResultado("Acciones repetidas en el resultado.", 422)
    estado = tablas.RECHAZADO if datos.estado == "rechazado" else tablas.EJECUTADO
    guardado = tablas.guardar_resultado(
        conexion, datos.plan_id, estado, datos.model_dump(mode="json"), bd.ahora()
    )
    if not guardado:
        raise ErrorResultado("Ese plan ya tiene resultado.", 409)
    return {"recibido": True, "plan_id": datos.plan_id}


# ---------------------------------------------------------------------------
# Informe
# ---------------------------------------------------------------------------


def _cves_abiertas(conexion: Any, equipo: almacen.Equipo) -> set[str]:
    from radar.equipos.vista import _abiertos_del_equipo

    abiertas = {h.cve for h in _abiertos_del_equipo(bd.leer_hallazgos(conexion), equipo.nombre)}
    for h in almacen.leer_hallazgos(conexion, equipo.id):
        abiertas.update((h.detalle or {}).get("cves") or [])
    return abiertas


def _momento(texto: str | None) -> datetime | None:
    if not texto:
        return None
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        return None


def estado_general(plan: dict[str, Any]) -> str:
    """exito, parcial, requiere_atencion, rechazado, pendiente o cancelado."""
    if plan["estado"] == tablas.CANCELADO:
        return "cancelado"
    resultado = plan.get("resultado")
    if not resultado:
        return "pendiente"
    if resultado["estado"] == "rechazado":
        return "rechazado"
    estados = {a["estado"] for a in resultado["acciones"]}
    ids_plan = {a["id"] for a in plan["plan"]["acciones"]}
    faltan = ids_plan - {a["id"] for a in resultado["acciones"]}
    if estados & ATENCION or resultado["estado"] == "interrumpido":
        return "requiere_atencion"
    if estados & NO_LOGRADO or faltan:
        return "parcial"
    return "exito"


def _verificacion(
    accion: dict[str, Any],
    resultado_accion: dict[str, Any] | None,
    abiertas: set[str],
    postura: dict[str, Any] | None,
    verificable: bool,
) -> dict[str, Any]:
    """Lo que dice el radar de la acción con el último inventario del equipo."""
    if not verificable:
        return {"estado": "pendiente", "texto": "Esperando el inventario posterior del equipo."}
    if accion["tipo"] == "postura":
        valor = (postura or {}).get(accion["regla"])
        if valor == "si":
            return {"estado": "confirmada", "texto": "El último reporte la muestra activa."}
        return {"estado": "sin_confirmar", "texto": f"El último reporte dice: {valor or 'sin dato'}."}
    cves = accion.get("cves") or []
    if not cves:
        return {"estado": "no_aplica", "texto": "La acción no tiene CVE asociadas."}
    siguen = sorted(set(cves) & abiertas)
    if not siguen:
        return {
            "estado": "confirmada",
            "texto": f"Las {len(cves)} CVE ya no aparecen en el cruce.",
            "cerradas": len(cves),
            "siguen": [],
        }
    texto = f"{len(cves) - len(siguen)} de {len(cves)} CVE cerradas."
    if resultado_accion and resultado_accion.get("reinicio_pendiente"):
        texto += " Falta reiniciar para que el cambio tome efecto."
    return {
        "estado": "parcial" if len(siguen) < len(cves) else "sin_confirmar",
        "texto": texto,
        "cerradas": len(cves) - len(siguen),
        "siguen": siguen[:20],
    }


def informe(conexion: Any, plan_id: str) -> dict[str, Any] | None:
    """Todo lo que muestra el informe de remediación de un plan. None si no existe."""
    from radar.equipos import parcheo, vista

    plan = tablas.leer_plan(conexion, plan_id)
    if plan is None:
        return None
    equipo = almacen.leer_equipo(conexion, plan["equipo_id"])
    resultado = plan.get("resultado")
    por_id = {a["id"]: a for a in (resultado or {}).get("acciones", [])}
    fin = _momento((resultado or {}).get("fin"))
    ultimo = _momento(equipo.ultimo_reporte) if equipo else None
    verificable = bool(resultado and fin and ultimo and ultimo > fin)
    abiertas = _cves_abiertas(conexion, equipo) if equipo else set()
    postura = equipo.postura.model_dump() if equipo and equipo.postura else None

    acciones = []
    for accion in plan["plan"]["acciones"]:
        propio = por_id.get(accion["id"])
        acciones.append(
            {
                "plan": accion,
                "resultado": propio,
                "etiqueta": ETIQUETAS.get(propio["estado"], "") if propio else "Sin resultado",
                "verificacion": _verificacion(accion, propio, abiertas, postura, verificable)
                if propio and propio["estado"] in ("aplicado", "ya_al_dia")
                else None,
            }
        )

    cves_plan = sorted({c for a in plan["plan"]["acciones"] for c in a.get("cves", [])})
    kev_plan = sorted({c for a in plan["plan"]["acciones"] for c in a.get("en_kev", [])})
    ahora = vista.detalle(conexion, equipo.id)["equipo"] if equipo else {}
    conteo = Counter(a["estado"] for a in (resultado or {}).get("acciones", []))
    clave = tablas.clave(conexion, plan["clave"])
    datos_propuesta = parcheo.propuesta(conexion, equipo.id) if equipo else None

    return {
        "plan_id": plan["id"],
        "estado_plan": plan["estado"],
        "estado_general": estado_general(plan),
        "equipo": {
            "id": plan["equipo_id"],
            "nombre": equipo.nombre if equipo else "(retirado)",
            "so": equipo.so.model_dump() if equipo and equipo.so else None,
            "plataforma": plan["plan"]["plataforma"],
            "ultimo_reporte": equipo.ultimo_reporte if equipo else None,
        },
        "aprobacion": {
            "por": plan["aprobado_por"],
            "creado": plan["creado"],
            "emitido": plan["plan"]["emitido"],
            "vence": plan["vence"],
            "clave": plan["clave"],
            "clave_nombre": clave["nombre"] if clave else None,
            "huella_plan": hashlib.sha256(plan["canonico"].encode("ascii")).hexdigest(),
            "huella_firma": hashlib.sha256(plan["firma"].encode("ascii")).hexdigest()[:16],
            "cancelado_por": plan.get("cancelado_por"),
        },
        "entrega": {
            "entregado": plan.get("entregado"),
            "entregas": plan.get("entregas") or 0,
            "recibido": plan.get("recibido"),
        },
        "ejecucion": None
        if not resultado
        else {
            "estado": resultado["estado"],
            "motivo": resultado.get("motivo"),
            "inicio": resultado.get("inicio"),
            "fin": resultado.get("fin"),
            "agente_version": resultado.get("agente_version"),
            "punto_restauracion": resultado.get("punto_restauracion"),
            "reinicio_pendiente": resultado.get("reinicio_pendiente")
            or any(a.get("reinicio_pendiente") for a in resultado["acciones"]),
        },
        "conteo": {estado: conteo.get(estado, 0) for estado in ETIQUETAS},
        "verificado_por_radar": verificable,
        "exposicion": {
            "antes": plan.get("antes"),
            "ahora": {
                "acciones_abiertas": ahora.get("acciones"),
                "peor_prioridad": ahora.get("peor_prioridad"),
                "postura": ahora.get("postura"),
                "ultimo_reporte": ahora.get("ultimo_reporte"),
            },
            "cves_en_plan": len(cves_plan),
            "kev_en_plan": len(kev_plan),
            "cves_siguen": sorted(set(cves_plan) & abiertas) if verificable else None,
            "kev_siguen": sorted(set(kev_plan) & abiertas) if verificable else None,
        },
        "acciones": acciones,
        "manuales": (datos_propuesta or {}).get("manuales", []),
        "etiquetas": ETIQUETAS,
    }


def resumen_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Fila del historial de planes de un equipo."""
    resultado = plan.get("resultado") or {}
    return {
        "plan_id": plan["id"],
        "estado": plan["estado"],
        "estado_general": estado_general(plan),
        "creado": plan["creado"],
        "aprobado_por": plan["aprobado_por"],
        "vence": plan["vence"],
        "entregas": plan.get("entregas") or 0,
        "recibido": plan.get("recibido"),
        "n_acciones": len(plan["plan"]["acciones"]),
        "conteo": dict(Counter(a["estado"] for a in resultado.get("acciones", []))),
        "reinicio_pendiente": bool(resultado.get("reinicio_pendiente")),
    }


def a_json(datos: Any) -> str:
    return json.dumps(datos, ensure_ascii=False)
