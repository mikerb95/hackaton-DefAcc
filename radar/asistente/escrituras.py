"""Escrituras que el asistente puede PROPONER. Ninguna se ejecuta sola.

Cada una tiene dos pasos:

- `preparar`: lee la base, valida existencia, estado y permiso, y arma la tarjeta de antes y
  después. No escribe nada. La tarjeta la arma el servidor, nunca el modelo: se aprueba lo
  que dice la base, no lo que el modelo cree.
- `ejecutar`: solo tras "Aprobar". Vuelve a preparar (la base pudo cambiar desde que se
  propuso, quizá hace horas) y entonces escribe con las mismas funciones que usa el panel.

Fuera de alcance siempre: borrar, revocar o retirar equipos, planes de parcheo, usuarios,
tokens, claves, modelo, inventarios y secretos.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from radar.asistente.bucle import Preparada, Resultado, exito, fallo
from radar.asistente.contexto import Contexto

ETIQUETA_ESTADO = {
    "nuevo": "Nuevo",
    "en_curso": "En curso",
    "mitigado": "Mitigado",
    "descartado": "Descartado",
}


class _Entrada(BaseModel):
    model_config = ConfigDict(extra="forbid")


@dataclass(frozen=True)
class Escritura:
    nombre: str
    descripcion: str
    entrada: type[_Entrada]
    roles: tuple[str, ...]  # quién puede PROPONERLA y APROBARLA
    preparar: Callable[[Any, Contexto], Preparada]
    escribir: Callable[[Any, Contexto], Any]


def vista_cambio(
    rotulo: str,
    titulo: str,
    contexto: str | None,
    cambios: list[tuple[str, str | None, str | None]],
    avisos: list[str],
    boton: str,
    nota: str = "Al aprobar se vuelve a revisar la base antes de guardar.",
) -> dict[str, Any]:
    return {
        "tipo": "cambio",
        "rotulo": rotulo,
        "titulo": titulo,
        "contexto": contexto,
        "cambios": [{"campo": c, "antes": a, "despues": d} for c, a, d in cambios if a != d],
        "avisos": avisos,
        "boton": boton,
        "nota": nota,
    }


def _datos():
    from radar.api.datos import obtener_datos

    return obtener_datos()


# ---------------------------------------------------------------------------
# Estado de un hallazgo
# ---------------------------------------------------------------------------


class EntradaEstado(_Entrada):
    id_hallazgo: str = Field(
        min_length=3, max_length=300, description="Id del hallazgo ('CVE|producto@versión'), sale de buscar_hallazgos."
    )
    estado: Literal["nuevo", "en_curso", "mitigado", "descartado"]
    comentario: str | None = Field(
        default=None, max_length=300, description="Solo si la persona lo dijo. No lo inventes."
    )


def _preparar_estado(e: EntradaEstado, _ctx: Contexto) -> Preparada:
    actual = next((h for h in _datos().hallazgos() if h.id == e.id_hallazgo), None)
    if actual is None:
        return Preparada(False, error="Ese hallazgo no existe. Búscalo con buscar_hallazgos.")
    if actual.estado == e.estado and (e.comentario or None) == (actual.comentario or None):
        return Preparada(False, error=f"El hallazgo ya está en {ETIQUETA_ESTADO[e.estado]}.")
    cambios = [("Estado", ETIQUETA_ESTADO[actual.estado], ETIQUETA_ESTADO[e.estado])]
    if e.comentario is not None:
        cambios.append(("Comentario", actual.comentario, e.comentario))
    return Preparada(
        True,
        origen=f"Estado de {actual.cve} en {actual.producto}",
        motivo=f"Pasar a {ETIQUETA_ESTADO[e.estado]}",
        vista=vista_cambio(
            "Hallazgo",
            f"{actual.cve} · {actual.producto} {actual.version_instalada}",
            f"Prioridad {actual.prioridad}" + (", en KEV" if actual.kev else "") + f", {len(actual.equipos)} equipo(s)",
            cambios,
            [],
            "Aprobar y guardar",
        ),
    )


def _escribir_estado(e: EntradaEstado, ctx: Contexto) -> Any:
    nuevo = _datos().cambiar_estado(e.id_hallazgo, e.estado, e.comentario, ctx.nombre)
    if nuevo is None:
        return fallo("El hallazgo ya no existe.")
    return {
        "hecho": True,
        "resumen": f"{nuevo.cve} en {nuevo.producto} quedó en {ETIQUETA_ESTADO[nuevo.estado]}.",
        "enlace": "/panel/#hallazgos",
    }


# ---------------------------------------------------------------------------
# Aprobar comunicado
# ---------------------------------------------------------------------------


class EntradaComunicado(_Entrada):
    producto: str = Field(
        min_length=1, max_length=200, description="Nombre exacto del producto, sale de productos_expuestos."
    )


def _preparar_comunicado(e: EntradaComunicado, ctx: Contexto) -> Preparada:
    datos = _datos()
    grupo = datos.grupo(e.producto)
    if grupo is None:
        return Preparada(False, error="Ese producto no tiene hallazgos. Búscalo con productos_expuestos.")
    aprobado = datos.aprobacion(e.producto)
    if aprobado:
        return Preparada(False, error=f"El comunicado de {e.producto} ya está aprobado por {aprobado.get('por')}.")
    analisis = datos.analisis(e.producto)
    origen = (
        "texto del agente" if analisis and analisis.origen == "agente" else "texto armado por código (respaldo)"
    )
    return Preparada(
        True,
        origen=f"Comunicado de {e.producto}",
        motivo="Aprobar el comunicado",
        vista=vista_cambio(
            "Comunicado",
            e.producto,
            f"Prioridad {grupo.prioridad}, {len(grupo.equipos)} equipo(s), {origen}",
            [("Comunicado", "Sin aprobar", f"Aprobado por {ctx.nombre}")],
            ["El comunicado queda listo para enviarse. El envío sigue siendo manual, desde la sección Hallazgos."],
            "Aprobar comunicado",
            "Se aprueba el texto que se ve hoy en el detalle del producto.",
        ),
    )


def _escribir_comunicado(e: EntradaComunicado, ctx: Contexto) -> Any:
    registro = _datos().aprobar(e.producto, ctx.nombre)
    if registro is None:
        return fallo("No hay comunicado para ese producto.")
    return {"hecho": True, "resumen": f"Comunicado de {e.producto} aprobado.", "enlace": "/panel/#hallazgos"}


# ---------------------------------------------------------------------------
# Aprobar equipo pendiente
# ---------------------------------------------------------------------------


class EntradaEquipo(_Entrada):
    equipo_id: str = Field(
        pattern=r"^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$",
        description="equipo_id del equipo pendiente, sale de la herramienta equipos.",
    )


def _preparar_equipo(e: EntradaEquipo, _ctx: Contexto) -> Preparada:
    if _datos().origen != "base":
        return Preparada(False, error="Los equipos necesitan una base conectada.")
    from radar import bd
    from radar.equipos import almacen

    conexion = bd.conectar(solo_lectura=True)
    try:
        equipo = almacen.leer_equipo(conexion, e.equipo_id)
    finally:
        conexion.close()
    if equipo is None:
        return Preparada(False, error="Ese equipo no existe. Búscalo con la herramienta equipos.")
    if equipo.revocado:
        return Preparada(False, error="Ese equipo está revocado; no se puede aprobar.")
    if not equipo.pendiente:
        return Preparada(False, error="Ese equipo ya está aprobado.")
    return Preparada(
        True,
        origen=f"Equipo {equipo.nombre}",
        motivo="Aprobar el equipo",
        vista=vista_cambio(
            "Equipo",
            equipo.nombre,
            f"Inscrito {equipo.inscrito}" + (f", agente {equipo.agente_version}" if equipo.agente_version else ""),
            [("Estado", "Pendiente de aprobar", "Aprobado")],
            [
                "El equipo empieza a reportar al radar y su inventario entra al cruce.",
                "Comprueba que el código que muestra el equipo coincide con el de la sección Equipos.",
            ],
            "Aprobar equipo",
        ),
    )


def _escribir_equipo(e: EntradaEquipo, ctx: Contexto) -> Any:
    from radar.api.agente import _conexion
    from radar.equipos import recepcion
    from radar.seguridad.limpieza import limpiar_texto

    conexion = _conexion()
    try:
        recibido = recepcion.aprobar(conexion, e.equipo_id, limpiar_texto(ctx.nombre, 100))
    except recepcion.ErrorAprobacion:
        return fallo("El equipo no existe, está revocado o ya estaba aprobado.")
    finally:
        conexion.close()
    return {
        "hecho": True,
        "resumen": "Equipo aprobado" + (" y su último reporte ya se cruzó." if recibido else "; entra con su próximo reporte."),
        "enlace": "/panel/#equipos",
    }


ESCRITURAS: tuple[Escritura, ...] = (
    Escritura(
        "proponer_estado_hallazgo",
        "Propone cambiar el estado de UN hallazgo (nuevo, en_curso, mitigado, descartado) y, si la "
        "persona lo dijo, su comentario. No se ejecuta sola: la persona ve el cambio y decide. "
        "Busca antes el id con buscar_hallazgos.",
        EntradaEstado,
        ("analista", "admin"),
        _preparar_estado,
        _escribir_estado,
    ),
    Escritura(
        "proponer_aprobar_comunicado",
        "Propone aprobar el comunicado ya redactado de un producto. No cambia el texto ni lo envía. "
        "No se ejecuta sola: la persona ve el cambio y decide. Busca antes el producto con "
        "productos_expuestos o detalle_producto.",
        EntradaComunicado,
        ("analista", "admin"),
        _preparar_comunicado,
        _escribir_comunicado,
    ),
    Escritura(
        "proponer_aprobar_equipo",
        "Propone aprobar un equipo que espera aprobación, para que empiece a reportar. No revoca ni "
        "retira equipos. No se ejecuta sola: la persona ve el cambio y decide. Busca antes el "
        "equipo_id con la herramienta equipos (solo_pendientes).",
        EntradaEquipo,
        ("admin",),
        _preparar_equipo,
        _escribir_equipo,
    ),
)

POR_NOMBRE = {e.nombre: e for e in ESCRITURAS}


def preparar(nombre: str, entrada: Any, ctx: Contexto) -> Preparada:
    esc = POR_NOMBRE.get(nombre)
    if esc is None:
        return Preparada(False, error=f"Acción desconocida: {nombre}.")
    if ctx.rol not in esc.roles:
        return Preparada(False, error="Tu rol no permite proponer esa acción.")
    return esc.preparar(esc.entrada.model_validate(entrada or {}), ctx)


def ejecutar(nombre: str, entrada: Any, ctx: Contexto) -> Resultado:
    """Solo tras aprobar. `ctx` es el de quien hizo clic, con su rol ACTUAL. Nunca lanza."""
    esc = POR_NOMBRE.get(nombre)
    if esc is None:
        return fallo(f"Acción desconocida: {nombre}.")
    if ctx.rol not in esc.roles:
        return fallo("El rol de quien aprobó no permite esta acción.")
    try:
        valida = esc.entrada.model_validate(entrada or {})
        preparada = esc.preparar(valida, ctx)
        if not preparada.ok:
            return fallo(f"Ya no se puede aplicar: {preparada.error}")
        datos = esc.escribir(valida, ctx)
    except Exception as error:  # noqa: BLE001
        return fallo(f"No se pudo guardar ({type(error).__name__}).")
    return datos if isinstance(datos, Resultado) else exito(datos)
