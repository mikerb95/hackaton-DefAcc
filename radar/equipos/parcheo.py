"""Planes de parcheo del lado servidor (docs/plan-parcheo.md).

1. `propuesta`: qué se puede parchear en un equipo, armado por código desde los mismos
   hallazgos que ve el panel. Cada acción automatizable sale del catálogo cerrado de
   `radar/seguridad/plan_parcheo.py`; lo que no se puede automatizar va a `manuales` con el
   motivo.
2. `borrador`: el plan canónico con las acciones que el admin marcó. El navegador firma esos
   bytes exactos con la clave del aprobador (Ed25519), que nunca llega al servidor.
3. `registrar`: comprueba la firma con las claves registradas, que las acciones sigan siendo
   las de la propuesta y que el equipo esté aprobado, y guarda el plan con la foto del
   "antes" para el reporte.

El agente vuelve a verificar todo con su propia clave fijada: el servidor no es quien decide.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from radar import bd
from radar.contratos import ORDEN_PRIORIDAD, Grupo, Hallazgo
from radar.equipos import almacen, remediacion
from radar.equipos import parcheo_almacen as tablas
from radar.equipos.almacen import Equipo
from radar.fuentes.nvd import normalizar_par
from radar.nucleo.agrupar import agrupar
from radar.seguridad import ed25519
from radar.seguridad import plan_parcheo as catalogo
from radar.seguridad.limpieza import limpiar_texto

MINUTOS_BORRADOR = 30  # un borrador firmado más tarde ya no se acepta
_PAR_WINDOWS = re.compile(r"^microsoft:windows_")

TITULOS_POSTURA = {
    "firewall": "Activar el firewall",
    "antivirus": "Activar la protección antivirus en tiempo real",
    "firmas_al_dia": "Actualizar las firmas del antivirus",
    "actualizaciones_automaticas": "Activar las actualizaciones automáticas de seguridad",
}
_EJECUTOR_POSTURA = {
    "windows": "postura_windows",
    "debian": "postura_debian",
    "rhel": "postura_rhel",
}


class ErrorPlan(ValueError):
    """El plan no se puede registrar. El mensaje es apto para mostrar."""

    def __init__(self, mensaje: str, codigo: int = 409):
        super().__init__(mensaje)
        self.codigo = codigo


# ---------------------------------------------------------------------------
# Propuesta
# ---------------------------------------------------------------------------


def plataforma_de(equipo: Equipo) -> str | None:
    if equipo.so is None:
        return None
    if equipo.so.familia == "windows":
        return "windows"
    return remediacion.distro_a_plataforma(equipo.so.distro)


def _abiertos(conexion: Any, equipo: Equipo) -> list[Hallazgo]:
    from radar.equipos.vista import _abiertos_del_equipo

    return _abiertos_del_equipo(bd.leer_hallazgos(conexion), equipo.nombre)


def _cves(grupo_o_lista: Any) -> tuple[list[str], list[str]]:
    cves = sorted(set(grupo_o_lista.cves))[: catalogo.MAX_CVES_ACCION]
    kev = sorted(set(grupo_o_lista.en_kev) & set(cves))
    return cves, kev


def _programa_registrado(conexion: Any, equipo: Equipo, producto: str, version: str) -> str:
    """El nombre tal como lo reportó el equipo (DisplayName), para que el agente encuentre la
    entrada del registro al verificar. Si no aparece, el nombre del producto."""
    filas = conexion.execute(
        "SELECT programa, version FROM inventario WHERE equipo = ? ORDER BY programa",
        [equipo.nombre],
    ).fetchall()
    clave = producto.lower().split()[0] if producto.strip() else ""
    candidatos = [p for p, v in filas if (v or "") == version and clave and clave in p.lower()]
    nombre = candidatos[0] if candidatos else producto
    return limpiar_texto(nombre, 160) or producto[:160]


def _accion_winget(
    conexion: Any, equipo: Equipo, grupo: Grupo, propios: list[Hallazgo]
) -> dict[str, Any] | None:
    pares = remediacion.pares_de_hallazgos(propios)
    paquete = remediacion.id_winget(pares)
    if paquete is None or paquete not in catalogo.WINGET_PERMITIDOS:
        return None
    version_actual = min(grupo.versiones) if grupo.versiones else None
    if version_actual and not catalogo.VERSION.match(version_actual):
        version_actual = None
    minimo = grupo.version_objetivo if grupo.tipo_objetivo in ("exacta", "posterior_a") else None
    if minimo and not catalogo.VERSION.match(minimo):
        minimo = None
    estricto = bool(minimo) and grupo.tipo_objetivo == "posterior_a"
    # Regla 5: con versionEndIncluding X no se dice "actualizar a X".
    if minimo and estricto:
        destino = f"a una versión posterior a {minimo}"
    elif minimo:
        destino = f"a {minimo} o posterior"
    else:
        destino = "a la última versión del catálogo de winget"
    cves, kev = _cves(grupo)
    return {
        "id": f"app:{paquete}",
        "tipo": "aplicacion",
        "ejecutor": "winget",
        "titulo": limpiar_texto(f"Actualizar {grupo.producto} {destino}", 200),
        "cves": cves,
        "en_kev": kev,
        "prioridad": grupo.prioridad,
        "paquete": paquete,
        "programa": _programa_registrado(conexion, equipo, grupo.producto, version_actual or ""),
        "version_actual": version_actual,
        "minimo": minimo,
        "estricto": estricto,
    }


def _es_windows(propios: list[Hallazgo]) -> bool:
    return any(
        h.rango is not None and _PAR_WINDOWS.match(normalizar_par(h.rango.par)) for h in propios
    )


def _accion_windows_update(grupos_so: list[Grupo]) -> dict[str, Any]:
    cves = sorted({c for g in grupos_so for c in g.cves})[: catalogo.MAX_CVES_ACCION]
    kev = sorted({c for g in grupos_so for c in g.en_kev} & set(cves))
    prioridad = min(
        (g.prioridad for g in grupos_so if g.prioridad),
        key=ORDEN_PRIORIDAD.__getitem__,
        default=None,
    )
    return {
        "id": "so:windows_update",
        "tipo": "so",
        "ejecutor": "windows_update",
        "titulo": "Instalar las actualizaciones de seguridad y críticas de Windows Update",
        "cves": cves,
        "en_kev": kev,
        "prioridad": prioridad,
        "categorias": ["criticas", "seguridad"],
    }


def _accion_paquete(plataforma: str, hallazgo: Any) -> dict[str, Any] | None:
    detalle = hallazgo.detalle or {}
    arreglo = detalle.get("version_arreglo")
    if not arreglo:
        return None
    patron = catalogo.PAQUETE_DEB if plataforma == "debian" else catalogo.PAQUETE_RPM
    binarios = sorted({b for b in detalle.get("binarios") or [] if patron.match(b)})
    binarios = binarios[: catalogo.MAX_PAQUETES]
    if not binarios or not catalogo.VERSION_PAQUETE.match(arreglo):
        return None
    cves = list(detalle.get("cves") or [])[: catalogo.MAX_CVES_ACCION]
    cves = [c for c in cves if catalogo.CVE.match(c)]
    kev = sorted(set(detalle.get("en_kev") or []) & set(cves))
    return {
        "id": f"pkg:{hallazgo.clave}"[:110],
        "tipo": "paquetes",
        "ejecutor": "apt" if plataforma == "debian" else "dnf",
        "titulo": limpiar_texto(
            f"Actualizar {hallazgo.clave} a {arreglo} o posterior ({len(binarios)} paquetes)",
            200,
        ),
        "cves": cves,
        "en_kev": kev,
        "prioridad": hallazgo.prioridad,
        "paquetes": binarios,
        "minimos": {b: arreglo for b in binarios},
    }


def _accion_postura(plataforma: str, hallazgo: Any) -> dict[str, Any] | None:
    regla = hallazgo.clave
    if regla not in catalogo.POSTURA_AUTOMATICA.get(plataforma, ()):
        return None
    return {
        "id": f"postura:{regla}",
        "tipo": "postura",
        "ejecutor": _EJECUTOR_POSTURA[plataforma],
        "titulo": TITULOS_POSTURA.get(regla, regla),
        "cves": [],
        "en_kev": [],
        "prioridad": hallazgo.prioridad,
        "regla": regla,
    }


def _manual(titulo: str, motivo: str, prioridad: str | None, cves: int = 0) -> dict[str, Any]:
    return {"titulo": titulo, "motivo": motivo, "prioridad": prioridad, "n_cves": cves}


def propuesta(conexion: Any, equipo_id: str) -> dict[str, Any] | None:
    """Acciones de parcheo posibles para un equipo, del catálogo cerrado. None si no existe."""
    equipo = almacen.leer_equipo(conexion, equipo_id)
    if equipo is None:
        return None
    plataforma = plataforma_de(equipo)
    datos: dict[str, Any] = {
        "equipo_id": equipo.id,
        "nombre": equipo.nombre,
        "plataforma": plataforma,
        "acciones": [],
        "manuales": [],
        "motivo": None,
    }
    if equipo.revocado:
        datos["motivo"] = "El equipo está revocado."
        return datos
    if equipo.pendiente:
        datos["motivo"] = "El equipo está pendiente de aprobación."
        return datos
    if plataforma is None:
        datos["motivo"] = "Sistema operativo sin gestor de parches conocido."
        return datos

    acciones: list[dict[str, Any]] = []
    manuales: list[dict[str, Any]] = []
    abiertos = _abiertos(conexion, equipo)
    grupos_so: list[Grupo] = []
    for grupo in agrupar(abiertos):
        propios = [h for h in abiertos if h.producto == grupo.producto]
        if _es_windows(propios):
            grupos_so.append(grupo)
            continue
        accion = (
            _accion_winget(conexion, equipo, grupo, propios) if plataforma == "windows" else None
        )
        if accion:
            acciones.append(accion)
        else:
            manuales.append(
                _manual(
                    f"Actualizar {grupo.producto}",
                    "Sin paquete en el catálogo del agente: se actualiza desde el sitio del "
                    "fabricante.",
                    grupo.prioridad,
                    grupo.n_cves,
                )
            )
    if grupos_so and plataforma == "windows":
        acciones.append(_accion_windows_update(grupos_so))

    for hallazgo in almacen.leer_hallazgos(conexion, equipo.id):
        if hallazgo.tipo == "paquete":
            accion = _accion_paquete(plataforma, hallazgo)
            if accion:
                acciones.append(accion)
            else:
                manuales.append(
                    _manual(
                        hallazgo.titulo,
                        "La distribución todavía no publica un arreglo para este paquete.",
                        hallazgo.prioridad,
                        (hallazgo.detalle or {}).get("n_cves", 0),
                    )
                )
        elif hallazgo.tipo == "postura":
            accion = _accion_postura(plataforma, hallazgo)
            if accion:
                acciones.append(accion)
            else:
                manuales.append(
                    _manual(
                        hallazgo.titulo,
                        "No se automatiza: no se puede hacer ni deshacer sin riesgo desde el "
                        "agente.",
                        hallazgo.prioridad,
                    )
                )
        else:
            manuales.append(_manual(hallazgo.titulo, hallazgo.pasos, hallazgo.prioridad))

    # Cada acción debe pasar el mismo catálogo que va a aplicar el agente.
    validas = [a for a in acciones if catalogo.validar_accion(a, plataforma) is None]
    datos["acciones"] = sorted(
        validas,
        key=lambda a: (
            catalogo.TIPOS.index(a["tipo"]),
            ORDEN_PRIORIDAD.get(a["prioridad"] or "", 9),
            a["id"],
        ),
    )
    datos["manuales"] = sorted(manuales, key=lambda m: ORDEN_PRIORIDAD.get(m["prioridad"] or "", 9))
    return datos


# ---------------------------------------------------------------------------
# Borrador y registro
# ---------------------------------------------------------------------------


def borrador(
    datos_propuesta: dict[str, Any],
    ids: list[str],
    aprobado_por: str,
    ahora: datetime | None = None,
) -> dict[str, Any]:
    """Plan canónico con las acciones elegidas, listo para firmar en el navegador."""
    if datos_propuesta.get("motivo"):
        raise ErrorPlan(datos_propuesta["motivo"])
    por_id = {a["id"]: a for a in datos_propuesta["acciones"]}
    elegidas = [por_id[i] for i in dict.fromkeys(ids) if i in por_id]
    if not elegidas:
        raise ErrorPlan("Elige al menos una acción de la propuesta.", 422)
    if len(elegidas) != len(set(ids)):
        raise ErrorPlan("Alguna acción ya no está en la propuesta: vuelve a abrir el equipo.")
    ahora = ahora or datetime.now(UTC)
    plan = {
        "version": catalogo.VERSION_PLAN,
        "plan_id": str(uuid.uuid4()),
        "equipo_id": datos_propuesta["equipo_id"],
        "plataforma": datos_propuesta["plataforma"],
        "emitido": catalogo.fecha(ahora),
        "vence": catalogo.fecha(ahora + timedelta(hours=catalogo.VIGENCIA_HORAS)),
        "aprobado_por": limpiar_texto(aprobado_por, 100) or "sin nombre",
        "acciones": catalogo.en_orden(elegidas),
    }
    catalogo.validar_plan(plan)
    return plan


def _b64(texto: str, largo: int, que: str) -> bytes:
    try:
        datos = base64.b64decode(texto, validate=True)
    except (binascii.Error, ValueError, TypeError) as error:
        raise ErrorPlan(f"{que} no es base64 válido.", 422) from error
    if len(datos) != largo:
        raise ErrorPlan(f"{que} debe medir {largo} bytes.", 422)
    return datos


def leer_clave_publica(texto: str) -> bytes:
    return _b64(texto, ed25519.LARGO_CLAVE, "La clave pública")


def foto_antes(conexion: Any, equipo: Equipo, plan: dict[str, Any]) -> dict[str, Any]:
    """Exposición del equipo al aprobar el plan, para comparar en el reporte."""
    from radar.equipos import vista

    detalle = vista.detalle(conexion, equipo.id) or {}
    fila = detalle.get("equipo") or {}
    cves = sorted({c for a in plan["acciones"] for c in a.get("cves", [])})
    return {
        "momento": plan["emitido"],
        "acciones_abiertas": fila.get("acciones"),
        "peor_prioridad": fila.get("peor_prioridad"),
        "cves_en_plan": cves,
        "kev_en_plan": sorted({c for a in plan["acciones"] for c in a.get("en_kev", [])}),
        "postura": fila.get("postura"),
        "so": fila.get("so"),
    }


def registrar(
    conexion: Any,
    equipo_id: str,
    canonico_texto: str,
    firma_b64: str,
    ahora: datetime | None = None,
) -> dict[str, Any]:
    """Guarda un plan firmado. Lanza `ErrorPlan` con el motivo si no se puede."""
    ahora = ahora or datetime.now(UTC)
    if not isinstance(canonico_texto, str) or len(canonico_texto) > 200_000:
        raise ErrorPlan("Plan demasiado grande.", 413)
    try:
        plan = json.loads(canonico_texto)
        catalogo.validar_plan(plan)
    except (ValueError, catalogo.PlanInvalido) as error:
        raise ErrorPlan(f"Plan inválido: {error}", 422) from error
    bytes_plan = canonico_texto.encode("ascii", errors="strict")
    if catalogo.canonico(plan) != bytes_plan:
        raise ErrorPlan("El plan no está en forma canónica.", 422)
    if plan["equipo_id"] != equipo_id:
        raise ErrorPlan("El plan es de otro equipo.", 422)
    emitido = catalogo.leer_fecha(plan["emitido"])
    if not (ahora - timedelta(minutes=MINUTOS_BORRADOR) <= emitido <= ahora + timedelta(minutes=2)):
        raise ErrorPlan("El borrador venció: vuelve a armar el plan.")

    firma = _b64(firma_b64, ed25519.LARGO_FIRMA, "La firma")
    clave = next(
        (
            c
            for c in tablas.claves_vigentes(conexion)
            if ed25519.verificar(base64.b64decode(c["publica"]), bytes_plan, firma)
        ),
        None,
    )
    if clave is None:
        raise ErrorPlan(
            "La firma no corresponde a ninguna clave de aprobación registrada y vigente.", 403
        )

    equipo = almacen.leer_equipo(conexion, equipo_id)
    if equipo is None:
        raise ErrorPlan("Equipo no encontrado.", 404)
    actual = propuesta(conexion, equipo_id)
    if actual is None or actual.get("motivo"):
        raise ErrorPlan((actual or {}).get("motivo") or "El equipo no admite planes.")
    if actual["plataforma"] != plan["plataforma"]:
        raise ErrorPlan("La plataforma del equipo cambió: vuelve a armar el plan.")
    vigentes = {a["id"]: a for a in actual["acciones"]}
    for accion in plan["acciones"]:
        if vigentes.get(accion["id"]) != accion:
            raise ErrorPlan(
                f"La acción {accion['id']} ya no coincide con la propuesta: vuelve a armar el plan."
            )
    if tablas.plan_activo(conexion, equipo_id):
        raise ErrorPlan("El equipo ya tiene un plan sin terminar: cancélalo o espera el resultado.")

    tablas.guardar_plan(
        conexion,
        plan,
        canonico_texto,
        firma_b64,
        clave["huella"],
        foto_antes(conexion, equipo, plan),
        bd.ahora(),
    )
    return {"plan_id": plan["plan_id"], "clave": clave["huella"], "vence": plan["vence"]}


# ---------------------------------------------------------------------------
# Lo que pide el agente
# ---------------------------------------------------------------------------


def plan_para_agente(conexion: Any, equipo: Equipo, ahora: datetime | None = None) -> dict | None:
    """El plan aprobado más antiguo y vigente del equipo, con su firma. None si no hay.

    Se entrega de nuevo hasta que llega el resultado (si el agente se cayó antes de leerlo).
    El agente se protege de ejecutar dos veces el mismo plan con su registro de `plan_id`.
    """
    if equipo.revocado or equipo.pendiente:
        return None
    ahora = ahora or datetime.now(UTC)
    fila = tablas.siguiente_para_agente(conexion, equipo.id, catalogo.fecha(ahora))
    if fila is None:
        return None
    tablas.marcar_entregado(conexion, fila["id"], bd.ahora())
    clave = tablas.clave(conexion, fila["clave"])
    return {
        "plan": fila["canonico"],
        "firma": fila["firma"],
        "clave": clave["publica"] if clave else None,
    }
