"""Órdenes `parchear` y `parcheo` del agente (docs/plan-parcheo.md).

    radar-agente parcheo habilitar --clave <base64>   # fija la clave del aprobador (admin/root)
    radar-agente parcheo estado
    radar-agente parcheo deshabilitar
    radar-agente parchear --ensayo                     # verifica el plan y mide, sin cambiar nada
    radar-agente parchear                              # lo que corre la tarea de parcheo

Orden de una corrida de `parchear`:
1. Toma el candado (una sola ejecución a la vez).
2. Envía los resultados que quedaron pendientes por falta de red.
3. Recupera los planes interrumpidos (diario sin cierre) y envía su resultado.
4. Pide el plan pendiente. Lo verifica (firma con la clave fijada, equipo, plataforma,
   vigencia, no repetido, catálogo). Si no pasa, envía el rechazo sin tocar nada.
5. Lo anota como ejecutado ANTES de empezar (un corte no lo repite), lo ejecuta, guarda el
   resultado en disco, lo envía y envía un inventario nuevo para que el radar verifique.
"""

from __future__ import annotations

import argparse
import json
import platform
from pathlib import Path
from typing import Any

from agente_local import envio, parcheo, reporte

SALIDA_OK, SALIDA_ERROR, SALIDA_PENDIENTE = 0, 1, 2


def _decir(mensaje: str) -> None:
    print(f"[radar-agente] {mensaje}", flush=True)


def plataforma_local() -> str | None:
    """windows, debian o rhel; la misma regla que usa el radar (remediacion.distro_a_plataforma)."""
    sistema = platform.system()
    if sistema == "Windows":
        return "windows"
    if sistema != "Linux":
        return None
    try:
        from agente_local import linux

        datos = linux.leer_os_release(Path("/etc/os-release").read_text(encoding="utf-8"))
    except OSError:
        return None
    distro = (datos.get("ID") or "").lower()
    if distro in ("ubuntu", "debian"):
        return "debian"
    if distro in ("rhel", "rocky", "almalinux", "centos", "fedora"):
        return "rhel"
    return None


def contexto_local(plataforma: str) -> parcheo.Contexto:
    corredor = parcheo.Corredor()
    if plataforma == "windows":
        from agente_local import parcheo_windows

        partes = parcheo_windows.contexto(corredor)
    else:
        from agente_local import parcheo_linux

        partes = parcheo_linux.contexto(corredor, plataforma)
    return parcheo.Contexto(corredor=corredor, **partes)


def _carpeta(estado: envio.Estado) -> Path:
    return estado.carpeta / parcheo.CARPETA


def _enviar_pendientes(estado: envio.Estado, abrir: Any = None) -> int:
    """Reintenta los resultados guardados. Devuelve cuántos quedan pendientes."""
    quedan = 0
    for ruta in parcheo.pendientes(_carpeta(estado)):
        try:
            resultado = json.loads(ruta.read_text(encoding="utf-8"))
            envio.enviar_resultado(estado, resultado, abrir)
        except envio.ErrorEnvio as error:
            # 4xx (salvo 408/429): el servidor no lo va a aceptar nunca; se conserva en
            # disco con otro nombre para la auditoría local y no se reintenta.
            if (
                error.codigo is not None
                and 400 <= error.codigo < 500
                and error.codigo not in (408, 429)
            ):
                ruta.rename(ruta.with_suffix(".rechazado"))
                _decir(f"El radar no aceptó el resultado {ruta.name}: {error}")
            else:
                quedan += 1
            continue
        except (OSError, ValueError):
            ruta.rename(ruta.with_suffix(".ilegible"))
            continue
        ruta.unlink(missing_ok=True)
    return quedan


def _recuperar(estado: envio.Estado, contexto: parcheo.Contexto | None) -> None:
    carpeta = _carpeta(estado)
    for ruta in parcheo.diarios_abiertos(carpeta):
        plan_id = ruta.stem
        try:
            plan = json.loads((carpeta / f"{plan_id}.plan.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            plan = None
        diario = parcheo.Diario(carpeta, plan_id)
        resultado = parcheo.recuperar_interrumpido(diario, plan, contexto)
        if resultado is None:
            continue
        parcheo.guardar_pendiente(carpeta, resultado)
        diario.escribir("fin_plan", resultado=resultado, recuperado=True)
        _decir(f"Plan {plan_id} había quedado interrumpido: se reporta como tal.")


def _plan_id_de(texto: Any) -> str | None:
    try:
        datos = json.loads(texto) if isinstance(texto, str) else None
    except ValueError:
        return None
    return datos.get("plan_id") if isinstance(datos, dict) else None


def _ensayo(plan: dict[str, Any], contexto: parcheo.Contexto) -> None:
    """Mide y prechequea cada acción sin cambiar nada (no corre apt-get update ni winget
    upgrade: solo lo que lee)."""
    for accion in parcheo.catalogo.en_orden(plan["acciones"]):
        ejecutor = contexto.ejecutores.get(accion["ejecutor"])
        if ejecutor is None:
            _decir(f"  {accion['id']}: sin ejecutor en este agente")
            continue
        try:
            medido = ejecutor.medir(accion)
        except Exception as error:  # noqa: BLE001
            _decir(f"  {accion['id']}: no se pudo medir ({error})")
            continue
        _decir(f"  {accion['id']}: {accion['titulo']} | estado actual {medido}")


def orden_parchear(args: argparse.Namespace, abrir: Any = None) -> int:
    estado = envio.Estado(Path(args.datos) if args.datos else None)
    config = parcheo.Config(estado.carpeta)
    entrega_local = None
    if args.plan:
        entrega_local = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    if not config.habilitado:
        if args.programado:
            return SALIDA_OK
        _decir("El parcheo no está habilitado en este equipo (radar-agente parcheo habilitar).")
        return SALIDA_ERROR
    if not estado.inscrito and entrega_local is None:
        _decir("El equipo no está inscrito: corre primero `inscribir`.")
        return SALIDA_ERROR
    plataforma = plataforma_local()
    if plataforma is None:
        _decir("Plataforma sin ejecutores de parcheo.")
        return SALIDA_ERROR
    carpeta = _carpeta(estado)
    try:
        with parcheo.Candado(carpeta):
            return _corrida(args, estado, config, plataforma, carpeta, entrega_local, abrir)
    except parcheo.Ocupado as error:
        _decir(str(error))
        return SALIDA_OK if args.programado else SALIDA_ERROR


def _corrida(
    args: argparse.Namespace,
    estado: envio.Estado,
    config: parcheo.Config,
    plataforma: str,
    carpeta: Path,
    entrega_local: dict[str, Any] | None,
    abrir: Any,
) -> int:
    contexto = contexto_local(plataforma) if not getattr(args, "contexto", None) else args.contexto
    if not args.ensayo:
        _recuperar(estado, contexto)
        if estado.inscrito:
            _enviar_pendientes(estado, abrir)

    entrega = entrega_local
    if entrega is None:
        try:
            entrega = envio.pedir_plan(estado, abrir)
        except envio.ErrorEnvio as error:
            _decir(f"No se pudo pedir el plan: {error}")
            return SALIDA_PENDIENTE
    if entrega is None:
        if not args.programado:
            _decir("No hay planes de parcheo pendientes para este equipo.")
        return SALIDA_OK

    try:
        plan, bytes_plan = parcheo.verificar_plan(entrega, config, estado.equipo_id, plataforma)
    except parcheo.Rechazo as rechazo:
        _decir(f"Plan rechazado: {rechazo}")
        plan_id = _plan_id_de(entrega.get("plan"))
        texto = entrega.get("plan")
        if args.ensayo or not isinstance(texto, str) or "ya se ejecutó" in str(rechazo):
            return SALIDA_ERROR
        resultado = parcheo.resultado_rechazo(
            plan_id, estado.equipo_id, texto.encode("ascii", errors="replace"), str(rechazo)
        )
        if resultado:
            if plan_id:
                config.registrar_ejecutado(plan_id)
            parcheo.guardar_pendiente(carpeta, resultado)
            if estado.inscrito:
                _enviar_pendientes(estado, abrir)
        return SALIDA_ERROR

    _decir(
        f"Plan {plan['plan_id']} verificado: {len(plan['acciones'])} acciones, aprobado por "
        f"{plan['aprobado_por']}."
    )
    if args.ensayo:
        _ensayo(plan, contexto)
        _decir("Ensayo: no se cambió nada y el plan sigue pendiente.")
        return SALIDA_OK

    # Primero se anota: si el equipo se apaga a mitad, el plan no se repite.
    config.registrar_ejecutado(plan["plan_id"])
    carpeta.mkdir(parents=True, exist_ok=True)
    (carpeta / f"{plan['plan_id']}.plan.json").write_text(
        json.dumps(plan, ensure_ascii=False), encoding="utf-8"
    )
    diario = parcheo.Diario(carpeta, plan["plan_id"])
    resultado = parcheo.ejecutar_plan(plan, bytes_plan, contexto, diario)
    parcheo.guardar_pendiente(carpeta, resultado)
    resumen = parcheo.resumen_texto(resultado)
    (carpeta / f"{plan['plan_id']}.txt").write_text(resumen + "\n", encoding="utf-8")
    print(resumen, flush=True)

    if not estado.inscrito:
        return SALIDA_OK
    quedan = _enviar_pendientes(estado, abrir)
    # Inventario nuevo: el cruce del radar es la verificación independiente.
    try:
        envio.enviar(estado, reporte.armar_reporte(estado.equipo_id), abrir)
    except envio.ErrorEnvio as error:
        _decir(f"El inventario posterior no se envió: {error}. Se reintenta en la próxima corrida.")
        return SALIDA_PENDIENTE
    return SALIDA_PENDIENTE if quedan else SALIDA_OK


def orden_parcheo(args: argparse.Namespace) -> int:
    estado = envio.Estado(Path(args.datos) if args.datos else None)
    config = parcheo.Config(estado.carpeta)
    if args.accion == "habilitar":
        if not args.clave:
            _decir("Falta --clave con la clave pública del aprobador (base64).")
            return SALIDA_ERROR
        try:
            huellas = config.habilitar(args.clave)
        except ValueError as error:
            _decir(str(error))
            return SALIDA_ERROR
        _decir(f"Parcheo habilitado. Claves de aprobación fijadas: {', '.join(huellas)}.")
        return SALIDA_OK
    if args.accion == "deshabilitar":
        config.deshabilitar()
        _decir("Parcheo deshabilitado: el agente ya no pide planes.")
        return SALIDA_OK
    from agente_local import ed25519

    _decir(f"parcheo {'habilitado' if config.habilitado else 'deshabilitado'}")
    for clave in config.claves:
        _decir(f"clave de aprobación {ed25519.huella(clave)}")
    _decir(f"plataforma {plataforma_local() or 'sin ejecutores'}")
    _decir(f"planes ejecutados {len(config.datos.get('ejecutados') or [])}")
    _decir(f"resultados pendientes de enviar {len(parcheo.pendientes(_carpeta(estado)))}")
    return SALIDA_OK


def registrar(sub: argparse._SubParsersAction) -> None:
    """Agrega las órdenes de parcheo al analizador de `__main__`."""
    parchear = sub.add_parser(
        "parchear", help="Pide, verifica y ejecuta el plan de parcheo firmado"
    )
    parchear.add_argument("--programado", action="store_true", help="Silencioso si no hay nada")
    parchear.add_argument("--ensayo", action="store_true", help="Verifica y mide, sin cambiar nada")
    parchear.add_argument("--plan", help="Archivo con {plan, firma} en vez de pedirlo al radar")
    parchear.set_defaults(funcion=orden_parchear)

    gestion = sub.add_parser("parcheo", help="Habilita, deshabilita o muestra el parcheo")
    gestion.add_argument("accion", choices=("habilitar", "deshabilitar", "estado"))
    gestion.add_argument(
        "--clave", action="append", help="Clave pública del aprobador en base64 (repetible)"
    )
    gestion.set_defaults(funcion=orden_parcheo)
