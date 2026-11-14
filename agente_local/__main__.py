"""Línea de órdenes del agente local.

    python -m agente_local recoger --salida reporte.json     # recoge y no envía nada
    python -m agente_local recoger --csv inventario.csv      # CSV con las columnas del radar
    python -m agente_local subir-csv --url https://radar     # fase 0: sube el CSV al panel
    python -m agente_local inscribir --url https://radar     # muestra el código de activación
    python -m agente_local enviar                            # lo que corre la tarea programada
    python -m agente_local aviso                             # notificación para el usuario
    python -m agente_local estado
    python -m agente_local desinscribir                      # borra la credencial

El agente solo recoge y envía. No recibe órdenes ni abre puertos.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path

from agente_local import VERSION, envio, orden_parcheo, reporte

SALIDA_OK, SALIDA_ERROR, SALIDA_PENDIENTE = 0, 1, 2


def _decir(mensaje: str) -> None:
    print(f"[radar-agente] {mensaje}", flush=True)


def _estado(args: argparse.Namespace) -> envio.Estado:
    return envio.Estado(Path(args.datos) if args.datos else None)


def orden_recoger(args: argparse.Namespace) -> int:
    estado = _estado(args)
    datos = reporte.armar_reporte(estado.equipo_id, solo_software=args.solo_software)
    if args.csv:
        Path(args.csv).write_text(reporte.a_csv(datos), encoding="utf-8", newline="")
        _decir(f"CSV escrito en {args.csv}")
    if args.salida:
        Path(args.salida).write_text(
            json.dumps(datos, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        _decir(f"Reporte escrito en {args.salida}")
    if not args.csv and not args.salida:
        print(json.dumps(datos, ensure_ascii=False, indent=2))
    else:
        _decir(f"{len(datos['software'])} programas en {datos['nombre_equipo']}. No se envió nada.")
    return SALIDA_OK


def orden_subir_csv(args: argparse.Namespace) -> int:
    estado = _estado(args)
    datos = reporte.armar_reporte(estado.equipo_id, solo_software=True)
    clave = args.clave or os.environ.get("RADAR_CLAVE_ACCESO")
    respuesta = envio.subir_csv(args.url, clave, reporte.a_csv(datos))
    lectura = respuesta.get("lectura") or {}
    _decir(
        f"Inventario de {datos['nombre_equipo']} subido: {lectura.get('filas', '?')} filas, "
        f"cruce {respuesta.get('cruce', '?')}."
    )
    return SALIDA_OK


def mostrar_codigo(codigo: str, url: str) -> None:
    """Muestra el código de activación de forma que se lea de lejos."""
    print(flush=True)
    print("  ============================================", flush=True)
    print(f"   Código de activación:  {codigo}", flush=True)
    print("  ============================================", flush=True)
    print(f"  Escríbelo en el panel del radar ({url}),", flush=True)
    print('  sección "Equipos con agente", para activar este equipo.', flush=True)
    print("  Puedes volver a verlo con: radar-agente estado", flush=True)
    print(flush=True)


def orden_inscribir(args: argparse.Namespace) -> int:
    estado = _estado(args)
    if estado.inscrito and not args.forzar:
        _decir(f"El equipo ya está inscrito en {estado.url}. Usa --forzar para repetir.")
        if estado.datos.get("codigo"):
            mostrar_codigo(estado.datos["codigo"], estado.url)
        return SALIDA_OK
    import socket

    token = args.token or os.environ.get("RADAR_AGENTE_TOKEN")
    codigo = envio.inscribir(estado, args.url, socket.gethostname(), token)
    _decir(f"Equipo {estado.equipo_id} inscrito en {estado.url}.")
    mostrar_codigo(codigo, estado.url)
    return SALIDA_OK


def orden_enviar(args: argparse.Namespace) -> int:
    estado = _estado(args)
    if not estado.inscrito:
        _decir("El equipo no está inscrito: corre primero `inscribir`.")
        return SALIDA_ERROR
    if args.programado and not estado.ruta_pendiente.exists():
        intervalo = envio.intervalo_de(estado.datos) or args.intervalo_horas
        ultimo = estado.datos.get("ultimo_envio", 0)
        if 0 <= time.time() - ultimo < intervalo * 3600:
            return SALIDA_OK
    if args.retraso_maximo > 0:
        # Retraso aleatorio para que toda la flota no llegue al radar al mismo tiempo.
        time.sleep(random.uniform(0, args.retraso_maximo))
    try:
        if estado.ruta_pendiente.exists():
            try:
                pendiente = json.loads(estado.ruta_pendiente.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise envio.ErrorEnvio("No se pudo leer el reporte pendiente.") from error
            envio.enviar(estado, pendiente)
        datos = reporte.armar_reporte(estado.equipo_id)
        intervalo = envio.enviar(estado, datos)
    except envio.ErrorEnvio as error:
        pendiente = estado.ruta_pendiente.exists()
        _decir(f"No se envió: {error}" + (" Queda pendiente." if pendiente else ""))
        return SALIDA_PENDIENTE if pendiente else SALIDA_ERROR
    estado.datos["ultimo_envio"] = time.time()
    estado.guardar()
    _decir(
        f"Reporte enviado: {len(datos['software'])} programas."
        + (f" Próximo en {intervalo} horas." if intervalo else "")
    )
    _actualizar_aviso(estado)
    return SALIDA_OK


def _actualizar_aviso(estado: envio.Estado) -> None:
    """Deja el aviso para quien usa el equipo. Si falla, el envío igual cuenta como hecho."""
    from agente_local import aviso

    try:
        datos = aviso.actualizar(estado)
    except (envio.ErrorEnvio, OSError) as error:
        _decir(f"Aviso para el usuario sin actualizar: {error}")
        return
    a = datos["acciones"]
    _decir(f"Aviso para el usuario: {a['inmediato']} para hoy, {a['semanal']} para esta semana.")


def orden_aviso(args: argparse.Namespace) -> int:
    """Lo que corre la tarea de cada usuario: notificación si hay algo urgente."""
    from agente_local import aviso

    carpeta = Path(args.datos) if args.datos else None
    if args.abrir:
        datos = aviso.leer(carpeta)
        if datos is None:
            _decir("Todavía no hay aviso del radar para este equipo.")
            return SALIDA_ERROR
        aviso.abrir_pagina(datos["enlace"])
        return SALIDA_OK
    _decir(aviso.avisar(carpeta, forzar=args.forzar))
    return SALIDA_OK


def orden_estado(args: argparse.Namespace) -> int:
    estado = _estado(args)
    _decir(f"versión {VERSION}")
    _decir(f"carpeta {estado.carpeta}")
    _decir(f"equipo {estado.datos.get('equipo_id', '(sin generar)')}")
    _decir(f"inscrito {'sí, en ' + estado.url if estado.inscrito else 'no'}")
    if estado.datos.get("codigo"):
        _decir(f"código de activación {estado.datos['codigo']}")
    _decir(f"reporte pendiente {'sí' if estado.ruta_pendiente.exists() else 'no'}")
    return SALIDA_OK


def orden_desinscribir(args: argparse.Namespace) -> int:
    _estado(args).borrar()
    _decir("Credencial y reporte pendiente borrados. El radar debe marcar el equipo como retirado.")
    return SALIDA_OK


def analizador() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="radar-agente", description="Agente local de inventario")
    p.add_argument("--datos", help="Carpeta de datos del agente (por defecto, la del sistema)")
    sub = p.add_subparsers(dest="orden", required=True)

    recoger = sub.add_parser("recoger", help="Recoge y escribe el reporte, sin enviar nada")
    recoger.add_argument("--salida", help="Archivo JSON del reporte")
    recoger.add_argument("--csv", help="Archivo CSV con las columnas del radar")
    recoger.add_argument("--solo-software", action="store_true", help="Sin hardware ni postura")
    recoger.set_defaults(funcion=orden_recoger)

    subir = sub.add_parser("subir-csv", help="Sube el inventario al panel (POST /api/inventario)")
    subir.add_argument("--url", required=True)
    subir.add_argument("--clave", help="Clave de acceso (mejor en RADAR_CLAVE_ACCESO)")
    subir.set_defaults(funcion=orden_subir_csv)

    inscribir = sub.add_parser(
        "inscribir", help="Inscribe el equipo y muestra su código de activación"
    )
    inscribir.add_argument("--url", required=True)
    inscribir.add_argument(
        "--token", help="Token de la organización, solo si el radar lo exige (RADAR_AGENTE_TOKEN)"
    )
    inscribir.add_argument("--forzar", action="store_true")
    inscribir.set_defaults(funcion=orden_inscribir)

    enviar = sub.add_parser("enviar", help="Recoge y envía el reporte")
    enviar.add_argument("--retraso-maximo", type=float, default=0, metavar="SEGUNDOS")
    enviar.add_argument("--programado", action="store_true", help="Respeta el intervalo guardado")
    enviar.add_argument("--intervalo-horas", type=int, choices=range(1, 169), default=12)
    enviar.set_defaults(funcion=orden_enviar)

    aviso = sub.add_parser("aviso", help="Notifica a quien usa el equipo si hay pendientes")
    aviso.add_argument("--forzar", action="store_true", help="Muestra el aviso aunque sea repetido")
    aviso.add_argument("--abrir", action="store_true", help="Abre la página del equipo y no avisa")
    aviso.set_defaults(funcion=orden_aviso)

    orden_parcheo.registrar(sub)

    sub.add_parser("estado", help="Muestra si el equipo está inscrito").set_defaults(
        funcion=orden_estado
    )
    sub.add_parser("desinscribir", help="Borra la credencial del equipo").set_defaults(
        funcion=orden_desinscribir
    )
    return p


def principal(argv: list[str] | None = None) -> int:
    args = analizador().parse_args(argv)
    try:
        return args.funcion(args)
    except reporte.PlataformaNoSoportada as error:
        _decir(str(error))
    except envio.ErrorEnvio as error:
        _decir(str(error))
    return SALIDA_ERROR


if __name__ == "__main__":
    sys.exit(principal())
