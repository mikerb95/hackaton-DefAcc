"""Bucle del worker: toma trabajos ``analizar`` pendientes de la tabla ``trabajos``.

Cada pocos segundos busca el trabajo pendiente más antiguo, lo pasa a ``en_curso``
(``bd.tomar_trabajo``), corre ``worker.analizar.correr`` y lo cierra como ``hecho`` o
``fallido`` con un resumen en ``detalle``. La descarga de fuentes va aparte
(``worker/descargar.py``).

Uso::

    uv run python -m worker.principal               # bucle, cada 5 s
    uv run python -m worker.principal --una-vez     # un trabajo (o ninguno) y sale
    uv run python -m worker.principal --sin-agente  # solo respaldo, sin créditos
    uv run python -m worker.principal --turso       # contra Turso compartido (explícito)

Si el entorno apunta a Turso (``TURSO_*`` sin ``RADAR_SQLITE``), se niega a correr salvo
con ``--turso``.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any

from radar import bd
from worker import analizar


def _log(mensaje: str) -> None:
    print(f"[worker] {mensaje}", file=sys.stderr, flush=True)


def atender_uno(conexion: Any, sin_agente: bool = False) -> bool:
    """Atiende un trabajo si hay. Devuelve True si tomó alguno."""
    trabajo = bd.tomar_trabajo(conexion, "analizar")
    if trabajo is None:
        return False
    _log(f"trabajo {trabajo.id}: {trabajo.detalle or 'analizar'}")
    try:
        resumen = analizar.correr(conexion, sin_agente=sin_agente)
    except Exception as error:  # noqa: BLE001 - el trabajo queda fallido, el bucle sigue
        _log(f"trabajo {trabajo.id} fallido: {type(error).__name__}: {error}")
        bd.terminar_trabajo(
            conexion, trabajo.id, ok=False, detalle=f"error: {type(error).__name__}"
        )
        return True
    ok = resumen["errores"] == 0
    bd.terminar_trabajo(conexion, trabajo.id, ok=ok, detalle=json.dumps(resumen))
    _log(f"trabajo {trabajo.id} {'hecho' if ok else 'fallido'}: {resumen}")
    return True


def principal(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--una-vez", action="store_true", help="Atiende a lo más un trabajo")
    parser.add_argument("--intervalo", type=float, default=5.0, help="Segundos entre revisiones")
    parser.add_argument("--sin-agente", action="store_true", help="Solo respaldo, sin créditos")
    parser.add_argument("--turso", action="store_true", help="Permite escribir en Turso compartido")
    args = parser.parse_args(argv)
    try:
        conexion = analizar.conectar_destino(args.turso)
    except analizar.DestinoNoPermitido as error:
        _log(f"no se corre: {error}")
        return 2
    motivo = analizar.modo_sin_agente(args.sin_agente)
    _log("modo sin créditos: " + motivo if motivo else "analista con Claude Agent SDK")
    try:
        if args.una_vez:
            atender_uno(conexion, args.sin_agente)
            return 0
        while True:
            if not atender_uno(conexion, args.sin_agente):
                time.sleep(args.intervalo)
    except KeyboardInterrupt:
        _log("detenido")
        return 0
    finally:
        conexion.close()


if __name__ == "__main__":
    raise SystemExit(principal())
