"""Paso del worker que corre el analista sobre los grupos que exigen acción.

Por cada grupo: ``analizar(grupo, defensa=True)``, luego ``decidir(...)`` contra el texto
de NVD y la flota completa, y se guarda el ``Analisis`` que salga (del agente si pasó el
verificador, el respaldo si no). El worker sí escribe; las herramientas del agente leen con
su propia conexión de solo lectura (``FuenteBase``).

Modo sin créditos: con ``sin_agente=True``, con ``RADAR_SIN_AGENTE=1`` o sin
``ANTHROPIC_API_KEY`` no se llama a ``query()`` y se guarda ``armar_respaldo(grupo)``. El
panel nunca queda vacío (regla 6).

Uso directo::

    uv run python -m worker.analizar                    # todos los grupos que exigen acción
    uv run python -m worker.analizar --producto WinRAR  # uno solo
    uv run python -m worker.analizar --sin-agente       # solo respaldo, sin créditos
    uv run python -m worker.analizar --turso            # contra Turso compartido (explícito)

Si el entorno apunta a Turso (``TURSO_*`` sin ``RADAR_SQLITE``), se niega a correr salvo
con ``--turso``.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable, Iterable
from typing import Any

from radar import bd, config
from radar.agente.herramientas import FuenteBase
from radar.agente.hooks import Traza
from radar.agente.verificador import decidir
from radar.contratos import Analisis, Grupo


def _log(mensaje: str) -> None:
    print(f"[worker.analizar] {mensaje}", file=sys.stderr, flush=True)


class DestinoNoPermitido(RuntimeError):
    """El worker apuntaría a Turso compartido sin que se haya pedido con ``--turso``."""


def conectar_destino(turso: bool = False) -> Any:
    """Conexión de escritura del worker. Se niega a abrir Turso salvo con ``turso=True``.

    Con ``TURSO_*`` en ``.env`` y sin ``RADAR_SQLITE``, ``bd.conectar()`` va a la base
    compartida: un worker de prueba escribiría análisis y cerraría trabajos ajenos. Las
    herramientas del agente siguen el mismo destino (``FuenteBase`` usa ``bd.conectar``).
    """
    destino = bd.destino()
    if destino == "turso" and not turso:
        raise DestinoNoPermitido(
            "el worker apunta a Turso compartido (TURSO_* en el entorno). Usa --turso si de "
            "verdad quieres escribir ahí, o RADAR_SQLITE=<ruta> para una base local."
        )
    return bd.conectar()


class Escritura:
    """Conexión de escritura del worker que se renueva.

    Turso cierra el stream HTTP de una conexión que quedó quieta mientras el agente
    trabaja ("stream not found"): con una sola conexión abierta al inicio, los análisis más
    largos se perdían al guardarse. Con ``abrir``, cada escritura usa una conexión viva y,
    si falla, reintenta una vez con una nueva. Las escrituras del worker son idempotentes
    (``INSERT OR REPLACE`` del análisis, cierre del trabajo); la traza puede quedar repetida.
    Sin ``abrir`` usa la conexión fija que recibe y nunca la cierra (pruebas, sqlite).
    """

    def __init__(self, conexion: Any = None, abrir: Callable[[], Any] | None = None) -> None:
        self._abrir = abrir
        self._conexion = conexion if abrir is None else None

    def usar(self, funcion: Callable[..., Any], *args: Any) -> Any:
        if self._abrir is None:
            return funcion(self._conexion, *args)
        for intento in (1, 2):
            try:
                if self._conexion is None:
                    self._conexion = self._abrir()
                return funcion(self._conexion, *args)
            except Exception as error:  # se reintenta una vez con otra conexión
                self.cerrar()
                if intento == 2:
                    raise
                _log(f"escritura falló ({type(error).__name__}); se reintenta con otra conexión")
        return None

    def cerrar(self) -> None:
        if self._abrir is not None and self._conexion is not None:
            try:
                self._conexion.close()
            except Exception:  # noqa: BLE001, S110 - una conexión muerta no se puede cerrar
                pass
            self._conexion = None


def modo_sin_agente(forzado: bool = False) -> str | None:
    """Motivo para no llamar al modelo, o ``None`` si se puede."""
    if forzado:
        return "pedido con --sin-agente"
    if (os.environ.get("RADAR_SIN_AGENTE") or "").strip() not in ("", "0"):
        return "RADAR_SIN_AGENTE activo"
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return "falta ANTHROPIC_API_KEY"
    return None


def exige_accion(grupo: Grupo) -> bool:
    """Lo que el analista redacta: prioridad inmediata o semanal, o alguna CVE en KEV. Lo
    demás se muestra con el respaldo que arma el panel."""
    return bool(grupo.en_kev) or grupo.prioridad in ("inmediato", "semanal")


def guardar_traza(conexion: Any, traza: Traza) -> None:
    for evento in traza.eventos:
        if evento.evento == "PreToolUse":
            bd.guardar_traza(conexion, evento.herramienta, str(evento.entrada), evento.decision)


def analizar_grupo(
    grupo: Grupo, flota: Iterable[str], sin_agente: bool
) -> tuple[Analisis, Traza, list[str]]:
    """Analiza un grupo y lo pasa por el verificador. Devuelve el análisis final, la traza y
    los problemas que encontró el verificador (vacío si pasó o si no hubo agente)."""
    from radar.agente.analista import analizar

    traza = Traza()
    fuente = FuenteBase(grupo)
    analisis = None if sin_agente else analizar(grupo, True, fuente=fuente, traza=traza)
    final, veredicto = decidir(
        analisis,
        grupo,
        textos_origen=fuente.textos_origen(),  # solo NVD y KEV, nunca el inventario
        cifras_permitidas=fuente.cifras_origen(),  # CVSS y EPSS por CVE
        equipos_flota=flota,
    )
    problemas = [f"{p.tipo}: {p.detalle}" for p in veredicto.problemas]
    return final, traza, problemas


def correr(
    conexion: Any,
    productos: Iterable[str] | None = None,
    sin_agente: bool = False,
    abrir: Callable[[], Any] | None = None,
) -> dict[str, Any]:
    """Analiza y guarda. ``conexion`` es de escritura y sirve para leer los grupos al
    inicio. Con ``abrir``, cada guardado usa una conexión renovable (``Escritura``), como
    hace falta con Turso. Devuelve un resumen con conteos."""
    motivo = modo_sin_agente(sin_agente)
    if motivo:
        _log(f"modo sin créditos ({motivo}): se guarda el respaldo")
    todos = bd.leer_grupos(conexion, config.Umbrales.desde_entorno())
    flota = sorted({e for g in todos for e in g.equipos})
    pedidos = set(productos or ())
    grupos = (
        [g for g in todos if g.producto in pedidos]
        if pedidos
        else [g for g in todos if exige_accion(g)]
    )
    resumen = {"grupos": len(grupos), "agente": 0, "respaldo": 0, "descartados": 0, "errores": 0}
    escritura = Escritura(conexion, abrir)
    try:
        _analizar_todos(grupos, flota, bool(motivo), escritura, resumen)
    finally:
        escritura.cerrar()
    return resumen


def _analizar_todos(
    grupos: list[Grupo],
    flota: list[str],
    sin_agente: bool,
    escritura: Escritura,
    resumen: dict[str, Any],
) -> None:
    for grupo in grupos:
        inicio = time.monotonic()
        try:
            final, traza, problemas = analizar_grupo(grupo, flota, sin_agente=sin_agente)
            escritura.usar(bd.guardar_analisis, final)
            escritura.usar(guardar_traza, traza)
        except Exception as error:  # noqa: BLE001 - un producto que falla no frena al resto
            resumen["errores"] += 1
            _log(f"{grupo.producto}: error ({type(error).__name__}: {error})")
            continue
        resumen[final.origen] += 1
        if problemas:
            resumen["descartados"] += 1
            _log(f"{grupo.producto}: verificador descartó: {'; '.join(problemas[:5])}")
        _log(f"{grupo.producto}: {final.origen} en {time.monotonic() - inicio:.1f} s")


def principal(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--producto", action="append", help="Solo este producto (repetible)")
    parser.add_argument("--sin-agente", action="store_true", help="Solo respaldo, sin créditos")
    parser.add_argument("--turso", action="store_true", help="Permite escribir en Turso compartido")
    args = parser.parse_args(argv)
    try:
        conexion = conectar_destino(args.turso)
    except DestinoNoPermitido as error:
        _log(f"no se corre: {error}")
        return 2
    try:
        resumen = correr(
            conexion, args.producto, args.sin_agente, abrir=lambda: conectar_destino(args.turso)
        )
    finally:
        conexion.close()
    print(resumen)
    return 1 if resumen["errores"] else 0


if __name__ == "__main__":
    raise SystemExit(principal())
