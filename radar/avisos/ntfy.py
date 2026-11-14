"""Notificación push por ntfy cuando una corrida detecta vulnerabilidades críticas nuevas.

Qué se avisa: hallazgos con prioridad `inmediato` (KEV, EPSS sobre el umbral o CVSS crítico),
precisos, abiertos, no avisados por la línea base y que nunca se mandaron antes por ntfy. Un
hallazgo que sube a inmediato (por ejemplo, entra a KEV) se avisa en esa corrida. Los no
precisos nunca generan aviso (misma regla que `radar.nucleo.corrida.pendientes_de_aviso`).

Un solo mensaje por corrida, agrupado por producto, para no inundar el teléfono. Lleva
producto, versión, CVE, marca KEV y cuántos equipos: nunca nombres de equipos ni personas,
porque un tópico de ntfy.sh lo puede leer cualquiera que conozca su nombre.

Configuración (`.env`; sin `NTFY_TOPICO` no se manda nada ni se toca la base):

- `NTFY_TOPICO`: tópico, 1 a 64 caracteres `[A-Za-z0-9_-]`. Debe ser difícil de adivinar.
- `NTFY_SERVIDOR`: por defecto `https://ntfy.sh` (sirve uno propio).
- `NTFY_TOKEN`: token de acceso `tk_...` si el tópico está protegido (opcional).
- `RADAR_URL_PUBLICA`: si está, la notificación abre `<url>/panel/` al tocarla.

Registro: tabla `avisos_ntfy` (una fila por hallazgo enviado), creada aquí con
`CREATE TABLE IF NOT EXISTS` y no en `radar/esquema.sql`, igual que `radar/ajustes.py`. La
primera vez que se crea, lo que ya estaba pendiente queda registrado sin mandarse: activar
ntfy no dispara el atraso acumulado, solo lo nuevo desde ese momento.

Si ntfy no responde, los hallazgos no se registran y se reintentan en la próxima corrida.
Nunca lanza: un aviso caído no detiene el cruce.

Prueba manual: `uv run python -m radar.avisos.ntfy --prueba`.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import httpx

from radar.contratos import Hallazgo
from radar.nucleo.agrupar import ESTADOS_CERRADOS
from radar.seguridad.limpieza import limpiar_texto

SERVIDOR_POR_DEFECTO = "https://ntfy.sh"
TIEMPO_S = 8.0
MAX_PRODUCTOS = 8  # productos que se listan; el resto va como "y N más"
MAX_CVES_POR_PRODUCTO = 3
_TOPICO = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

ESQUEMA_AVISOS_NTFY = """
CREATE TABLE IF NOT EXISTS avisos_ntfy (
  hallazgo TEXT PRIMARY KEY,
  enviado TEXT NOT NULL,
  silenciado INTEGER NOT NULL DEFAULT 0
);
"""

Estado = Literal["sin_configurar", "sin_novedades", "linea_base", "enviado", "fallo"]


@dataclass(frozen=True)
class Configuracion:
    servidor: str
    topico: str
    token: str | None = None
    url_panel: str | None = None


@dataclass
class Resultado:
    estado: Estado
    hallazgos: list[str] = field(default_factory=list)
    detalle: str = ""


def _log(mensaje: str) -> None:
    print(f"[ntfy] {mensaje}", file=sys.stderr, flush=True)


def configuracion() -> Configuracion | None:
    """La configuración del entorno, o None si ntfy no está activo o está mal configurado."""
    topico = (os.environ.get("NTFY_TOPICO") or "").strip()
    if not topico:
        return None
    if not _TOPICO.match(topico):
        _log("NTFY_TOPICO no es válido (1 a 64 caracteres A-Z, a-z, 0-9, _ o -); no se avisa.")
        return None
    servidor = (os.environ.get("NTFY_SERVIDOR") or "").strip().rstrip("/") or SERVIDOR_POR_DEFECTO
    if not servidor.startswith(("https://", "http://")):
        _log("NTFY_SERVIDOR debe empezar con https:// o http://; no se avisa.")
        return None
    token = (os.environ.get("NTFY_TOKEN") or "").strip() or None
    publica = (os.environ.get("RADAR_URL_PUBLICA") or "").strip().rstrip("/")
    url_panel = f"{publica}/panel/" if publica.startswith(("https://", "http://")) else None
    return Configuracion(servidor, topico, token, url_panel)


def criticos(hallazgos: Iterable[Hallazgo]) -> list[Hallazgo]:
    """Hallazgos que merecen un aviso push (sin mirar lo ya enviado)."""
    return [
        h
        for h in hallazgos
        if h.prioridad == "inmediato"
        and h.preciso
        and not h.avisado
        and h.estado not in ESTADOS_CERRADOS
        and not h.propuesto_resuelto
    ]


# ---------------------------------------------------------------------------
# Mensaje
# ---------------------------------------------------------------------------


def armar_mensaje(hallazgos: list[Hallazgo], url_panel: str | None = None) -> dict[str, Any]:
    """Cuerpo JSON de ntfy. Todo texto que viene del inventario pasa por `limpiar_texto`."""
    por_producto: dict[str, list[Hallazgo]] = {}
    for h in hallazgos:
        por_producto.setdefault(h.producto, []).append(h)

    def peso(item: tuple[str, list[Hallazgo]]) -> tuple[int, float, int]:
        lista = item[1]
        return (
            -int(any(h.kev for h in lista)),
            -max((h.cvss or 0.0) for h in lista),
            -len({e for h in lista for e in h.equipos}),
        )

    ordenados = sorted(por_producto.items(), key=peso)
    cves = {h.cve for h in hallazgos}
    en_kev = {h.cve for h in hallazgos if h.kev}
    equipos = {e for h in hallazgos for e in h.equipos}

    lineas: list[str] = []
    for producto, lista in ordenados[:MAX_PRODUCTOS]:
        versiones = sorted({limpiar_texto(h.version_instalada, 40) for h in lista})
        ids = sorted({h.cve for h in lista}, key=lambda c: (c not in en_kev, c))
        mostradas = []
        for c in ids[:MAX_CVES_POR_PRODUCTO]:
            mostradas.append(f"{c} (KEV)" if c in en_kev else c)
        resto = len(ids) - len(mostradas)
        if resto > 0:
            mostradas.append(f"+{resto}")
        n_equipos = len({e for h in lista for e in h.equipos})
        lineas.append(
            f"- {limpiar_texto(producto, 60)} {', '.join(versiones)}: "
            f"{', '.join(mostradas)} | {n_equipos} equipo{'s' if n_equipos != 1 else ''}"
        )
    sobran = len(ordenados) - MAX_PRODUCTOS
    if sobran > 0:
        lineas.append(f"y {sobran} producto{'s' if sobran != 1 else ''} más en el panel")
    if any(h.ransomware for h in hallazgos):
        lineas.append("Hay CVE usadas en campañas de ransomware (KEV).")

    n = len(cves)
    titulo = f"Radar: {n} vulnerabilidad{'es' if n != 1 else ''} crítica{'s' if n != 1 else ''} nueva{'s' if n != 1 else ''}"
    cuerpo: dict[str, Any] = {
        "title": titulo,
        "message": (
            f"{len(equipos)} equipo{'s' if len(equipos) != 1 else ''} expuesto"
            f"{'s' if len(equipos) != 1 else ''}, {len(en_kev)} en KEV.\n" + "\n".join(lineas)
        ),
        "priority": 5 if en_kev else 4,
        "tags": ["rotating_light"] if en_kev else ["warning"],
    }
    if url_panel:
        cuerpo["click"] = url_panel
    return cuerpo


def enviar(
    config: Configuracion, cuerpo: dict[str, Any], cliente: httpx.Client | None = None
) -> None:
    """Publica en ntfy (JSON a la raíz del servidor, acepta UTF-8). Lanza si falla."""
    cabeceras = {"Authorization": f"Bearer {config.token}"} if config.token else {}
    datos = {"topic": config.topico, **cuerpo}
    if cliente is None:
        with httpx.Client(timeout=TIEMPO_S) as propio:
            r = propio.post(config.servidor, json=datos, headers=cabeceras)
    else:
        r = cliente.post(config.servidor, json=datos, headers=cabeceras, timeout=TIEMPO_S)
    r.raise_for_status()


# ---------------------------------------------------------------------------
# Registro de lo enviado
# ---------------------------------------------------------------------------


def _tabla_existe(conexion: Any) -> bool:
    fila = conexion.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'avisos_ntfy'"
    ).fetchone()
    return fila is not None


def _registrados(conexion: Any) -> set[str]:
    return {f[0] for f in conexion.execute("SELECT hallazgo FROM avisos_ntfy").fetchall()}


def _registrar(conexion: Any, ids: list[str], silenciado: bool) -> None:
    from radar import bd

    momento = datetime.now(UTC).isoformat(timespec="seconds")
    bd._en_lotes(
        conexion,
        "INSERT OR IGNORE INTO avisos_ntfy (hallazgo, enviado, silenciado) VALUES (?, ?, ?)",
        [(i, momento, int(silenciado)) for i in ids],
    )
    conexion.commit()


# ---------------------------------------------------------------------------
# Entrada desde la corrida
# ---------------------------------------------------------------------------


def notificar(
    conexion: Any,
    hallazgos: Iterable[Hallazgo],
    cliente: httpx.Client | None = None,
    config: Configuracion | None = None,
) -> Resultado:
    """Manda un aviso con los críticos nuevos de `hallazgos` y los registra. Nunca lanza."""
    try:
        config = config or configuracion()
        if config is None:
            return Resultado("sin_configurar")
        candidatos = criticos(hallazgos)
        nueva = not _tabla_existe(conexion)
        conexion.executescript(ESQUEMA_AVISOS_NTFY)
        if nueva:
            ids = sorted({h.id for h in candidatos})
            _registrar(conexion, ids, silenciado=True)
            _log(f"línea base: {len(ids)} críticos ya pendientes quedan registrados sin aviso.")
            return Resultado("linea_base", ids)
        ya = _registrados(conexion)
        nuevos = [h for h in candidatos if h.id not in ya]
        if not nuevos:
            return Resultado("sin_novedades")
        enviar(config, armar_mensaje(nuevos, config.url_panel), cliente)
        ids = sorted({h.id for h in nuevos})
        _registrar(conexion, ids, silenciado=False)
        _log(f"aviso enviado: {len({h.cve for h in nuevos})} CVE críticas, {len(ids)} hallazgos.")
        return Resultado("enviado", ids)
    except Exception as e:  # noqa: BLE001 - el aviso nunca detiene la corrida
        detalle = f"{type(e).__name__}: {limpiar_texto(e, 200)}"
        _log(f"no se pudo avisar ({detalle}); se reintenta en la próxima corrida.")
        return Resultado("fallo", detalle=detalle)


# ---------------------------------------------------------------------------
# Línea de comandos
# ---------------------------------------------------------------------------


def principal(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Avisos del radar por ntfy")
    p.add_argument(
        "--prueba", action="store_true", help="Manda un mensaje de prueba al tópico configurado"
    )
    args = p.parse_args(argv)
    config = configuracion()
    if config is None:
        print("[ntfy] Falta NTFY_TOPICO en .env (o no es válido).", flush=True)
        return 1
    if not args.prueba:
        p.print_help()
        return 0
    try:
        enviar(
            config,
            {
                "title": "Radar: prueba de avisos",
                "message": "Si ves esto, las vulnerabilidades críticas nuevas llegarán aquí.",
                "priority": 3,
                "tags": ["white_check_mark"],
                **({"click": config.url_panel} if config.url_panel else {}),
            },
        )
    except Exception as e:  # noqa: BLE001
        print(f"[ntfy] Falló: {type(e).__name__}: {e}", flush=True)
        return 1
    print(f"[ntfy] Prueba enviada a {config.servidor}/{config.topico}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(principal())
