"""Escenarios de la suite de inyección: un grupo de origen y una fuente de datos envenenada.

El grupo de cada caso sale del cruce real del radar (``radar.nucleo.corrida.cruzar``)
contra las CVE, KEV y EPSS de ``datos_locales/radar.db``, con el producto y la versión
reales de la fila envenenada. Los equipos son sintéticos (la base todavía no tiene
inventario) más el equipo de la fila del caso.

CI no tiene la base (``datos_locales/`` no se sube), así que los grupos se congelan en
``evals/grupos_reales.json`` (solo datos públicos: IDs de CVE, KEV, CVSS, EPSS)::

    uv run python -m evals.escenarios --congelar
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from datos_prueba.casos_inyeccion import TODOS, CasoInyeccion
from radar.contratos import Grupo

RAIZ = Path(__file__).resolve().parents[1]
CONGELADOS = Path(__file__).with_name("grupos_reales.json")
BASE_LOCAL = RAIZ / "datos_locales" / "radar.db"

# Equipos sanos del mismo producto por escenario, más la fila envenenada.
EQUIPOS_POR_GRUPO = 3


def _clave(caso: CasoInyeccion) -> str:
    return f"{caso.producto_real}@{caso.version_real}"


def _producto_ajeno(caso: CasoInyeccion) -> str:
    return "WinRAR" if caso.producto == "Google Chrome" else "Google Chrome"


# ---------------------------------------------------------------------------
# Grupos de origen
# ---------------------------------------------------------------------------


def grupos_desde_base(casos: Iterable[CasoInyeccion], ruta: Path = BASE_LOCAL) -> dict[str, dict]:
    """Corre el cruce real para cada par producto y versión de los casos."""
    from radar import bd
    from radar.contratos import Activo
    from radar.nucleo.corrida import cruzar

    conexion = bd.conectar(solo_lectura=True, ruta_sqlite=ruta)
    salida: dict[str, dict] = {}
    for caso in casos:
        clave = _clave(caso)
        if clave in salida:
            continue
        activo = Activo(
            clave=f"{caso.producto}@{caso.version_real}",
            producto=caso.producto,
            nombre=caso.producto,
            version=caso.version_real,
            cpes=[caso.producto_real],
            equipos=["EQUIPO-000"],
        )
        cves = bd.leer_cves(conexion, [caso.producto_real])
        senales = bd.leer_senales(conexion, [c.id for c in cves])
        resultado = cruzar([activo], cves, senales)
        if not resultado.grupos:
            raise ValueError(f"El cruce no dio hallazgos para {clave}: el caso no tiene objetivo")
        grupo = resultado.grupos[0]
        salida[clave] = grupo.model_dump(mode="json", exclude={"equipos"})
    return salida


def congelar(ruta_base: Path = BASE_LOCAL, destino: Path = CONGELADOS) -> Path:
    datos = grupos_desde_base(TODOS, ruta_base)
    destino.write_text(
        json.dumps(datos, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return destino


def grupos_congelados(ruta: Path = CONGELADOS) -> dict[str, dict]:
    return json.loads(ruta.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Escenario
# ---------------------------------------------------------------------------


def _fila(equipo: str, caso: CasoInyeccion) -> dict[str, str]:
    """Fila sana del mismo producto, con el nombre como lo reporta un RMM."""
    return {
        "equipo": equipo,
        "programa": caso.producto,
        "proveedor": "",
        "version": caso.version_real,
    }


@dataclass
class Escenario:
    caso: CasoInyeccion
    grupo: Grupo
    # Filas que devuelve equipos_afectados para el producto del grupo (incluye la envenenada).
    filas: list[dict[str, str]]
    # Filas de otro producto: lo que un agente podría filtrar si se lo piden (caso 6).
    filas_ajenas: list[dict[str, str]]
    producto_ajeno: str
    origen: str  # "base" o "congelado"
    flota: list[str] = field(default_factory=list)

    @property
    def equipos_ajenos(self) -> list[str]:
        return [f["equipo"] for f in self.filas_ajenas]


def armar_escenario(
    caso: CasoInyeccion, indice: int, datos_grupo: dict[str, Any], origen: str
) -> Escenario:
    base = 100 + 10 * indice
    sanos = [f"EQUIPO-{base + i:03d}" for i in range(1, EQUIPOS_POR_GRUPO + 1)]
    ajenos = [f"EQUIPO-{900 + 10 * indice + i:03d}" for i in range(1, 4)]
    grupo = Grupo(**{**datos_grupo, "equipos": sorted([*sanos, caso.equipo])})
    filas = [_fila(e, caso) for e in sanos] + [caso.fila()]
    producto_ajeno = _producto_ajeno(caso)
    filas_ajenas = [
        {"equipo": e, "programa": producto_ajeno, "proveedor": "", "version": "1.0.0"}
        for e in ajenos
    ]
    return Escenario(
        caso=caso,
        grupo=grupo,
        filas=filas,
        filas_ajenas=filas_ajenas,
        producto_ajeno=producto_ajeno,
        origen=origen,
        flota=[*grupo.equipos, *ajenos],
    )


def escenarios(
    casos: Iterable[CasoInyeccion] = TODOS, usar_base: bool | None = None
) -> list[Escenario]:
    """Un escenario por caso. Usa la base local si existe (o si se pide); si no, lo congelado."""
    lista = list(casos)
    if usar_base is None:
        usar_base = BASE_LOCAL.exists()
    if usar_base:
        datos, origen = grupos_desde_base(lista), "base"
    else:
        datos, origen = grupos_congelados(), "congelado"
    indices = {c.id: i for i, c in enumerate(TODOS)}
    return [armar_escenario(c, indices[c.id], datos[_clave(c)], origen) for c in lista]


def principal() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--congelar", action="store_true", help="escribe grupos_reales.json")
    args = parser.parse_args()
    if args.congelar:
        print(f"Escrito {congelar()}")
    else:
        for e in escenarios():
            g = e.grupo
            print(f"{e.caso.id} {g.producto} {g.versiones} {g.n_cves} CVE, KEV {g.en_kev}")


if __name__ == "__main__":
    principal()
