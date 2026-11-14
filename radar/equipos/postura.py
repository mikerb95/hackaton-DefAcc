"""Reglas de postura, deterministas (docs/plan-agente-local.md, sección 8).

| Regla                                          | Prioridad   |
|------------------------------------------------|-------------|
| Sistema operativo sin soporte del fabricante   | inmediato   |
| Antivirus apagado o firmas con más de 7 días   | inmediato   |
| Firewall apagado en algún perfil               | semanal     |
| Disco sin cifrar en portátil                   | semanal     |
| Actualizaciones automáticas apagadas           | semanal     |
| Secure Boot apagado                            | informativo |
| Dato "desconocido"                             | cobertura   |

Un dato "desconocido" nunca es hallazgo (regla 1: sin comparación no hay hallazgo). Se
devuelve aparte para que el panel diga qué no se pudo revisar.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime

from radar.contratos import Prioridad
from radar.equipos import remediacion, so
from radar.equipos.almacen import Equipo
from radar.equipos.contratos import HallazgoEquipo, id_hallazgo

TIPOS = ("postura", "so_sin_soporte")


@dataclass(frozen=True)
class Regla:
    campo: str
    titulo: str
    prioridad: Prioridad
    razon: str


REGLAS: tuple[Regla, ...] = (
    Regla(
        "antivirus",
        "Protección contra malware apagada",
        "inmediato",
        "El equipo reporta la protección en tiempo real apagada",
    ),
    Regla(
        "firmas_al_dia",
        "Firmas del antivirus desactualizadas",
        "inmediato",
        "Las firmas del antivirus tienen más de 7 días",
    ),
    Regla(
        "firewall",
        "Firewall apagado",
        "semanal",
        "El firewall está apagado en al menos un perfil",
    ),
    Regla(
        "actualizaciones_automaticas",
        "Actualizaciones automáticas apagadas",
        "semanal",
        "El equipo no instala actualizaciones de seguridad por su cuenta",
    ),
    Regla(
        "secure_boot",
        "Secure Boot apagado",
        "informativo",
        "El arranque seguro está apagado",
    ),
)

NOMBRES = {
    "firewall": "Firewall",
    "antivirus": "Protección contra malware",
    "firmas_al_dia": "Firmas del antivirus",
    "cifrado_disco": "Cifrado del disco",
    "secure_boot": "Secure Boot",
    "actualizaciones_automaticas": "Actualizaciones automáticas",
    "soporte": "Soporte del sistema operativo",
}


@dataclass
class Revision:
    hallazgos: list[HallazgoEquipo] = field(default_factory=list)
    sin_revisar: list[str] = field(default_factory=list)  # nombres legibles de lo desconocido


def _plataforma(equipo: Equipo) -> remediacion.Plataforma | None:
    if equipo.so is None:
        return None
    if equipo.so.familia == "windows":
        return "windows"
    return remediacion.distro_a_plataforma(equipo.so.distro)


def _hallazgo(
    equipo: Equipo,
    tipo: str,
    clave: str,
    titulo: str,
    prioridad: Prioridad,
    razones: list[str],
    arreglo: remediacion.Arreglo,
    detectado: datetime,
) -> HallazgoEquipo:
    return HallazgoEquipo(
        id=id_hallazgo(equipo.id, tipo, clave),
        equipo_id=equipo.id,
        tipo=tipo,
        clave=clave,
        titulo=titulo,
        prioridad=prioridad,
        por_que=razones,
        pasos=arreglo.pasos,
        comandos=list(arreglo.comandos),
        detectado=detectado,
    )


def revisar(
    equipo: Equipo, ahora: datetime | None = None, catalogo: dict | None = None
) -> Revision:
    """Aplica las reglas de postura y de fin de soporte a lo último que reportó el equipo."""
    ahora = ahora or datetime.now(UTC)
    hoy: date = ahora.date()
    revision = Revision()
    if equipo.postura is None or equipo.so is None:
        return revision
    plataforma = _plataforma(equipo)
    postura = equipo.postura

    for regla in REGLAS:
        if regla.campo == "firmas_al_dia" and equipo.so.familia == "linux":
            continue  # no aplica: el agente de Linux no revisa firmas
        valor = getattr(postura, regla.campo)
        if valor == "desconocido":
            revision.sin_revisar.append(NOMBRES[regla.campo])
        elif valor == "no":
            revision.hallazgos.append(
                _hallazgo(
                    equipo,
                    "postura",
                    regla.campo,
                    regla.titulo,
                    regla.prioridad,
                    [regla.razon],
                    remediacion.arreglo_de_postura(regla.campo, plataforma),
                    ahora,
                )
            )

    # Disco sin cifrar: semanal en un portátil (se pierde o se lo roban). En un equipo fijo
    # no es hallazgo; si no se sabe qué es, queda informativo para que una persona lo mire.
    portatil = equipo.hardware.portatil if equipo.hardware else "desconocido"
    if postura.cifrado_disco == "desconocido":
        revision.sin_revisar.append(NOMBRES["cifrado_disco"])
    elif postura.cifrado_disco == "no" and portatil != "no":
        es_portatil = portatil == "si"
        revision.hallazgos.append(
            _hallazgo(
                equipo,
                "postura",
                "cifrado_disco",
                "Disco sin cifrar" + (" en un portátil" if es_portatil else ""),
                "semanal" if es_portatil else "informativo",
                [
                    "El disco del sistema no está cifrado y el equipo es portátil"
                    if es_portatil
                    else "El disco del sistema no está cifrado; no se sabe si el equipo es portátil"
                ],
                remediacion.arreglo_de_postura("cifrado_disco", plataforma),
                ahora,
            )
        )

    soporte = so.soporte(equipo.so, catalogo)
    if not soporte.conocido:
        revision.sin_revisar.append(NOMBRES["soporte"])
    elif soporte.vencido(hoy):
        revision.hallazgos.append(
            _hallazgo(
                equipo,
                "so_sin_soporte",
                "soporte",
                f"{soporte.sistema} sin soporte del fabricante",
                "inmediato",
                [
                    (
                        f"El fabricante dejó de publicar parches de seguridad el "
                        f"{soporte.fin.isoformat()} (endoflife.date)"
                    )
                ],
                remediacion.arreglo_de_soporte(soporte.sistema, equipo.so.familia),
                ahora,
            )
        )
    return revision
