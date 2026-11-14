"""Quién pregunta. Sale de la sesión (o del enlace firmado de /mi-equipo/), nunca del cuerpo
de la petición."""

from __future__ import annotations

from dataclasses import dataclass

# Roles del panel (radar/api/acceso.py) más el de quien usa un equipo en /mi-equipo/.
ROLES = ("lector", "analista", "admin", "equipo")
ETIQUETAS = {
    "lector": "rol lector (solo consulta)",
    "analista": "rol analista",
    "admin": "rol administrador",
    "equipo": "persona que usa el equipo",
}


@dataclass(frozen=True)
class Contexto:
    usuario_id: str  # "sesion:7", "clave:programa", "local:local" o "equipo:<uuid>"
    nombre: str
    rol: str
    via: str  # "sesion", "clave", "local" o "equipo"
    cuenta_id: int | None = None  # id en la tabla usuarios, si entró con sesión
    equipo_id: str | None = None  # solo en /mi-equipo/

    @property
    def es_admin(self) -> bool:
        return self.rol == "admin"
