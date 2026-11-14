"""Lo mínimo hacia la API: limpieza del texto no confiable y ocultamiento de datos personales.

Decisión del dueño (docs/plan-asistente.md): se ocultan correos, teléfonos, IP y usuarios
del PC. Pasan nombre de equipo, producto, versión y CVE, que es lo que el asistente necesita
para responder.

Dos capas, en este orden:

1. Claves que nunca salen (credenciales, huellas, hardware, usuarios del PC, IP): se quitan.
2. Cada cadena pasa por `radar/seguridad/limpieza.py` (recorte, invisibles, `<` y `>`) y por
   los patrones de correo, teléfono e IP.

Las versiones se parecen a una IP ("10.0.0.1"): en las claves de versión no se busca IP.

Módulo puro.
"""

from __future__ import annotations

import re
from typing import Any

from radar.seguridad.limpieza import LONGITUD_MAXIMA_LARGA, limite_para, limpiar_texto

# Claves que se quitan enteras, en cualquier nivel.
CLAVES_FUERA = frozenset(
    {
        "ip",
        "ips",
        "mac",
        "usuario_pc",
        "usuario_so",
        "usuarios_pc",
        "usuario_equipo",
        "correo",
        "email",
        "telefono",
        "celular",
        "hardware",
        "credencial",
        "huella",
        "codigo",
        "token",
        "clave",
        "contrasena",
        "sesion",
        "secreto",
        "firma",
        "reporte_pendiente",
    }
)

# Claves de texto legítimamente largo en las respuestas del asistente.
_LARGAS = frozenset({"comunicado", "analisis", "texto", "detalle"})

_CORREO = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_TELEFONO = re.compile(r"(?<![\w.])(?:\+?57[\s-]?)?(?:3\d{2}|60\d)[\s-]?\d{3}[\s-]?\d{4}\b")
_OCTETO = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = re.compile(rf"(?<![\w.]){_OCTETO}(?:\.{_OCTETO}){{3}}(?![\w.])")
# Usuario de Windows o de dominio: DOMINIO\usuario, o la carpeta C:\Users\usuario.
_USUARIO_WIN = re.compile(r"\b(?:[A-Za-z0-9_-]{2,}\\[A-Za-z0-9._-]{2,}|[A-Za-z]:\\Users\\[^\\\s]+)", re.IGNORECASE)
_USUARIO_HOME = re.compile(r"/home/[^/\s]+")


def _es_version(clave: str | None) -> bool:
    return bool(clave) and ("version" in clave or "objetivo" in clave or clave in {"versiones", "activo", "id"})


def ocultar(texto: str, clave: str | None = None) -> str:
    texto = _CORREO.sub("[correo oculto]", texto)
    texto = _TELEFONO.sub("[teléfono oculto]", texto)
    if not _es_version(clave):
        texto = _IPV4.sub("[IP oculta]", texto)
    texto = _USUARIO_WIN.sub("[usuario oculto]", texto)
    return _USUARIO_HOME.sub("/home/[usuario oculto]", texto)


def proteger(valor: Any, clave: str | None = None) -> Any:
    """Copia de `valor` sin claves sensibles, con cada cadena limpia y sin datos personales."""
    if isinstance(valor, dict):
        return {
            k: proteger(v, str(k).lower())
            for k, v in valor.items()
            if str(k).lower() not in CLAVES_FUERA
        }
    if isinstance(valor, list | tuple):
        return [proteger(v, clave) for v in valor]
    if isinstance(valor, str):
        maximo = LONGITUD_MAXIMA_LARGA if clave in _LARGAS else limite_para(clave)
        return ocultar(limpiar_texto(valor, maximo), clave)
    return valor
