"""OSV.dev: avisos de seguridad de las distribuciones Linux, con la versión del paquete de
cada distribución (docs/plan-agente-local.md, sección 7). Gratis y sin clave.

Por qué OSV y no el CPE de NVD: las distribuciones aplican parches sin cambiar la versión
de origen. `openssl 3.0.2` en Ubuntu 22.04 puede estar parchado aunque NVD diga que 3.0.2
es vulnerable. OSV compara contra la versión del paquete de la distribución.

Comprobado contra la API el 14 de noviembre de 2026:
- `POST /v1/querybatch` responde, por cada consulta, los avisos que afectan a esa versión
  (solo `id` y `modified`). El detalle se pide con `GET /v1/vulns/{id}`.
- Ecosistemas: `Ubuntu:22.04:LTS`, `Debian:12`, `Rocky Linux:9`, `AlmaLinux:9`.
- Debian y Ubuntu publican por paquete fuente; Rocky y AlmaLinux por paquete binario, con
  la época en la versión (`1:3.0.7-24.el9`).
- El ID de CVE viene en `upstream` (o en `aliases`); la versión de arreglo, en
  `affected[].ranges[].events[].fixed`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

import httpx

URL = "https://api.osv.dev/v1"
LOTE_CONSULTAS = 500
TIEMPO = httpx.Timeout(60.0)
CABECERAS = {"User-Agent": "radar-vulnerabilidades/0.1"}
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Versiones LTS de Ubuntu: su ecosistema en OSV lleva el sufijo ":LTS".
_UBUNTU_LTS = re.compile(r"^\d\d\.04$")


@dataclass(frozen=True)
class Consulta:
    paquete: str
    version: str
    ecosistema: str

    def cuerpo(self) -> dict[str, Any]:
        return {
            "package": {"name": self.paquete, "ecosystem": self.ecosistema},
            "version": self.version,
        }


def ecosistema(distro: str | None, version: str | None) -> str | None:
    """Ecosistema de OSV para una distribución (`ID` y `VERSION_ID` de os-release), o None
    si el radar no sabe cruzarla. Sin ecosistema no hay cruce: va a cobertura."""
    if not distro or not version:
        return None
    distro = distro.strip().lower()
    version = version.strip()
    mayor = version.split(".")[0]
    if not mayor.isdigit():
        return None
    if distro == "ubuntu":
        partes = version.split(".")
        if len(partes) < 2 or not partes[1].isdigit():
            return None
        corta = f"{partes[0]}.{partes[1]}"
        # LTS: la versión de abril de los años pares (22.04, 24.04).
        lts = bool(_UBUNTU_LTS.match(corta)) and int(partes[0]) % 2 == 0
        return f"Ubuntu:{corta}:LTS" if lts else f"Ubuntu:{corta}"
    if distro == "debian":
        return f"Debian:{mayor}"
    if distro == "rocky":
        return f"Rocky Linux:{mayor}"
    if distro == "almalinux":
        return f"AlmaLinux:{mayor}"
    return None


def usa_paquete_fuente(ecosistema_osv: str) -> bool:
    """Debian y Ubuntu publican sus avisos por paquete fuente."""
    return ecosistema_osv.startswith(("Debian", "Ubuntu"))


def _cliente(cliente: httpx.Client | None) -> tuple[httpx.Client, bool]:
    if cliente is not None:
        return cliente, False
    return httpx.Client(timeout=TIEMPO, headers=CABECERAS), True


def consultar_lote(
    consultas: Iterable[Consulta], cliente: httpx.Client | None = None
) -> dict[Consulta, dict[str, str]]:
    """Avisos que afectan a cada consulta: `{consulta: {id_aviso: modificado}}`.

    Sigue la paginación (`next_page_token`) de las consultas con muchos avisos.
    """
    lista = list(dict.fromkeys(consultas))
    salida: dict[Consulta, dict[str, str]] = {c: {} for c in lista}
    cliente, propio = _cliente(cliente)
    try:
        pendientes: list[tuple[Consulta, str | None]] = [(c, None) for c in lista]
        while pendientes:
            lote, pendientes = pendientes[:LOTE_CONSULTAS], pendientes[LOTE_CONSULTAS:]
            cuerpo = {
                "queries": [
                    c.cuerpo() | ({"page_token": ficha} if ficha else {}) for c, ficha in lote
                ]
            }
            r = cliente.post(f"{URL}/querybatch", json=cuerpo)
            r.raise_for_status()
            resultados = r.json().get("results", [])
            for (consulta, _), resultado in zip(lote, resultados, strict=False):
                for aviso in resultado.get("vulns") or []:
                    salida[consulta][aviso["id"]] = aviso.get("modified", "")
                if resultado.get("next_page_token"):
                    pendientes.append((consulta, resultado["next_page_token"]))
    finally:
        if propio:
            cliente.close()
    return salida


def reducir(aviso: dict[str, Any]) -> dict[str, Any]:
    """Deja del aviso solo lo que usa el radar (lo que se guarda en la caché)."""
    cves = sorted(
        {
            x
            for x in [*(aviso.get("upstream") or []), *(aviso.get("aliases") or [])]
            if _CVE.match(x)
        }
        | ({aviso["id"]} if _CVE.match(aviso.get("id", "")) else set())
    )
    vector = next(
        (
            s.get("score")
            for s in aviso.get("severity") or []
            if s.get("type") == "CVSS_V3" and isinstance(s.get("score"), str)
        ),
        None,
    )
    afectados = []
    for a in aviso.get("affected") or []:
        paquete = a.get("package") or {}
        arreglos = [
            evento["fixed"]
            for rango in a.get("ranges") or []
            if rango.get("type") == "ECOSYSTEM"
            for evento in rango.get("events") or []
            if evento.get("fixed")
        ]
        afectados.append(
            {
                "ecosistema": paquete.get("ecosystem"),
                "paquete": paquete.get("name"),
                "arreglos": arreglos,
            }
        )
    return {
        "id": aviso.get("id"),
        "modified": aviso.get("modified"),
        "cves": cves,
        "vector": vector,
        "afectados": afectados,
    }


def descargar_aviso(id_aviso: str, cliente: httpx.Client | None = None) -> dict[str, Any]:
    """Detalle de un aviso, ya reducido."""
    cliente, propio = _cliente(cliente)
    try:
        r = cliente.get(f"{URL}/vulns/{id_aviso}")
        r.raise_for_status()
        return reducir(r.json())
    finally:
        if propio:
            cliente.close()


def arreglos_de(aviso: dict[str, Any], ecosistema_osv: str, paquete: str) -> list[str]:
    """Versiones de arreglo que publica el aviso (ya reducido) para ese paquete."""
    return [
        version
        for a in aviso.get("afectados") or []
        if a.get("ecosistema") == ecosistema_osv and a.get("paquete") == paquete
        for version in a.get("arreglos") or []
    ]
