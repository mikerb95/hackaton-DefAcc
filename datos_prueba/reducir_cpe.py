"""Reduce el diccionario oficial de CPE de NVD a pares de aplicación con un título.

Fuente: https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz (85 MB comprimido,
911 MB descomprimido, 1,87 millones de nombres CPE). Se descarga a mano una vez:

    curl --http1.1 -o /ruta/nvdcpe-2.0.tar.gz \
        https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz
    uv run python -m datos_prueba.reducir_cpe /ruta/nvdcpe-2.0.tar.gz

Salida (`radar/datos/cpe_pares.json.gz`, unos 50 000 pares, 1 MB):
    {"vendor:producto": {"t": título en inglés sin versión, "n": nombres CPE, "dep": 1}}
`dep` aparece solo si todos los nombres del par están deprecados en NVD. El par
conserva el escape de NVD (`notepad-plus-plus:notepad\\+\\+`). Solo librería estándar.
"""

from __future__ import annotations

import argparse
import collections
import gzip
import json
import re
import tarfile
from pathlib import Path

SALIDA = Path(__file__).resolve().parent.parent / "radar" / "datos" / "cpe_pares.json.gz"


def _titulo_sin_version(titulo: str, version: str) -> str:
    if version in ("*", "-", ""):
        return titulo.strip()
    limpio = re.sub(r"\s*" + re.escape(version) + r".*$", "", titulo, flags=re.IGNORECASE)
    return (limpio or titulo).strip()


def reducir(ruta_tar: Path) -> dict[str, dict]:
    pares: dict[str, dict] = {}
    with tarfile.open(ruta_tar) as tar:
        for miembro in tar:
            if not miembro.isfile() or not miembro.name.endswith(".json"):
                continue
            datos = json.load(tar.extractfile(miembro))
            for producto in datos["products"]:
                cpe = producto["cpe"]
                campos = cpe["cpeName"].split(":")
                if campos[2] != "a":  # solo aplicaciones
                    continue
                clave = f"{campos[3]}:{campos[4]}"
                titulo = next((t["title"] for t in cpe.get("titles", []) if t["lang"] == "en"), "")
                e = pares.setdefault(clave, {"n": 0, "dep": True, "titulos": collections.Counter()})
                e["n"] += 1
                e["dep"] = e["dep"] and cpe["deprecated"]
                e["titulos"][_titulo_sin_version(titulo, campos[5].replace("\\", ""))] += 1
    return {
        k: {"t": v["titulos"].most_common(1)[0][0], "n": v["n"], **({"dep": 1} if v["dep"] else {})}
        for k, v in sorted(pares.items())
    }


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("tar", type=Path)
    p.add_argument("--salida", type=Path, default=SALIDA)
    a = p.parse_args(argv)
    pares = reducir(a.tar)
    with gzip.GzipFile(a.salida, "wb", mtime=0) as fh:  # mtime fijo: bytes reproducibles
        fh.write(json.dumps(pares, ensure_ascii=False, separators=(",", ":")).encode())
    print(f"{len(pares)} pares -> {a.salida}")


if __name__ == "__main__":
    main()
