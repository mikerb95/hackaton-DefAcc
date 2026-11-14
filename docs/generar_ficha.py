"""Convierte docs/FICHA_TECNICA.md en docs/FICHA_TECNICA.pdf (A4, máximo 2 páginas).

    uv run python docs/generar_ficha.py            # genera y comprueba páginas y tamaño
    uv run python docs/generar_ficha.py --html     # deja también el HTML para revisarlo

Solo librería estándar: el Markdown de la ficha (títulos, párrafos, listas, tablas, citas,
bloques de código, negritas, código en línea y enlaces) se pasa a HTML aquí mismo, y el PDF
lo imprime Chromium o Chrome sin interfaz (`--print-to-pdf`). Las páginas se cuentan con
`pdfinfo` (poppler) si está. La ficha no lleva Mermaid: si algún día lo trae, hay que
exportar el diagrama a SVG y enlazarlo como imagen, porque Chromium no lo dibuja.

Chromium instalado como snap no ve el /tmp del sistema: el HTML temporal se escribe junto
a la ficha y se borra al terminar.
"""

from __future__ import annotations

import argparse
import html
import re
import shutil
import subprocess
import sys
from pathlib import Path

DOCS = Path(__file__).resolve().parent
ENTRADA = DOCS / "FICHA_TECNICA.md"
SALIDA = DOCS / "FICHA_TECNICA.pdf"
PAGINAS_MAXIMAS = 2
TAMANO_MAXIMO = 10 * 1024 * 1024
NAVEGADORES = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")

CSS = """
@page { size: A4; margin: 13mm 14mm 13mm 14mm; }
* { box-sizing: border-box; }
body { font-family: "Inter", "Helvetica Neue", Arial, sans-serif; font-size: 9.2pt;
       line-height: 1.32; color: #1a1a1a; margin: 0; }
h1 { font-size: 15pt; margin: 0 0 4pt; }
h2 { font-size: 11pt; margin: 9pt 0 3pt; padding-bottom: 1pt; border-bottom: 0.6pt solid #bbb;
     break-after: avoid; }
p { margin: 0 0 4pt; }
ul, ol { margin: 0 0 4pt 0; padding-left: 13pt; }
li { margin: 0 0 1.5pt; }
table { border-collapse: collapse; width: 100%; margin: 2pt 0 5pt; font-size: 8.4pt;
        break-inside: avoid; }
th, td { border: 0.5pt solid #c8c8c8; padding: 1.8pt 4pt; text-align: left; vertical-align: top; }
th { background: #f1f1f1; font-weight: 600; }
code { font-family: "DejaVu Sans Mono", Menlo, monospace; font-size: 8.2pt;
       background: #f4f4f4; padding: 0 1.5pt; border-radius: 2pt; }
pre { font-family: "DejaVu Sans Mono", Menlo, monospace; font-size: 7.6pt; line-height: 1.25;
      background: #f6f6f6; padding: 4pt 6pt; margin: 2pt 0 5pt; border-radius: 3pt;
      white-space: pre; overflow: hidden; break-inside: avoid; }
pre code { background: none; padding: 0; font-size: inherit; }
blockquote { margin: 2pt 0 5pt; padding: 3pt 7pt; background: #f3f6fa; border-radius: 3pt;
             color: #333; }
blockquote p { margin: 0; }
hr { border: 0; border-top: 0.6pt solid #ccc; margin: 6pt 0; }
a { color: #1a4f8a; text-decoration: none; }
"""


# ---------------------------------------------------------------------------
# Markdown mínimo -> HTML
# ---------------------------------------------------------------------------


def _en_linea(texto: str) -> str:
    """Código en línea, negritas, cursivas y enlaces. Escapa el resto."""
    partes = re.split(r"(`[^`]+`)", texto)
    salida = []
    for parte in partes:
        if parte.startswith("`") and parte.endswith("`") and len(parte) > 1:
            salida.append(f"<code>{html.escape(parte[1:-1])}</code>")
            continue
        t = html.escape(parte, quote=False)
        t = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", r'<a href="\2">\1</a>', t)
        t = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", t)
        t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", t)
        salida.append(t)
    return "".join(salida)


def _celdas(linea: str) -> list[str]:
    linea = linea.strip().strip("|")
    return [c.strip() for c in linea.split("|")]


def markdown_a_html(md: str) -> str:
    lineas = md.splitlines()
    out: list[str] = []
    i = 0

    def es_inicio_de_bloque(s: str) -> bool:
        return bool(
            re.match(r"(#{1,6}\s|```|>|\s*[-*]\s|\s*\d+\.\s|\|)", s) or s.strip() in ("---", "")
        )

    while i < len(lineas):
        linea = lineas[i]
        s = linea.strip()
        if not s:
            i += 1
            continue
        if s.startswith("```"):
            i += 1
            bloque = []
            while i < len(lineas) and not lineas[i].strip().startswith("```"):
                bloque.append(lineas[i])
                i += 1
            i += 1
            out.append(f"<pre><code>{html.escape(chr(10).join(bloque))}</code></pre>")
            continue
        m = re.match(r"(#{1,6})\s+(.*)", s)
        if m:
            n = len(m.group(1))
            out.append(f"<h{n}>{_en_linea(m.group(2))}</h{n}>")
            i += 1
            continue
        if s == "---":
            out.append("<hr>")
            i += 1
            continue
        if s.startswith("|"):
            filas = []
            while i < len(lineas) and lineas[i].strip().startswith("|"):
                filas.append(lineas[i])
                i += 1
            encabezado = _celdas(filas[0])
            cuerpo = [f for f in filas[1:] if not re.match(r"^\s*\|?[\s:|-]+\|?\s*$", f)]
            t = ["<table><thead><tr>"]
            t += [f"<th>{_en_linea(c)}</th>" for c in encabezado]
            t.append("</tr></thead><tbody>")
            for f in cuerpo:
                t.append("<tr>" + "".join(f"<td>{_en_linea(c)}</td>" for c in _celdas(f)) + "</tr>")
            t.append("</tbody></table>")
            out.append("".join(t))
            continue
        if s.startswith(">"):
            texto = []
            while i < len(lineas) and lineas[i].strip().startswith(">"):
                texto.append(lineas[i].strip()[1:].strip())
                i += 1
            out.append(f"<blockquote><p>{_en_linea(' '.join(texto))}</p></blockquote>")
            continue
        m = re.match(r"\s*([-*]|\d+\.)\s+(.*)", linea)
        if m:
            ordenada = m.group(1)[0].isdigit()
            items: list[str] = []
            while i < len(lineas):
                m = re.match(r"\s*([-*]|\d+\.)\s+(.*)", lineas[i])
                if m:
                    items.append(m.group(2).strip())
                    i += 1
                elif lineas[i].startswith("  ") and lineas[i].strip() and items:
                    items[-1] += " " + lineas[i].strip()  # continuación del ítem
                    i += 1
                else:
                    break
            etiqueta = "ol" if ordenada else "ul"
            out.append(
                f"<{etiqueta}>"
                + "".join(f"<li>{_en_linea(t)}</li>" for t in items)
                + f"</{etiqueta}>"
            )
            continue
        parrafo = [s]
        i += 1
        while i < len(lineas) and lineas[i].strip() and not es_inicio_de_bloque(lineas[i]):
            parrafo.append(lineas[i].strip())
            i += 1
        out.append(f"<p>{_en_linea(' '.join(parrafo))}</p>")
    return "\n".join(out)


def documento(md: str, titulo: str) -> str:
    return (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        f"<title>{html.escape(titulo)}</title><style>{CSS}</style></head>"
        f"<body>{markdown_a_html(md)}</body></html>"
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def navegador() -> str:
    for nombre in NAVEGADORES:
        ruta = shutil.which(nombre)
        if ruta:
            return ruta
    raise SystemExit(
        "No hay Chromium ni Chrome en el PATH. Instala uno (por ejemplo `snap install chromium`)."
    )


def imprimir_pdf(html_ruta: Path, pdf_ruta: Path) -> None:
    comando = [
        navegador(),
        "--headless",
        "--disable-gpu",
        "--no-pdf-header-footer",
        "--no-sandbox",
        f"--print-to-pdf={pdf_ruta}",
        html_ruta.as_uri(),
    ]
    r = subprocess.run(comando, capture_output=True, text=True, timeout=120)
    if r.returncode != 0 or not pdf_ruta.exists():
        raise SystemExit(f"Chromium no generó el PDF:\n{r.stderr[-2000:]}")


def contar_paginas(pdf_ruta: Path) -> int | None:
    if shutil.which("pdfinfo"):
        r = subprocess.run(["pdfinfo", str(pdf_ruta)], capture_output=True, text=True)
        m = re.search(r"^Pages:\s+(\d+)", r.stdout, re.MULTILINE)
        if m:
            return int(m.group(1))
    # Respaldo sin poppler: cuenta los objetos de página del PDF.
    datos = pdf_ruta.read_bytes()
    n = len(re.findall(rb"/Type\s*/Page[^s]", datos))
    return n or None


def generar(entrada: Path = ENTRADA, salida: Path = SALIDA, dejar_html: bool = False) -> dict:
    md = entrada.read_text(encoding="utf-8")
    titulo = next((ln[2:].strip() for ln in md.splitlines() if ln.startswith("# ")), "Ficha")
    html_ruta = salida.with_name("_ficha_temporal.html")
    html_ruta.write_text(documento(md, titulo), encoding="utf-8")
    try:
        imprimir_pdf(html_ruta, salida)
    finally:
        if dejar_html:
            html_ruta.replace(salida.with_suffix(".html"))
        else:
            html_ruta.unlink(missing_ok=True)
    paginas = contar_paginas(salida)
    tamano = salida.stat().st_size
    return {
        "pdf": str(salida),
        "paginas": paginas,
        "tamano_bytes": tamano,
        "cumple": paginas is not None and paginas <= PAGINAS_MAXIMAS and tamano <= TAMANO_MAXIMO,
        "marcadores_sin_llenar": len(re.findall(r"\[reporte:", md)),
    }


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--html", action="store_true", help="deja docs/FICHA_TECNICA.html")
    a = p.parse_args(argv)
    r = generar(dejar_html=a.html)
    print(
        f"{r['pdf']}: {r['paginas']} páginas, {r['tamano_bytes'] / 1024:.0f} KB "
        f"(máximo {PAGINAS_MAXIMAS} páginas y {TAMANO_MAXIMO // (1024 * 1024)} MB)"
    )
    if r["marcadores_sin_llenar"]:
        print(f"Aviso: quedan {r['marcadores_sin_llenar']} marcadores [reporte: ...] sin llenar.")
    if not r["cumple"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
