"""Texto de respaldo armado por código, sin modelo (regla 6).

Se usa cuando el modelo falla, se pasa de tope o su comunicado no pasa el verificador.
Solo dice lo que trae el grupo: no inventa cómo se explota ni promete versiones que la
fuente no da (regla 5). Los nombres que vienen del inventario (producto, equipos)
pasan por la limpieza aunque aquí no haya modelo: el texto termina en el panel y en
avisos.
"""

from __future__ import annotations

from radar.agente.verificador import porcentaje
from radar.contratos import Analisis, Grupo
from radar.seguridad.limpieza import limpiar_texto

# Cuántos equipos se nombran en el comunicado de TI antes de resumir con "y N más".
MAX_EQUIPOS_NOMBRADOS = 10

_PLAZO_USUARIOS = {
    "inmediato": "hoy",
    "semanal": "esta semana",
    "informativo": "en la próxima actualización programada",
    "boletin": "en la próxima actualización programada",
}


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    return f"{n} {singular if n == 1 else (plural or singular + 's')}"


def _lista(elementos: list[str]) -> str:
    if len(elementos) <= 1:
        return "".join(elementos)
    return ", ".join(elementos[:-1]) + " y " + elementos[-1]


def _versiones(grupo: Grupo) -> str:
    return _lista([limpiar_texto(v) for v in grupo.versiones])


def _equipos_ti(grupo: Grupo) -> str:
    nombres = [limpiar_texto(e) for e in grupo.equipos]
    if len(nombres) > MAX_EQUIPOS_NOMBRADOS:
        # Sin cifra del resto: el verificador solo admite cifras del origen y el total
        # ya va entre paréntesis.
        nombres = nombres[:MAX_EQUIPOS_NOMBRADOS] + ["los demás"]
    return _lista(nombres)


def remediacion(grupo: Grupo) -> str:
    producto = limpiar_texto(grupo.producto)
    objetivo = limpiar_texto(grupo.version_objetivo) if grupo.version_objetivo else None
    if grupo.tipo_objetivo == "exacta" and objetivo:
        return f"Actualizar {producto} a la versión {objetivo} o una más reciente."
    if grupo.tipo_objetivo == "posterior_a" and objetivo:
        return (
            f"Actualizar {producto} a una versión posterior a {objetivo}. La fuente solo "
            f"dice que {objetivo} sigue afectada: confirmar la versión de arreglo en el "
            "aviso del fabricante."
        )
    return (
        f"Los datos de NVD no permiten afirmar una versión de arreglo para {producto}. "
        "Revisar el aviso del fabricante antes de actualizar."
    )


_RIESGO = {
    "inmediato": "Riesgo alto",
    "semanal": "Riesgo medio",
    "informativo": "Riesgo bajo",
    "boletin": "Riesgo bajo",
}

_DECISION = {
    "inmediato": "aprobar la actualización hoy, fuera de la ventana habitual si hace falta",
    "semanal": "aprobar la actualización dentro de esta semana",
    "informativo": "incluirla en la próxima actualización programada",
    "boletin": "incluirla en la próxima actualización programada",
}


def _gerencia(grupo: Grupo, producto: str, n_equipos: str, n_cves: str, n_kev: int) -> str:
    """Riesgo, alcance y decisión que se pide. Sin nombres de equipos ni CVE."""
    riesgo = _RIESGO.get(grupo.prioridad or "", "Riesgo sin calcular")
    texto = f"{riesgo}: {producto} tiene {n_cves} conocidas"
    if n_kev:
        texto += f", {n_kev} con ataques confirmados en el mundo real"
        if grupo.ransomware:
            texto += " (también usadas para ransomware)"
    texto += f". Alcance: {n_equipos} de la organización."
    decision = _DECISION.get(grupo.prioridad or "", "revisar el caso con TI")
    return texto + f" Decisión que se pide: {decision}."


def armar_respaldo(grupo: Grupo) -> Analisis:
    producto = limpiar_texto(grupo.producto)
    versiones = _versiones(grupo)
    n_equipos = _plural(grupo.n_equipos, "equipo")
    n_cves = _plural(grupo.n_cves, "CVE", "CVE")
    n_kev = len(grupo.en_kev)

    kev_resumen = ""
    if n_kev:
        kev_resumen = (
            f", {n_kev} de ellas con explotación confirmada (catálogo KEV de CISA): "
            "hay atacantes usándolas"
        )
        if grupo.ransomware:
            kev_resumen += ", también en campañas de ransomware"
    resumen = f"{producto} {versiones} está instalado en {n_equipos} y tiene {n_cves}{kev_resumen}."

    como = (
        "El radar no redacta cómo se explota sin el análisis del agente. El detalle de "
        "cada CVE está en NVD."
    )
    if n_kev:
        como += " Las CVE en KEV tienen explotación confirmada: " + ", ".join(grupo.en_kev) + "."

    accion = remediacion(grupo)

    partes_ti = [f"Prioridad {grupo.prioridad or 'sin calcular'}: {producto} {versiones}"]
    partes_ti.append(f"en {_equipos_ti(grupo)} ({n_equipos}).")
    detalle = f"{n_cves}"
    if n_kev:
        detalle += f", {n_kev} en KEV ({', '.join(grupo.en_kev)})"
        if grupo.ransomware:
            detalle += ", usadas en ransomware"
    else:
        detalle += ", ninguna en KEV"
    detalle += "."
    partes_ti.append(detalle)
    if grupo.peor_cvss is not None:
        partes_ti.append(f"Peor CVSS {grupo.peor_cvss:.1f}.")
    if grupo.peor_epss is not None:
        partes_ti.append(f"Peor EPSS {porcentaje(grupo.peor_epss)}%.")
    else:
        partes_ti.append("EPSS sin dato.")
    partes_ti.append(f"Acción: {accion}")
    comunicado_ti = " ".join(partes_ti)

    plazo = _PLAZO_USUARIOS.get(grupo.prioridad or "", "pronto")
    usuarios = f"Vamos a actualizar {producto} en tu equipo {plazo}."
    if n_kev:
        usuarios += " Es urgente: hay atacantes aprovechando esta falla."
    usuarios += (
        f" Si ves un aviso para actualizar {producto}, acéptalo. No hace falta que hagas nada más."
    )

    gerencia = _gerencia(grupo, producto, n_equipos, n_cves, n_kev)

    return Analisis(
        producto=grupo.producto,
        resumen=resumen,
        como_se_explota=como,
        remediacion=accion,
        mitigacion_temporal=None,
        comunicado_ti=comunicado_ti,
        comunicado_usuarios=usuarios,
        comunicado_gerencia=gerencia,
        verificado=True,
        origen="respaldo",
    )
