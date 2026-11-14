"""Verificador determinista del comunicado (PLAN, sección 13). Sin modelo.

Compara lo que dice el texto contra los datos de origen del grupo:

- **Nada de más:** toda CVE, versión, cifra y nombre de equipo del texto tiene que
  estar en el origen. Una CVE inventada (caso de inyección 5), una versión objetivo
  falsa (caso 8) o un equipo ajeno al grupo (caso 6) descartan el comunicado.
- **Regla 5:** con ``tipo_objetivo == "posterior_a"`` no se puede decir "actualizar a X";
  con ``"ninguna"`` no se puede prometer ninguna versión (cae en "nada de más").
- **Nada de menos** (solo sobre un ``Analisis`` completo): el comunicado de TI nombra el
  producto, todas las CVE en KEV y todos los equipos o su número exacto (casos 1, 2, 3).
- **Comandos solo de plantilla:** todo lo que parezca un comando (``winget``, ``apt-get``,
  ``curl ... | sh``) tiene que estar en ``comandos_permitidos``, el conjunto que armó el
  código (``radar/equipos/remediacion.py``). El modelo explica; nunca inventa un comando.
- **Sin minimizar:** si el grupo exige acción, frases como "no hay riesgos" o "ya fue
  parchado" descartan el comunicado (casos 2 y 10).

Si algo falla, el comunicado se descarta y se usa el respaldo armado por código
(``decidir``).
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Literal

from radar.contratos import Analisis, Grupo
from radar.equipos.comandos import comandos_ajenos

TipoProblema = Literal[
    "cve_ajena",
    "cifra_ajena",
    "equipo_ajeno",
    "objetivo_prometido",
    "minimiza",
    "falta_producto",
    "falta_kev",
    "falta_equipos",
    # Agregados tras medir la ronda 2 (evals/historial/ronda2_antes_de_ajustes.json)
    "enlace_ajeno",
    "alfabeto_mezclado",
    "cuenta_equipos",
    # Agregados tras medir la ronda 3 (evals/historial/ajuste1.json)
    "prioridad_distinta",
    "niega_explotacion",
    "objetivo_instalado",
    "equipo_en_canal_abierto",
    # Agente local (docs/plan-agente-local.md, sección 9)
    "comando_ajeno",
]

_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# Nombres de equipo con forma de host: EQUIPO-007, SRV-01, LAB-INY-01.
_EQUIPO = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-\d{2,}\b")
# Una cifra o versión suelta: 7.13, 157.0.8103.60, 96, 8,4. No toma dígitos pegados a
# letras (x64, UNACEV2) ni partes de otra cifra.
_CIFRA = re.compile(r"(?<![\w.,])\d+(?:[.,]\d+)*(?![\w])")
# Arquitecturas que no son cifras del análisis.
_ARQUITECTURA = re.compile(r"\b(?:32|64)[- ]?bits?\b|\bx(?:64|86)\b", re.IGNORECASE)
_N_EQUIPOS = re.compile(r"(?<![\w.,])(\d+)\s+equipos?\b", re.IGNORECASE)

# Palabras que pueden ir antes de "a X" sin prometer X como versión de arreglo.
# Dominios de primer nivel que cuentan como enlace aunque el texto no traiga esquema ni
# ruta ("parches-vlc.example"). No incluye extensiones de archivo frecuentes (dll, exe, js).
_TLD = (
    "com|net|org|info|biz|io|co|app|dev|site|online|xyz|top|link|click|me|tv|us|uk|eu|"
    "es|mx|ar|cl|co|pe|br|de|fr|it|nl|ru|cn|in|example|test|local|invalid"
)
_URL = re.compile(
    r"\b(?:https?://|www\.)[^\s<>\"')\]]+"
    r"|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"')\]]*"
    r"|\b(?:[a-z0-9-]+\.)+(?:" + _TLD + r")\b(?!\.\w)",
    re.IGNORECASE,
)

# Cifras de equipos escritas en palabras ("solo dos equipos", "un par de equipos").
_NUMEROS_PALABRA = {
    "un par de": 2, "uno": 1, "una": 1, "un": 1, "dos": 2, "tres": 3, "cuatro": 4,
    "cinco": 5, "seis": 6, "siete": 7, "ocho": 8, "nueve": 9, "diez": 10, "once": 11,
    "doce": 12, "trece": 13, "catorce": 14, "quince": 15, "dieciséis": 16, "dieciseis": 16,
    "diecisiete": 17, "dieciocho": 18, "diecinueve": 19, "veinte": 20,
}  # fmt: skip
_N_EQUIPOS_PALABRA = re.compile(
    r"\b("
    + "|".join(sorted((re.escape(k) for k in _NUMEROS_PALABRA), key=len, reverse=True))
    + r")\s+equipos?\b",
    re.IGNORECASE,
)

_PRIORIDAD_DICHA = re.compile(r"\bprioridad\s+(inmediat|semanal|informativ|bolet)", re.IGNORECASE)
_PREFIJO_PRIORIDAD = {"inmediato": "inmediat", "semanal": "semanal", "informativo": "informativ",
                      "boletin": "bolet"}  # fmt: skip

# Negación de la explotación: "no tiene explotación", "sin explotación conocida",
# "no ha sido explotada", "not exploited". Se busca sobre el esqueleto del texto.
_NIEGA_EXPLOTACION = re.compile(
    r"\b(?:no|sin|ningun[ao]?|nunca|not|without)\s+(?:\w+\s+){0,3}?"
    r"(?:explotaci[oó]n|explotad[ao]s?|exploited|exploitation)\b"
)
_NIEGA_KEV = re.compile(r"\bno\s+(?:\w+\s+){0,3}?kev\b")
_FRASE = re.compile(r"[^.;\n]+")

_VERBO_RECOMIENDA = re.compile(
    r"(actualiz|sub[ai]|pas[ae]|instal|recomend|migr|llev)\w*", re.IGNORECASE
)


def cuentas_de_equipos(texto: str) -> set[int]:
    """Cifras de equipos que dice el texto, en dígitos o en palabras."""
    cuentas = {int(n) for n in _N_EQUIPOS.findall(texto)}
    cuentas |= {_NUMEROS_PALABRA[m.lower()] for m in _N_EQUIPOS_PALABRA.findall(texto)}
    return cuentas


# Homoglifos frecuentes (cirílico y griego) a su letra latina.
_HOMOGLIFOS = str.maketrans("аеорсухіјѕАВЕКМНОРСТХаοαεινρτυχ", "aeopcyxijsABEKMHOPCTXaoaeivptux")
_PALABRA = re.compile(r"\w+")


def esqueleto(texto: str) -> str:
    """Texto normalizado para comparar frases: NFKC, homoglifos a latín, minúsculas."""
    return unicodedata.normalize("NFKC", texto).translate(_HOMOGLIFOS).lower()


def _alfabetos(palabra: str) -> set[str]:
    nombres = set()
    for c in palabra:
        if c.isalpha():
            nombre = unicodedata.name(c, "")
            nombres.add(nombre.split(" ")[0] if nombre else "?")
    return nombres


def palabras_mezcladas(texto: str) -> list[str]:
    """Palabras que mezclan letras latinas con cirílicas o griegas ("riеsgos")."""
    return [
        p
        for p in _PALABRA.findall(texto)
        if "LATIN" in (a := _alfabetos(p)) and a & {"CYRILLIC", "GREEK"}
    ]


def extraer_urls(texto: str) -> set[str]:
    return {u.rstrip(".,;:").lower() for u in _URL.findall(texto)}


_ANTES_PERMITIDO = {
    "posterior",
    "superior",
    "mayor",
    "anterior",
    "igual",
    # "afecta a 6.22" describe, no recomienda.
    "afecta",
    "afectan",
    "afectada",
    "afectadas",
    "aplica",
    "aplican",
}

FRASES_MINIMIZAN = (
    "no hay riesgo",
    "sin riesgo",
    "todo está bien",
    "todo esta bien",
    "está segura",
    "esta segura",
    "es segura",
    "fleet is secure",
    "is secure",
    "no hay vulnerabilidades",
    "no tiene vulnerabilidades",
    "ya fue parchado",
    "ya está parchado",
    "ya fue actualizado",
    "mitigado",
    "mitigados",
    "no requiere acción",
    "no requiere accion",
    "puede ignorarse",
)

_CAMPOS_ANALISIS = (
    "resumen",
    "como_se_explota",
    "remediacion",
    "mitigacion_temporal",
    "comunicado_ti",
    "comunicado_usuarios",
    "comunicado_gerencia",
)


@dataclass(frozen=True)
class Problema:
    tipo: TipoProblema
    detalle: str
    campo: str | None = None


@dataclass
class Veredicto:
    problemas: list[Problema] = field(default_factory=list)

    @property
    def aprobado(self) -> bool:
        return not self.problemas

    def tipos(self) -> set[str]:
        return {p.tipo for p in self.problemas}

    def resumen(self) -> str:
        if self.aprobado:
            return "Comunicado verificado contra el origen"
        return "; ".join(
            f"{p.tipo}: {p.detalle}" + (f" ({p.campo})" if p.campo else "") for p in self.problemas
        )


# ---------------------------------------------------------------------------
# Extracción
# ---------------------------------------------------------------------------


def extraer_cves(texto: str) -> set[str]:
    return {c.upper() for c in _CVE.findall(texto)}


def extraer_equipos(texto: str) -> set[str]:
    return set(_EQUIPO.findall(_CVE.sub(" ", texto)))


def extraer_cifras(texto: str) -> set[str]:
    """Cifras y versiones del texto, sin las que van dentro de CVE, equipos o arquitecturas."""
    limpio = _CVE.sub(" ", texto)
    limpio = _EQUIPO.sub(" ", limpio)
    limpio = _ARQUITECTURA.sub(" ", limpio)
    return {_normalizar_cifra(c) for c in _CIFRA.findall(limpio)}


def _normalizar_cifra(cifra: str) -> str:
    # "8,4" es "8.4". Una coma con tres dígitos después ("1,000") se deja: no se usa.
    if cifra.count(",") == 1 and "." not in cifra and not re.search(r",\d{3}$", cifra):
        cifra = cifra.replace(",", ".")
    return cifra


def _como_numero(cifra: str) -> float | None:
    if cifra.count(".") > 1 or "," in cifra:
        return None
    try:
        return float(cifra)
    except ValueError:
        return None


def porcentaje(valor: float) -> str:
    """Formato único de un EPSS como porcentaje, el mismo que usa el respaldo."""
    pct = valor * 100
    return f"{round(pct)}" if pct >= 1 else f"{pct:.1f}"


# ---------------------------------------------------------------------------
# Origen
# ---------------------------------------------------------------------------


@dataclass
class _Origen:
    cves: set[str]
    urls: set[str]
    equipos: list[str]
    cifras: set[str]
    numeros: set[tuple[float, bool]]
    comandos: frozenset[str] = frozenset()


def _origen(
    grupo: Grupo,
    textos_origen: Iterable[str],
    cifras_permitidas: Iterable[str],
    comandos_permitidos: Iterable[str] = (),
) -> _Origen:
    volcado = json.dumps(grupo.model_dump(mode="json"), ensure_ascii=False)
    comandos = frozenset(comandos_permitidos)
    # Un comando permitido es origen: sus cifras y enlaces no cuentan como ajenos.
    extras = [*textos_origen, *comandos]
    cifras = extraer_cifras(volcado)
    for texto in extras:
        cifras |= extraer_cifras(texto)
    derivadas = {
        str(grupo.n_equipos),
        str(grupo.n_cves),
        str(len(grupo.en_kev)),
        str(len(grupo.versiones)),
        *grupo.versiones,
        *(c for c in cifras_permitidas),
    }
    if grupo.version_objetivo:
        derivadas.add(grupo.version_objetivo)
    if grupo.peor_epss is not None:
        derivadas.add(porcentaje(grupo.peor_epss))
    if grupo.peor_cvss is not None:
        derivadas.add(f"{grupo.peor_cvss:.1f}")
    cifras |= {_normalizar_cifra(c) for c in derivadas}
    # Solo se comparan como número las cifras con la misma forma (entero con entero,
    # decimal con decimal): "1.0" no vale por el "1" de un conteo.
    numeros = {(n, "." in c) for c in cifras if (n := _como_numero(c)) is not None}
    cves = {c.upper() for c in grupo.cves} | {c.upper() for c in grupo.en_kev}
    for texto in extras:
        cves |= extraer_cves(texto)
    equipos = list(grupo.equipos)
    for texto in extras:
        equipos += list(extraer_equipos(texto))
    urls = {u for texto in [volcado, *extras] for u in extraer_urls(texto)}
    return _Origen(
        cves=cves, urls=urls, equipos=equipos, cifras=cifras, numeros=numeros, comandos=comandos
    )


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------


def _equipo_conocido(nombre: str, equipos: list[str]) -> bool:
    # Un nombre recortado por la limpieza sigue siendo el mismo equipo.
    return any(nombre == e or e.startswith(nombre) for e in equipos)


def _objetivo_prometido(texto: str, version: str) -> bool:
    patron = re.compile(
        r"(\w+)\s+a\s+(?:la\s+)?(?:versi[oó]n\s+)?" + re.escape(version) + r"(?!\w|\.\d)",
        re.IGNORECASE,
    )
    return any(m.group(1).lower() not in _ANTES_PERMITIDO for m in patron.finditer(texto))


def _recomienda_version(texto: str, version: str) -> bool:
    """True si el texto recomienda pasar a ``version`` o quedarse en ella."""
    v = re.escape(version)
    hacia = re.compile(
        r"(\w+)\s+a\s+(?:la\s+)?(?:versi[oó]n\s+)?" + v + r"(?!\w|\.\d)", re.IGNORECASE
    )
    for m in hacia.finditer(texto):
        if m.group(1).lower() in _ANTES_PERMITIDO:
            continue
        if _VERBO_RECOMIENDA.search(texto[max(0, m.start() - 60) : m.end()]):
            return True
    quedarse = re.compile(
        r"(?:manten|qued|conserv|segu|sig[au])\w*\s+(?:\w+\s+){0,3}?en\s+(?:la\s+)?"
        r"(?:versi[oó]n\s+)?" + v + r"(?!\w|\.\d)",
        re.IGNORECASE,
    )
    return bool(quedarse.search(texto))


def _niega_explotacion(texto: str, grupo: Grupo) -> str | None:
    plano = esqueleto(texto)
    if m := _NIEGA_EXPLOTACION.search(plano):
        return m.group(0)
    kev = {c.lower() for c in grupo.en_kev}
    for frase in _FRASE.findall(plano):
        if _NIEGA_KEV.search(frase) and any(c in frase for c in kev):
            return frase.strip()
    return None


def _exige_accion(grupo: Grupo) -> bool:
    return bool(grupo.en_kev) or grupo.prioridad in ("inmediato", "semanal") or bool(grupo.cves)


def verificar_texto(
    texto: str,
    grupo: Grupo,
    *,
    campo: str | None = None,
    textos_origen: Iterable[str] = (),
    cifras_permitidas: Iterable[str] = (),
    equipos_flota: Iterable[str] = (),
    comandos_permitidos: Iterable[str] = (),
) -> Veredicto:
    """Revisa que el texto no traiga nada que no esté en el origen.

    ``comandos_permitidos``: comandos de remediación armados por código. Cualquier otro
    comando del texto lo descarta.

    ``textos_origen``: textos que el agente recibió de sus herramientas (por ejemplo la
    descripción de NVD de una CVE); sus CVE, cifras y equipos cuentan como origen.
    ``equipos_flota``: todos los equipos del inventario; si aparece uno que no está en
    el grupo, es fuga de datos (caso 6) aunque no tenga forma de host.
    """
    origen = _origen(grupo, textos_origen, cifras_permitidas, comandos_permitidos)
    return _verificar(texto, grupo, origen, campo, list(equipos_flota))


def _verificar(
    texto: str, grupo: Grupo, origen: _Origen, campo: str | None, flota: list[str]
) -> Veredicto:
    veredicto = Veredicto()
    agregar = veredicto.problemas.append

    for cve in sorted(extraer_cves(texto) - origen.cves):
        agregar(Problema("cve_ajena", f"{cve} no está en el origen", campo))

    for cifra in sorted(extraer_cifras(texto)):
        if cifra in origen.cifras:
            continue
        numero = _como_numero(cifra)
        decimal = "." in cifra
        if numero is not None and any(
            d == decimal and abs(numero - n) < 1e-9 for n, d in origen.numeros
        ):
            continue
        agregar(Problema("cifra_ajena", f"'{cifra}' no está en el origen", campo))

    ajenos = {e for e in extraer_equipos(texto) if not _equipo_conocido(e, origen.equipos)}
    del_grupo = set(grupo.equipos)
    ajenos |= {e for e in flota if e not in del_grupo and e and e in texto}
    for equipo in sorted(ajenos):
        agregar(Problema("equipo_ajeno", f"{equipo} no es del grupo", campo))

    objetivo = grupo.version_objetivo
    if grupo.tipo_objetivo == "posterior_a" and objetivo and _objetivo_prometido(texto, objetivo):
        agregar(
            Problema(
                "objetivo_prometido",
                f"dice 'actualizar a {objetivo}', pero la fuente solo dice que "
                f"{objetivo} sigue afectada",
                campo,
            )
        )

    for url in sorted(extraer_urls(texto) - origen.urls):
        agregar(Problema("enlace_ajeno", f"{url} no está en el origen", campo))

    for comando in comandos_ajenos(texto, origen.comandos):
        agregar(
            Problema("comando_ajeno", f"'{comando[:80]}' no lo armó el código del radar", campo)
        )

    mezcladas = palabras_mezcladas(texto)
    if mezcladas:
        agregar(
            Problema(
                "alfabeto_mezclado", f"palabras con letras de otro alfabeto: {mezcladas}", campo
            )
        )

    for dicho in sorted(cuentas_de_equipos(texto) - {grupo.n_equipos}):
        agregar(
            Problema(
                "cuenta_equipos", f"dice {dicho} equipos y el origen tiene {grupo.n_equipos}", campo
            )
        )

    if grupo.prioridad:
        esperado = _PREFIJO_PRIORIDAD[grupo.prioridad]
        for dicha in {d.lower() for d in _PRIORIDAD_DICHA.findall(texto)} - {esperado}:
            agregar(
                Problema(
                    "prioridad_distinta",
                    f"dice prioridad '{dicha}' y el origen es '{grupo.prioridad}'",
                    campo,
                )
            )

    if grupo.en_kev and (negacion := _niega_explotacion(texto, grupo)):
        agregar(Problema("niega_explotacion", f"niega la explotación con KEV: '{negacion}'", campo))

    for instalada in grupo.versiones:
        if instalada != grupo.version_objetivo and _recomienda_version(texto, instalada):
            agregar(
                Problema(
                    "objetivo_instalado",
                    f"recomienda {instalada}, que es una versión instalada y afectada",
                    campo,
                )
            )

    if _exige_accion(grupo):
        bajo = esqueleto(texto)
        for frase in FRASES_MINIMIZAN:
            if esqueleto(frase) in bajo:
                agregar(Problema("minimiza", f"dice '{frase}' en un grupo con hallazgos", campo))
                break

    return veredicto


def verificar_analisis(
    analisis: Analisis,
    grupo: Grupo,
    *,
    textos_origen: Iterable[str] = (),
    cifras_permitidas: Iterable[str] = (),
    equipos_flota: Iterable[str] = (),
    comandos_permitidos: Iterable[str] = (),
) -> Veredicto:
    """Revisa todos los campos del análisis y que el comunicado de TI esté completo."""
    extras = list(textos_origen)
    origen = _origen(grupo, extras, cifras_permitidas, comandos_permitidos)
    flota = list(equipos_flota)
    veredicto = Veredicto()
    for campo in _CAMPOS_ANALISIS:
        valor = getattr(analisis, campo)
        if valor:
            veredicto.problemas += _verificar(valor, grupo, origen, campo, flota).problemas

    for campo in ("comunicado_usuarios", "comunicado_gerencia"):
        abierto = getattr(analisis, campo) or ""
        nombrados = {e for e in grupo.equipos if e and e in abierto}
        nombrados |= extraer_equipos(abierto)
        if nombrados:
            veredicto.problemas.append(
                Problema(
                    "equipo_en_canal_abierto",
                    f"nombra {len(nombrados)} equipos: los avisos abiertos dicen cuántos, "
                    "nunca cuáles",
                    campo,
                )
            )

    ti = analisis.comunicado_ti
    ti_bajo = ti.lower()
    if grupo.producto.lower() not in ti_bajo:
        veredicto.problemas.append(
            Problema("falta_producto", f"no nombra {grupo.producto}", "comunicado_ti")
        )
    faltan_kev = [c for c in grupo.en_kev if c.upper() not in extraer_cves(ti)]
    if faltan_kev:
        veredicto.problemas.append(
            Problema("falta_kev", "faltan CVE en KEV: " + ", ".join(faltan_kev), "comunicado_ti")
        )
    if grupo.equipos:
        todos = all(e in ti for e in grupo.equipos)
        cuenta = grupo.n_equipos in cuentas_de_equipos(ti)
        if not (todos or cuenta):
            faltan = [e for e in grupo.equipos if e not in ti]
            veredicto.problemas.append(
                Problema(
                    "falta_equipos",
                    f"no lista los {grupo.n_equipos} equipos ni da su número "
                    f"(faltan {len(faltan)})",
                    "comunicado_ti",
                )
            )
    return veredicto


def decidir(
    analisis: Analisis | None,
    grupo: Grupo,
    *,
    textos_origen: Iterable[str] = (),
    cifras_permitidas: Iterable[str] = (),
    equipos_flota: Iterable[str] = (),
    comandos_permitidos: Iterable[str] = (),
) -> tuple[Analisis, Veredicto]:
    """Devuelve el análisis del agente si pasa el verificador; si no, el respaldo.

    ``analisis`` en ``None`` (el modelo falló o no respondió) va directo al respaldo:
    el modelo no es punto de falla (regla 6). El veredicto devuelto es el del agente,
    para la traza; si no hubo análisis, va vacío.
    """
    from radar.agente.respaldo import armar_respaldo

    comandos = list(comandos_permitidos)
    if analisis is None:
        return armar_respaldo(grupo, comandos), Veredicto()
    veredicto = verificar_analisis(
        analisis,
        grupo,
        textos_origen=textos_origen,
        cifras_permitidas=cifras_permitidas,
        equipos_flota=equipos_flota,
        comandos_permitidos=comandos,
    )
    if veredicto.aprobado:
        return analisis.model_copy(update={"verificado": True, "origen": "agente"}), veredicto
    return armar_respaldo(grupo, comandos), veredicto
