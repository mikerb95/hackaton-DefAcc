"""Extrae de un texto todo lo que parece un comando, para compararlo con el conjunto que
armó el código (docs/plan-agente-local.md, sección 9).

Lo usa el verificador: un comando que no esté en el conjunto permitido descarta el texto
y se usa el respaldo. Así una inyección en un `DisplayName` o en un nombre de paquete no
puede colar `curl ... | sh` en las instrucciones que lee una persona de TI.

Qué cuenta como comando:
- un cmdlet de PowerShell (`Verbo-Nombre`), con o sin argumentos;
- un programa que solo se usa como comando (`winget`, `apt-get`, `sudo`, `powershell`,
  `msiexec`...) seguido de argumentos;
- un programa que también es nombre de producto o palabra corriente (`python`, `curl`,
  `npm`, `snap`...) solo si trae forma de comando: una opción (`-x`), una ruta, una URL,
  un signo de shell o un verbo como `install`;
- el contenido de un tramo entre comillas invertidas o de un bloque de código, si cumple
  lo anterior o trae un signo de shell (`|`, `&&`, `;`, `$(`, `>`).

"Python 3.12 está afectado" y "se actualiza con winget" son menciones, no comandos.
Ante la duda es comando, y si no está permitido se descarta: falla hacia el lado seguro.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Programas que solo aparecen como comando. No incluye palabras que también son español
# corriente ("net", "sc", "at", "cp").
_FUERTES = (
    "sudo|winget|choco|scoop|apt-get|aptitude|dpkg-reconfigure|dnf|yum|zypper|pacman|"
    r"powershell\.exe|powershell|pwsh|cmd\.exe|cmd /c|sh -c|msiexec|regsvr32|rundll32|mshta|"
    "certutil|bitsadmin|wmic|schtasks|reg add|reg delete|icacls|takeown|netsh|systemctl|ufw|"
    "firewall-cmd|setenforce|iptables|nft|chmod|chown|rm -|mkfs|dd if=|crontab|manage-bde|"
    "iex|irm|iwr"
)
# Programas que también son nombre de producto o palabra corriente: piden forma de comando.
_AMBIGUOS = (
    "apt|dpkg|rpm|snap|flatpak|pip3|pip|npm|npx|curl|wget|bash|zsh|python3|python|perl|ruby|"
    "service|ssh|scp|ncat|nc|socat"
)
# Cmdlets de PowerShell: Verbo-Nombre con verbos que cambian o descargan algo.
_CMDLET = (
    r"(?:Set|New|Remove|Add|Enable|Disable|Invoke|Start|Stop|Install|Uninstall|Update|"
    r"Restart|Register|Unregister|Import|Export|Clear|Copy|Move|Rename|Out|Expand)-[A-Z][A-Za-z]+"
)
_ANTES = r"(?<![\w./\\-])"
_INICIO = re.compile(
    _ANTES
    + r"(?:(?P<cmdlet>"
    + _CMDLET
    + r")|(?P<fuerte>(?:"
    + _FUERTES
    + r"))(?![\w-])|(?P<ambiguo>(?:"
    + _AMBIGUOS
    + r"))(?![\w-]))",
    re.IGNORECASE,
)
# Forma de comando: una opción, un signo de shell, una asignación, una ruta, una URL o un
# verbo de gestor de paquetes.
_EVIDENCIA = re.compile(
    r"\s-{1,2}\w|\||&&|>|\$\(|\$\w|=\S|\s(?:\.{0,2}|~)/\S|https?:|\s[A-Za-z]:\\"
    r"|\b(?:install|reinstall|upgrade|update|remove|uninstall|purge)\b",
    re.IGNORECASE,
)
_PRIMER_ARGUMENTO_VERSION = re.compile(r"^\S+\s+v?\d")
# El comando sigue hasta el salto de línea, una comilla invertida o el final de la frase
# (punto, punto y coma, coma o dos puntos seguidos de espacio o del final).
_FIN = re.compile(r"[\n`]|[.;,:](?=\s|$)|\s[)\]]|$")
_INVERTIDAS = re.compile(r"```(?:[a-z]*\n)?(.*?)```|`([^`\n]+)`", re.DOTALL)
_SIGNOS_SHELL = re.compile(r"\||&&|\$\(|;|>|<")
_ESPACIOS = re.compile(r"\s+")


def normalizar(comando: str) -> str:
    """Forma única de un comando para compararlo: espacios colapsados, sin signos de cierre."""
    texto = _ESPACIOS.sub(" ", comando).strip()
    return texto.strip("`'\"").rstrip(".,;:").strip()


def _es_comando(candidato: str, inicio: re.Match) -> bool:
    """Decide si el tramo que empieza por un programa conocido es un comando o una mención."""
    limpio = candidato.strip()
    if inicio.group("cmdlet"):
        return True
    con_argumentos = " " in limpio
    evidencia = bool(_EVIDENCIA.search(limpio))
    if inicio.group("ambiguo"):
        return con_argumentos and evidencia
    # Fuerte: basta un argumento, salvo que sea un número de versión ("sudo 1.9.9 está
    # afectado"), que es una mención del producto.
    if not con_argumentos:
        return False
    return evidencia or not _PRIMER_ARGUMENTO_VERSION.match(limpio)


def _linea_de_codigo_es_comando(linea: str) -> bool:
    limpio = linea.strip()
    if not limpio:
        return False
    inicio = _INICIO.match(limpio)
    if inicio is not None and _es_comando(limpio, inicio):
        return True
    return " " in limpio and bool(_SIGNOS_SHELL.search(limpio))


def extraer_comandos(texto: str) -> list[str]:
    """Comandos que aparecen en el texto, normalizados y sin repetir, en orden de aparición."""
    encontrados: list[str] = []

    def agregar(candidato: str) -> None:
        normal = normalizar(candidato)
        if normal and normal not in encontrados:
            encontrados.append(normal)

    for m in _INVERTIDAS.finditer(texto):
        bloque = m.group(1) if m.group(1) is not None else m.group(2)
        for linea in bloque.splitlines():
            if _linea_de_codigo_es_comando(linea):
                agregar(linea)
    # Lo que está entre comillas invertidas ya se revisó: se quita para no contarlo dos veces.
    resto = _INVERTIDAS.sub(" ", texto)

    posicion = 0
    while True:
        inicio = _INICIO.search(resto, posicion)
        if inicio is None:
            break
        fin = _FIN.search(resto, inicio.end())
        corte = fin.start() if fin else len(resto)
        candidato = resto[inicio.start() : corte]
        if _es_comando(candidato, inicio):
            agregar(candidato)
            posicion = max(corte, inicio.end())
        else:
            # Era una mención: se sigue buscando justo después, por si el comando viene
            # más adelante en la misma frase.
            posicion = inicio.end()
    return encontrados


def comandos_ajenos(texto: str, permitidos: Iterable[str]) -> list[str]:
    """Comandos del texto que no están en el conjunto que armó el código."""
    conjunto = {normalizar(c) for c in permitidos}
    return [c for c in extraer_comandos(texto) if c not in conjunto]
