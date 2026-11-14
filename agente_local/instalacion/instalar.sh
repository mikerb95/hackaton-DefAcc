#!/bin/sh
# Instala el agente local del radar en Linux (docs/agente-local.md).
#
#   sudo sh agente_local/instalacion/instalar.sh   # la URL sale de configuracion.txt (zip del panel)
#   sudo sh instalar.sh https://radar    # o se pasa a mano
#
# Qué hace: copia el agente a /opt/radar-agente, inscribe el equipo, hace el primer envío,
# activa un temporizador de systemd y muestra el código de activación para escribirlo en
# el panel. No instala un demonio residente ni abre puertos.
#
# Requiere root, /usr/bin/python3 y systemd. Instalador de desarrollo, no el paquete .deb o
# .rpm firmado del plan (fase 3).
set -eu

AQUI="$(cd "$(dirname "$0")" && pwd)"
# configuracion.txt va junto al instalador o en la raíz del zip (dos carpetas arriba).
CONFIGURACION="$AQUI/configuracion.txt"
[ -f "$CONFIGURACION" ] || CONFIGURACION="$AQUI/../../configuracion.txt"

leer() {
    [ -f "$CONFIGURACION" ] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "$CONFIGURACION" | tr -d '\r' | head -n 1
}

URL="${1:-$(leer url)}"
TOKEN="${RADAR_AGENTE_TOKEN:-$(leer token)}"
[ -n "$URL" ] || { echo "Falta la URL del radar: sudo sh instalar.sh https://tu-radar" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Hay que correr este guion como root (sudo)." >&2; exit 1; }
[ -x /usr/bin/python3 ] || { echo "No se encontró /usr/bin/python3." >&2; exit 1; }

# El código del agente viene junto al instalador (paquete del panel) o en la carpeta de
# arriba (repositorio).
if [ -f "$AQUI/agente_local/__main__.py" ]; then CODIGO="$AQUI/agente_local"; else CODIGO="$AQUI/.."; fi
DESTINO=/opt/radar-agente

install -d -m 0755 "$DESTINO/agente_local"
install -m 0644 "$CODIGO"/*.py "$DESTINO/agente_local/"
install -m 0644 "$AQUI/ejecutar.py" "$DESTINO/ejecutar.py"
install -d -m 0700 /var/lib/radar-agente

if [ -n "$TOKEN" ]; then export RADAR_AGENTE_TOKEN="$TOKEN"; fi
/usr/bin/python3 -I "$DESTINO/ejecutar.py" inscribir --url "$URL"
unset RADAR_AGENTE_TOKEN

# Primer envío ya mismo, para que el equipo aparezca en el panel con sus datos.
/usr/bin/python3 -I "$DESTINO/ejecutar.py" enviar || true

install -m 0644 "$AQUI/radar-agente.service" /etc/systemd/system/radar-agente.service
install -m 0644 "$AQUI/radar-agente.timer" /etc/systemd/system/radar-agente.timer
systemctl daemon-reload
systemctl enable --now radar-agente.timer

echo "Agente instalado en $DESTINO. Escribe el código de arriba en el panel para activarlo."
