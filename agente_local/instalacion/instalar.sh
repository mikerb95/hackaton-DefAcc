#!/bin/sh
# Instala el agente local del radar en Linux (docs/agente-local.md).
#
#   sudo RADAR_AGENTE_TOKEN=<token> sh instalar.sh https://radar.ejemplo
#
# Qué hace: copia el agente a /opt/radar-agente, canjea el token de inscripción por la
# credencial del equipo y activa un temporizador de systemd (cada 12 horas y al arrancar,
# con retraso aleatorio). No instala un demonio residente ni abre puertos.
#
# Requiere root y python3. Es el instalador de desarrollo, no el paquete .deb o .rpm
# firmado del plan (fase 3).
set -eu

URL="${1:?Uso: sudo RADAR_AGENTE_TOKEN=<token> sh instalar.sh <url del radar>}"
: "${RADAR_AGENTE_TOKEN:?Falta RADAR_AGENTE_TOKEN en el entorno}"
[ "$(id -u)" -eq 0 ] || { echo "Hay que correr este guion como root." >&2; exit 1; }
command -v python3 >/dev/null || { echo "No se encontró python3." >&2; exit 1; }

AQUI="$(cd "$(dirname "$0")" && pwd)"
DESTINO=/opt/radar-agente

install -d -m 0755 "$DESTINO/agente_local"
install -m 0644 "$AQUI"/../*.py "$DESTINO/agente_local/"
install -d -m 0700 /var/lib/radar-agente

(cd "$DESTINO" && python3 -m agente_local inscribir --url "$URL")

install -m 0644 "$AQUI/radar-agente.service" /etc/systemd/system/radar-agente.service
install -m 0644 "$AQUI/radar-agente.timer" /etc/systemd/system/radar-agente.timer
systemctl daemon-reload
systemctl enable --now radar-agente.timer

echo "Agente instalado en $DESTINO. Temporizador radar-agente.timer activo."
