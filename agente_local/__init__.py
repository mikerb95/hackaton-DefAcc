"""Agente local de inventario del radar (docs/plan-agente-local.md).

Recoge software, sistema operativo, parches, hardware y postura de un PC con Windows o
Linux y lo envía al radar. No abre puertos ni acepta comandos. Si se habilita al instalar,
también aplica planes de parcheo firmados por la clave del aprobador fijada en el equipo, y
solo con su catálogo cerrado de acciones (docs/plan-parcheo.md).

Solo usa la librería estándar a propósito: se copia a un PC y corre con el Python que
haya, sin instalar nada. No importes nada de `radar` aquí.
"""

VERSION = "0.2.0"
