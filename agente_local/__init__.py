"""Agente local de inventario del radar (docs/plan-agente-local.md).

Recoge software, sistema operativo, parches, hardware y postura de un PC con Windows o
Linux y lo envía al radar. Solo recoge y envía: no recibe órdenes, no abre puertos y no
aplica parches.

Solo usa la librería estándar a propósito: se copia a un PC y corre con el Python que
haya, sin instalar nada. No importes nada de `radar` aquí.
"""

VERSION = "0.1.0"
