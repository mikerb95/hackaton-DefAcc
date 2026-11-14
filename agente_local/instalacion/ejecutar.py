"""Entrada instalada: usar con Python -I y una carpeta protegida."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from agente_local.__main__ import principal

sys.exit(principal())
