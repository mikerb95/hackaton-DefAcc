"""Pruebas de la guarda del plugin: hooks.json, limpiar_salida.py y aprobar_escritura.py.

Los scripts se corren como los corre Claude Code: un proceso aparte con la entrada
del hook por stdin y la respuesta en stdout.
"""

import json
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

from datos_prueba.casos_inyeccion import CASOS, caso_por_numero

RAIZ = Path(__file__).resolve().parents[1]
SCRIPTS = RAIZ / "plugin" / "scripts"
HOOKS = RAIZ / "plugin" / "hooks" / "hooks.json"


def _correr(script: Path, entrada: object, datos: Path | None = None) -> tuple[int, dict]:
    texto = entrada if isinstance(entrada, str) else json.dumps(entrada)
    entorno = {"PATH": "/usr/bin:/bin"}
    if datos is not None:
        entorno["CLAUDE_PLUGIN_DATA"] = str(datos)
    proceso = subprocess.run(
        [sys.executable, "-I", str(script)],
        input=texto,
        capture_output=True,
        text=True,
        env=entorno,
        timeout=20,
        check=False,
    )
    return proceso.returncode, json.loads(proceso.stdout)


def _post(texto: str, nombre: str = "mcp__plugin_radar_radar__equipos_expuestos") -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": nombre,
        "tool_input": {},
        "tool_use_id": "toolu_prueba",
        "tool_response": [{"type": "text", "text": texto}],
    }


def _texto_de(salida: dict) -> str:
    actualizado = salida["hookSpecificOutput"]["updatedToolOutput"]
    bloques = actualizado["content"] if isinstance(actualizado, dict) else actualizado
    return "".join(b["text"] for b in bloques)


# --- Copia exacta ---


def test_limpieza_del_plugin_es_copia_exacta():
    original = (RAIZ / "radar" / "seguridad" / "limpieza.py").read_bytes()
    copia = (SCRIPTS / "limpieza.py").read_bytes()
    assert original == copia, "cp radar/seguridad/limpieza.py plugin/scripts/limpieza.py"


# --- hooks.json ---


def test_hooks_json_engancha_lo_que_debe():
    hooks = json.loads(HOOKS.read_text(encoding="utf-8"))["hooks"]
    (pre,) = hooks["PreToolUse"]
    (post,) = hooks["PostToolUse"]
    assert pre["matcher"] == "mcp__plugin_radar_radar__cargar_inventario"
    # El nombre del servidor a secas no dispara: va con el prefijo del plugin.
    assert post["matcher"] == "mcp__plugin_radar_radar__.*"
    for grupo, script in [(pre, "aprobar_escritura.py"), (post, "limpiar_salida.py")]:
        (hook,) = grupo["hooks"]
        assert hook["type"] == "command"
        assert hook["onFailure"] == "block"
        assert hook["command"] == "python3"
        assert hook["args"] == [f"${{CLAUDE_PLUGIN_ROOT}}/scripts/{script}"]
        assert (SCRIPTS / script).is_file()


# --- limpiar_salida.py ---


@pytest.mark.parametrize("caso", CASOS, ids=lambda c: c.id)
def test_limpiar_salida_con_cada_caso(caso, tmp_path):
    datos = {"equipos": [{"equipo": caso.equipo, "programa": caso.programa}], "n": 1}
    codigo, salida = _correr(SCRIPTS / "limpiar_salida.py", _post(json.dumps(datos)), tmp_path)
    assert codigo == 0
    assert salida["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    actualizado = salida["hookSpecificOutput"]["updatedToolOutput"]
    assert isinstance(actualizado, list), "misma forma que tool_response"
    texto = _texto_de(salida)
    assert texto.startswith("<datos_no_confiables>")
    cuerpo = texto.splitlines()[2]
    assert "\r" not in cuerpo
    assert all(c == " " or unicodedata.category(c) not in {"Cc", "Cf", "Zl", "Zp"} for c in cuerpo)
    assert json.loads(cuerpo)["n"] == 1


def test_caso_9_no_llega_la_instruccion_final(tmp_path):
    caso = caso_por_numero(9)
    _, salida = _correr(SCRIPTS / "limpiar_salida.py", _post(json.dumps([caso.equipo])), tmp_path)
    assert "INSTRUCCION-FINAL-09" not in _texto_de(salida)


def test_caso_4_no_cierra_la_etiqueta(tmp_path):
    caso = caso_por_numero(4)
    _, salida = _correr(SCRIPTS / "limpiar_salida.py", _post(caso.programa), tmp_path)
    texto = _texto_de(salida)
    assert "</datos>" not in texto
    assert texto.count("</datos_no_confiables>") == 1


def test_respeta_la_forma_envuelta(tmp_path):
    entrada = _post("x")
    entrada["tool_response"] = {"content": [{"type": "text", "text": "a\nb"}]}
    _, salida = _correr(SCRIPTS / "limpiar_salida.py", entrada, tmp_path)
    assert isinstance(salida["hookSpecificOutput"]["updatedToolOutput"], dict)
    assert "a b" in _texto_de(salida)


@pytest.mark.parametrize("entrada", ["no es json", "[1, 2]", "", "null"])
def test_entrada_rota_retiene_y_sale_con_0(entrada, tmp_path):
    codigo, salida = _correr(SCRIPTS / "limpiar_salida.py", entrada, tmp_path)
    assert codigo == 0
    assert "retenida" in _texto_de(salida)


def test_sin_limpieza_py_retiene_y_no_deja_pasar_el_crudo(tmp_path):
    aislado = tmp_path / "scripts"
    aislado.mkdir()
    shutil.copy(SCRIPTS / "limpiar_salida.py", aislado / "limpiar_salida.py")
    crudo = caso_por_numero(1).programa
    codigo, salida = _correr(aislado / "limpiar_salida.py", _post(crudo), tmp_path)
    assert codigo == 0
    texto = _texto_de(salida)
    assert "retenida" in texto
    assert "parchado" not in texto


def test_traza_sin_texto_crudo(tmp_path):
    crudo = caso_por_numero(2).proveedor
    _correr(SCRIPTS / "limpiar_salida.py", _post(crudo), tmp_path)
    lineas = (tmp_path / "traza.jsonl").read_text(encoding="utf-8").splitlines()
    registro = json.loads(lineas[-1])
    assert registro["herramienta"] == "mcp__plugin_radar_radar__equipos_expuestos"
    assert registro["retenido"] is False
    assert "instruccion" in registro["senales"]
    assert "no hay riesgos" not in lineas[-1]


def test_sin_carpeta_de_datos_igual_limpia():
    codigo, salida = _correr(SCRIPTS / "limpiar_salida.py", _post("hola\nmundo"))
    assert codigo == 0 and "hola mundo" in _texto_de(salida)


# --- aprobar_escritura.py ---


def _pre(entrada_herramienta: object) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__plugin_radar_radar__cargar_inventario",
        "tool_input": entrada_herramienta,
        "tool_use_id": "toolu_prueba",
    }


def test_escritura_pide_aprobacion(tmp_path):
    filas = [caso.fila() for caso in CASOS]
    codigo, salida = _correr(SCRIPTS / "aprobar_escritura.py", _pre({"filas": filas}), tmp_path)
    assert codigo == 0
    hso = salida["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "ask"
    assert "10 elementos" in hso["permissionDecisionReason"]
    assert "parchado" not in hso["permissionDecisionReason"]


def test_escritura_resume_texto_largo_y_limpia(tmp_path):
    entrada = {"contenido": "a,b\n" * 100, "nombre": "inv\n.csv"}
    _, salida = _correr(SCRIPTS / "aprobar_escritura.py", _pre(entrada), tmp_path)
    motivo = salida["hookSpecificOutput"]["permissionDecisionReason"]
    assert "texto de 400 caracteres" in motivo
    assert "\n" not in motivo


@pytest.mark.parametrize("entrada", ["no es json", "[]"])
def test_escritura_con_entrada_rota_niega(entrada, tmp_path):
    codigo, salida = _correr(SCRIPTS / "aprobar_escritura.py", entrada, tmp_path)
    assert codigo == 0
    assert salida["hookSpecificOutput"]["permissionDecision"] == "deny"
