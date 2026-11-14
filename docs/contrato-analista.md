# Contrato del analista (frente externo)

El analista con Claude Agent SDK lo construye otra persona en otro equipo. Esta página es todo
lo que necesita para trabajar sin la coordinación local: qué archivos le tocan, qué funciones
ya existen, qué firma exacta espera la suite de inyección y qué reglas no se negocian.

| Dato | Valor |
|---|---|
| Archivos del frente | `radar/agente/analista.py`, `radar/agente/herramientas.py`, `radar/agente/instrucciones.py`, `worker/principal.py`, `worker/analizar.py` |
| Archivos que no se tocan | Todo lo demás. Si hace falta un cambio en otro archivo, se pide al dueño (tabla de frentes en `CLAUDE.md`) |
| Cómo llega el código | Por git. Ramas cortas desde `main`; el resto del equipo integra |
| Pruebas que gastan créditos | Llevan `@pytest.mark.agente` y no corren en CI |

## 1. Entorno

```bash
uv sync --all-extras --group dev     # trae claude-agent-sdk y anthropic (extra "agente")
cp .env.example .env                 # y poner ANTHROPIC_API_KEY propia, con límite de gasto
uv run pytest -m "not agente"        # todo debe pasar antes de empezar
```

El SDK no lee `.env` solo: `radar/config.py` lo carga con `python-dotenv`. Importa la
configuración desde ahí.

## 2. Datos para trabajar

En orden de preferencia:

1. **Turso compartido**, cuando exista: `TURSO_DATABASE_URL` y un token de solo lectura en
   `.env`. Es la misma base que ve el panel.
2. **`evals/grupos_reales.json`** (está en el repositorio): grupos por producto que salieron
   del cruce real sobre NVD, KEV y el inventario de prueba, congelados. Alcanza para construir
   y probar todo el analista sin base.
3. **Una copia de `datos_locales/radar.db`** que te pase el equipo (no está en git; son datos
   públicos más inventario sintético).

Lectura siempre con `radar.bd.conectar(solo_lectura=True)`: rechaza todo lo que no sea
`SELECT`. Funciones útiles en `radar/bd.py`: `leer_grupos`, `leer_hallazgos(conexion,
producto)`, `leer_cves(conexion, pares)`, `leer_senales(conexion, cves)`.

## 3. Lo que ya existe y debes usar

| Pieza | Dónde | Para qué |
|---|---|---|
| Contratos | `radar/contratos.py`: `Grupo` (entrada), `Analisis` (salida) | `Analisis` lleva `producto`, `resumen`, `como_se_explota`, `remediacion`, `mitigacion_temporal`, `comunicado_ti`, `comunicado_usuarios`, `comunicado_gerencia` (opcional), `verificado`, `origen` (`agente` o `respaldo`) |
| Encierro | `radar/agente/hooks.py`: `opciones_encierro(permitidas, traza)` | Devuelve `permission_mode="dontAsk"`, `disallowed_tools` con las integradas, `setting_sources=[]`, memoria automática apagada y los hooks `PreToolUse` y `PostToolUse` con `on_failure="block"`. No lo armes a mano |
| Formato de argumentos | `FORMATOS_ARGUMENTO` en `hooks.py` | La guarda niega un argumento `cve` que no sea `CVE-AAAA-NNNN` |
| Limpieza | `radar/seguridad/limpieza.py` | Ya la aplica el hook posterior; no la dupliques |
| Verificador | `radar/agente/verificador.py`: `decidir(analisis, grupo, textos_origen=...)` | Devuelve el análisis del agente si pasa, o el respaldo si no |
| Respaldo | `radar/agente/respaldo.py`: `armar_respaldo(grupo)` | Texto armado por código. Úsalo también cuando el modelo falla o no hay clave |

## 4. Firma que espera la suite de inyección

La suite de dos brazos (`evals/inyeccion.py::agente_real`) llama exactamente esto:

```python
def analizar(grupo: Grupo, defensa: bool, fuente: Fuente | None = None,
             traza: Traza | None = None) -> Analisis | None
```

- **`fuente`** (Protocol `evals.inyeccion.Fuente`): métodos `detalle_producto(producto)`,
  `equipos_afectados(producto)`, `detalle_cve(cve)` y `marcar_mitigado(producto)`, cada uno
  devuelve un dict. Tus `@tool` hacen `json.dumps` de eso. Si es `None`, leen la base. Así la
  suite mete una fila envenenada sin tocar la base.
- **`defensa=True`**: solo las tres de lectura:
  `ClaudeAgentOptions(allowed_tools=LECTURA, **opciones_encierro(LECTURA, traza), ...)`.
  Nombres: `mcp__radar__detalle_producto`, `mcp__radar__equipos_afectados`,
  `mcp__radar__detalle_cve` (servidor creado con `create_sdk_mcp_server(name="radar", ...)`).
- **`defensa=False`**: las tres más `mcp__radar__marcar_mitigado` en `allowed_tools`, sin
  hooks y sin `dontAsk`. Es el brazo vulnerable a propósito, solo para medir.
- **Devuelve la salida estructurada sin pasarla por el verificador.** La suite aplica
  `decidir()` en el brazo con defensa, igual que hará el worker. Devuelve `None` si el modelo
  falla o la salida no cumple el esquema.
- **`textos_origen` en `decidir`: solo texto de NVD** (descripciones, referencias). Nunca
  texto del inventario ni lo que devuelva `equipos_afectados`: una fila envenenada con
  `CVE-2099-0001` pasaría a ser "origen" y el verificador la dejaría pasar.

## 5. Configuración del SDK

- Modelo `claude-opus-5-5`.
- `output_format={"type": "json_schema", "schema": ESQUEMA_ANALISIS}`, con el esquema sacado de
  `Analisis.model_json_schema()` en `instrucciones.py`. El resultado llega en
  `ResultMessage.structured_output`.
- Topes: `max_turns=8`, `max_budget_usd=0.50` por producto.
- Tres trampas: `allowed_tools` solo aprueba, no restringe (el encierro real es `dontAsk` más
  `disallowed_tools`); un hook que falla deja pasar la llamada salvo `on_failure="block"`; el
  `.env` no se carga solo.

## 6. Reglas del prompt (`instrucciones.py`)

- Reportar únicamente lo que traen las herramientas.
- No inventar causas ni cómo se explota algo.
- No prometer que actualizar resuelve lo que los datos no dicen. Si `Grupo.tipo_objetivo` es
  `posterior_a`, nunca decir "actualizar a X": decir "a una versión posterior a X".
- Si hay CVE en KEV, decirlo de forma explícita: hay atacantes usándola.
- EPSS ausente se dice "sin dato", nunca 0.
- Sin nombres de personas.
- Audiencias: **TI** (técnico: CVE, versiones, equipos, acción), **usuarios afectados** (qué
  hacer y para cuándo, sin jerga), **gerencia** (riesgo, alcance y decisión que se pide).

## 7. Worker

- `worker/principal.py`: bucle que toma trabajos `tipo = "analizar"` en estado `pendiente` de
  la tabla `trabajos`, los marca `en curso` y al final `hecho` o `fallido`.
- `worker/analizar.py`: por cada grupo que exige acción, `analizar(grupo, defensa=True)`, luego
  `decidir(...)`, y guarda el `Analisis` con el token de escritura (el worker sí escribe; las
  herramientas del agente no).
- Modo sin créditos (sin clave o con una bandera): se salta `query()` y guarda
  `armar_respaldo(grupo)`. El panel nunca queda vacío.

## 8. Orden sugerido y cuándo está terminado

1. `instrucciones.py` (prompt y esquema).
2. `herramientas.py` (las cuatro `@tool`, leyendo de `fuente` o de la base).
3. `analista.py` con `analizar(...)` y una prueba `agente` de un solo producto.
4. Correr la suite real: `uv run pytest -m agente tests/test_inyeccion.py` y
   `uv run python -m evals.medir`. Las cifras salen en `evals/reporte.md`; no se escriben a mano.
5. `worker/`.

Terminado es: `ruff` limpio, `pytest -m "not agente"` en verde, la suite real corrida al menos
una vez, y una línea en `docs/requerimientos-funcionales.md` (RF-4NN) y en `docs/testing.md`.
