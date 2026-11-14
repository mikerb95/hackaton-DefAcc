# Requerimientos no funcionales

Cómo debe comportarse el radar más allá de lo que hace: cuánto cuesta, cuánto tarda, cuánto
puede gastar el agente, cómo trata a las fuentes públicas, quién ve el mapa de exposición y
cómo se reproduce una medición. Cada requerimiento dice su estado, dónde está implementado
y cómo se comprueba. Las cifras salen de `evals/reporte.md` o de pytest, nunca a mano.

| Total | Implementados | Parciales | Planeados |
|---|---|---|---|
| 6 | 6 | 0 | 0 |

---

### RNF-01 · Costo cero salvo la API de Claude

**Estado:** Implementado

El radar funciona sin pagar ningún servicio salvo la API de Claude. Las fuentes (NVD, KEV,
EPSS y el diccionario de CPE) son públicas y gratuitas; la clave de NVD, también gratuita,
solo acorta las pausas entre peticiones. La API y el dashboard corren en Vercel y la base en
Turso. Todo lo determinista (ingesta, normalizador, cruce, priorización, agrupación, texto de
respaldo) corre sin modelo: el radar entrega hallazgos, prioridades y comunicados de respaldo
aunque no haya `ANTHROPIC_API_KEY`. La única parte con costo variable es el analista (RNF-03)
y, si se activa la bandera, el desempate del normalizador.

Prioridad alta. `radar/fuentes/`, `radar/nucleo/`, `radar/ingesta/`, `radar/agente/respaldo.py`;
variables en `.env.example`. Prueba: la suite completa corre sin clave de Anthropic (las
pruebas que llaman a Claude llevan el marcador `agente` y no corren en CI).

### RNF-02 · Tiempo de respuesta de la carga y el cruce

**Estado:** Implementado (medido en sqlite local y en Vercel contra Turso)

Una carga de inventario de tamaño realista se lee, se normaliza y se cruza contra todas las
CVE guardadas en segundos, dentro de una petición a la API. La cifra vigente, por etapa
(lectura, carga del diccionario, normalización y cruce), está en la sección "Punta a punta"
de `evals/reporte.md`, que la vuelve a medir cada vez; varía entre corridas.

- El diccionario de CPE se guarda con las palabras ya ordenadas: `ratio` sobre eso da el
  mismo resultado que `token_sort_ratio` sin reordenar 150 000 textos en cada consulta.
- La carga del snapshot completo de NVD, KEV y EPSS en sqlite tarda unos 15 s
  (`worker/descargar.py --desde-snapshot`); es trabajo del worker, no de la petición.
- Sobre Turso cada lectura es una petición HTTP; la base inserta en lotes (de unas 125 000
  peticiones a unas 1400). Medido en la preview de Vercel contra Turso: `POST /api/inventario`
  con el inventario de prueba tarda 9,6 s (antes 14,5 s).

Prioridad alta. `datos_prueba/integracion.py` (mide por etapa), `radar/ingesta/normalizador.py`,
`radar/nucleo/corrida.py`, `radar/bd.py`. Prueba: `tests/test_integracion.py`.

### RNF-03 · Topes de gasto del agente

**Estado:** Implementado

Cada análisis tiene un tope de turnos y de gasto: `max_turns=8` y `max_budget_usd=0.50`
por producto (`MAX_TURNOS` y `MAX_PRESUPUESTO_USD` en `radar/agente/analista.py`, según
`docs/contrato-analista.md`). Se analiza por producto, no por CVE ni por
equipo, así que el gasto crece con los productos afectados y no con el tamaño del
inventario. Si el modelo se pasa del tope, falla o su comunicado no pasa el verificador, el
comunicado lo arma código con el texto de respaldo: el modelo no es punto de falla.

El desempate del normalizador, cuando se activa, es una sola llamada corta por nombre
empatado (`effort: low`, `max_tokens` 256, salida restringida a "1" a "5" o "ninguno"). Sin
la bandera `RADAR_DESEMPATE_MODELO=1` no se llama.

Prioridad alta. `radar/agente/analista.py`, `radar/agente/respaldo.py`,
`radar/agente/verificador.py`, `radar/ingesta/normalizador.py`. Prueba: `tests/test_analista.py`, `tests/test_verificador.py`
y `tests/test_normalizador.py` (desempate con modelo sustituido, sin API).

### RNF-04 · Respeto a los límites de las fuentes

**Estado:** Implementado

El radar consulta las fuentes públicas sin sobrecargarlas y sin confundir una fuente caída
con un cero:

| Fuente | Cómo se consulta |
|---|---|
| NVD API 2.0 | 2000 resultados por página; pausa de 6 s entre peticiones sin clave y 0,7 s con clave; ventanas de 120 días como máximo; ante 429 espera lo que diga `Retry-After` (o 30 s); ante 5xx o red, hasta 6 intentos con espera creciente |
| CISA KEV | Un archivo por descarga; se empareja por ID de CVE, nunca por nombre de fabricante |
| FIRST EPSS | El worker baja el CSV diario completo en una sola petición (`descargar_completo`); la API de FIRST en lotes de 100 queda para consultas de pocas CVE (`consultar_api`). Una CVE que no aparece queda sin dato, no en 0 |
| Diccionario de CPE | Se descarga una vez a mano y se reduce a 1 MB (`radar/datos/cpe_pares.json.gz`); el normalizador no consulta NVD |

Cada corrida registra qué fuente respondió (`Ejecucion.fuentes`). Si la red falla, el
snapshot local reemplaza la descarga.

Prioridad media. `radar/fuentes/nvd.py`, `radar/fuentes/kev.py`, `radar/fuentes/epss.py`,
`worker/descargar.py`, `datos_prueba/reducir_cpe.py`. Prueba: `tests/test_bd.py` (fuente caída
registrada) y `tests/test_prioridad.py` (EPSS ausente).

### RNF-05 · Privacidad del mapa de exposición

**Estado:** Implementado

Qué equipo tiene qué vulnerabilidad explotable le sirve a un atacante, así que solo lo ve la
organización dueña del inventario. La información de vulnerabilidades ya es pública; lo
privado es el cruce.

- La API exige la cabecera `X-Clave-Acceso` cuando `CLAVE_ACCESO` está definida (en Vercel
  lo está).
- El agente lee la base con una conexión de solo lectura (`TURSO_AUTH_TOKEN_LECTURA` en
  Turso) que además rechaza escrituras en código.
- El comunicado para usuarios y gerencia dice cuántos equipos, nunca cuáles, y no nombra CVE.
- El texto del inventario se trata como no confiable: se limpia antes de llegar al modelo y
  el servidor MCP no devuelve frases con forma de instrucción.
- Los secretos viven solo en `.env`, que no se sube. La demo usa un inventario sintético.

Prioridad alta. `radar/api/acceso.py`, `radar/bd.py` (`ConexionSoloLectura`),
`radar/seguridad/limpieza.py`, `radar/mcp/`. Detalle y límites declarados en
[AMENAZAS.md](AMENAZAS.md) y [LIMITES.md](LIMITES.md).

### RNF-06 · Reproducibilidad con semilla fija

**Estado:** Implementado

Cualquiera reproduce el mismo inventario de prueba y las mismas cifras. El generador usa la
semilla `20261114` y fechas fijas: dos corridas dan los mismos bytes en CSV, Excel y
respuesta conocida. La respuesta se mide contra un snapshot de NVD y KEV del 14 de
noviembre de 2026, calculado con un script auxiliar independiente del cruce, así que las
cifras no cambian cuando NVD publica CVE nuevas. EPSS no está congelado: se baja el día que
se corre y las prioridades que dependen solo de EPSS se dicen así.

Prioridad media. `datos_prueba/generar.py`, `datos_prueba/semilla.py`, `datos_prueba/respuesta.py`.
Prueba: `tests/test_datos_prueba.py::test_dos_corridas_dan_los_mismos_bytes`.

---

## Lo que todavía no está

Nada pendiente en estos seis requerimientos. Los tiempos de RNF-02 varían entre corridas:
la cifra vigente es la de `evals/reporte.md`.
