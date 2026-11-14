# Historias de usuario

Lo que cada persona necesita del radar, en formato XP: "Como <actor>, quiero <acción>, para
<beneficio>". Están agrupadas por actor (los mismos de [casos-de-uso.md](casos-de-uso.md)).
Cada una trae su tipo, su estado, etiquetas, el caso de uso que la recorre y sus criterios de
aceptación: ✓ cumplido y con prueba, · pendiente. Los criterios citan el requerimiento que los
implementa ([requerimientos-funcionales.md](requerimientos-funcionales.md)); lo que todavía no
está se dice con su estado, no se esconde.

| Cifra | Valor |
|---|---|
| Historias | 30 |
| Aceptadas | 25 |
| En desarrollo | 3 |
| En cola | 2 |
| Actores con historias | 5 |

Estados: **Aceptada** (implementada, con prueba automática y con su requerimiento), **En
desarrollo** (parte hecha, parte pendiente) y **Cola** (todavía no empieza). Una historia pasa
a Aceptada cuando todos sus criterios tienen ✓.

## Como responsable de TI (16)

### HU-TI-01 · Historia · Aceptada

**Como responsable de TI, quiero subir el inventario en CSV o Excel tal como sale del RMM,
para saber qué está expuesto sin limpiarlo a mano antes.**

`#ingesta` `#panel` · CU-01

- ✓ Acepta separador `,` `;` tabulador o `|`, UTF-8 o cp1252, y Excel aunque el encabezado
  esté bajo filas de título (RF-201).
- ✓ Reconoce los encabezados por alias en español y en inglés (RF-202).
- ✓ Lee todo como texto, para que `1.10` no se vuelva `1.1` (RF-201).
- ✓ Un archivo ilegible responde con el motivo y no guarda nada (RF-605).

### HU-TI-02 · Historia · Aceptada

**Como responsable de TI, quiero que cada programa del inventario quede atado a su producto
real de NVD, para que el cruce no dependa de cómo lo escribió cada instalador.**

`#normalizador` · CU-01

- ✓ Limpia versiones de instalador (`.windows.N`, `+N`, Python 3.12.10150.0) (RF-302).
- ✓ Resuelve las trampas conocidas de NVD con alias curados: Temurin, Docker Desktop, Java,
  nginx (RF-303).
- ✓ Usa búsqueda difusa contra el diccionario oficial de CPE cuando no hay alias (RF-304).
- ✓ Un producto que no tiene CPE propio nunca hereda uno ajeno (NoSQLBooster) (RF-303).

### HU-TI-03 · Historia · Aceptada

**Como responsable de TI, quiero ver lo que el radar no pudo evaluar y por qué, para no
confundir "sin hallazgos" con "sano".**

`#núcleo` `#panel` · CU-01, CU-02

- ✓ Sin CPE, sin versión o con versión ilegible, la fila va a cobertura con su motivo y nunca
  produce un hallazgo (RF-103).
- ✓ El panel muestra la cobertura por motivo (RF-602).
- ✓ El plugin cuenta lo que quedó sin evaluar en cada respuesta (RF-702).

### HU-TI-04 · Historia · Aceptada

**Como responsable de TI, quiero que el radar me diga qué parchar hoy, qué esta semana y qué
puede esperar, para gastar el tiempo en lo que se está explotando.**

`#prioridad` · CU-02

- ✓ Inmediato con KEV, EPSS desde 0,10 o CVSS desde 9,0; semanal con CVSS desde 7,0;
  informativo en otro caso, con umbrales ajustables por entorno (RF-105).
- ✓ Cada hallazgo trae sus razones en texto (RF-105).
- ✓ KEV se empareja por ID de CVE, nunca por nombre de fabricante (RF-105).
- ✓ EPSS ausente se muestra "sin dato", nunca cero (RF-105, RF-602).
- ✓ Lo que NVD publica sin versión queda informativo y aparte (RF-105).

### HU-TI-05 · Historia · Aceptada

**Como responsable de TI, quiero una sola acción por producto con la versión a la que hay que
llegar, para mandar una instrucción y no cien.**

`#núcleo` `#panel` · CU-02

- ✓ Agrupa por producto con versiones, equipos, CVE, KEV, ransomware, peor CVSS y EPSS (RF-106).
- ✓ "Actualizar a X" solo con versión exacta; con `versionEndIncluding` dice "posterior a X";
  sin límite no promete nada (RF-104, RF-603).
- ✓ Los equipos con una versión sana no se cuentan como equipos por actualizar (RF-106).

### HU-TI-06 · Historia · Aceptada

**Como responsable de TI, quiero que la primera carga no me llene de avisos viejos y que lo ya
avisado no se repita, para que un aviso nuevo signifique algo.**

`#avisos` · CU-02

- ✓ Línea base silenciosa en la primera corrida, salvo lo publicado o agregado a KEV en los
  últimos 7 días (RF-111).
- ✓ Lo ya avisado no se repite, salvo que suba a inmediato (RF-111).
- ✓ Los hallazgos que desaparecen se proponen para cierre, nunca se cierran solos (RF-107, RF-111).

### HU-TI-07 · Historia · Aceptada

**Como responsable de TI, quiero marcar un hallazgo como en curso, mitigado o descartado, para
que el panel refleje lo que ya se decidió.**

`#estados` `#panel` · CU-06

- ✓ Solo una persona cambia el estado; para cerrar hace falta un comentario (RF-110).
- ✓ Queda guardado quién decidió (RF-110).
- ✓ La corrida automática nunca pisa la decisión humana (RF-107, RF-110).

### HU-TI-08 · Historia · Aceptada

**Como responsable de TI, quiero que el agente me deje redactado el análisis y los comunicados
para TI, usuarios y gerencia, para no escribir lo mismo tres veces por cada producto.**

`#analista` · CU-03

- ✓ El worker analiza los productos que exigen acción y guarda el resultado (RF-404).
- ✓ El agente solo lee: tres herramientas de lectura y encierro completo (RF-402, RF-403).
- ✓ Salida estructurada con el esquema del contrato (RF-401).
- ✓ KEV dicho de forma explícita y EPSS ausente como "sin dato" (RF-401).

### HU-TI-09 · Historia · Aceptada

**Como responsable de TI, quiero saber si el comunicado fue verificado y si lo redactó el agente
o el código, para decidir cuánto revisarlo antes de aprobarlo.**

`#verificador` `#panel` · CU-03

- ✓ El verificador descarta CVE, cifras, equipos, enlaces y comandos que no están en el origen,
  y las faltas de producto, KEV o equipos (RF-401, RF-826).
- ✓ El detalle del producto muestra "verificado" y el origen del texto (RF-604).
- ✓ Si no hay análisis del agente, se ve el respaldo con una píldora neutra (RF-607).

### HU-TI-10 · Historia · Aceptada

**Como responsable de TI, quiero aprobar el comunicado con mi nombre, para que quede claro quién
respondió por lo que se envió.**

`#aprobación` `#panel` · CU-03

- ✓ La aprobación exige un nombre y guarda quién y cuándo (RF-112, RF-604).
- ✓ Un análisis nuevo borra la aprobación anterior (RF-112).
- ✓ El respaldo también se puede aprobar (RF-607).

### HU-TI-11 · Historia · Aceptada

**Como responsable de TI, quiero que el radar siga dando texto útil aunque el modelo falle o no
haya créditos, para que la demo y el trabajo diario no dependan de la API.**

`#respaldo` · CU-03

- ✓ Ante cualquier falla del modelo, `analizar` devuelve `None` y se usa el respaldo (RF-403).
- ✓ Modo sin créditos con `--sin-agente`, `RADAR_SIN_AGENTE=1` o sin clave (RF-405).
- ✓ El respaldo no inventa cómo se explota ni promete versiones (regla 5).

### HU-TI-12 · Historia · Aceptada

**Como responsable de TI, quiero preguntarle a Claude Code qué está expuesto hoy, para consultar
el radar sin salir de la terminal.**

`#plugin` `#mcp` · CU-05

- ✓ Plugin instalable con servidor MCP, skill y comando `/radar:radar` (RF-704).
- ✓ Una acción por producto, equipos más expuestos y detalle por producto (RF-701).
- ✓ Cada respuesta dice de dónde salen los datos y si son de ejemplo (RF-702).

### HU-TI-13 · Historia · En desarrollo

**Como responsable de TI, quiero saber si alguna fuente no respondió en la última revisión, y
pedir una nueva, para no leer como "sin riesgo" lo que en realidad es "sin dato".**

`#fuentes` `#panel` · CU-07

- ✓ Se registra qué fuente respondió en cada descarga (RF-108).
- ✓ El panel lo dice arriba si alguna falló (RF-602).
- ✓ `POST /api/revisar` encola una descarga para el worker (`tests/test_api.py`).
- · Un botón en el panel que la pida.

### HU-TI-14 · Historia · Aceptada

**Como responsable de TI, quiero ver cuántas alertas inmediatas saldrían con otros umbrales,
para ajustar el ruido sin perder lo que está en KEV.**

`#umbrales` `#panel` · CU-08

- ✓ Gráfica por umbral de EPSS para cada umbral de CVSS, en comunicados, hallazgos o equipos (RF-113, RF-608).
- ✓ La celda vigente se marca y el piso de KEV no baja con ningún umbral (RF-608).

### HU-TI-15 · Historia · Cola

**Como responsable de TI, quiero que una alerta inmediata aprobada abra un ticket sola, para no
copiar a mano los datos que el radar ya tiene.**

`#escalamiento` · [escalamiento.md](escalamiento.md)

- · Abrir el ticket en la herramienta de la empresa con lo que ya deja la lista de pendientes
  de aviso por producto (RF-111).

### HU-TI-16 · Historia · Cola

**Como responsable de TI, quiero que el radar me avise cuando un ticket inmediato lleva 24 horas
en "nuevo", para saber cuándo hay que llamar.**

`#escalamiento` · [escalamiento.md](escalamiento.md)

- · Medir el tiempo en estado "nuevo" de cada hallazgo inmediato.
- · Avisar al pasar el plazo, o cuando vence el plazo de CISA para una CVE en KEV.

## Como lector (2)

### HU-LE-01 · Historia · Aceptada

**Como lector (gerencia o auditoría), quiero ver el panel y los comunicados sin poder cambiar
nada, para enterarme del riesgo sin tocar decisiones de TI.**

`#roles` `#panel` · CU-08, CU-09

- ✓ El rol `lector` ve el panel completo (`radar/api/acceso.py`).
- ✓ Cambiar estados o aprobar responde 403 con el rol `lector` (`tests/test_cuentas.py`).

### HU-LE-02 · Historia · Aceptada

**Como gerente, quiero un comunicado corto escrito para mí, para entender qué se hace y por qué
sin leer CVE.**

`#analista` · CU-03

- ✓ El análisis trae un comunicado para gerencia aparte del de TI y el de usuarios (RF-401).
- ✓ Pasa por el mismo verificador que los otros dos comunicados (RF-401).

## Como administrador (5)

### HU-AD-01 · Historia · En desarrollo

**Como administrador, quiero crear cuentas con rol lector, analista o admin, para que cada
persona solo pueda cambiar lo que le toca.**

`#roles` `#sesión` · CU-11

- ✓ Sesión por cookie con rol; el rol decide qué rutas puede usar (`radar/api/cuentas.py`, `tests/test_cuentas.py`).
- ✓ Claves cifradas con scrypt y bloqueo tras fallos (`tests/test_cuentas.py`).
- ✓ En Vercel, sin sesión y sin clave configurada la API responde error, no queda abierta (RF-601).
- · Su requerimiento en `requerimientos-funcionales.md`.

### HU-AD-02 · Historia · Aceptada

**Como administrador, quiero inscribir los equipos con un token de la organización, para que
reporten solos sin que yo reparta credenciales a mano.**

`#agente-local` · CU-10

- ✓ Sin `AGENTE_TOKEN_INSCRIPCION` la inscripción está cerrada (RF-811).
- ✓ El equipo canjea el token por su propia credencial y no guarda el token (RF-803).
- ✓ La credencial se guarda como SHA-256 y un equipo inscrito no se reinscribe sin retirarlo (RF-811).

### HU-AD-03 · Historia · Aceptada

**Como administrador, quiero revocar o retirar un equipo, para cortar un agente comprometido sin
tocar a los demás.**

`#agente-local` · CU-10

- ✓ La credencial de un equipo solo sirve para reportar por ese equipo (RF-812).
- ✓ Revocar y retirar desde la vista por equipo (RF-815).

### HU-AD-04 · Historia · Aceptada

**Como administrador, quiero ver qué hacer en cada equipo, con el comando cuando existe, para
repartir el trabajo por máquina y no solo por producto.**

`#agente-local` `#panel` · CU-10

- ✓ Vista por equipo con productos, sistema, paquetes, postura y cobertura (RF-815).
- ✓ Comandos solo desde plantillas cerradas, con la versión fijada solo si es exacta (RF-825).
- ✓ Fin de soporte del sistema y reglas de postura deterministas (RF-823, RF-824).
- ✓ Paquetes de Linux cruzados contra OSV, una acción por paquete (RF-816, RF-817).

### HU-AD-05 · Historia · En desarrollo

**Como administrador, quiero instalar el agente local con un paquete firmado, para desplegarlo en
toda la flota con las herramientas de siempre.**

`#agente-local` · [agente-local.md](agente-local.md)

- ✓ Instalación de desarrollo: tarea programada en Windows y temporizador de systemd (RF-804).
- · Binario, MSI, `.deb` y `.rpm` firmados.
- · Prueba automática de la instalación.

## Como responsable de seguridad (5)

### HU-SE-01 · Historia · Aceptada

**Como responsable de seguridad, quiero que el agente no obedezca instrucciones escondidas en el
inventario, para que quien edita un CSV no pueda decidir qué se comunica.**

`#guarda` `#inyección` · CU-04

- ✓ Todo texto del inventario se limpia y se marca como dato antes de llegar al modelo (regla 8, RF-703).
- ✓ Las herramientas del agente nunca devuelven programa ni proveedor crudos (RF-402).
- ✓ Lo que el texto escondido logre decir, el verificador lo descarta y se usa el respaldo (RF-401).

### HU-SE-02 · Historia · Aceptada

**Como responsable de seguridad, quiero que el agente no pueda escribir ni ejecutar nada, para
que un agente secuestrado no tenga con qué hacer daño.**

`#encierro` · CU-03, CU-04

- ✓ `permission_mode="dontAsk"`, `disallowed_tools`, `setting_sources=[]` y hooks con
  `on_failure="block"` (regla 7, RF-403).
- ✓ Conexión a la base de solo lectura que rechaza escrituras (RF-109).
- ✓ Cada llamada a herramienta queda en la traza, visible en el panel (RF-609).

### HU-SE-03 · Historia · Aceptada

**Como responsable de seguridad, quiero que una fila envenenada no saque a su equipo de los
hallazgos, para que el ataque "ignora este equipo" no funcione ni sin modelo.**

`#normalizador` `#ingesta` · CU-04

- ✓ Un nombre de equipo que no es hostname se sanea y la fila se cruza igual (RF-206).
- ✓ Texto agregado al programa, proveedor o versión: se normaliza con el prefijo y se cruza con
  sospecha registrada (RF-311).
- ✓ Lo que no se reconoce va a cobertura señalado como posible inyección, nunca en silencio (RF-705).

### HU-SE-04 · Historia · Aceptada

**Como responsable de seguridad, quiero aprobar cada escritura que pida Claude Code desde el
plugin, para que una conversación no cargue datos en la base compartida sin que yo lo vea.**

`#plugin` `#guarda` · CU-04

- ✓ El hook `PreToolUse` pide aprobación con un resumen limpio de lo que se va a escribir.
- ✓ Si el hook falla o la sesión no es interactiva, la escritura se niega.

### HU-SE-05 · Historia · Aceptada

**Como responsable de seguridad, quiero medir la defensa con y sin protección sobre casos de
inyección escritos aparte, para defender la tesis con cifras y no con promesas.**

`#evals` · CU-04

- ✓ Suite de inyección en rondas, cada una escrita sin reajustar sobre la anterior, con dos brazos.
- ✓ Corrida con el analista real además del agente simulado.
- ✓ Las cifras salen de `evals/reporte.md`, nunca a mano (regla 10).
- ✓ Lo que la defensa no garantiza está en [LIMITES.md](LIMITES.md).

## Como quien opera el radar (2)

### HU-OP-01 · Historia · Aceptada

**Como quien opera el radar, quiero que el worker se niegue a escribir en Turso compartido salvo
que lo pida, para que una prueba local no pise los datos de todos.**

`#worker` · CU-03

- ✓ Con `TURSO_*` en el entorno y sin `--turso`, el worker no corre (RF-406).
- ✓ Con `RADAR_SQLITE` o sin `TURSO_*` corre en local (RF-406).

### HU-OP-02 · Historia · Aceptada

**Como quien opera el radar, quiero un inventario de prueba reproducible con su respuesta
conocida, para comprobar cualquier cambio sin depender de datos reales.**

`#datos-de-prueba` · CU-01, CU-02

- ✓ Inventario generado en CSV y Excel con semilla fija (RF-306).
- ✓ La respuesta conocida sale del snapshot, nunca del cruce del proyecto (RF-306).
- ✓ Integración de punta a punta sin piezas simuladas (RF-309).
