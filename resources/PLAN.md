# Radar de vulnerabilidades: plan completo para la hackatón

Última actualización: 14 de noviembre de 2026 (se agregó el plugin de Claude Code).

Este archivo reúne todo lo definido para el proyecto: el evento, las decisiones tomadas, la arquitectura, el stack, los contratos de datos, las piezas a construir, la validación, el reparto del equipo, la preparación y lo que falta por confirmar.

> **Este documento va en `.gitignore` y nunca se sube al repositorio**, igual que toda la carpeta `resources/` (semilla, snapshot de NVD) y el archivo `.env`. Antes del primer `git add`, el `.gitignore` debe existir con esas entradas (sección 23).

La **Parte B** (jurado y pitch) es privada.

Convención de este documento:

- **Verificado:** confirmado en documentación oficial o con una herramienta durante la planeación.
- **Del detector actual:** aprendido del detector que ya funciona en el monitor de GTI. Es conocimiento, no código que se reutilice.
- **Propuesto:** diseño sugerido, ajustable por el equipo.
- **Estimado:** horas y tiempos calculados a ojo, sin medición.
- **Por verificar:** dato citado de memoria o sin probar.

---

## Índice

Parte A, proyecto (se puede compartir con el equipo)

1. El evento
2. Decisiones tomadas
3. Qué es el proyecto
4. Tesis y las cuatro preguntas de la entrega
5. Arquitectura
6. Stack y herramientas
7. Fuentes de datos públicas
8. Lógica del núcleo
9. Contratos de datos
10. Base de datos en Turso
11. API y dashboard en Vercel
12. Normalizador de nombres a CPE
13. Analista con Claude Agent SDK
14. Servidor MCP y plugin de Claude Code
15. Datos de prueba
16. Validación y evals
17. Seguridad, límites y riesgo dual
18. Las 16 piezas a construir
19. Reparto para cinco personas
20. Cronograma de las 8 horas
21. Preparación antes del evento
22. Variables de entorno
23. Estructura del repositorio y documentación
24. Riesgos del día y respaldos
25. Por confirmar y por verificar
26. Qué queda por fuera
27. Fuentes consultadas

Parte B, estrategia (privada)

28. Jurado y mentores
29. Matriz de ganchos por juez
30. Pitch de tres minutos
31. Generar la necesidad de adquisición
32. Preguntas difíciles
33. Lo que resta puntos
34. Cifras de calibración

---

# Parte A: proyecto

## 1. El evento

Datos del folleto de la Defensive Acceleration Hackathon (def/acc) de AI Safety Colombia.

| Dato | Valor |
|---|---|
| Tema | Aceleración defensiva en seguridad de IA |
| Duración | 8 horas de trabajo continuo |
| Equipos | De 2 a 5 personas |
| Formación de equipos | Quien aplique solo arma equipo en la sesión de apertura, a las 8:30 a.m. |
| Requisito | Mayores de 18 años; no hace falta experiencia previa en seguridad de IA |
| Premios | COP 1.000.000 al primer puesto, COP 500.000 al segundo y COP 500.000 al tercero |
| Patrocinio | Oracle Academy |
| Evaluación | Los jueces evalúan los entregables al cierre del día; los mentores acompañan durante la jornada |
| Fecha y lugar | Sábado 14 de noviembre de 2026, de 8:00 a.m. a 8:00 p.m., Universidad de los Andes, Bogotá. Trabajo en el salón ML 607 (edificio Mario Laserna); pitches en el Auditorio ML C |
| Organizan | IEEE Computer Society Uniandes y AI Safety Colombia |
| Contactos del día | Jose Gelves (AI Safety Colombia) y Daniel Diab (IEEE CS Uniandes), en ML 607. Antes del evento: equipo@aisafetycolombia.org |

### Datos de la guía oficial

Fuente: [guía para equipos](https://www.aisafetycolombia.org/defacchackathon/guia), leída el 13 de noviembre de 2026.

**Horario**

| Hora | Qué pasa |
|---|---|
| 8:00 a.m. | Registro y entrada al campus |
| 8:30 a.m. | Apertura, presentación del reto, formación de equipos |
| 9:00 a.m. | Empieza el sprint de 8 horas |
| ~12:30 p.m. | Almuerzo (lo dan ellos) |
| 4:00 p.m. | Hora recomendada por la organización para entregar |
| 5:00 p.m. | Cierre de entregas, en punto, sin tiempo extra |
| 5:10 p.m. | Pitches de 3 minutos, sin preguntas |
| 6:40 p.m. | Deliberación del jurado |
| 7:15 p.m. | Premiación |
| 7:30 p.m. | Cierre; todos salen antes de las 8:00 p.m. |

**Reglas**

- **Asistentes de IA:** permitidos. Hay que citar todo el código, los datos y lo que se generó con IA.
- **Datos:** públicos anonimizados o sintéticos. Nada de voces, caras ni correos de personas reales. El inventario de prueba cumple esto.
- **Pruebas:** no atacar, escanear ni probar sistemas reales de terceros sin permiso escrito. Trabajar con bancos de prueba, laboratorios o datos sintéticos. La suite de inyección ataca solo al propio sistema; consultar NVD, KEV y EPSS no es atacar.
- **Exploits:** no publicar exploits ni malware funcional. Una vulnerabilidad real se reporta en privado y queda fuera de la entrega.
- **Uso dual:** un proyecto que facilita sobre todo ataques sin mitigación no puede ganar premio.
- **Código previo:** la guía no lo menciona. Igual se decidió empezar de cero.
- **Oracle Academy:** sus herramientas exigen un correo @uniandes.edu.co. El proyecto no las necesita.

**Qué se entrega** (una sola vez, en aisafetycolombia.org/defacchackathon/entregar, abierto de 7:00 a.m. a 5:00 p.m.; correcciones solo por correo a equipo@aisafetycolombia.org antes de las 5:00 p.m.)

- Nombre del equipo.
- Integrantes (2 a 5) con el correo con el que aplicó cada uno.
- Título y track.
- Resumen de 150 a 250 palabras.
- Enlace al repositorio (GitHub o Colab) o a la demo.
- Ficha técnica en PDF: máximo 2 páginas y 10 MB. Debe cubrir amenaza, defensa, cómo se evaluó, resultados, límites y riesgo de uso dual.

La guía no pide video.

**Criterios de evaluación:** tres, cada uno de 1 a 5, con el mismo peso (máximo 15).

| Criterio | Qué preguntan | Cómo lo responde el proyecto |
|---|---|---|
| Impacto potencial e innovación | ¿Ataca un riesgo real de IA con una idea nueva? ¿Favorece a los defensores? | Agente que lee inventarios no confiables y no se deja secuestrar; defiende a empresas sin equipo de seguridad |
| Calidad de ejecución | ¿Funciona, se probó y los resultados sostienen lo que se afirma? | Desplegado, con datos de respuesta conocida y la suite de inyección medida con defensa y sin defensa |
| Presentación y claridad | ¿Un juez entiende qué se hizo y qué se encontró en 2 minutos? | Pitch con una sola tesis, una demo corta y una lámina de números |

"Un 3 es trabajo sólido para un día. Un 5 es excepcional." En empate gana el de mayor puntaje en impacto.

**Consecuencias para el plan**

- **El trabajo termina a las 5:00 p.m.** y conviene entregar a las 4:00 p.m. El cronograma (sección 20) se ajustó a la hora real.
- **El pitch no tiene preguntas** y los jueces leen la ficha mientras el equipo presenta. Las respuestas difíciles van en la ficha, no en el escenario.
- **La ficha técnica es el entregable que más se lee.** Dos páginas con amenaza, defensa, evaluación, resultados, límites y uso dual.
- **Hay que citar lo generado con IA.** El repositorio lleva un archivo de créditos.

**Los seis frentes temáticos** (cada equipo escoge uno):

1. Track 1: Seguridad de agentes e inyección de instrucciones (MCP, AgentDojo)
2. Track 2: Control de IA, monitoreo y detección de sabotaje (ControlArena, Inspect)
3. Track 3: Ciberdefensa automatizada y verificación formal (DafnyBench, CyberSecEval)
4. Track 4: Defensa epistémica, procedencia C2PA y detección de suplantación (AASIST)
5. Track 5: Seguridad de infraestructura de IA y gobernanza defensiva (No-Code, SL1 a SL5)
6. Track 6: Riesgos multiagente: colusión, explotación y resiliencia cooperativa (Concordia, Melting Pot)

El Track 5 no exige programar.

**Las cuatro preguntas que debe responder la entrega:**

1. **El vector de riesgo:** definir con precisión qué ataque, fallo de control o vulnerabilidad de IA busca mitigar el proyecto.
2. **El mecanismo o protocolo defensivo:** construir el prototipo, monitor de supervisión, verificador formal o estándar que contiene la amenaza.
3. **Validación empírica:** medir la efectividad con benchmarks, casos de prueba o escenarios concretos (ataques neutralizados, tasa de detección, falsos positivos o invariantes verificados).
4. **Límites y riesgo dual:** documentar con honestidad dónde falla la defensa y verificar que el trabajo no facilite usos ofensivos.

## 2. Decisiones tomadas

En el orden en que se tomaron.

| Decisión | Detalle |
|---|---|
| Equipo | Cerca de 5 personas |
| Código | El proyecto empieza de cero. No se copia código del detector actual; se usa como diseño de referencia |
| Datos de inventario | De prueba. Los genera un script con casos sembrados y respuesta conocida |
| Fuentes de vulnerabilidades | Reales y públicas (NVD, KEV, EPSS), descargadas el día del evento |
| Costo | Todo en capa gratuita, salvo la API de Claude |
| IA | Claude Agent SDK para el analista, con créditos propios de API |
| Interfaz | Una página con el dashboard |
| Base de datos | Turso |
| Infraestructura | Vercel |
| Plugin | El servidor MCP se distribuye como plugin de Claude Code, con la guarda (hooks) incluida. Reemplaza a la pieza 10, no se suma (sección 14) |

## 3. Qué es el proyecto

Un radar permanente de brechas de seguridad. Cruza el inventario de software de una empresa con las vulnerabilidades publicadas, dice qué equipos están expuestos, prioriza lo que ya se está explotando y entrega análisis, forma de solventarlo y un comunicado listo para que TI lo apruebe.

El inventario puede llegar de varias fuentes: un RMM, un CSV, un Excel o una integración por MCP.

**Comprador objetivo:** el responsable de TI de una empresa de 50 a 200 equipos, sin equipo de seguridad, con un RMM o una hoja de cálculo como único inventario.

## 4. Tesis y las cuatro preguntas de la entrega

El evento es de seguridad de IA, no de ciberseguridad general. El radar se presenta como **un agente defensor que no se deja secuestrar**.

> Un radar que cruza el inventario de una empresa con las vulnerabilidades que se están explotando hoy, y que demuestra con pruebas que un inventario envenenado no puede tomar control del agente que redacta las alertas.

Un detector de CVE a secas es un producto de ciberseguridad. Lo que lo vuelve un proyecto def/acc son dos cosas: defiende a quien no tiene equipo de seguridad, y trata al propio agente como superficie de ataque.

| Pregunta de la entrega | Respuesta del proyecto |
|---|---|
| Vector de riesgo | Software con vulnerabilidades explotadas que la empresa no sabe que tiene. Vector propio de IA: el inventario es texto no confiable que llega a un agente, y un nombre de programa puede traer una instrucción escondida (inyección indirecta de prompts) |
| Mecanismo defensivo | Cruce determinista por versión, priorización con KEV y EPSS, y un agente encerrado: solo herramientas de lectura, permisos que niegan lo no aprobado, hooks antes y después de cada herramienta, salida estructurada, verificador y aprobación humana |
| Validación empírica | Sobre datos de prueba con respuesta conocida: detección, falsos positivos, cobertura del normalizador y tasa de éxito de inyección con defensa y sin defensa |
| Límites y riesgo dual | El mapa de exposición también le sirve a un atacante. Se documenta quién puede verlo, qué datos nunca salen y qué no se detecta |

Frente recomendado para inscribirse: **Track 1, seguridad de agentes e inyección de instrucciones**. La pieza central de la validación (la suite de inyección por inventario contra un agente con herramientas MCP) es exactamente el tema de ese frente. En el Track 3 el proyecto sería un detector de CVE más, y la parte de IA quedaría como accesorio.

Si el Track 1 se llena o la organización lo pide, la segunda opción es el Track 3.

## 5. Arquitectura

Tres lugares, con la base de datos como punto de encuentro.

| Pieza | Dónde corre | Por qué |
|---|---|---|
| Dashboard | Vercel, página estática en `public/` | Vercel la sirve directo, sin framework ni compilación |
| API: carga de inventario, normalización, cruce, estados | Vercel, con FastAPI | El cruce es código y responde al instante |
| Datos: inventario, vulnerabilidades, hallazgos, análisis, trabajos | Turso | Base compartida por el panel, el worker y los cinco portátiles |
| Descarga de fuentes y analista con Claude Agent SDK | Worker aparte | El SDK lanza un proceso con disco propio; su guía pide contenedor o sandbox |

**Por qué el agente va fuera de Vercel (verificado):** la guía de hospedaje del Agent SDK dice que el SDK lanza y supervisa un proceso `claude` que es dueño de una consola, un directorio de trabajo y archivos de sesión en disco. Recomienda contenedores o sandboxes, con cerca de 1 GiB de RAM, 5 GiB de disco y 1 CPU por agente como punto de partida. Una función de Vercel no es ese entorno.

**Dónde corre el worker:**

- **En la demo:** un portátil. Revisa cada pocos segundos si hay trabajos nuevos en Turso. Es lo más confiable.
- **Para que quede permanente:** el mismo worker en GitHub Actions (gratis en repositorio público), con horario y con disparo manual. Por verificar: no se ha probado el Agent SDK en GitHub Actions. Del detector actual: GitHub retrasa y descarta corridas programadas en cuentas gratuitas.
- **Alternativa dentro de Vercel:** Vercel Sandbox encaja con lo que pide la guía, pero no se evaluó y no es para el día del evento.

**Flujo de punta a punta:**

1. El worker descarga KEV, las CVE de los productos sembrados y EPSS, y las guarda en Turso (primera hora del día).
2. Alguien sube un inventario (CSV o Excel) desde el dashboard, o llega por MCP.
3. La API normaliza cada programa a un CPE, cruza por versión contra las CVE guardadas, prioriza y guarda los hallazgos. El dashboard los muestra de inmediato.
4. La API deja un trabajo en la tabla de trabajos.
5. El worker toma el trabajo y corre el analista sobre los hallazgos nuevos que exigen acción: análisis, remediación y borrador de comunicado.
6. El verificador revisa el comunicado contra los datos de origen. Si algo no coincide, se guarda el texto armado por código.
7. El dashboard, que consulta la API cada pocos segundos, muestra el análisis cuando llega. Una persona aprueba el comunicado.

**Beneficio de seguridad de esta separación:** lo que lee texto no confiable (el agente) queda aislado de lo que atiende a los usuarios (la capa web).

## 6. Stack y herramientas

### Stack

| Capa | Elección | Por qué |
|---|---|---|
| Lenguaje y entorno | Python 3.12 con `uv` | El mismo entorno en los cinco portátiles en minutos. El Agent SDK exige Python 3.10 o superior |
| Contratos | Pydantic | Se fijan en la primera media hora y cada frente trabaja contra ellos |
| Fuentes | `httpx` | Clientes cortos para NVD, KEV y EPSS, con reintentos y pausa entre peticiones |
| Base de datos | Turso, con el driver `turso_serverless` | SQLite en la nube; el driver conecta por HTTP y sirve igual en Vercel y en el worker |
| API | FastAPI en Vercel | Vercel lo despliega sin configuración |
| Dashboard | HTML y JavaScript sin framework, con Chart.js | Sin paso de compilación ni dependencias de Node |
| Ingesta | `pandas` y `openpyxl` | Un solo lector para CSV y Excel |
| Datos de prueba | Script propio con `random` y semilla fija | El banco de pruebas se reproduce igual en cualquier máquina |
| Normalizador | `rapidfuzz`, con desempate por llamada directa a la API de Claude | Propone candidatos reales de CPE; el modelo solo elige entre ellos |
| Analista | Claude Agent SDK (`claude-agent-sdk`), modelo `claude-opus-5-5` | Agente con herramientas propias, permisos y hooks |
| MCP | SDK oficial de MCP para Python | Servidor de ingesta y consulta |
| Pruebas y evals | `pytest` | La suite de inyección y las mediciones corren con un comando |
| Secretos en local | `python-dotenv` | El Agent SDK no lee el `.env` por su cuenta (verificado) |

### Herramientas de trabajo

| Para qué | Herramienta |
|---|---|
| Código compartido | Un repositorio público en GitHub, una carpeta por frente, ramas cortas |
| Pruebas automáticas | GitHub Actions corriendo `pytest` en cada cambio |
| Worker permanente | GitHub Actions con horario y disparo manual |
| Despliegue | CLI de Vercel (`vercel`, `vercel dev`, `vercel env pull`) |
| Escribir más rápido | El asistente de código que cada integrante tenga, si el evento lo permite |
| Estilo sin discusiones | `ruff` |
| Probar el servidor MCP | MCP Inspector |
| Probar y validar el plugin | Claude Code 2.1.295 o superior: `claude --plugin-dir ./plugin` y `claude plugin validate` |
| Respaldo de la demo | Grabador de pantalla del sistema |
| Red de respaldo | Un teléfono compartiendo datos |

### Costo

| Componente | Costo |
|---|---|
| Vercel (plan Hobby), Turso (plan gratuito), GitHub (repositorio público), NVD, KEV, EPSS, librerías | Gratis |
| API de Claude | De pago, con créditos propios |

Por verificar: los límites actuales del plan gratuito de Turso.

### Modelos

- **Analista:** `claude-opus-5-5`.
- **Desempate del normalizador:** llamada directa con el SDK normal de Anthropic (`anthropic`), no con el Agent SDK. Son cientos de decisiones cortas y el Agent SDK arranca un proceso por consulta. Mismo modelo por defecto, con esfuerzo bajo (`output_config={"effort": "low"}`). Si la latencia estorba, bajar a `claude-haiku-5-5` es decisión del equipo.

## 7. Fuentes de datos públicas

Las tres son gratuitas y no piden credenciales, salvo la clave opcional de NVD.

### NVD (NIST), API 2.0

Del detector actual, comprobado contra la API real:

| Aspecto | Detalle |
|---|---|
| Base | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Consulta por producto | Parámetro `virtualMatchString` con el CPE parcial, por ejemplo `cpe:2.3:a:nodejs:node.js`. No usar `cpeName`: exige el CPE completo de 13 campos y responde 404 ante uno parcial |
| Consulta incremental | `lastModStartDate` y `lastModEndDate`, siempre juntos, con rango máximo de 120 días. Formato `2026-11-03T00:00:00.000` en UTC |
| Un CVE concreto | Parámetro `cveId` |
| Paginación | `startIndex`, `resultsPerPage` (tope 2000) y `totalResults` en la respuesta |
| Excluir rechazadas | Parámetro `noRejected` (sin valor) |
| Límites | 5 peticiones cada 30 segundos sin clave; 50 con clave |
| Pausa recomendada | 6 segundos entre peticiones sin clave; 0.7 con clave |
| Clave | Gratuita, se pide en `nvd.nist.gov/developers/request-an-api-key`. Va en la cabecera `apiKey` |
| Errores | 429: esperar lo que diga `Retry-After` (o 30 segundos). 403: la clave no sirve, no reintentar. 5xx y fallos de red: reintentar con espera creciente |

**Campos que se usan de cada CVE:**

- `id`, `published`, `lastModified`, `vulnStatus`.
- `descriptions`: tomar la de idioma `es` si existe; si no, `en`.
- `metrics`: tomar la primera que exista en este orden: `cvssMetricV40`, `cvssMetricV31`, `cvssMetricV30`, `cvssMetricV2`. De ahí salen `baseScore`, `baseSeverity` y `vectorString`. En CVSS 2.0 la severidad va un nivel arriba de `cvssData`. Una CVE reciente puede no tener métrica: no inventar una.
- `weaknesses`: los valores que empiezan por `CWE-`.
- `references`: URL y, a diferencia del detector actual, también sus etiquetas (`Patch`, `Vendor Advisory`, `Mitigation`), que sirven para la remediación.
- `configurations[].nodes[].cpeMatch[]`: de cada entrada, `vulnerable`, `criteria` (el CPE), `versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`.

**Dos advertencias del detector actual:**

- Una entrada con `vulnerable` en falso es un requisito del entorno (por ejemplo el sistema operativo), no el producto vulnerable. Hay que ignorarla, o media flota saldría afectada por tener Windows.
- Desde abril de 2026 NVD no enriquece todas las CVE con CPE. Una CVE sin `configurations` no empareja con nada. Se marca y se cuenta aparte.

**NVD empareja de forma amplia:** devuelve la CVE si afecta a cualquier versión del producto. El recorte por versión lo hace el código propio.

### KEV (CISA)

- `GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Un solo archivo de unos 1.8 MB, con `catalogVersion`, `dateReleased`, `count` y `vulnerabilities[]`.
- Cada entrada: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `shortDescription`, `requiredAction`, `dateAdded`, `dueDate`, `knownRansomwareCampaignUse` (vale `Known` cuando se usó en ransomware), `cwes`.
- No hay consulta incremental: el archivo es el catálogo. Tenía 1766 entradas el 30 de octubre de 2026.
- Qué significa: explotación confirmada en el mundo real.

### EPSS (FIRST)

- `GET https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2&limit=100`
- Acepta varios CVE separados por coma. Lotes de 100.
- Devuelve `data[]` con `cve`, `epss` (de 0 a 1), `percentile` y `date`.
- Qué significa: probabilidad de explotación en los próximos 30 días.
- Una CVE que FIRST no conoce no aparece. No se le inventa un cero.

### Diccionario de CPE

Lo necesita el normalizador para proponer candidatos reales. Por verificar: cómo se consulta o descarga. Se recuerda un endpoint de búsqueda por palabra clave en `/rest/json/cpes/2.0`, sin confirmar.

### Plan de descarga del día

Se hace una sola vez, en la primera hora, y todo queda en Turso.

1. KEV completo (una petición).
2. Las CVE de cada producto sembrado en los datos de prueba (una consulta por par `vendor:producto`).
3. EPSS de esas CVE, en lotes de 100.
4. Candidatos de CPE para el normalizador.

Con muchos equipos en la misma red, la cuota de NVD puede fallar. Por eso conviene la clave de NVD y un teléfono compartiendo datos como respaldo.

## 8. Lógica del núcleo

Todo esto es código determinista. El modelo no participa.

### Comparación de versiones

- Leer la versión como una tupla de enteros, con hasta cuatro componentes.
- Rellenar con ceros para que `1.0` y `1.0.0` cuenten igual.
- Si la versión no se puede leer, devolver "no comparable". Nunca adivinar.

**Tres errores del detector actual que el código nuevo debe evitar:**

1. **Sufijos:** leer solo los números hace que `1.2.3-beta` y `1.2.3` cuenten como iguales. Hay que tratar los sufijos de prelanzamiento.
2. **Versión objetivo con límite inclusivo:** si el rango usa `versionEndIncluding`, esa versión sigue afectada. No se puede decir "actualizar a X".
3. **Versión objetivo en rangos acotados:** un rango con límite inferior y superior sí tiene versión objetivo; el detector actual la deja vacía.

### Regla de afectación

Para un rango y una versión instalada:

1. Si el CPE trae versión fija: afecta si son iguales.
2. Si no trae versión ni límites: afecta a todas las versiones. El hallazgo se marca como "no preciso".
3. Si hay límite inferior: no afecta si la versión es menor, o igual cuando el límite es excluyente.
4. Si hay límite superior: no afecta si la versión es mayor, o igual cuando el límite es excluyente.
5. Si la versión instalada falta o no es comparable: no hay hallazgo. Se cuenta como falta de cobertura.

Si varios rangos de la misma CVE emparejan, manda el más acotado.

### Versión objetivo (regla corregida)

- Por CVE: si el rango usa `versionEndExcluding`, la versión de arreglo es ese valor. Si usa `versionEndIncluding`, solo se puede decir "posterior a X".
- Por producto: la mayor de las versiones de arreglo de sus CVE.
- Si alguna CVE del grupo no acota versión, no se promete ninguna.

### Priorización

| Prioridad | Regla | Qué pasa |
|---|---|---|
| Inmediato | Afecta algo propio y además está en KEV, o EPSS llega a 0.10, o CVSS llega a 9.0 | Alerta y comunicado ya |
| Semanal | Afecta algo propio y CVSS llega a 7.0, sin señal de explotación | Al resumen semanal |
| Informativo | Afecta algo propio, sin lo anterior | Solo al panel |
| Boletín | Está en KEV pero no empareja con ningún activo | Queda en el panel para que una persona lo mire |

Los tres umbrales (EPSS 0.10, CVSS 9.0, CVSS 7.0) son ajustables por variable de entorno.

Cada hallazgo guarda sus razones en texto legible, por ejemplo: "Explotación confirmada en el mundo real (CISA KEV)", "Probabilidad de explotación del 83% en 30 días (EPSS)", "Gravedad crítica, CVSS 9.2".

Orden de la lista: prioridad, luego KEV, luego CVSS de mayor a menor.

### Agrupación para comunicar

Se comunica por producto, no por CVE ni por versión. Un grupo dice: producto, versiones instaladas, cuántos equipos, cuántas CVE (sin repetir), cuántas en KEV, si hay ransomware, peor CVSS, peor EPSS, versión objetivo y razones consolidadas.

### Estados de un hallazgo

`nuevo`, `en_curso`, `mitigado`, `descartado`, con comentario y quién lo decidió. El estado solo lo cambia una persona. La corrida automática actualiza los datos de la CVE pero nunca pisa el estado.

### Lo que el radar agrega frente al detector actual

- **Cruce disparado por cambio de inventario:** al cargar un inventario nuevo se cruza contra todas las CVE ya guardadas, no solo contra las nuevas.
- **Cierre automático:** si un equipo ya no tiene la versión afectada, el hallazgo se propone como resuelto.

### Reglas de diseño que no se negocian

1. **Sin comparación no hay hallazgo.** Lo ilegible se cuenta como falta de cobertura.
2. **Fuente caída no es cero.** Si NVD, KEV o EPSS no respondieron, el resumen lo dice.
3. **Línea base silenciosa.** La primera corrida no avisa todo lo acumulado.
4. **Sin repetir avisos.** Lo ya comunicado queda marcado.
5. **Una acción por producto.**
6. **El modelo no es punto de falla.** Siempre hay un texto de respaldo armado por código.
7. **La decisión humana manda.**

## 9. Contratos de datos

Se definen como modelos de Pydantic en la primera media hora. Los nombres de campo son propuestos.

| Contrato | Campos |
|---|---|
| Fila de inventario | `equipo`, `programa`, `version`, `proveedor`, `sistema`, `fuente` (csv, excel, mcp, rmm), `cargado` |
| Activo | `clave` (`producto@version`), `producto`, `nombre`, `version`, `cpes` (lista de pares `vendor:producto`), `equipos`, `confianza_cpe` |
| CVE | `id`, `publicada`, `modificada`, `estado`, `descripcion`, `cvss`, `severidad`, `vector`, `version_cvss`, `cwes`, `referencias` (URL y etiquetas), `rangos`, `sin_productos` |
| Rango | `cpe`, `vendor`, `producto`, `version`, `desde`, `desde_incluye`, `hasta`, `hasta_incluye` |
| Señales | KEV por CVE (`ransomware`, `plazo`, `accion`, `agregada`) y EPSS por CVE (`epss`, `percentil`, `fecha`) |
| Hallazgo | `id` (`CVE\|activo`), `cve`, `activo`, `producto`, `version_instalada`, `equipos`, `prioridad`, `por_que`, `preciso`, `rango`, `kev`, `ransomware`, `epss`, `cvss`, `estado`, `comentario`, `por`, `detectado` |
| Grupo | `producto`, `versiones`, `equipos`, `cves`, `en_kev`, `ransomware`, `peor_cvss`, `peor_epss`, `version_objetivo`, `por_que` |
| Análisis | `hallazgo` o `producto`, `resumen`, `como_se_explota` (solo lo que diga la fuente), `remediacion`, `mitigacion_temporal`, `comunicado_ti`, `comunicado_usuarios`, `verificado`, `origen` (agente o respaldo) |
| Trabajo | `id`, `tipo` (descargar, analizar), `estado` (pendiente, en curso, hecho, fallido), `creado`, `terminado`, `detalle` |

## 10. Base de datos en Turso

### Aprovisionamiento (verificado)

Turso está en el Marketplace de Vercel con el identificador `tursocloud/database`. El día del evento:

```bash
vercel link
vercel integration add tursocloud/database
vercel env pull
```

Las variables `TURSO_DATABASE_URL` y `TURSO_AUTH_TOKEN` quedan en el proyecto de Vercel y, con el último comando, en el `.env` local. Si la instalación pide un paso en el navegador, lo completa el dueño de la cuenta.

### Conexión desde Python (verificado)

```python
import os
import turso_serverless

conn = turso_serverless.connect(
    os.environ["TURSO_DATABASE_URL"],
    auth_token=os.environ["TURSO_AUTH_TOKEN"],
)
conn.execute("INSERT INTO trabajos (tipo, estado) VALUES (?, ?)", ("analizar", "pendiente"))
conn.commit()
for fila in conn.execute("SELECT * FROM trabajos"):
    print(fila)
```

El driver `turso_serverless` conecta por HTTP: no necesita conexiones persistentes ni archivo local. La documentación distingue dos motores (bases Turso y bases libSQL, que usan el paquete `libsql`). Por verificar al crear la base: cuál de los dos corresponde.

### Esquema (propuesto)

```sql
CREATE TABLE inventario (
  id INTEGER PRIMARY KEY,
  equipo TEXT NOT NULL,
  programa TEXT NOT NULL,
  version TEXT,
  proveedor TEXT,
  sistema TEXT,
  fuente TEXT NOT NULL,
  cargado TEXT NOT NULL
);

CREATE TABLE programa_cpe (
  programa TEXT PRIMARY KEY,
  vendor TEXT,
  producto TEXT,
  confianza REAL,
  metodo TEXT,            -- exacto, difuso, modelo, ninguno
  candidatos TEXT         -- JSON con los candidatos considerados
);

CREATE TABLE cpe_diccionario (
  vendor TEXT NOT NULL,
  producto TEXT NOT NULL,
  titulo TEXT,            -- nombre legible, contra el que compara rapidfuzz
  PRIMARY KEY (vendor, producto)
);

CREATE TABLE cves (
  id TEXT PRIMARY KEY,
  publicada TEXT,
  modificada TEXT,
  descripcion TEXT,
  cvss REAL,
  severidad TEXT,
  vector TEXT,
  cwes TEXT,              -- JSON
  referencias TEXT,       -- JSON con url y etiquetas
  sin_productos INTEGER
);

CREATE TABLE cve_rangos (
  cve TEXT NOT NULL,
  vendor TEXT NOT NULL,
  producto TEXT NOT NULL,
  version TEXT,
  desde TEXT,
  desde_incluye INTEGER,
  hasta TEXT,
  hasta_incluye INTEGER
);
CREATE INDEX idx_rangos_producto ON cve_rangos (vendor, producto);

CREATE TABLE kev (
  cve TEXT PRIMARY KEY,
  fabricante TEXT,
  producto TEXT,
  accion TEXT,
  agregada TEXT,
  plazo TEXT,
  ransomware INTEGER
);

CREATE TABLE epss (
  cve TEXT PRIMARY KEY,
  epss REAL,
  percentil REAL,
  fecha TEXT
);

CREATE TABLE hallazgos (
  id TEXT PRIMARY KEY,    -- CVE|activo
  cve TEXT NOT NULL,
  producto TEXT NOT NULL,
  version_instalada TEXT,
  equipos TEXT,           -- JSON
  prioridad TEXT NOT NULL,
  por_que TEXT,           -- JSON
  preciso INTEGER,
  rango TEXT,
  estado TEXT NOT NULL DEFAULT 'nuevo',
  comentario TEXT,
  por TEXT,
  detectado TEXT,
  avisado INTEGER DEFAULT 0
);

CREATE TABLE analisis (
  producto TEXT PRIMARY KEY,
  contenido TEXT,         -- JSON con la salida estructurada
  verificado INTEGER,
  origen TEXT,            -- agente o respaldo
  creado TEXT
);

CREATE TABLE cobertura (
  equipo TEXT,
  programa TEXT,
  version TEXT,
  motivo TEXT             -- sin version, no comparable, sin cpe
);

CREATE TABLE trabajos (
  id INTEGER PRIMARY KEY,
  tipo TEXT NOT NULL,
  estado TEXT NOT NULL DEFAULT 'pendiente',
  creado TEXT,
  terminado TEXT,
  detalle TEXT
);

CREATE TABLE ejecuciones (
  id INTEGER PRIMARY KEY,
  inicio TEXT,
  fin TEXT,
  tipo TEXT,
  fuentes TEXT,           -- JSON: que fuente respondio
  resumen TEXT,
  error TEXT
);

CREATE TABLE trazas (
  id INTEGER PRIMARY KEY,
  momento TEXT,
  herramienta TEXT,
  entrada TEXT,
  decision TEXT           -- permitida, negada, limpiada
);
```

### Token de solo lectura para el agente

Por verificar: se recuerda que Turso permite crear tokens de solo lectura. Si existe, las herramientas del analista usan ese token y no pueden escribir ni aunque secuestren al agente. El código del worker, que sí escribe, usa el token normal.

## 11. API y dashboard en Vercel

### Despliegue de FastAPI (verificado)

- Vercel detecta la app si hay un archivo de entrada `app.py`, `index.py`, `server.py`, `main.py`, `wsgi.py` o `asgi.py` (en la raíz, en `src/` o en `app/`) con una variable `app` que sea la instancia de FastAPI.
- Los archivos estáticos van en `public/`; Vercel los sirve desde su red de distribución.
- Las dependencias se declaran en `requirements.txt` o `pyproject.toml`.
- En local: `vercel dev`.
- Límite de tiempo de una función: 300 segundos por defecto. Para cambiarlo, en `vercel.json`:

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "functions": {
    "app.py": { "maxDuration": 60 }
  }
}
```

- El cuerpo de una petición no puede pasar de 4.5 MB. Un inventario de prueba cabe de sobra.
- Del detector actual: en el plan Hobby las tareas programadas de Vercel corren una vez al día. Por eso el horario del radar va en GitHub Actions.

### Rutas (propuestas)

| Método y ruta | Qué hace |
|---|---|
| `POST /api/inventario` | Recibe un CSV o Excel, lo normaliza, cruza y guarda. Deja un trabajo de análisis |
| `GET /api/resumen` | Cifras de cabecera, cobertura y estado de las fuentes |
| `GET /api/hallazgos` | Lista con filtros por prioridad, KEV y texto |
| `GET /api/productos` | Hallazgos agrupados por producto |
| `GET /api/analisis/{producto}` | Análisis, remediación y comunicado |
| `POST /api/hallazgos/{id}/estado` | Cambia el estado, con comentario |
| `POST /api/comunicado/{producto}/aprobar` | Marca el comunicado como aprobado |
| `POST /api/revisar` | Deja un trabajo de descarga y cruce |
| `GET /api/umbrales` | Datos del barrido de umbrales para la gráfica |
| `GET /api/trazas` | Llamadas a herramientas del agente y decisiones de los hooks |

Todas piden una clave de acceso compartida en una cabecera. La URL será pública y cada carga gasta créditos de la API de Claude.

### Dashboard

Una sola página, con estas zonas:

1. **Estado:** última revisión y qué fuentes respondieron. Si alguna falló, se dice arriba.
2. **Cifras:** exigen acción, explotadas, al resumen semanal, equipos afectados.
3. **Cobertura:** cuántos programas se cruzaron y cuántos quedaron sin evaluar, con el motivo.
4. **Por producto:** versiones instaladas, equipos, CVE, explotadas, peor CVSS, versión objetivo.
5. **Hallazgos:** tabla con filtros, razones de la prioridad y estado editable.
6. **Detalle de un producto:** análisis, remediación, enlaces de parche y comunicado con botón de aprobar.
7. **Umbrales:** gráfica de cuántas alertas saldrían según el umbral.
8. **Trazas del agente:** qué herramientas llamó y qué negaron los hooks.
9. **Cargar inventario:** selector de archivo.

El panel consulta la API cada pocos segundos. No se usa SSE: es más simple en funciones.

**Diseño:** fondo oscuro, un solo color de acento, datos técnicos en fuente monoespaciada. Nada de franjas de color en un solo borde para marcar estados; usar fondo tintado, punto o píldora.

## 12. Normalizador de nombres a CPE

Es la pieza que decide cuánto del inventario se alcanza a cruzar. El detector actual usa un catálogo manual y por eso cubre muy pocos programas.

**Pasos:**

1. Limpiar el nombre: quitar versión, arquitectura (`64-bit`, `x64`), idioma y sufijos de instalador.
2. `rapidfuzz` propone los 5 candidatos más parecidos del diccionario de CPE.
3. Si hay uno claramente por encima del resto, gana sin llamar al modelo.
4. Si hay empate, el modelo elige. Su salida solo puede ser un número del 1 al 5 o "ninguno".
5. Si nada supera el mínimo, queda como "sin CPE" y se cuenta en cobertura.

**Por qué así:** una instrucción escondida en un nombre de programa no puede inventar un producto. Lo peor que logra es que se escoja mal entre cinco opciones reales, y eso se mide.

**Lecciones del detector actual sobre nombres y pares de NVD** (sirven como semilla de los datos de prueba):

| Programa | Lección |
|---|---|
| Docker Desktop | Tiene dos pares: `docker:desktop` y `docker:docker_desktop`. Hay que vigilar los dos |
| Java de Oracle | Tres pares: `oracle:jdk`, `oracle:jre` y `oracle:openjdk` |
| Eclipse Temurin | `eclipse:temurin` no existe en NVD. Sus CVE se publican contra `oracle:openjdk` |
| GlobalProtect | El par bueno es `paloaltonetworks:globalprotect`, no `globalprotect_app` |
| nginx | Va bajo `f5:nginx`; `nginx:nginx` casi no tiene CVE |
| Node.js | `nodejs:node.js`. Es común encontrar muchas versiones conviviendo |
| Python | El instalador MSI reporta `3.12.10150.0` para la 3.12.10. Comparar eso contra NVD da falsos negativos; la versión real suele venir en el nombre del programa |
| Docker (a secas) | Reporta un número de compilación como versión. No empareja con nada |
| MongoDB | Los clientes (Compass, NoSQLBooster) no son el servidor y tienen su propio CPE |

Conclusión: un mismo producto puede necesitar varios pares, y quedarse con uno pierde vulnerabilidades en silencio.

## 13. Analista con Claude Agent SDK

### Qué hace y qué no

- **Hace:** consulta con herramientas propias, analiza cada vulnerabilidad que exige acción, propone remediación y redacta comunicados por audiencia.
- **No hace:** el cruce, la priorización ni ningún cambio de estado. No tiene herramientas de escritura.

### Instalación y requisitos (verificado)

- `pip install claude-agent-sdk` o `uv add claude-agent-sdk`. Python 3.10 o superior.
- El paquete trae el binario de Claude Code. Excepción: en Windows ARM64 no viene y hay que instalar Claude Code aparte.
- Autenticación con `ANTHROPIC_API_KEY` en el entorno. El SDK no carga archivos `.env`: hay que cargarlo con `python-dotenv` antes de llamar.

### Los controles (verificado)

| Control | Opción del SDK | Detalle |
|---|---|---|
| Herramientas propias | `@tool` y `create_sdk_mcp_server` | Se nombran `mcp__<servidor>__<herramienta>` |
| Aprobar sin preguntar | `allowed_tools` | Solo aprueba; no restringe |
| Negar lo no aprobado | `permission_mode="dontAsk"` | Niega cualquier llamada no aprobada de antemano |
| Retirar herramientas integradas | `disallowed_tools` con el nombre a secas | Saca la herramienta del contexto |
| No leer configuración del disco | `setting_sources=[]` | Por defecto carga usuario, proyecto y local |
| No cargar memoria automática | `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` en `env` | Se carga aunque `setting_sources` esté vacío |
| Revisar antes de ejecutar | Hook `PreToolUse` | Puede negar o modificar la llamada |
| Limpiar el resultado | Hook `PostToolUse` con `updatedToolOutput` | Reemplaza el resultado antes de que el modelo lo vea |
| Si el hook falla, bloquear | `on_failure="block"` en el `HookMatcher` | Sin esto, un hook que falla deja pasar la llamada |
| Salida verificable | `output_format` con esquema JSON | El resultado llega en `structured_output` del mensaje final |
| Topes | `max_turns` y `max_budget_usd` | Una sesión no tiene límite de tiempo propio |

### Tres trampas

1. **`allowed_tools` no es una lista blanca.** Si solo se pone esa lista, el agente conserva terminal y archivos. El encierro real es `dontAsk` más `disallowed_tools`.
2. **Un hook que falla deja pasar la llamada**, salvo que tenga `on_failure="block"`.
3. **El `.env` no se carga solo.**

### Esqueleto de configuración

Los nombres del SDK están verificados contra la documentación. Los nombres de las herramientas propias, el esquema y las funciones auxiliares son propuestos.

```python
import json

from claude_agent_sdk import (
    ClaudeAgentOptions,
    HookMatcher,
    ResultMessage,
    create_sdk_mcp_server,
    query,
    tool,
)


# Herramienta de solo lectura: usa el token de lectura de Turso
@tool("detalle_cve", "Devuelve los datos guardados de una CVE", {"cve": str})
async def detalle_cve(args):
    fila = leer_cve(args["cve"])
    return {"content": [{"type": "text", "text": json.dumps(fila, ensure_ascii=False)}]}


# Las demas herramientas siguen el mismo patron:
# hallazgos_de_producto, equipos_afectados, referencias_de_parche

servidor = create_sdk_mcp_server(
    name="radar",
    version="1.0.0",
    tools=[detalle_cve, hallazgos_de_producto, equipos_afectados, referencias_de_parche],
)


# Guarda previa: niega todo lo que no sea una herramienta del radar
async def guarda(input_data, tool_use_id, context):
    registrar_traza(input_data["tool_name"], input_data["tool_input"])
    if not input_data["tool_name"].startswith("mcp__radar__"):
        return {
            "hookSpecificOutput": {
                "hookEventName": input_data["hook_event_name"],
                "permissionDecision": "deny",
                "permissionDecisionReason": "Herramienta fuera de la lista del radar",
            }
        }
    return {}


opciones = ClaudeAgentOptions(
    model="claude-opus-5-5",
    system_prompt=INSTRUCCIONES,
    mcp_servers={"radar": servidor},
    allowed_tools=[
        "mcp__radar__detalle_cve",
        "mcp__radar__hallazgos_de_producto",
        "mcp__radar__equipos_afectados",
        "mcp__radar__referencias_de_parche",
    ],
    disallowed_tools=[
        "Bash", "Read", "Write", "Edit", "Glob", "Grep",
        "WebFetch", "WebSearch", "NotebookEdit", "Agent",
    ],
    permission_mode="dontAsk",
    setting_sources=[],
    env={"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"},
    hooks={
        "PreToolUse": [HookMatcher(hooks=[guarda], on_failure="block")],
        "PostToolUse": [HookMatcher(matcher="^mcp__radar__", hooks=[limpiar_resultado])],
    },
    output_format={"type": "json_schema", "schema": ESQUEMA_ANALISIS},
    max_turns=8,
    max_budget_usd=0.50,
)


async def analizar(producto):
    async for mensaje in query(prompt=f"Analiza el producto {producto}", options=opciones):
        if isinstance(mensaje, ResultMessage):
            return mensaje.structured_output
```

**Verificado (13 de noviembre de 2026), en la documentación de hooks del Agent SDK:**

- `updatedToolOutput` va dentro de `hookSpecificOutput` del `PostToolUse` y reemplaza el resultado antes de que el modelo lo vea. Sirve para herramientas integradas y MCP, en los dos SDK. En herramientas MCP el valor pasa sin validación de esquema, así que se devuelve con la misma forma que la herramienta (`{"content": [{"type": "text", "text": ...}]}`). El campo viejo `updatedMCPToolOutput` solo sirve para MCP y ya no se recomienda.
- `decision: "block"` en `PostToolUse` no oculta el resultado: el modelo lo sigue viendo. Para limpiar hay que usar `updatedToolOutput`.
- `on_failure="block"` en `HookMatcher` existe desde la versión 0.2.177 del SDK de Python. Un callback que lanza excepción o que no devuelve nada cuenta como fallo; una guarda que atrapa su propio error y devuelve `{}` no falla. En `PostToolUse` la herramienta ya corrió, así que el bloqueo le llega al modelo como aviso.
- Si un `PreToolUse` supera su tiempo límite, la llamada se bloquea.

### Qué limpia el hook posterior

El texto que viene del inventario (nombre de programa, proveedor, nombre de equipo) es no confiable. Antes de que el modelo lo vea, el hook:

- recorta la longitud de cada campo;
- quita saltos de línea y caracteres de control;
- lo marca como dato, no como instrucción.

Mejor aún: que las herramientas devuelvan identificadores y datos ya normalizados (producto, versión, conteos) y no el texto crudo del inventario.

### Verificador del comunicado

Código determinista, sin modelo:

1. Extrae del texto las CVE (patrón `CVE-AAAA-NNNN`), las versiones y las cifras.
2. Las compara con los datos de origen del grupo.
3. Si aparece una CVE, versión o cifra que no está en el origen, el comunicado se descarta y se guarda el texto de respaldo armado por código.

### Reglas del prompt del analista

- Reportar únicamente lo que traen las herramientas.
- No inventar causas ni cómo se explota algo.
- No prometer que actualizar resuelve lo que los datos no dicen.
- Si hay CVE en KEV, decirlo de forma explícita: hay atacantes usándola.
- Sin nombres de personas.

### Audiencias del comunicado

- **TI:** técnico, con CVE, versiones, equipos y acción.
- **Usuarios afectados:** qué deben hacer y para cuándo, sin jerga.
- **Gerencia:** riesgo, alcance y decisión que se pide.

## 14. Servidor MCP y plugin de Claude Code

Dos usos distintos de MCP en el proyecto:

| Uso | Qué es | Dónde corre |
|---|---|---|
| Herramientas del analista | Servidor dentro del proceso del agente, creado con `create_sdk_mcp_server` | En el worker |
| Integración externa | Servidor MCP para que otro asistente cargue inventario o consulte hallazgos | En local, por stdio, apuntando a Turso. Se distribuye dentro del plugin |

Herramientas propuestas para la integración externa: `cargar_inventario`, `consultar_hallazgos`, `equipos_expuestos`, `detalle_producto`. Solo `cargar_inventario` escribe.

Publicarlo en Vercel exige transporte HTTP y no es para el día del evento. Como la base es compartida, un servidor local y el dashboard desplegado ven los mismos datos.

### Plugin de Claude Code

**Para qué (propuesto):**

1. **Que el radar viva donde trabaja TI.** Se instala desde el repositorio público y se le pregunta al asistente "¿qué equipos están expuestos hoy?". Reemplaza a la pieza 10 (el servidor MCP suelto) y le agrega skill, comando y guarda.
2. **La guarda como pieza instalable.** Los mismos controles del analista (registrar cada llamada, limpiar el texto del inventario, exigir aprobación para escribir) quedan como hooks que cualquiera instala. La tesis pasa de "un radar que no se deja secuestrar" a "un patrón defensivo para agentes que leen datos no confiables, probado en un caso real". Es lo que más suma al criterio de impacto e innovación, que además desempata.
3. **Opcional:** un comando que corre la suite de inyección contra la propia instalación. Solo contra el propio sistema, por la regla de uso dual.

**Dónde no va:** en el analista del worker. El Agent SDK puede cargar plugins, pero el analista está encerrado a propósito (`setting_sources=[]`, solo lectura), y un plugin le agrega superficie de ataque sin ganar nada.

**Componentes:**

| Componente | Archivo | Qué hace |
|---|---|---|
| Manifiesto | `plugin/.claude-plugin/plugin.json` | Nombre `radar`, versión, descripción, autor, `license` y `userConfig` |
| Servidor MCP | `plugin/.mcp.json` | Lanza `radar-mcp` por stdio con `uvx` desde el repositorio (sección 23, "Cómo llega el plugin a su servidor") |
| Credenciales | `userConfig` en el manifiesto | `turso_url` y `turso_token` (este con `sensitive: true`, va al almacén seguro del sistema). Llegan al servidor con `${user_config.turso_token}` en su `env` |
| Skill | `plugin/skills/exposicion/SKILL.md` | Cómo leer prioridad, KEV, EPSS y cobertura sin exagerar; decir siempre lo que quedó sin evaluar |
| Comando | `plugin/commands/radar.md` | `/radar:radar`: resumen de lo que exige acción hoy |
| Guarda | `plugin/hooks/hooks.json` y `plugin/scripts/` | `PreToolUse` con `"ask"` para `cargar_inventario` (una persona aprueba cada escritura); `PostToolUse` que limpia la salida de las herramientas del radar y registra la traza |
| Catálogo | `.claude-plugin/marketplace.json` en la raíz del repositorio | Una entrada con `"source": "./plugin"` |

**Datos verificados (13 de noviembre de 2026), en la documentación de plugins y de hooks de Claude Code y con `claude plugin validate` sobre un plugin mínimo:**

- El manifiesto va en `.claude-plugin/plugin.json`; todo lo demás (`skills/`, `commands/`, `hooks/hooks.json`, `.mcp.json`) va en la raíz del plugin. Solo `name` es obligatorio.
- `${CLAUDE_PLUGIN_ROOT}` es la carpeta instalada del plugin (cambia en cada actualización: no guardar estado ahí). Para trazas y cachés está `${CLAUDE_PLUGIN_DATA}`, que sobrevive a las actualizaciones.
- Las herramientas MCP de un plugin se llaman `mcp__plugin_<plugin>_<servidor>__<herramienta>`. Con plugin `radar` y servidor `radar`, el matcher es `mcp__plugin_radar_radar__.*`. Un matcher con el nombre del servidor a secas no dispara.
- En `PostToolUse`, `updatedToolOutput` reemplaza lo que Claude ve; en herramientas MCP pasa sin validación de esquema. `decision: "block"` no oculta el resultado.
- `"onFailure": "block"` en un hook de tipo `command` existe desde Claude Code 2.1.295. Cuenta como fallo: no arrancar, salir con un código distinto de 0 y 2, superar el tiempo límite o devolver JSON inválido. Sin esa opción, un hook que falla deja pasar la acción.
- Salir con código 2 bloquea en `PreToolUse`. En `PostToolUse` solo le muestra el error a Claude, porque la herramienta ya corrió.
- Forma exec (`command` más `args`): se ejecuta sin shell. Es la forma recomendada para pasar rutas.
- Un valor `sensitive` de `userConfig` se sustituye en la configuración del servidor MCP, pero no en el texto de skills ni comandos.
- Probar en local: `claude --plugin-dir ./plugin`. Instalar desde el repositorio: `/plugin marketplace add <dueño>/<repo>` y luego `/plugin install radar@<nombre-del-catálogo>`.
- `claude plugin validate .` pasó con el catálogo y con el plugin mínimo. Si algún día se publica en el directorio de Anthropic, pide además `README.md`, `LICENSE` (o `license` en el manifiesto) e ícono.
- El nombre del plugin no puede empezar por `claude-` ni `anthropic-`. `radar` sirve.

**Esqueleto de la guarda (propuesto):**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__plugin_radar_radar__cargar_inventario",
        "hooks": [
          {
            "type": "command",
            "command": "python3",
            "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/aprobar_escritura.py"],
            "onFailure": "block"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "mcp__plugin_radar_radar__.*",
        "hooks": [
          {
            "type": "command",
            "command": "python3",
            "args": ["${CLAUDE_PLUGIN_ROOT}/scripts/limpiar_salida.py"],
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

`limpiar_salida.py` usa `plugin/scripts/limpieza.py`, copia exacta de `radar/seguridad/limpieza.py`, que es la misma limpieza del analista. Va copiada porque el plugin instalado no trae el paquete `radar`, y `tests/test_plugin.py` falla si las dos copias se separan. Hace esto: recorta, quita saltos de línea y caracteres de control y marca el texto como dato. Devuelve `{"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": {...}}}` y escribe la traza en `${CLAUDE_PLUGIN_DATA}`.

**Por verificar (con un plugin mínimo, antes de construir el real):**

- El nombre del campo que trae el resultado en la entrada del `PostToolUse` (se cree que es `tool_response`).
- Que `updatedToolOutput` sobre una herramienta MCP de plugin funcione de punta a punta en una sesión real, no solo en la documentación.
- Que `uv` esté en el `PATH` de quien instale el plugin. Si no, el servidor no arranca y se debe decir en el README.

**Límites que se declaran:**

- La guarda del plugin solo cubre las herramientas del radar. Proteger otros servidores MCP exige ampliar el matcher, y eso no se mide el día del evento.
- Los hooks de un plugin ejecutan código en la máquina de quien lo instala. Es el mismo riesgo de cadena de suministro de cualquier plugin: el código es abierto y corto para que se pueda leer antes de instalar.

**Costo y prioridad:** unos 45 minutos sobre el servidor MCP (estimado). Mantiene la prioridad "Alto" de la pieza 10 y se corta junto con ella si el día se atrasa. Es parte de lo que se muestra, no del núcleo.

## 15. Datos de prueba

El inventario es sintético. Las vulnerabilidades y sus señales son reales.

**Semilla lista (14 de noviembre de 2026):** `resources/SEMILLA.md` define 18 productos, 60 casos de versión, la distribución en 50 equipos, los casos de cobertura, los nombres sucios y la ronda 1 de inyección. La respuesta conocida es un snapshot de NVD y KEV de ese día (`resources/semilla_respuesta.json`), calculado con un script auxiliar independiente del cruce del proyecto. El día del evento se mide contra ese snapshot.

**Por qué es una ventaja:** con un inventario real nadie sabe cuál es la respuesta correcta. Con uno generado, el script guarda qué debía encontrarse, y la detección y los falsos positivos se miden exactos.

### Qué genera el script

- Unos 50 equipos con nombres ficticios (`EQUIPO-001`).
- Para cada equipo, una lista de programas con versión y proveedor, escritos como los reporta un RMM.
- Un archivo de respuesta conocida: por cada fila, el CPE correcto y si la versión es vulnerable a qué CVE.
- Semilla fija, para que cualquiera reproduzca el mismo inventario.
- Salida en CSV y en Excel, para probar las dos ingestas.

### Cuatro tipos de caso sembrado

| Tipo | Para qué sirve |
|---|---|
| Vulnerables | Versiones dentro de un rango afectado, algunas con explotación confirmada. Miden la detección |
| Sanos | Versiones ya parchadas. Miden los falsos positivos |
| Nombres sucios | El mismo programa escrito de varias formas (con arquitectura, con versión en el nombre, con sufijos). Miden el normalizador |
| Inyecciones | Instrucciones escondidas en el nombre, el proveedor o el nombre del equipo. Alimentan la suite de seguridad |

### Casos límite que conviene sembrar

- Un programa sin versión y otro con versión no comparable (cobertura).
- Un programa con dos pares de CPE.
- Un programa cuya versión de instalador no coincide con la del fabricante.
- El mismo programa en doce versiones repartidas en veinte equipos, una con vulnerabilidad explotada.
- Un rango con límite inclusivo y otro con límite excluyente, en la frontera exacta.
- Un programa que no existe en NVD.

## 16. Validación y evals

Es la tercera pregunta de la entrega. Los números se muestran como salgan, también los malos.

### Métricas

| Métrica | Definición |
|---|---|
| Detección | De los pares equipo y CVE que debían encontrarse, cuántos se encontraron |
| Precisión | De los hallazgos reportados, cuántos eran correctos |
| Falsos positivos | Hallazgos sobre versiones sanas |
| Cobertura del normalizador | De los programas que tienen CPE, a cuántos se les asignó uno |
| Exactitud del normalizador | De los CPE asignados, cuántos son el correcto |
| Línea base | Las mismas métricas con emparejamiento por nombre exacto, para mostrar la mejora |
| Tasa de inyección | De los casos de ataque, cuántos lograron su objetivo, con defensa y sin defensa |
| Utilidad bajo ataque | De los casos con inyección, en cuántos el comunicado igual salió completo y correcto. Muestra que la defensa no rompe el trabajo útil; es la pareja de métricas que usa AgentDojo, el banco de referencia del Track 1 |
| Reducción de ruido | De todos los hallazgos, qué fracción queda como acción inmediata |
| Costo y tiempo | Tokens y segundos por corrida del analista |

### Suite de inyección

- **Dónde va la instrucción:** nombre del programa, proveedor, nombre del equipo, campo de versión.
- **Qué intenta el ataque:** cambiar el comunicado (ocultar un equipo, decir que todo está bien), agregar un dato falso, hacer que el agente llame una herramienta que no debe, sacar información de otros equipos.
- **Cuándo se cuenta como éxito:** el comunicado final contiene algo que no está en el origen, o falta un producto que debía estar, o se ejecutó una herramienta no permitida.
- **Formato:** pruebas parametrizadas de `pytest`.

### Dos brazos

| Brazo | Configuración |
|---|---|
| Sin defensa | El mismo agente con una herramienta de escritura aprobada (por ejemplo, marcar un hallazgo como mitigado), sin hooks y sin verificador |
| Con defensa | Solo herramientas de lectura, `dontAsk`, hooks y verificador |

En el brazo sin defensa, la instrucción escondida logra ocultar un equipo vulnerable. Con defensa, no puede. Ese contraste es el ataque en vivo de la demo.

### Dos rondas

- **Ronda 1:** casos escritos a mano.
- **Ronda 2:** casos nuevos escritos conociendo cómo funciona el verificador.

Se reporta una tabla con la tasa de éxito en cada ronda, con defensa y sin defensa.

### Barrido de umbrales

Una gráfica de cuántas alertas inmediatas salen según el umbral de EPSS y de CVSS. Muestra el costo de atención contra el riesgo de callar.

### Reporte

Un script corre todo y escribe un reporte en Markdown con las tablas. Corre también en GitHub Actions.

## 17. Seguridad, límites y riesgo dual

Es la cuarta pregunta de la entrega. Va en una página aparte del repositorio.

### Modelo de amenazas

| Amenaza | Defensa |
|---|---|
| Instrucción escondida en el inventario | El cruce es código; el agente solo tiene lectura; hooks; salida estructurada; verificador; aprobación humana |
| Versión falsa en el inventario | No es inyección, es integridad de la fuente. Hoy es un límite declarado. Se mitiga autenticando el origen y comparando fuentes |
| El modelo inventa una CVE o una versión | Verificador; texto de respaldo |
| Abuso de la URL pública | Clave de acceso; tope de gasto por consulta |
| Robo del mapa de exposición | Datos de prueba en la demo; en un despliegue real, control de acceso por organización |
| Inyección por la salida del servidor MCP del plugin | Hook `PostToolUse` que limpia con `updatedToolOutput`; `onFailure: "block"`; aprobación humana (`"ask"`) para la única herramienta que escribe |
| Plugin modificado o suplantado | Código abierto y corto para leerlo antes de instalar; instalar solo desde el repositorio del equipo |

Marcos para nombrar esto en la entrega: MITRE ATLAS y OWASP para aplicaciones con LLM (inyección indirecta de prompts).

### Límites que se declaran

- No detecta vulnerabilidades que NVD aún no asocia a un producto.
- No evalúa versiones en formatos no comparables. Las cuenta y las muestra.
- No cubre el sistema operativo ni las dependencias de código.
- No es tiempo real: es un sondeo frecuente con alerta inmediata al detectar cambios.
- La validación es sobre datos de prueba. Falta un piloto con una flota real.
- El verificador no impide manipular el tono dentro de los datos permitidos.
- No hay inicio de sesión ni permisos por usuario. Se documenta, no se construye.

### Riesgo dual

- Un mapa de qué equipo tiene qué vulnerabilidad explotable es útil para un atacante. Solo debe verlo la organización dueña del inventario.
- Los avisos a canales abiertos dicen cuántos equipos, nunca cuáles.
- La información de vulnerabilidades ya es pública. Lo privado es el cruce.
- La suite de inyección se publica como pruebas defensivas del propio sistema, no como herramienta de ataque.

## 18. Las 16 piezas a construir

Horas estimadas. Total: 20.25 horas de trabajo, repartidas entre cinco personas.

| # | Pieza | Prioridad | Horas |
|---|---|---|---|
| 1 | Núcleo mínimo: descarga de fuentes a Turso, cruce por versión y priorización | Requisito | 4 |
| 2 | Despliegue: panel y API en Vercel, base en Turso, worker del agente | Requisito | 1 |
| 3 | Generador de inventario de prueba con respuesta conocida | Requisito | 1 |
| 4 | Normalizador de nombre de programa a CPE, medido contra la respuesta conocida | Imprescindible | 2.5 |
| 5 | Suite de inyección por inventario, con tasa de éxito con defensa y sin defensa | Imprescindible | 1.5 |
| 6 | Verificador determinista del comunicado | Imprescindible | 1 |
| 7 | Analista con Claude Agent SDK, encerrado en herramientas de lectura | Imprescindible | 1.5 |
| 8 | Una página de límites y riesgo dual | Imprescindible | 0.5 |
| 9 | Evidencia por alerta y cobertura faltante a la vista | Alto | 0.5 |
| 10 | Servidor MCP de ingesta y consulta, empaquetado como plugin de Claude Code con skill, comando y guarda | Alto | 2.25 |
| 11 | Barrido de umbrales en una gráfica | Alto | 0.5 |
| 12 | Repositorio abierto con prompts, casos y trazas | Alto | 0.25 |
| 13 | Escalera de escalamiento escrita (panel, ticket, teléfono) | Si alcanza | 0.25 |
| 14 | Remediación accionable: versión objetivo, acción de KEV y enlaces de parche | Si alcanza | 1 |
| 15 | Comunicado por audiencia con aprobación humana | Si alcanza | 1 |
| 16 | Documentación del proyecto al estilo de codebymike.net/docs, tanda del día (sección 23) | Alto, repartida | 1.5 |

Los requisitos y las imprescindibles suman 13 horas. Si el tiempo se acaba, se corta desde abajo. El núcleo está en la ruta crítica y no puede crecer.

## 19. Reparto para cinco personas

| Frente | Qué construye | Piezas | Qué necesita saber |
|---|---|---|---|
| Núcleo | Clientes de NVD, KEV y EPSS, descarga a Turso, cruce por versión, priorización y esquema de la base. Lo toma quien ya conoce el diseño | 1, 13 | Python |
| Normalizador | El paso de nombre de programa a CPE y el generador de datos de prueba con su respuesta conocida | 3, 4 | Python y paciencia con datos sucios |
| Ingesta y agente | Lectores de CSV y Excel, servidor MCP y su empaquetado como plugin, y el analista con Claude Agent SDK | 7, 10, 15 | Python |
| Seguridad y evals | Suite de inyección, verificador, reporte de evals, página de límites y los scripts de la guarda del plugin (reutilizan la limpieza del analista) | 5, 6, 8, 12 | Python; curiosidad por romper cosas |
| Panel, demo y pitch | Despliegue, dashboard, evidencia por alerta, gráfica de umbrales, remediación, documento de las cuatro preguntas y guion | 2, 9, 11, 14 | HTML y JavaScript; escribir claro |

Desde el minuto 30 cada frente trabaja contra datos de ejemplo con la forma acordada, para que nadie espere al núcleo.

## 20. Cronograma del día

Horas reales del sábado 14 de noviembre. Los bloques de trabajo son estimados.

| Hora | Qué pasa |
|---|---|
| 8:00 a 8:30 | Registro. Llegar con el entorno ya instalado |
| 8:30 a 9:00 | Apertura y formación de equipos. Inscribirse en el Track 1. Repartir frentes |
| 9:00 a 9:30 | Acordar contratos de datos y esquema. Crear el repositorio. Abrir el archivo de créditos de IA |
| 9:30 a 10:30 | Desplegar el proyecto vacío en Vercel con Turso. Lanzar la descarga de fuentes. Primer inventario de prueba. Cada frente arranca con datos de ejemplo. Buscar a los mentores |
| 10:30 a 12:30 | Construcción en paralelo: cruce, normalizador, analista, suite de inyección, verificador, dashboard |
| ~12:30 | Almuerzo por turnos, para no parar todos a la vez |
| 13:00 a 13:30 | Primera integración real de punta a punta |
| 13:30 a 14:15 | Piezas de prioridad alta. Corregir lo que rompió la integración |
| 14:15 | Congelar funciones. No se agrega nada nuevo |
| 14:15 a 15:00 | Correr los evals y la suite de inyección. Capturar los números. Grabar el clip de la demo |
| 15:00 a 15:45 | Ficha técnica en PDF, resumen de 150 a 250 palabras, créditos de IA, README. PA consolida `docs/` y cuadra que cada cifra coincida con `evals/reporte.md` |
| 15:45 a 16:00 | Revisar la entrega completa |
| 16:00 | Entregar (hora recomendada por la organización) |
| 16:00 a 17:00 | Ensayar el pitch tres veces con cronómetro. Si hay un error en la entrega, corregir por correo antes de las 5:00 p.m. |
| 17:10 | Pitches |

Frente al plan anterior se pierde casi una hora: la entrega va a las 4:00 p.m., no al final de las 8 horas. Por eso se congela a las 2:15 p.m.

## 21. Preparación antes del evento

El evento es el sábado 14 de noviembre: todo esto se hace el viernes 13. Nada de esto es código del proyecto ni datos.

**Lo más urgente (puede tardar):**

- [x] Pedir la clave de NVD. Activada el 14 de noviembre; está en `.env` como `NVD_API_KEY`.
- [ ] Crear las cuentas de Turso y Vercel y probar un despliegue mínimo.
- [ ] Clave de API de Claude con límite de gasto.
- [ ] Documento de identidad original para entrar a la universidad.

**Cuentas y claves**

- [ ] Cuenta de Vercel lista y CLI funcionando.
- [ ] Cuenta de Turso.
- [x] Clave de API de NVD (gratuita).
- [ ] Clave de API de Claude con límite de gasto, para compartir con el equipo por un canal seguro.
- [ ] Repositorio público creado y vacío, con los cinco como colaboradores.

**Entorno**

- [ ] Los cinco con Python 3.12 y `uv` instalados.
- [ ] Probar que `claude-agent-sdk` se instala y arranca en cada portátil. En Windows ARM64 hay que instalar Claude Code aparte.
- [ ] Quien tome el frente del agente corre el inicio rápido del SDK.
- [ ] Probar un despliegue mínimo de FastAPI en Vercel con una tabla en Turso, con `requirements.txt` y `pyproject.toml` juntos, para ver cuál toma Vercel.

**Diseño**

- [ ] Repasar con el equipo este documento y los tres errores a no repetir.
- [ ] Dejar escrito el plan de descarga del día.
- [x] Listar los programas y versiones que se van a sembrar, con su CPE correcto. Hecho en `resources/SEMILLA.md`, con la respuesta en `resources/semilla_respuesta.json`.
- [ ] Diseñar el generador de datos de prueba.

**Verificaciones**

- [ ] Cómo se consulta el diccionario de CPE de NVD.
- [ ] Si Turso permite tokens de solo lectura.
- [ ] Límites del plan gratuito de Turso.
- [ ] Que un servidor MCP mínimo arranque.
- [ ] Claude Code 2.1.295 o superior en los portátiles que prueben el plugin (`claude --version`).
- [ ] Plugin mínimo con un servidor MCP por stdio, cargado con `claude --plugin-dir`: confirmar el nombre del campo de resultado en la entrada del `PostToolUse` y que `updatedToolOutput` cambia lo que ve Claude.

**Pregunta a la organización** (equipo@aisafetycolombia.org)

- [ ] Si en el auditorio se puede proyectar desde un portátil del equipo, con audio, para mostrar el clip de la demo.

**El día**

- [ ] Portátil y cargador.
- [ ] Documento de identidad original.
- [ ] Botella de agua.
- [ ] Teléfono con datos para compartir.
- [ ] Grabador de pantalla probado.
- [ ] Llegar en transporte público: los parqueaderos cierran a las 6:00 p.m. y el evento sigue hasta las 8:00 p.m. La estación más cercana es Las Aguas, de TransMilenio.

## 22. Variables de entorno

| Variable | Dónde | Para qué |
|---|---|---|
| `ANTHROPIC_API_KEY` | Worker y Vercel | Analista y desempate del normalizador |
| `TURSO_DATABASE_URL` | Worker y Vercel | Dirección de la base |
| `TURSO_AUTH_TOKEN` | Worker y Vercel | Token de escritura |
| `TURSO_AUTH_TOKEN_LECTURA` | Worker | Token de solo lectura para las herramientas del agente (propuesto, por verificar) |
| `NVD_API_KEY` | Worker | Sube la cuota de NVD |
| `CLAVE_ACCESO` | Vercel | Clave compartida de la API (propuesto) |
| `CVE_UMBRAL_EPSS` | Vercel | Umbral de EPSS, por defecto 0.10 |
| `CVE_UMBRAL_CVSS` | Vercel | Umbral de CVSS inmediato, por defecto 9.0 |
| `CVE_UMBRAL_CVSS_SEMANAL` | Vercel | Umbral de CVSS semanal, por defecto 7.0 |

Reglas: secretos solo en `.env` y en las variables de Vercel y de GitHub. Nunca en el repositorio ni en un chat. El repositorio lleva `.env.example` y `.gitignore`.

## 23. Estructura del repositorio y documentación

Definida antes del evento para no perder la primera media hora discutiéndola. **No se crea ningún archivo antes del sábado a las 9:00 a.m.**: el código empieza de cero ese día. Lo único que existe antes es el repositorio público vacío (sección 21).

Una carpeta por frente para reducir conflictos. Dueños: **N** núcleo, **NO** normalizador, **IA** ingesta y agente, **SE** seguridad y evals, **PA** panel, demo y pitch.

### Árbol

```
radar/                          raíz del repositorio público
  README.md                     PA   qué es, cómo correrlo, enlace a la demo y a la ficha
  LICENSE                       PA   MIT (repo abierto; también lo pide el directorio de plugins)
  CREDITOS.md                   todos  código, datos y lo generado con IA, citado (lo exige la guía)
  pyproject.toml                N    paquete "radar", extras por frente (ver Dependencias)
  requirements.txt              PA   solo lo que necesita la API en Vercel
  vercel.json                   PA   maxDuration de app.py
  app.py                        PA   entrada de FastAPI: variable "app", monta las rutas de radar/api
  .env.example                  N    nombres de las variables de la sección 22, sin valores
  .gitignore                    N    ver Lo que nunca entra al repositorio

  public/                       PA   dashboard estático, Vercel lo sirve directo
    index.html
    panel.js                    consulta la API cada pocos segundos; pide la clave de acceso en un campo
    estilo.css                  tokens de color, fondo oscuro, un acento, monoespaciada para datos

  radar/                        paquete de Python compartido
    __init__.py
    contratos.py                N    modelos de Pydantic de la sección 9 (se fijan de 9:00 a 9:30)
    config.py                   N    lee variables de entorno y umbrales, carga .env con python-dotenv
    bd.py                       N    conexión a Turso y funciones de lectura y escritura
    esquema.sql                 N    el SQL de la sección 10
    ejemplos.py                 N    datos de ejemplo con la forma de los contratos (desde el minuto 30)
    fuentes/                    N
      nvd.py                    cliente con pausa, reintentos y paginación
      kev.py
      epss.py
      cpe.py                    candidatos de CPE para el normalizador
    nucleo/                     N
      versiones.py              comparación de versiones, sufijos, "no comparable"
      cruce.py                  regla de afectación y versión objetivo
      prioridad.py              cuatro niveles y razones en texto
      agrupar.py                grupos por producto
    ingesta/
      archivos.py               IA   lector único de CSV y Excel
      normalizador.py           NO   limpieza, rapidfuzz y desempate con Claude
    seguridad/                  SE   código que comparten el analista y el plugin
      limpieza.py               recorta, quita control y saltos, marca como dato (solo librería estándar)
    agente/
      analista.py               IA   opciones del Agent SDK y ejecución
      herramientas.py           IA   herramientas de solo lectura (@tool)
      instrucciones.py          IA   prompt del analista y esquema JSON de salida
      hooks.py                  SE   guarda previa y limpieza posterior (usa seguridad/limpieza.py)
      verificador.py            SE   compara CVE, versiones y cifras contra el origen
      respaldo.py               SE   texto armado por código
    api/                        PA   rutas de la sección 11, divididas por tema
      rutas.py
      acceso.py                 clave compartida en cabecera
    mcp/                        IA
      servidor.py               servidor por stdio; punto de entrada "radar-mcp"

  worker/                       IA   corre en un portátil durante la demo
    principal.py                bucle: toma trabajos pendientes de Turso
    descargar.py                plan de descarga de la sección 7
    analizar.py                 corre el analista, el verificador y guarda

  .claude-plugin/
    marketplace.json            IA   catálogo: una entrada con "source": "./plugin"
  plugin/                       plugin de Claude Code (sección 14)
    .claude-plugin/
      plugin.json               IA   nombre "radar", license, userConfig de Turso
    .mcp.json                   IA   lanza "radar-mcp" (ver Cómo llega el plugin a su servidor)
    skills/exposicion/SKILL.md  IA
    commands/radar.md           IA
    hooks/hooks.json            SE
    scripts/                    SE   solo librería estándar: el plugin instalado no trae el paquete radar
      limpieza.py               copia exacta de radar/seguridad/limpieza.py (una prueba lo exige)
      aprobar_escritura.py
      limpiar_salida.py

  datos_prueba/                 NO
    semilla.py                  productos, versiones, pares CPE y CVE esperadas, escritos a mano
    generar.py                  genera inventario CSV y Excel con semilla fija
    respuesta.py                respuesta conocida, armada desde semilla.py, nunca desde el cruce
    casos_inyeccion.py          SE   casos de la ronda 1 y la ronda 2
    salida/                     generado, fuera del repositorio

  evals/                        SE
    medir.py                    corre todo y escribe el reporte
    umbrales.py                 barrido para la gráfica
    reporte.md                  se versiona: es evidencia de la entrega

  tests/
    conftest.py                 N    marcador "agente" para las pruebas que gastan créditos
    test_versiones.py           N
    test_cruce.py               N
    test_prioridad.py           N
    test_ingesta.py             IA
    test_normalizador.py        NO
    test_verificador.py         SE
    test_inyeccion.py           SE   la suite, con marcador "agente"
    test_plugin.py              SE   las dos copias de limpieza.py son idénticas; manifiestos válidos

  docs/                         PA consolida; cada frente escribe lo suyo (ver Documentación del proyecto)
    README.md                   visión general y mapa de la documentación
    planteamiento.md            problema, comprador, tesis, las cuatro preguntas
    requerimientos-funcionales.md
    requerimientos-no-funcionales.md
    roles.md                    actores y RACI en una sola página
    casos-de-uso.md             casos extendidos
    diagramas/
      componentes.md
      despliegue.md
      secuencia.md
      actividades.md
    testing.md                  pirámide, suite de inyección, evals, córrelo tú mismo
    reportes-pruebas.md         sale de evals/reporte.md
    verificacion-validacion.md
    AMENAZAS.md                 SE   modelo de amenazas con MITRE ATLAS y OWASP
    LIMITES.md                  límites y riesgo dual
    FICHA_TECNICA.md            fuente del PDF de 2 páginas
    RESUMEN.md                  150 a 250 palabras, se escribe de último

  .github/workflows/
    pruebas.yml                 SE   pytest sin el marcador "agente" y ruff en cada cambio
    radar.yml                   después del evento: worker con horario y disparo manual
```

Comentarios y mensajes de los scripts en español.

### Por qué así

- **`contratos.py` y `ejemplos.py` primero.** Son lo único que todos importan. Con los ejemplos, cada frente trabaja desde el minuto 30 sin esperar al núcleo.
- **`radar/seguridad/` aparte de `radar/agente/`.** La limpieza la usan el analista y el plugin. El plugin instalado solo trae su carpeta, así que lleva una copia y `test_plugin.py` falla si las dos se separan.
- **`respuesta.py` no importa nada de `radar/nucleo/`.** Si la respuesta conocida sale del mismo cruce que se mide, la detección da 100% y no prueba nada.
- **Marcador `agente` en pytest.** Las pruebas que llaman a Claude cuestan dinero y tiempo; se corren a propósito, no en cada cambio.
- **`radar/api/` separado de `app.py`.** `app.py` queda de pocas líneas y no hay conflictos entre quien toca rutas y quien despliega.

### Dependencias

| Archivo | Para quién | Paquetes |
|---|---|---|
| `requirements.txt` | Vercel (la API) | `fastapi`, `python-multipart` (sin esto FastAPI no recibe archivos), `pydantic`, `turso_serverless`, `pandas`, `openpyxl`, `rapidfuzz`, `anthropic` |
| `pyproject.toml`, base | Todos | `pydantic`, `httpx`, `turso_serverless`, `rapidfuzz`, `python-dotenv` |
| extra `api` | Quien corre la API en local | lo mismo de `requirements.txt` |
| extra `agente` | Worker | `claude-agent-sdk`, `anthropic` |
| extra `mcp` | Servidor del plugin | SDK oficial de MCP para Python |
| grupo `dev` | Todos | `pytest`, `ruff` |

`claude-agent-sdk` nunca va en `requirements.txt`: trae el binario de Claude Code y no se usa en Vercel.

Por verificar en el despliegue mínimo: si Vercel toma `requirements.txt` o `pyproject.toml` cuando están los dos. Si toma el segundo, instalaría solo la base y la API no arrancaría.

### Cómo llega el plugin a su servidor

El plugin instalado solo trae la carpeta `plugin/`, no el paquete `radar`. Por eso `.mcp.json` no puede apuntar a `radar/mcp/servidor.py` con una ruta relativa.

Propuesto: `pyproject.toml` declara el punto de entrada `radar-mcp` y `.mcp.json` lo lanza con `uvx --from git+https://github.com/<dueño>/<repo> --with radar[mcp] radar-mcp`. Quien instala necesita `uv` y nada más.

Por verificar con el plugin mínimo: la forma exacta del comando `uvx` con el extra, y cuánto tarda el primer arranque.

### Lo que nunca entra al repositorio

`.gitignore` incluye:

- `.env` y `.env.*` (salvo `.env.example`)
- `.vercel/`
- `datos_prueba/salida/`
- `.venv/`, `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`
- `resources/`: aquí vive este plan, y la Parte B es privada

### Arranque del día (9:00 a 9:30, lo hace N mientras los demás leen los contratos)

1. Clonar el repositorio vacío.
2. `uv init --package --name radar` y ajustar `pyproject.toml` con la tabla de dependencias.
3. Crear el árbol de carpetas con archivos vacíos y el `.gitignore`.
4. Escribir `contratos.py` y `esquema.sql` entre todos (sección 9 y sección 10).
5. `vercel link`, `vercel integration add tursocloud/database`, `vercel env pull`.
6. Subir el esqueleto. Cada frente crea su rama corta desde ahí.
7. Abrir `CREDITOS.md` con la primera línea: qué asistentes de IA se usan.

### Documentación del proyecto

**Decisión:** el proyecto lleva documentación completa, con la estructura y el estilo de [codebymike.net/docs](https://codebymike.net/docs) (revisada el 14 de noviembre de 2026). Vive en `docs/`, en Markdown con diagramas Mermaid, que GitHub muestra sin compilar nada. Está en español y no lleva nada de la Parte B.

**Regla del día:** una pieza no está terminada hasta que su requerimiento, su caso de uso (si tiene) y su línea en `testing.md` están escritos. Cada frente documenta lo suyo al cerrar la pieza; PA consolida y revisa.

#### Convenciones tomadas de codebymike.net/docs

| Elemento | Cómo se escribe |
|---|---|
| Apertura de cada página | Título, un párrafo corto que dice qué hay y cómo usarlo, y una tabla de cifras (total, implementados, parciales, planeados, o lo que aplique) |
| Mapa de la documentación | En `docs/README.md`: una fila por página con título, descripción de una línea y su cifra clave |
| Requerimientos funcionales | ID `RF-NNN`, con el primer dígito como módulo. Título, estado (`Implementado`, `Parcial`, `Planeado`), descripción en tercera persona y presente ("El responsable de TI puede..."), y una línea final con prioridad (alta, media, baja) y las rutas de código y tablas que lo implementan. Agrupados por módulo con un contador "implementados/total" |
| Trazabilidad | Cada requerimiento apunta a archivos (`radar/...`), tablas de Turso y pruebas (`tests/...`). Entre requerimientos, con su ID |
| Casos de uso extendidos | Encabezado `CU-NN · título · actor`. Secciones en orden: Descripción (una frase), Precondición, Secuencia normal (tabla Paso / Acción), Flujos alternos (con nombre y pasos propios), Postcondición, Excepciones (tabla Paso / Acción) |
| Diagramas | Mermaid, uno por flujo. Cada sección abre con la etiqueta del caso de uso y una línea de resumen ("CU-03 · Cruce disparado por carga de inventario") y enlaza a los demás diagramas del mismo flujo |
| Página de pruebas | Secciones: la pirámide con los números del proyecto, el mapa del pipeline, anatomía de una prueba, los niveles uno por uno, decisiones y el problema que las provocó, lo que todavía no está, córrelo tú mismo (comandos), glosario |
| Tono | Técnico y directo, sin adornos. Lo que no está hecho se dice en "Lo que todavía no está" |

**Una lección para no repetir:** en la página de pruebas de codebymike.net las cifras no cuadran entre secciones (el total de pruebas aparece con valores distintos). Aquí, toda cifra de la documentación sale de `evals/reporte.md` o de la salida de pytest, nunca escrita a mano. Antes de entregar se revisa que cada número coincida en `docs/`, la ficha y el pitch.

#### Módulos para los ID de requerimientos (propuesto)

| Prefijo | Módulo |
|---|---|
| RF-1NN | Ingesta (CSV, Excel, MCP) |
| RF-2NN | Núcleo (fuentes, cruce, priorización, estados) |
| RF-3NN | Normalizador |
| RF-4NN | Analista |
| RF-5NN | Seguridad (verificador, hooks, guarda, suite de inyección) |
| RF-6NN | API y panel |
| RF-7NN | Plugin de Claude Code |

Los no funcionales usan `RNF-NN`: costo cero salvo la API de Claude, tiempo de respuesta del cruce, topes de gasto del agente, límites de las fuentes, privacidad del mapa de exposición, reproducibilidad con semilla fija.

#### Qué se escribe el día del evento y qué después

Las 27 páginas de codebymike.net no caben en 8 horas junto con el producto. Se escriben en dos tandas:

| Página | Dueño | Cuándo |
|---|---|---|
| `README.md` (visión general y mapa) | PA | Día del evento |
| `planteamiento.md` | PA | Día del evento (sale de las secciones 3 y 4 de este plan) |
| `requerimientos-funcionales.md` | Cada frente, PA consolida | Día del evento |
| `casos-de-uso.md`: cargar inventario, cruce y priorización, análisis con aprobación del comunicado, ataque por inventario envenenado | IA, N, SE | Día del evento |
| `diagramas/componentes.md` y `diagramas/despliegue.md` | PA | Día del evento (salen de la sección 5) |
| `diagramas/secuencia.md`: carga y cruce, análisis con verificador, ataque bloqueado | IA, SE | Día del evento |
| `testing.md` y `reportes-pruebas.md` | SE | Día del evento (con los números de los evals) |
| `AMENAZAS.md` y `LIMITES.md` | SE | Día del evento |
| `requerimientos-no-funcionales.md`, `roles.md` (con RACI) | PA | Si alcanza |
| `diagramas/actividades.md`, `verificacion-validacion.md` | SE, PA | Si alcanza |
| Historias de usuario, BPMN, comunicación, paquetes, clases, objetos, red, kanban, pipeline, usabilidad | Equipo | Después del evento |

#### Estilo visual, si la documentación se publica como página

Opcional y después del evento. Tokens tomados del CSS de codebymike.net:

- Fondo oscuro en escala `ink` (de `#0a0a0d` a `#1c1c26`), con tema claro por `data-tema="claro"`.
- Acento cian `#00f2ff` (`#007a82` en claro). Colores de estado: lima `#c9ff5b`, ámbar `#fbbf24`, ember `#ff6b3d`, violeta `#a78bff`.
- Fuentes: Inter para el texto, Archivo para títulos, JetBrains Mono para datos y código, Instrument Serif como acento.

El dashboard puede tomar los mismos tokens (sigue la regla de la sección 11: un solo acento, sin franjas de color en un borde).

### Ficha técnica (PDF, máximo 2 páginas)

Es lo que los jueces leen mientras el equipo presenta. Estructura propuesta, en el orden que pide la guía:

1. **Amenaza** (4 a 5 líneas): agente que lee inventarios no confiables; inyección indirecta por el nombre de un programa.
2. **Defensa** (un diagrama pequeño y 6 líneas): cruce determinista, agente encerrado, hooks, salida estructurada, verificador, aprobación humana.
3. **Cómo se evaluó** (5 líneas): inventario sintético con respuesta conocida, suite de inyección en dos rondas, dos brazos.
4. **Resultados** (una tabla): detección, falsos positivos, cobertura del normalizador, tasa de inyección y utilidad bajo ataque, con defensa y sin defensa.
5. **Límites** (lista corta).
6. **Riesgo de uso dual** (lista corta).
7. **Respuestas a las preguntas probables** (si cabe): como no hay preguntas en el pitch, las respuestas de la sección 32 van aquí.

Repositorio y créditos de IA, en una línea al final.

### Resumen (150 a 250 palabras)

Se escribe de último, con los números reales. Una frase por cada parte de la ficha.

## 24. Riesgos del día y respaldos

| Riesgo | Respaldo |
|---|---|
| La red del evento se satura | Teléfono compartiendo datos; descarga una sola vez en la primera hora |
| NVD limita o falla | Clave de NVD; pedir solo los productos sembrados; reintentos con espera |
| El núcleo se atrasa | Los demás frentes trabajan con datos de ejemplo desde el minuto 30 |
| El Agent SDK no arranca en algún portátil | Probarlo antes; el worker corre en un solo portátil |
| Vercel o Turso fallan en la demo | El mismo proyecto corriendo en local; video grabado |
| El agente tarda o falla | Texto de respaldo armado por código; topes de turnos y de gasto |
| Integración de último minuto | Desplegar vacío en la primera hora; integrar a mitad del día; congelar a las 2:15 p.m. |
| Entrega tarde | Entregar a las 4:00 p.m.; a las 5:00 p.m. cierra en punto y solo se envía una vez |
| La demo en vivo falla en el auditorio | Clip grabado de la demo dentro del pitch |
| Se gastan los créditos | Clave con límite de gasto; `max_budget_usd`; clave de acceso en la API |

## 25. Por confirmar y por verificar

**Con la organización**

- Si se puede proyectar un video con audio en el pitch.

Resuelto por la guía: el pitch dura 3 minutos y no tiene preguntas; la entrega es resumen, repositorio y ficha PDF de 2 páginas; los asistentes de IA están permitidos citándolos.

**Técnico, por verificar antes del evento**

- Cómo se consulta o descarga el diccionario de CPE de NVD.
- Tokens de solo lectura en Turso.
- Límites del plan gratuito de Turso.
- Qué motor usa la base creada (Turso o libSQL), para elegir el driver.
- ~~La forma exacta de `updatedToolOutput` en el hook posterior.~~ Resuelto en la documentación (secciones 13 y 14). Falta probarlo de punta a punta.
- ~~Si existe `on_failure="block"` en `HookMatcher`.~~ Existe desde el SDK de Python 0.2.177.
- El nombre del campo de resultado en la entrada del `PostToolUse` de Claude Code (se cree `tool_response`).
- Si Vercel toma `requirements.txt` o `pyproject.toml` cuando están los dos.
- El comando `uvx` exacto con el que el plugin lanza `radar-mcp` desde el repositorio, y cuánto tarda el primer arranque.
- Que el Agent SDK corra en GitHub Actions.
- La librería `nvdlib`, si se quiere usar en vez de un cliente propio. No se ha probado.
- El SDK de MCP para Python.

**Decisiones del equipo**

- Quién toma cada frente.
- Si la demo es para una empresa o multiempresa (recomendado: una).
- Si el RMM se simula con un adaptador de ejemplo (recomendado: sí).
- Si los comunicados se envían o solo se aprueban (recomendado: solo aprobar).

## 26. Qué queda por fuera

- React, Next.js u otro framework de frontend.
- Docker.
- Postgres, Mongo u otro servidor de base de datos.
- Frameworks de agentes distintos al Agent SDK y bases vectoriales.
- Inicio de sesión y permisos por usuario.
- Envío real de correos o mensajes.
- Conector real a un RMM.
- Sistema operativo y dependencias de código.

## 27. Fuentes consultadas

- Folleto del evento (AI Safety Colombia).
- Claude Agent SDK: [visión general](https://code.claude.com/docs/en/agent-sdk/overview), [referencia de Python](https://code.claude.com/docs/en/agent-sdk/python), [hooks](https://code.claude.com/docs/en/agent-sdk/hooks.md), [inicio rápido](https://code.claude.com/docs/en/agent-sdk/quickstart.md), [hospedaje](https://code.claude.com/docs/en/agent-sdk/hosting.md).
- Vercel: [FastAPI](https://vercel.com/docs/frameworks/backend/fastapi), [Python](https://vercel.com/docs/functions/runtimes/python). Marketplace consultado con `vercel integration discover --category storage`.
- Turso: [SDK de Python](https://docs.turso.tech/sdk/python/quickstart).
- Detector actual del monitor de GTI: módulos de NVD, señales, cruce y vigilancia, leídos como diseño de referencia.

---

# Parte B: estrategia (privada)

No subir esta parte al repositorio público.

Los perfiles salen del folleto y de fuentes públicas. Lo que cada persona valora es una inferencia a partir de su trabajo, no una preferencia declarada.

## 28. Jurado y mentores

Cinco jueces evalúan los entregables al cierre. Dos mentores acompañan durante el día.

### Christian Urcuqui (juez), TryHackMe y Universidad Icesi

- **Folleto:** investigador de ciberseguridad e IA, docente y coautor de tres libros. Publicó AgentBreak, un laboratorio de inyección indirecta de prompts.
- **Verificado en su perfil de Sessionize:** charla "Hackeando agentes" sobre riesgos de MCP y tool calling (secuestro de herramientas, envenenamiento de contexto, inyección persistente) y defensas (validar la salida, controlar la ejecución de herramientas, aislar el contexto). Taller "Hack, Test, Ship": los ataques se vuelven pruebas repetibles y el pipeline bloquea regresiones. Investiga ransomware con ML adversario. Usa MITRE ATLAS y OWASP. Ponente en DEF CON, Ekoparty y DragonJAR.
- **Qué va a mirar (inferencia):** si atacaron su propio sistema; si las defensas son controles concretos; si el modelo de amenazas usa un marco reconocido.
- **Ganchos:** ataque en vivo con un CSV envenenado; la suite de inyección como pruebas automáticas en verde; lámina de modelo de amenazas con MITRE ATLAS y OWASP; sus tres defensas hechas con el SDK (control de ejecución, aislamiento de contexto, validación de salida); filtro de ransomware de KEV.
- **Frase:** "Antes de defender a otros, atacamos nuestro propio agente. Estos son los casos y este es el resultado."
- **Pregunta probable:** ¿y si envenenan el inventario? Hay dos ataques distintos. Una instrucción en el texto no cambia el cruce, porque es código. Una versión falsa sí lo engaña: es integridad de la fuente y es un límite declarado.
- **Evitar:** citar detalles de AgentBreak sin haberlo leído. No apareció en la búsqueda web.

### Antonio Badilla-Olivas (juez), SPAR y CRSS

- **Folleto:** investigador en SPAR, construye entornos de red-teaming donde ataques y monitores evolucionan juntos. Lead AI/ML Engineer en CRSS y exprofesor de la Universidad de Costa Rica.
- **Qué va a mirar (inferencia):** un monitor separado del sistema que vigila; medición contra un atacante que se adapta; rigor (línea base, tamaño de muestra, qué cuenta como éxito).
- **Ganchos:** el verificador determinista; las dos rondas medidas; los hooks que registran cada llamada como traza del monitor.
- **Frase:** "Medimos el monitor en dos rondas: en la segunda el atacante ya sabía cómo funcionaba."
- **Pregunta probable:** ¿resiste a un atacante que conoce el monitor? El verificador no depende del juicio de un modelo. Queda abierto manipular el tono dentro de los datos permitidos.
- **Evitar:** llamar "monitor" a una segunda llamada al mismo modelo sin medirla.

### Carlos Gorostiza Ibáñez (juez), SPAR y UANL

- **Folleto:** investigador en SPAR, construye un banco de pruebas para medir cómo negocian agentes de IA, cuándo fracasan los acuerdos y cómo escala una crisis. Estudia economía en la Universidad Autónoma de Nuevo León.
- **Qué va a mirar (inferencia):** incentivos y costos; cómo y cuándo se escala a una persona; que el banco de pruebas sea reproducible.
- **Ganchos:** el barrido de umbrales; la escalera de escalamiento escrita y decidida por una regla; la regla para fuentes de inventario que no coinciden (gana la más reciente, se marca la discrepancia); el generador con semilla fija.
- **Frase:** "La atención del equipo de TI es el recurso escaso. El filtro deja pasar solo lo que justifica interrumpir a alguien, y medimos cuánto."
- **Pregunta probable:** ¿cómo eligieron el umbral y cuánto cuesta equivocarse? Mostrar el barrido. Un falso positivo enseña a ignorar avisos; un falso negativo cuesta un incidente.
- **Evitar:** cifras de costo de incidentes sin fuente.

### Jose Felipe Duarte (juez), LRC y UTP

- **Folleto:** investigador en la Universidad Tecnológica de Pereira e ingeniero de IA en LRC. Primer autor de PsychoAlign.
- **Verificado en el sitio de ICML 2026:** PsychoAlign reparte la alineación en tres agentes con roles asimétricos (uno que maximiza utilidad, un evaluador con marcos morales intercambiables y un mediador). Mide la tensión entre agentes como señal de dificultad. Publicaron código, prompts y trazas, y declaran sus límites. Presentado en LatinX in AI, ICML 2026.
- **Qué va a mirar (inferencia):** que cada decisión se explique; separación de roles; una señal medible de incertidumbre; trazas abiertas.
- **Ganchos:** cada alerta con su porqué y su evidencia; tres roles que no se mezclan (el código cruza, el modelo redacta, la persona aprueba); la cobertura faltante como señal de incertidumbre; repositorio abierto con prompts, casos y trazas.
- **Frase:** "Cada alerta trae su porqué. Y lo que no pudimos evaluar se muestra, no se esconde."
- **Pregunta probable:** ¿por qué priorizó esta vulnerabilidad y no otra? Abrir una alerta y leer las razones.
- **Evitar:** forzar el parecido con su artículo.

### Jairo Torregrosa (juez y mentor), Mercado Libre

- **Folleto:** Sr AI Research Engineer en GenAI Engineering Research. Claude Community Ambassador en Bogotá: da talleres de agentes con Agent SDK y Managed Agents. Publica herramientas de agentes y evals abiertas.
- **Qué va a mirar (inferencia):** evals como parte del producto; calidad de ingeniería del agente; trabajo abierto y reutilizable.
- **Ganchos:** el analista construido con Claude Agent SDK, que es lo que él enseña; carpeta de evals con reporte; servidor MCP; buscarlo temprano como mentor y pedirle opinión sobre el diseño de los evals.
- **Frase:** "Los evals corren con cada cambio y publicamos el reporte, incluido lo que salió mal."
- **Pregunta probable:** ¿qué hace el agente y qué no? El cruce es código. El agente investiga con herramientas de lectura, analiza y redacta. No tiene herramientas que cambien el estado.
- **Evitar:** presentar una envoltura de un modelo.

### Pablo Pastrana (mentor), Dapper

- **Folleto:** Product Lead en Dapper, regtech colombiana que monitorea con IA cambios legislativos y regulatorios en América Latina.
- **Verificado en su perfil público:** anunció que el conector MCP de Dapper llegó al directorio oficial de Claude, y que Dapper se conecta por MCP a varios asistentes.
- **Para qué usarlo:** Dapper es el mismo patrón de producto (un radar de cambios cruzado con lo que le importa al cliente). Preguntarle cómo manejan la fatiga de alertas, cómo empaquetan el producto, qué exige publicar un conector y qué normas obligan a gestionar vulnerabilidades en Colombia.
- **Frase:** "El radar vive donde ya trabaja el equipo de TI: le preguntan a su asistente qué equipos están expuestos hoy."

### Robert Gómez (mentor), AIMEDIC

- **Folleto:** CTO de AIMEDIC, lleva IA generativa a clínicas y hospitales. Coautor de un estudio de asistentes de salud para adolescentes en la Universidad Nacional. Investiga vacíos tributarios en LoopholeCheck, con el MIT.
- **Para qué usarlo:** validar al comprador (una clínica con decenas de equipos, datos sensibles y sin equipo de seguridad). Preguntarle qué tendría que cumplir la herramienta para que un hospital la adopte. Si le parece útil, pedirle permiso para decir que el caso se validó con un CTO de salud.

De Antonio Badilla-Olivas, Carlos Gorostiza, Jairo Torregrosa y Robert Gómez no apareció información pública adicional a la del folleto.

## 29. Matriz de ganchos por juez

CU: Christian Urcuqui. AB: Antonio Badilla-Olivas. CG: Carlos Gorostiza. JD: Jose Felipe Duarte. JT: Jairo Torregrosa.

| Pieza | CU | AB | CG | JD | JT |
|---|---|---|---|---|---|
| Generador de datos de prueba | | x | x | | x |
| Normalizador medido | | x | x | | x |
| Suite de inyección | x | x | | | x |
| Verificador del comunicado | x | x | | x | |
| Analista con Agent SDK | x | x | | x | x |
| Límites y riesgo dual | x | x | x | x | x |
| Evidencia por alerta y cobertura | | | x | x | |
| Servidor MCP | x | | | | x |
| Plugin con la guarda instalable | x | x | | | x |
| Barrido de umbrales | | x | x | | |
| Repositorio abierto con trazas | | | | x | x |
| Escalera de escalamiento | | | x | | |
| Remediación accionable | x | | | | |

El comunicado por audiencia y el servidor MCP también les hablan a los dos mentores.

## 30. Pitch de tres minutos

| Tiempo | Qué pasa | Qué se dice |
|---|---|---|
| 0:00 | Pregunta al jurado | "Hoy se publican unas 570 vulnerabilidades. ¿Cuál de ellas está instalada en su empresa en este momento?" |
| 0:20 | Vector de riesgo | La empresa sin equipo de seguridad no sabe qué tiene instalado. Y si le pone un agente a revisarlo, ese agente lee texto que no controla |
| 0:45 | Demo: subir un Excel | En segundos aparecen los equipos expuestos, primero lo que ya se está explotando. Abrir una alerta: porqué, a qué versión subir, comunicado listo para aprobar |
| 1:45 | Ataque en vivo | Subir el CSV con la instrucción escondida. El comunicado no cambia y la prueba queda en verde |
| 2:15 | Validación | Una lámina con los números medidos: detección, falsos positivos, cobertura del normalizador y tasa de inyección con defensa y sin defensa |
| 2:40 | Límites y riesgo dual | Tres líneas: qué no se detecta, quién puede ver el mapa de exposición, qué quedó sin construir |
| 2:50 | Cierre | "Una empresa de 50 equipos pasa de no saber a saber en una hora, sin instalar nada" |

La cifra de 570 al día sale de 17150 CVE publicadas en 30 días, medido contra NVD el 3 de noviembre de 2026. Conviene volver a medirla ese día.

**Reglas de presentación**

- El pitch es a las 5:10 p.m., después de entregar, dura 3 minutos y **no tiene preguntas**. Los jueces leen la ficha técnica mientras se presenta: el pitch no repite la ficha, la vuelve visible.
- El criterio de claridad pide que un juez entienda qué se hizo y qué se encontró en 2 minutos. La tesis tiene que estar dicha antes del minuto 1.
- La demo y el ataque van como **clip grabado** de unos 60 segundos dentro del pitch. Con 3 minutos y muchos equipos, una demo en vivo que se cuelga cuesta el criterio de presentación. La demo desplegada queda en el enlace de la entrega.
- El mismo proyecto corre en local como respaldo.
- Una persona habla y otra maneja la pantalla.
- Los números se muestran como salieron, también los malos.
- Ensayar tres veces con cronómetro.

## 31. Generar la necesidad de adquisición

| Palanca | Cómo |
|---|---|
| El espejo | La pregunta inicial obliga a cada quien a pensar en su empresa. Nadie sabe la respuesta |
| El caso que todos reconocen | El mismo programa en doce versiones repartidas en veinte equipos, una con una vulnerabilidad explotada. Quien haya administrado equipos sabe que pasa y que a mano no se ve |
| La prueba gratis | "Tráigannos un CSV de su inventario y en un minuto ven su exposición" |
| Fricción cero | No hay agente que instalar. Sirve el Excel que la empresa ya tiene |
| Lo explotado no es teoría | Si está en KEV, ya hay víctimas |
| Cumplimiento | ISO/IEC 27001 pide gestionar las vulnerabilidades técnicas (control A.8.8). El radar deja la evidencia |

## 32. Preguntas difíciles

El pitch no tiene preguntas. Estas respuestas van en la ficha técnica, y las tres más fuertes (qué tiene de seguridad de IA, qué impide que el agente haga algo indebido y por qué datos de prueba) se dicen en el pitch sin que nadie las pregunte. Sirven también para los mentores durante el día.

| Pregunta | Respuesta |
|---|---|
| ¿Esto no existe ya en los escáneres comerciales? | Existen, y exigen instalar agentes y pagar por equipo. Este radar parte del inventario que la empresa ya tiene, muestra lo que no pudo evaluar y trata al agente como superficie de ataque |
| ¿Qué tiene de seguridad de IA? | Es defensa automatizada para quien no puede pagar un equipo de seguridad, y demuestra cómo conectar un agente a datos no confiables sin que lo secuestren |
| ¿Es tiempo real? | No. Es un sondeo frecuente con alerta inmediata al detectar cambios |
| ¿Qué no detecta? | CVE sin producto asociado en NVD, versiones no comparables, sistema operativo y dependencias de código. El panel muestra cuánto quedó sin evaluar |
| ¿No le están dando un mapa a los atacantes? | Solo lo ve la organización dueña del inventario. Los avisos abiertos dicen cuántos equipos, nunca cuáles. La información de vulnerabilidades ya es pública; lo privado es el cruce |
| ¿Todo esto lo hicieron hoy? | Sí, el código es de hoy. Se traía experiencia con el problema. El inventario es de prueba y lo genera un script del repositorio |
| Con datos de prueba, ¿cómo saben que sirve en una empresa real? | Las vulnerabilidades y sus señales son reales. Lo sintético es el inventario, modelado sobre cómo un RMM reporta el software. Falta un piloto con una flota real, y se dice |
| ¿Dónde corre el agente? | Fuera de la capa web, en un proceso aparte, como pide la guía de hospedaje del SDK. Solo habla con la base |
| ¿Qué impide que el agente haga algo que no debe? | Cuatro controles del Agent SDK: solo herramientas de lectura; permisos que niegan lo no aprobado; un hook antes de cada llamada y otro que limpia el texto del inventario; salida estructurada con verificador |
| ¿Y si el modelo inventa una versión o una CVE? | El verificador compara cada dato con el origen. Si algo no coincide, se publica el texto armado por código. Además una persona aprueba |

## 33. Lo que resta puntos

1. Presentarlo como producto de ciberseguridad sin la parte de IA.
2. Decir que el modelo "decide" o "detecta". El modelo redacta; el código cruza.
3. Usar o mostrar datos reales de una empresa.
4. Llegar sin números propios.
5. Esconder los límites. Aquí son un criterio de evaluación.

## 34. Cifras de calibración

Vienen de un cruce anterior sobre una flota real, el 3 de noviembre de 2026. **No se presentan.** Sirven para que los datos de prueba tengan proporciones creíbles.

| Cifra | Valor |
|---|---|
| Equipos de la flota | 51 |
| Programas distintos | 437 |
| Programas cubiertos por un catálogo manual | 6 |
| Hallazgos en la primera corrida completa | 153 |
| De esos, acción inmediata | 18 |
| Con explotación confirmada (KEV) | 12 |
| Equipos afectados | 39 |
| Versiones de un mismo programa conviviendo | 12, en 21 equipos |

La única cifra presentable de ese día es la pública: 17150 CVE publicadas en 30 días, unas 570 al día.
