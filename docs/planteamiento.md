# Planteamiento

Qué problema resuelve el radar, para quién, y por qué es un proyecto de seguridad de IA y no
solo un detector de CVE. Léelo primero; el resto de la documentación da por sabido lo que hay
aquí.

| Cifra | Valor |
|---|---|
| Fuentes públicas que cruza | 3 (NVD, CISA KEV, EPSS) |
| Formas de entrada del inventario | 3 (CSV, Excel, MCP) |
| Track de la hackatón | 1, seguridad de agentes e inyección de instrucciones |

## Qué es

Un radar permanente de brechas de seguridad. Cruza el inventario de software de una empresa con
las vulnerabilidades publicadas, dice qué equipos están expuestos, prioriza lo que ya se está
explotando y entrega análisis, forma de solventarlo y un comunicado listo para que TI lo
apruebe.

El inventario puede llegar de un RMM, un CSV, un Excel o una integración por MCP.

## Para quién

El responsable de TI de una empresa de 50 a 200 equipos, sin equipo de seguridad, con un RMM o
una hoja de cálculo como único inventario. No tiene tiempo de leer NVD cada mañana ni de
decidir cuál de cien CVE importa hoy.

## Tesis

> Un radar que cruza el inventario de una empresa con las vulnerabilidades que se están
> explotando hoy, y que demuestra con pruebas que un inventario envenenado no puede tomar
> control del agente que redacta las alertas.

Un detector de CVE a secas es un producto de ciberseguridad. Lo que lo vuelve un proyecto
def/acc son dos cosas: defiende a quien no tiene equipo de seguridad, y trata al propio agente
como superficie de ataque.

## Las cuatro preguntas de la entrega

| Pregunta | Respuesta del proyecto |
|---|---|
| Vector de riesgo | Software con vulnerabilidades explotadas que la empresa no sabe que tiene. Vector propio de IA: el inventario es texto no confiable que llega a un agente, y un nombre de programa puede traer una instrucción escondida (inyección indirecta de prompts) |
| Mecanismo defensivo | Cruce determinista por versión, priorización con KEV y EPSS, y un agente encerrado: solo herramientas de lectura, permisos que niegan lo no aprobado, hooks antes y después de cada herramienta, salida estructurada, verificador y aprobación humana |
| Validación empírica | Sobre datos de prueba con respuesta conocida: detección, falsos positivos, cobertura del normalizador y tasa de éxito de inyección con defensa y sin defensa. Los números están en [reportes-pruebas.md](reportes-pruebas.md) |
| Límites y riesgo dual | El mapa de exposición también le sirve a un atacante. Se documenta quién puede verlo, qué datos nunca salen y qué no se detecta, en [LIMITES.md](LIMITES.md) |

## Por qué el Track 1

La pieza central de la validación es una suite de inyección por inventario contra un agente
con herramientas MCP: es exactamente el tema del Track 1. En el Track 3 el proyecto sería un
detector de CVE más, y la parte de IA quedaría como accesorio.

## Principios que no se negocian

Son las reglas que cualquier cambio tiene que respetar. Cada una tiene prueba en
[testing.md](testing.md).

| Principio | Qué significa en la práctica |
|---|---|
| Sin comparación no hay hallazgo | Versión ilegible o programa sin CPE van a cobertura con su motivo; nunca se adivina |
| Fuente caída no es cero | Si NVD, KEV o EPSS no responden, el panel lo dice arriba. Un EPSS ausente se muestra "sin dato", nunca 0 |
| KEV se empareja por ID de CVE | Nunca por nombre de fabricante |
| No se promete una versión que NVD no da | Con `versionEndIncluding` X se dice "posterior a X", nunca "actualizar a X" |
| El modelo no es punto de falla | Siempre hay un texto de respaldo armado por código |
| El agente solo lee | Encierro por permisos, herramientas negadas, sin configuración heredada y hooks que bloquean ante cualquier falla |
| Todo texto del inventario es no confiable | Se limpia antes de llegar al modelo y se escapa antes de pintarse en el panel |

## Lo que todavía no está

- El worker en GitHub Actions con horario: en la demo corre en un portátil.
- Vercel Sandbox como alternativa al worker: no se evaluó.
