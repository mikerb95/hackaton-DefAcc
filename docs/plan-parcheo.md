# Parcheo desde el agente local: diseño

Estado: en construcción (14 nov 2026). Cambia el principio 1 de
[`plan-agente-local.md`](plan-agente-local.md): el agente ya no solo recoge y envía; también
aplica parches que una persona aprobó y firmó. Este documento dice cómo, sin convertir al
radar en un canal de ejecución remota.

## 1. Qué garantiza y qué no

Ningún parcheo puede prometer cero fallas: un instalador falla por red, por bloqueos o por un
paquete retenido. Lo que este diseño garantiza es otra cosa, que sí se puede probar:

1. **El agente nunca deja el equipo peor de lo que estaba.** Antes de cada acción mide el
   estado, ensaya cuando el gestor lo permite y guarda lo necesario para volver atrás. Después
   verifica. Si la verificación falla, revierte y vuelve a verificar.
2. **El reporte nunca miente.** Cada acción termina en un estado medido, no supuesto. Si algo
   quedó a medias, el reporte lo dice con ese nombre (`fallido_sin_revertir`, `interrumpido`).
   La verificación final la hace el radar: el equipo envía un inventario nuevo y el cruce dice
   qué CVE quedaron cerradas.
3. **El agente nunca reinicia el equipo.** Si una acción pide reinicio, queda marcada como
   "reinicio pendiente" y el reporte lo destaca.
4. **El agente solo sabe hacer cosas de defensa.** Aunque llegue un plan bien firmado, solo
   ejecuta su catálogo cerrado: actualizar paquetes de una lista blanca, instalar
   actualizaciones de seguridad del sistema y endurecer la postura. Nunca un comando en texto.

## 2. Flujo

```
Panel (admin)                      Servidor (Vercel + Turso)              Agente (PC)
-------------                      -------------------------              -----------
abre el equipo  ---------------->  propuesta: acciones armadas por código
marca acciones  ---------------->  borrador: plan canónico (plan_id,
                                   equipo, emitido, vence, acciones)
firma en el navegador
(Ed25519, clave que solo
 tiene el admin)  -------------->  verifica firma con claves registradas,
                                   guarda plan + firma + foto "antes"
                                                                  <------ GET /api/agente/plan (cada 15 min,
                                                                          solo si el parcheo está habilitado)
                                   devuelve plan + firma  ------------->  verifica firma con su clave fijada,
                                                                          equipo, vigencia, no repetido,
                                                                          catálogo cerrado
                                                                          ejecuta con diario, verifica, revierte
                                                                  <------ POST /api/agente/parcheo/resultado
                                                                  <------ POST /api/agente/reporte (inventario nuevo)
                                   recruza: CVE cerradas "después"
reporte en el panel y PDF  <-----  reporte = plan + resultado + antes/después
```

## 3. Por qué la firma va en el navegador del admin

Si el servidor firmara, quien tome Vercel o Turso podría fabricar planes. Con la clave en el
navegador del admin (archivo JWK que solo él guarda), el servidor solo almacena firmas: tomar el
servidor no da ejecución en los PC. Límite declarado: si el atacante controla el JavaScript del
panel justo cuando el admin firma, puede hacerle firmar otro plan. Aun así ese plan solo puede
contener acciones del catálogo cerrado (actualizar y endurecer), que es la segunda barrera.

La clave pública se fija en el agente al instalarlo (`-ClaveAprobacion` / `--clave-aprobacion`).
El servidor nunca puede cambiarla. El servidor también registra las claves públicas para no
guardar planes con firmas inválidas, pero quien decide es el agente.

## 4. El plan

JSON canónico (claves ordenadas, sin espacios, UTF-8). Lo arma el servidor y el navegador
firma esos bytes exactos.

| Campo | Qué es |
|---|---|
| `version` | 1 |
| `plan_id` | uuid4: el agente no ejecuta dos veces el mismo plan |
| `equipo_id` | el agente rechaza un plan de otro equipo |
| `emitido`, `vence` | vigencia de 72 horas; el agente rechaza un plan vencido |
| `aprobado_por` | nombre de la sesión del admin |
| `acciones` | lista ordenada, cada una con su `ejecutor` y parámetros validados |

Ejecutores del catálogo cerrado (los mismos patrones validan en el servidor y en el agente):

| Ejecutor | Plataforma | Parámetros | Reversión |
|---|---|---|---|
| `winget` | Windows | `paquete` (de la tabla curada), `minimo`, `estricto` | reinstala la versión previa si el catálogo la tiene |
| `windows_update` | Windows | `categorias` (seguridad, críticas) | no reversible; exige punto de restauración |
| `apt` | Debian/Ubuntu | `paquetes`, `minimos` por paquete | `apt-get install pkg=previa` si sigue disponible |
| `dnf` | RHEL y derivados | `paquetes` o `aviso` | `dnf history undo` |
| `postura` | ambas | `regla` (firewall, antivirus, firmas_al_dia, actualizaciones_automaticas) | restaura el estado previo medido |

Cifrado de disco, Secure Boot y SELinux se quedan manuales: no se pueden hacer ni deshacer sin
riesgo desde un agente.

## 5. Ejecución en el agente

Por cada acción, en este orden fijo (aplicaciones, paquetes, postura, sistema operativo):

1. **Prechequeo.** Mide el estado actual. Si ya está al día: `ya_al_dia`. Si una condición de
   seguridad no se cumple (sin winget, simulación de apt que borraría paquetes, firewall que
   cortaría el SSH, sin punto de restauración para Windows Update): `omitido` con el motivo.
2. **Respaldo.** Guarda la versión o el estado previo y comprueba si se puede revertir.
3. **Ejecución** sin shell, con argumentos fijos y tiempo máximo.
4. **Verificación** independiente de lo que diga el instalador (registro de Windows,
   `dpkg-query`, `rpm -q`, estado del firewall).
5. **Reversión** si falla la verificación, y nueva verificación: `revertido` o
   `fallido_sin_revertir`.

Todo queda en un diario (`parcheo/<plan_id>.jsonl`, con `fsync` en cada línea). Si el proceso
muere a mitad, la próxima corrida encuentra el diario sin cierre, mide el estado real y reporta
la acción como `interrumpido`, sin reintentarla.

Estados finales de una acción: `aplicado`, `ya_al_dia`, `revertido`, `sin_cambios`,
`omitido`, `fallido_sin_revertir`, `interrumpido`, `rechazado`. Más la marca
`reinicio_pendiente`.

## 6. Reporte

Informe de remediación por plan, en el panel y como PDF (vista de impresión):

- Encabezado: equipo, plan, aprobado por, huella de la clave, fechas, versión del agente.
- Resumen ejecutivo: estado general, acciones por resultado, CVE y KEV cerradas, reinicio
  pendiente, lo que requiere atención.
- Antes y después: exposición al aprobar frente a la del último cruce.
- Detalle por acción: objetivo, antes y después, CVE, resultado, verificación, reversibilidad.
- Acciones manuales que siguen abiertas.
- Anexo técnico: cronología, comandos ejecutados, códigos de salida, salida recortada, huella
  SHA-256 del plan y de la firma.

Toda la salida que viene del equipo es texto no confiable: se limpia con
`radar/seguridad/limpieza.py` y se muestra escapada.

## 7. Seguridad

| Amenaza | Defensa |
|---|---|
| Tomar el servidor o la base para ejecutar en los PC | La firma la hace la clave del admin, que no está en el servidor; el agente verifica con su clave fijada |
| Repetir un plan viejo | `plan_id` registrado en el agente y vigencia de 72 h |
| Plan para otro equipo | `equipo_id` dentro de lo firmado |
| Plan firmado con algo dañino | Catálogo cerrado en el agente: sin comandos en texto, patrones estrictos, lista blanca de winget |
| Nombre de paquete envenenado en el inventario | Patrones sin espacios ni signos de shell; ejecución sin shell |
| Agente que no quiere parchear | El parcheo se habilita al instalar; sin eso el agente ni pide planes |
| Salida del instalador con inyección | Se limpia, se recorta y nunca llega al modelo |

## 8. Pruebas

Todo lo que ejecuta comandos se prueba con ejecutores simulados en pytest (sin instalar
nada). La prueba real es en el PC con Windows 11 del usuario, con un punto de restauración
antes, siguiendo [`agente-local.md`](agente-local.md).
