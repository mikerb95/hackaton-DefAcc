# Diagramas de actividades

Cuatro flujos de control internos del radar, en notación de actividades: dónde se decide,
qué camino toma cada rama y dónde termina. Complementan los diagramas de secuencia
([secuencia.md](secuencia.md)): la secuencia muestra quién le habla a quién; la actividad
muestra las decisiones. Cada sección abre con su caso de uso
([casos-de-uso.md](../casos-de-uso.md)), los archivos que lo implementan, el diagrama y la
decisión de diseño que explica su forma. Están en Mermaid para que GitHub los muestre sin
compilar nada.

| Cifra | Valor |
|---|---|
| Diagramas | 4 |
| Casos de uso que recorren | CU-01, CU-02, CU-03, CU-04 |
| Carriles en total | 13 |
| Finales que no son hallazgo ni texto del agente | cobertura, respaldo, escritura negada |

## Notación

| Elemento | Cómo se dibuja |
|---|---|
| Inicio | círculo `Inicio` |
| Acción | rectángulo redondeado |
| Decisión | rombo, con la guarda de cada salida entre corchetes: `[sí]`, `[no]` |
| Carril | recuadro con el nombre de quien hace la acción |
| Final de actividad | círculo doble `Fin` |
| Final de flujo | círculo doble con el destino (`Cobertura`, `Respaldo`): esa rama termina ahí y no vuelve a unirse |
| Bucle | flecha que vuelve a una acción anterior, con su guarda |

---

## CU-01 · Normalización de una fila del inventario

CU-01 · Cómo una fila del inventario termina en un activo con CPE o en cobertura con su
motivo, y dónde entra el modelo (solo en el empate, y solo con la bandera). Archivos:
`radar/ingesta/archivos.py`, `radar/ingesta/normalizador.py::normalizar`, `decidir`. Ver
también: [carga y cruce en secuencia](secuencia.md#cu-02--carga-de-inventario-y-cruce).

```mermaid
flowchart TD
    INI((Inicio))

    subgraph ING["Ingesta"]
        A1(Leer fila del CSV o Excel)
        D1{¿Trae equipo y programa?}
        A2(Descartar la fila con su número y motivo)
        D2{¿El equipo es un hostname válido?}
        A3("Reemplazar por nombre saneado, EQUIPO-017~f502")
    end

    subgraph NOR["Normalizador"]
        A4(Separar programa, proveedor y versión del texto agregado)
        D3{¿Hay texto agregado o señal de instrucción?}
        A5(Registrar sospecha: equipo, campos y señales, sin el texto)
        A6(Calcular versión comparable)
        D4{¿Versión vacía o ilegible?}
        A7(Limpiar el nombre)
        D5{¿Hay alias curado?}
        D6{¿El alias tiene CPE?}
        A8(Buscar los 5 pares más parecidos con rapidfuzz)
        D7{¿Alguno supera el mínimo?}
        D8{¿Gana claro o desempata el código?}
        D9{¿Fila sospechosa con empate?}
        A9("Agrupar en Activo producto@versión con sus pares")
    end

    subgraph MOD["Claude, solo con RADAR_DESEMPATE_MODELO=1"]
        D10{¿Bandera activa?}
        A10(Elegir entre los 5: 1 a 5 o ninguno)
        D11{¿Respondió un número?}
    end

    COB(((Cobertura con motivo)))
    FIN(((Fin: activo listo para el cruce)))
    DESC(((Fin: fila descartada)))

    INI --> A1 --> D1
    D1 -->|"[no]"| A2 --> DESC
    D1 -->|"[sí]"| D2
    D2 -->|"[no]"| A3 --> A4
    D2 -->|"[sí]"| A4
    A4 --> D3
    D3 -->|"[sí]"| A5 --> A6
    D3 -->|"[no]"| A6
    A6 --> D4
    D4 -->|"[sí]: sin_version o no_comparable"| COB
    D4 -->|"[no]"| A7 --> D5
    D5 -->|"[sí]"| D6
    D6 -->|"[no]: sin_cpe"| COB
    D6 -->|"[sí]"| D9
    D5 -->|"[no]"| A8 --> D7
    D7 -->|"[no]: sin_cpe"| COB
    D7 -->|"[sí]"| D8
    D8 -->|"[sí]"| D9
    D8 -->|"[empate]"| D10
    D10 -->|"[no]: gana el primero, confianza 0,7"| D9
    D10 -->|"[sí]"| A10 --> D11
    D11 -->|"[sí]"| D9
    D11 -->|"[ninguno o falla]: sin_cpe"| COB
    D9 -->|"[sí]: sin_cpe"| COB
    D9 -->|"[no]: confianza 0,6 si es sospechosa"| A9 --> FIN
```

Por qué tiene esta forma: hay tres salidas a cobertura y ninguna a "hallazgo sin comparar"
(regla 1). La rama de la sospecha no corta el flujo: una fila con texto agregado se sigue
normalizando con el prefijo, porque mandarla a cobertura le daría al atacante justo lo que
pide (sacar el equipo de los hallazgos). Solo cae a cobertura si el prefijo no se reconoce o
queda en empate, y entonces se cuenta como posible inyección, no en silencio. El modelo está
en un carril propio que se puede apagar sin cambiar el resto: si falla, decide el código.

---

## CU-02 · Afectación y prioridad de una CVE sobre un activo

CU-02 · La regla de afectación de cada rango de NVD contra la versión instalada, cuál rango
manda y cómo se prioriza el hallazgo. Archivos: `radar/nucleo/cruce.py::afecta`,
`evaluar_cve`, `radar/nucleo/prioridad.py::priorizar`.

```mermaid
flowchart TD
    INI((Inicio))

    subgraph CRU["Núcleo: cruce"]
        A1(Tomar un rango de la CVE para un par del activo)
        D1{¿Versión fija en el CPE?}
        D2{¿Igual a la instalada?}
        D3{¿Tiene límites?}
        D4{¿Algún límite ilegible?}
        D5{¿La instalada cae dentro de los límites?}
        A2(Anotar rango preciso)
        A3(Anotar rango que afecta a todas)
        D6{¿Quedan rangos?}
        D7{¿Hay rangos precisos?}
        A4(Manda el más acotado: versión fija, dos límites, uno)
        D8{¿Hay rangos que afectan a todas?}
    end

    subgraph PRI["Núcleo: prioridad"]
        A5(Sumar razones: KEV, ransomware, EPSS, CVSS)
        D9{¿Hallazgo preciso?}
        D10{¿En KEV o EPSS desde el umbral o CVSS desde 9,0?}
        D11{¿CVSS desde 7,0?}
        INM(Inmediato)
        SEM(Semanal)
        INF(Informativo)
    end

    NO(((Fin: la CVE no afecta al activo)))
    FIN(((Fin: hallazgo con prioridad y razones)))

    INI --> A1 --> D1
    D1 -->|"[sí]"| D2
    D2 -->|"[sí]"| A2
    D2 -->|"[no]"| D6
    D1 -->|"[no]"| D3
    D3 -->|"[no]"| A3
    D3 -->|"[sí]"| D4
    D4 -->|"[sí]: no se adivina"| D6
    D4 -->|"[no]"| D5
    D5 -->|"[sí]"| A2
    D5 -->|"[no]"| D6
    A2 --> D6
    A3 --> D6
    D6 -->|"[sí]"| A1
    D6 -->|"[no]"| D7
    D7 -->|"[sí]"| A4 --> A5
    D7 -->|"[no]"| D8
    D8 -->|"[sí]: no preciso"| A5
    D8 -->|"[no]"| NO
    A5 --> D9
    D9 -->|"[no]"| INF
    D9 -->|"[sí]"| D10
    D10 -->|"[sí]"| INM
    D10 -->|"[no]"| D11
    D11 -->|"[sí]"| SEM
    D11 -->|"[no]"| INF
    INM --> FIN
    SEM --> FIN
    INF --> FIN
```

Por qué tiene esta forma: un límite ilegible no empareja, en vez de suponer que afecta
(nunca se adivina una versión). Un rango preciso gana sobre uno que afecta "a todas", y la
decisión "no preciso" sale antes de mirar KEV o CVSS: una CVE que NVD publica sin versión
queda informativa aunque esté en KEV, porque no se puede confirmar con la versión instalada.
Sin esa rama, cada versión sana de Chrome tendría 13 avisos inmediatos
([verificacion-validacion.md](../verificacion-validacion.md)). EPSS ausente agrega la razón
"sin dato" y no cuenta como bajo. Las entradas `vulnerable: false` no llegan a este flujo:
se descartan al leer NVD. La versión instalada ilegible tampoco: ya quedó en cobertura en CU-01.

---

## CU-03 · Análisis de un producto con verificador y respaldo

CU-03 · Lo que hace el worker por cada producto que exige acción, desde lanzar al agente
hasta guardar un texto que nunca queda vacío, y dónde entra la persona. Archivos:
`worker/principal.py`, `worker/analizar.py`, `radar/agente/analista.py`, `hooks.py`,
`verificador.py::decidir`, `respaldo.py`, `radar/api/rutas.py`. Ver también:
[ataque bloqueado en el analista](secuencia.md#cu-04--ataque-bloqueado-en-el-analista).

```mermaid
flowchart TD
    INI((Inicio))

    subgraph WRK["Worker"]
        A1(Tomar el trabajo analizar más antiguo)
        D1{¿Apunta a Turso sin --turso?}
        A2(Leer grupos y elegir inmediatos, semanales o con KEV)
        A3(Tomar el siguiente grupo)
        D2{¿Hay créditos y clave?}
        A4(Guardar análisis y traza)
        D3{¿Quedan grupos?}
        D4{¿Hubo errores al guardar?}
    end

    subgraph AGE["Analista, Agent SDK encerrado"]
        A5(Lanzar con dontAsk, disallowed_tools, setting_sources vacío, 8 turnos, 0,50 USD)
        A6(Pedir una herramienta)
        D5{"Hook PreToolUse: ¿herramienta de la lista y argumentos limpios?"}
        A7(Negar la llamada y anotarla en la traza)
        A8(Hook PostToolUse: limpiar el resultado)
        D6{¿Necesita más datos y quedan turnos?}
        D7{¿Entregó salida estructurada válida?}
    end

    subgraph VER["Verificador, sin modelo"]
        D8{¿Nada de más, nada de menos, regla 5 y sin minimizar?}
        A9(Usar el texto del agente, verificado)
        A10(Armar el respaldo por código)
    end

    subgraph PER["Responsable de TI"]
        A11(Revisar el detalle del producto en el panel)
        D9{¿Aprueba?}
        A12(Aprobar con su nombre)
    end

    NOCORRE(((Fin: el worker no corre)))
    FIN(((Fin: comunicado aprobado)))
    PEND(((Fin: queda sin aprobar)))

    INI --> A1 --> D1
    D1 -->|"[sí]"| NOCORRE
    D1 -->|"[no]"| A2 --> A3 --> D2
    D2 -->|"[no]"| A10
    D2 -->|"[sí]"| A5 --> A6 --> D5
    D5 -->|"[no]"| A7 --> D6
    D5 -->|"[sí]"| A8 --> D6
    D6 -->|"[sí]"| A6
    D6 -->|"[no]"| D7
    D7 -->|"[no]: falla, tope o negativa"| A10
    D7 -->|"[sí]"| D8
    D8 -->|"[sí]"| A9 --> A4
    D8 -->|"[no]: se registran los problemas"| A10 --> A4
    A4 --> D3
    D3 -->|"[sí]"| A3
    D3 -->|"[no]"| D4
    D4 -->|"[no]: trabajo hecho"| A11
    D4 -->|"[sí]: trabajo fallido, los demás quedan guardados"| A11
    A11 --> D9
    D9 -->|"[sí]"| A12 --> FIN
    D9 -->|"[no]"| PEND
```

Por qué tiene esta forma: todos los caminos del carril del agente terminan en el verificador
o en el respaldo, y los dos llevan a guardar. No hay una salida en la que el producto quede sin
texto (regla 6). El verificador no tiene modelo: compara contra los textos de NVD y las cifras
del grupo, nunca contra el inventario. Un hook que falla niega la llamada (`on_failure="block"`)
en vez de dejarla pasar. La persona está al final y fuera del bucle: el radar redacta y
verifica, pero solo una persona con nombre aprueba, y un análisis nuevo borra esa aprobación.

---

## CU-04 · Carga desde Claude Code con la guarda del plugin

CU-04 · Qué pasa cuando alguien pide en Claude Code cargar un inventario que puede venir
envenenado: la aprobación antes de escribir, la limpieza después y lo que pasa si una de
las dos falla. Archivos: `plugin/hooks/`, `plugin/scripts/aprobar_escritura.py`,
`limpiar_salida.py`, `radar/mcp/servidor.py`. Ver también:
[ataque bloqueado en el plugin](secuencia.md#cu-04--ataque-bloqueado-en-el-plugin).

```mermaid
flowchart TD
    INI((Inicio))

    subgraph TI["Responsable de TI"]
        A1(Pedir que cargue el inventario)
        D1{¿Aprueba la escritura?}
        A9(Leer la respuesta y revisar las filas señaladas)
    end

    subgraph CC["Claude Code"]
        A2(Llamar a cargar_inventario)
        D2{¿Sesión interactiva?}
        A8(Responder con los hallazgos del cruce)
    end

    subgraph GU["Guarda del plugin"]
        D3{"Hook PreToolUse: ¿entrada legible?"}
        A3(Pedir aprobación con un resumen limpio)
        A4(Hook PostToolUse: limpiar, envolver en datos_no_confiables y trazar)
        D4{¿La limpieza falló?}
        A5(Devolver salida fija: retenida por la guarda)
    end

    subgraph MCP["Servidor radar-mcp"]
        A6(Leer el archivo, sanear equipos, normalizar, cruzar y encolar análisis)
        A7(Limpiar la respuesta con limpiar_estructura)
    end

    NEG(((Fin: escritura negada, la base queda igual)))
    FIN(((Fin: inventario cruzado, instrucciones sin obedecer)))

    INI --> A1 --> A2 --> D3
    D3 -->|"[no]: deny"| NEG
    D3 -->|"[sí]"| D2
    D2 -->|"[no]: el ask cuenta como negado"| NEG
    D2 -->|"[sí]"| A3 --> D1
    D1 -->|"[no]"| NEG
    D1 -->|"[sí]"| A6 --> A7 --> A4 --> D4
    D4 -->|"[sí]"| A5 --> A8
    D4 -->|"[no]"| A8
    A8 --> A9 --> FIN
```

Por qué tiene esta forma: las tres ramas que no son la aprobación explícita terminan en el
mismo final (escritura negada), así que la falla del hook, la sesión sin persona y el "no"
dan el mismo resultado. La limpieza está dos veces, en el servidor y en el hook, porque un
`PostToolUse` que falla deja pasar el texto original aunque tenga `onFailure: block`
(verificado el 14 de noviembre de 2026); por eso la rama de falla devuelve una salida fija
y no el texto. Un nombre de equipo válido como hostname pero con forma de instrucción pasa el
saneo: lo que lo contiene es que sigue limpio y marcado como dato (ver
[LIMITES.md](../LIMITES.md)).
