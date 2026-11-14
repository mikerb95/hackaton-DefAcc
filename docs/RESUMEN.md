# Resumen

**Amenaza.** Un agente que lee inventarios lee texto no confiable: quien escriba
en él puede esconder una instrucción en un programa, equipo, proveedor o versión para ocultar un equipo, inventar una CVE o negar el riesgo.

**Defensa.** Código determinista decide qué está expuesto cruzando el
inventario con NVD, KEV y EPSS y reconoce el producto aunque el nombre traiga texto
agregado; el agente solo lee, el texto del inventario se limpia y se marca como dato, y
cada comunicado se verifica contra el origen y lo aprueba una persona.

**Evaluación.** Se midió con un inventario sintético de 52 equipos y respuesta calculada
aparte, y con una suite de inyección por rondas, con y sin defensa, cuya última
ronda se escribió sin reajustar.

**Resultados.** El cruce encontró 1500 de 1500 pares CVE y versión sin falsos positivos; el
normalizador acertó el 83,3 % de los nombres fuera de la semilla, frente al 49,4 % de la
línea base; con un agente que obedece todo, la tasa de inyección bajó de 8 de 8 a 6 de
8, sin ningún equipo oculto. Cargar y cruzar 1333 filas tarda unos 10 s en Vercel.

**Límites.** Contra un modelo que obedece, las defensas no impiden un comunicado torcido con
datos permitidos; falta medir el analista real y la validación es sintética.

**Uso dual.** El mapa de exposición solo lo ve la organización dueña, los avisos abiertos
dicen cuántos equipos y nunca cuáles, y la suite se publica como prueba defensiva.
