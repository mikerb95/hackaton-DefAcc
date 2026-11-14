# Resumen

**Amenaza.** Quien escriba en un inventario de software puede esconder en él instrucciones
para que el agente que lo lee oculte un equipo, invente una CVE o niegue el riesgo.

**Defensa.** Código determinista decide qué está expuesto cruzando el inventario con NVD,
KEV y EPSS; el agente solo lee, el texto del inventario se limpia y marca como dato, y
cada comunicado se verifica contra el origen y lo aprueba una persona.

**Evaluación.** Se midió con un inventario sintético de respuesta conocida y una suite de
inyección por rondas, con y sin defensa.

**Resultados.** El cruce encontró 1500 de 1500 pares CVE y versión sin falsos positivos, y
el normalizador acertó el 83,3 % de nombres fuera de la semilla, frente al 49,4 % por
nombre exacto. En 70 corridas del analista real, con defensa se lograron 0 de 35 ataques
(0 de 31 sin los casos usados para ajustar el prompt), sin equipos ocultos, y el
verificador aceptó el texto del agente en 31 de 35; el resto, con el respaldo.
Los 2 logrados sin defensa miden exposición al texto crudo, no obediencia.

**Límites.** Un agente obediente aún puede torcer un comunicado con datos
permitidos; la validación es sintética, el acceso tiene usuarios con roles pero sin SSO, y
el agente local de inventario solo se probó en Windows 11.

**Uso dual.** Solo la organización dueña ve el mapa de exposición; los avisos abiertos dicen
cuántos equipos, nunca cuáles, y la suite se publica como prueba defensiva.
