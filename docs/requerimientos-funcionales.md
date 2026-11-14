## Núcleo (versiones, cruce, prioridad, agrupación, descarga)

- **RF-101** Comparar versiones de hasta cuatro componentes, con relleno de ceros, sufijos de prelanzamiento y metadatos de compilación; lo ilegible es "no comparable" y nunca se adivina. `radar/nucleo/versiones.py`.
- **RF-102** Decidir si un rango de NVD afecta a una versión instalada (versión fija, límites inclusivos y excluyentes, "afecta a todas" como no preciso); ignorar `vulnerable: false`. `radar/nucleo/cruce.py`.
- **RF-103** Sin comparación no hay hallazgo: sin CPE, sin versión o versión ilegible van a cobertura con su motivo. `radar/nucleo/cruce.py`.
- **RF-104** Versión objetivo por CVE y por producto: `versionEndExcluding` da versión exacta, `versionEndIncluding` solo "posterior a", sin límite superior no se promete nada. `radar/nucleo/cruce.py`.
- **RF-105** Priorizar en inmediato, semanal, informativo y boletín con umbrales ajustables (`CVE_UMBRAL_EPSS`, `CVE_UMBRAL_CVSS`, `CVE_UMBRAL_CVSS_SEMANAL`) y razones en texto; KEV se empareja por ID de CVE; EPSS ausente no es cero. `radar/nucleo/prioridad.py`.
- **RF-106** Agrupar por producto (una acción por producto) con versiones, equipos, CVE, KEV, ransomware, peor CVSS y EPSS, versión objetivo y razones. `radar/nucleo/agrupar.py`.
- **RF-107** Corrida completa: cruzar el inventario contra todas las CVE guardadas, guardar sin pisar la decisión humana y proponer como resueltos los hallazgos que desaparecen. `radar/nucleo/corrida.py`.
- **RF-108** Cargar NVD y KEV desde el snapshot local y EPSS del día, registrando qué fuente respondió. `worker/descargar.py --desde-snapshot`.
- **RF-109** Persistencia en sqlite local con el esquema de Turso; el cambio a Turso es solo de conexión. Conexión de solo lectura para el agente que rechaza escrituras. `radar/bd.py`.
