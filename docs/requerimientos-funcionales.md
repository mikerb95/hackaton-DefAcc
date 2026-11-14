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

## Normalizador y datos de prueba

- **RF-301** Normalizar cada fila del inventario a un activo `producto@versión` con uno o más pares de CPE, o a cobertura con motivo (`sin_version`, `no_comparable`, `sin_cpe`). `radar/ingesta/normalizador.py`.
- **RF-302** Versión comparable: limpiar `.windows.N` y `+N`, y usar la versión del nombre cuando el instalador reporta otra (Python 3.12.10 reporta 3.12.10150.0). `radar/ingesta/normalizador.py`.
- **RF-303** Tabla curada de alias para trampas conocidas de NVD (Temurin en `oracle:openjdk`, Docker Desktop con dos pares, Java con tres, nginx en `f5:nginx`, Notepad++, Acrobat Reader DC); NoSQLBooster nunca recibe `mongodb:mongodb`. `radar/ingesta/normalizador.py`.
- **RF-304** Búsqueda difusa (rapidfuzz) contra el diccionario oficial de CPE de NVD reducido (`radar/datos/cpe_pares.json.gz`, 50 515 pares), con desempate por pares deprecados, popularidad y proveedor; plugins de Jenkins excluidos salvo que se nombren. `radar/ingesta/normalizador.py`, `datos_prueba/reducir_cpe.py`.
- **RF-305** Desempate con Claude solo entre los 5 candidatos (salida "1" a "5" o "ninguno"), detrás de la bandera `RADAR_DESEMPATE_MODELO=1`; ante cualquier falla decide el código. `radar/ingesta/normalizador.py`.
- **RF-306** Inventario de prueba reproducible (CSV y Excel, 52 equipos, relleno de 15 a 25 programas por equipo, filas de inyección aparte) con su respuesta conocida, que sale del snapshot y nunca del cruce. `datos_prueba/generar.py`, `datos_prueba/respuesta.py`.
- **RF-307** Medir el normalizador contra la respuesta conocida, con la línea base por nombre exacto y la variante sin alias. `datos_prueba/medir_normalizador.py`.
