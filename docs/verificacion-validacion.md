## Decisiones del núcleo que cambian cifras

Tres decisiones del cruce, aprobadas por el equipo. Cada una tiene prueba.

| Decisión | Por qué | Efecto medible | Prueba |
|---|---|---|---|
| El CVSS de una CVE es la primera métrica que trae NVD, en orden 4.0, 3.1, 3.0, 2.0 (suele ser la del fabricante o CNA), no la "Primary" de NVD | Es el mismo criterio de la respuesta conocida, escrita aparte del cruce; mezclar criterios daría diferencias que no son errores de detección | PuTTY 0.81 queda en 3.7 (informativo) y MongoDB Compass 1.36.3 en 7.5; con la Primary serían 5.9 y 9.8 | `tests/test_cruce.py::test_respuesta_conocida_completa` |
| Un hallazgo no preciso (NVD no dice qué versiones afecta) es siempre "informativo", aunque tenga KEV o CVSS alto; sus razones lo dicen | No se puede confirmar con la versión instalada. Sin esto, cada versión sana de Chrome tendría 13 avisos inmediatos | Los 1098 pares no precisos por equipo del inventario de prueba quedan en el panel sin disparar alertas | `tests/test_prioridad.py::test_no_preciso_queda_informativo` |
| Un grupo por producto se arma con los hallazgos precisos; los no precisos suman solo una razón aparte y no bloquean la versión objetivo | Comunicar por producto exige decir qué equipos actualizar y a qué versión | Chrome: 30 equipos (los que tienen 156.0.8079.100 y 157.0.8103.60), versión objetivo 157.0.8103.78. Sin la regla serían 50 equipos (incluidos 20 sanos) y ninguna versión objetivo | `tests/test_corrida.py::test_grupos_y_cierre` |

**Por qué Chrome dice 30 equipos y no 50:** 20 equipos tienen Chrome 157.0.8103.78, que no tiene ninguna CVE precisa. Solo les tocan 13 CVE que NVD publica sin versión ("afectan a todas"), y esas no se pueden confirmar con la versión instalada. Se muestran aparte para que una persona las revise, pero no se cuentan como equipos por actualizar.
