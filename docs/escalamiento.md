# Escalera de escalamiento

Qué pasa con una alerta según su prioridad, y cuándo sube de panel a ticket y de ticket a teléfono. El radar automatiza el primer peldaño (panel y lista de pendientes de aviso); el ticket y la llamada los hace una persona con los datos que el radar ya dejó listos.

| Peldaño | Cuándo | Quién | Con qué |
|---|---|---|---|
| 1 · Panel | Todo hallazgo. Informativo y semanal se quedan aquí; lo semanal entra al resumen de la semana (`pendientes_de_aviso(prioridades=("semanal",))`) | El radar, solo | Grupo por producto con razones, equipos y versión objetivo |
| 2 · Ticket | Prioridad inmediata: KEV, EPSS desde 0,10 o CVSS desde 9,0. Sale de `pendientes_de_aviso()` cuando una persona aprueba el comunicado | Responsable de TI | Comunicado aprobado, lista de equipos, versión objetivo y la acción que exige CISA para la CVE en KEV |
| 3 · Teléfono | Inmediato con ransomware conocido (KEV), o plazo de CISA vencido o a 2 días o menos, o ticket inmediato que sigue en estado "nuevo" 24 horas después | Responsable de TI llama al dueño del equipo o a su jefe | El mismo ticket; la llamada no agrega datos, acorta el tiempo |

Reglas:

- **Una acción por producto.** Se escala el grupo, no cada CVE.
- **Sin repetir.** Lo que ya se avisó no vuelve a subir, salvo que gane prioridad (por ejemplo, su CVE entra a KEV).
- **La decisión humana manda.** Cerrar (mitigado o descartado) exige quién y un comentario; el radar solo propone cierres.
- **Lo no preciso no escala.** Una CVE que NVD publica sin versión se queda en el panel hasta que una persona la confirme.

Lo que todavía no está: el radar no abre tickets ni llama; no mide las 24 horas del peldaño 3 (hoy se ve por la fecha de detección y el estado en el panel).
