# Agente local de inventario

Qué se construyó del plan de [plan-agente-local.md](plan-agente-local.md), cómo se usa y qué
falta. Todo esto vive en la rama `agente-local`.

El agente es un programa pequeño que corre en cada PC con Windows o Linux, levanta el
inventario (software, sistema operativo, parches, hardware y postura de seguridad) y lo envía
al radar. El radar lo cruza y muestra, por equipo, qué está mal y cómo resolverlo. Reemplaza
al CSV y al RMM para quien no tiene ninguno de los dos.

## Estado por fase del plan

| Fase del plan | Estado | Dónde |
|---|---|---|
| 0. Colector que escribe el CSV actual y lo sube | Hecho y probado en un PC con Windows 11 | `agente_local/`, orden `subir-csv` |
| 1. Contrato `ReporteEquipo`, inscripción, reporte, tablas, vista por equipo | Hecho | `radar/equipos/`, `radar/api/agente.py`, `public/` |
| 2. Cruce de sistema operativo: Windows con NVD, Linux con OSV, fin de soporte | Hecho. Falta MSRC (qué KB corrige cada CVE) | `radar/equipos/so.py`, `paquetes.py`, `radar/fuentes/osv.py`, `finsoporte.py` |
| 3. Agente empaquetado y firmado | Parcial: agente en Python con instaladores de desarrollo. Faltan el binario en Go, el MSI, el `.deb` y el `.rpm` firmados | `agente_local/instalacion/` |
| 4. Remediación con plantillas, verificador ampliado y reglas de postura | Hecho | `radar/equipos/remediacion.py`, `comandos.py`, `postura.py`, `radar/agente/verificador.py` |
| 5. Piloto con una flota real | No hecho: necesita equipos reales y permiso escrito | |

## Probarlo en cinco pasos

Todo en local, con sqlite. Solo en máquinas del equipo (regla del evento).

```bash
uv sync --all-extras

# 1. Radar con base y la inscripción abierta
export RADAR_DATOS=base AGENTE_TOKEN_INSCRIPCION=un-token-largo
uv run python -m worker.descargar --en-linea --pares rarlab:winrar google:chrome
uv run uvicorn app:app --port 8000

# 2. En el PC: ver qué recoge, sin enviar nada
python -m agente_local recoger --salida reporte.json

# 3. Inscribir el PC (canjea el token por la credencial del equipo)
RADAR_AGENTE_TOKEN=un-token-largo python -m agente_local inscribir --url http://localhost:8000

# 4. Enviar el reporte
python -m agente_local enviar

# 4b. Aprobar el equipo en el panel (sección "Equipos con agente", botón "Aprobar equipo")

# 5. Si el PC es Linux, cruzar sus paquetes contra OSV
uv run python -m worker.equipos
```

El panel (http://localhost:8000/) muestra la sección "Equipos con agente". Al abrir un equipo
se ve qué hacer en él, con el comando cuando hay plantilla, y qué no se pudo revisar.

Para que el sistema operativo Windows se cruce, el worker tiene que bajar sus CVE:
`uv run python -m worker.descargar --en-linea` ya incluye los pares de los Windows de la flota
(por ejemplo `microsoft:windows_11_23h2`).

La fase 0, sin inscripción ni contratos nuevos, es una sola orden:

```bash
RADAR_CLAVE_ACCESO=la-clave python -m agente_local subir-csv --url https://radar.ejemplo
```

## Qué recoge

| Dato | Windows | Linux |
|---|---|---|
| Software | Las claves `Uninstall` del registro (64 bits, 32 bits y una por perfil). Nunca `Win32_Product` | `dpkg-query` o `rpm`, con el paquete fuente; `snap` y `flatpak` |
| Sistema | `CurrentBuild` más `UBR` (`10.0.22631.4317`), versión y edición | `os-release` y kernel |
| Parches | Lista de KB (informativa: manda el build) | No aplica |
| Hardware | Fabricante, modelo, BIOS, procesador, memoria, TPM, si es portátil | Lo mismo, desde `/sys` y `/proc` |
| Postura | Firewall, antimalware, firmas, BitLocker, Secure Boot, Windows Update | Firewall, SELinux o AppArmor, cifrado, Secure Boot, actualizaciones automáticas |

No recoge archivos, historial, nombres de usuario ni contenido de documentos. Cada dato de
postura es `si`, `no` o `desconocido`; nunca se adivina, y `desconocido` va a cobertura, no a
hallazgo. Sin privilegios de administrador varios datos de postura quedan en `desconocido`.

## Cómo se cruza cada cosa

| Qué | Contra qué | Por qué así |
|---|---|---|
| Aplicaciones (registro, snap, flatpak) | NVD por CPE, con el núcleo de siempre | Entran a `inventario` con `fuente = agente` |
| Sistema operativo Windows | NVD por CPE (`microsoft:windows_11_23h2`) y rango de build | El sistema entra al cruce como un activo más: misma regla de afectación, misma prioridad |
| Paquetes de la distribución (dpkg, rpm) | OSV.dev | Las distribuciones parchan sin cambiar la versión de origen: cruzar por CPE daría falsos positivos en masa |
| Fin de soporte | Copia de endoflife.date | Un sistema sin soporte es hallazgo inmediato aunque no empareje ninguna CVE |
| Postura | Reglas fijas | Tabla en `radar/equipos/postura.py` |

KEV y EPSS se aplican igual en todos los casos, por ID de CVE.

Los paquetes Linux se cruzan en `worker/equipos.py` y no en la API, porque OSV se consulta
por red. La API deja un trabajo `cruzar_so` y el worker lo toma.

Con equipos con agente, una carga de CSV o Excel ya no reemplaza todo el inventario: reemplaza
lo cargado por archivo, y el cruce se hace sobre todo (archivos, reportes y sistema
operativo). Sin agentes, la carga se comporta como antes.

## Seguridad

| Amenaza | Defensa |
|---|---|
| Instrucción escondida en un `DisplayName` (cualquier usuario puede escribir en `HKCU`) | El agente no interpreta nada. El radar limpia y recorta cada cadena al recibirla (160 caracteres) y otra vez antes de que un modelo la vea. El normalizador solo elige entre CPE reales |
| Nombre de equipo envenenado | Se sanea a un hostname (RFC 1123) y el equipo se cruza igual |
| Comando malicioso en las instrucciones (`curl ... \| sh`) | Los comandos salen de plantillas cerradas del código y cada pieza variable se valida. El verificador extrae del texto todo lo que parezca un comando y descarta el texto si alguno no lo armó el código |
| Robo de la credencial de un equipo | Solo sirve para enviar reportes de ese equipo. En la base se guarda su SHA-256, no la credencial. Se revoca sin tocar a los demás |
| Alguien con el token de inscripción | Puede inscribir equipos nuevos, pero quedan pendientes: su inventario no entra al cruce hasta que TI los aprueba en la consola, y hay un tope de 200 pendientes. No puede reemplazar la credencial de un equipo ya inscrito |
| El servidor como objetivo | No hay canal de órdenes. La respuesta a un reporte es `202` y el intervalo; el agente no lee nada más |
| Redirección que se lleva la credencial | El agente no sigue redirecciones y solo envía por HTTPS |
| Reporte enorme | 1 MB y 5000 programas por reporte; lo que excede se recorta y se cuenta |

La API del agente (`/api/agente/*`) no usa la clave compartida del panel: la inscripción pide
`AGENTE_TOKEN_INSCRIPCION` y cada reporte pide la credencial del equipo. Sin esa variable, la
inscripción está cerrada.

## Comprobado contra las fuentes reales

Hecho el 14 de noviembre de 2026, sobre lo que el plan dejó "por verificar":

- **CPE de Windows en NVD.** Las CVE traen un CPE por versión (`windows_10_22h2`,
  `windows_11_23h2`, `windows_11_24h2`) con `versionEndExcluding` por build.
- **OSV.** `POST /v1/querybatch` responde para `Ubuntu:22.04:LTS`, `Debian:12`,
  `Rocky Linux:9` y `AlmaLinux:9`. Debian y Ubuntu publican por paquete fuente; Rocky y
  AlmaLinux por binario, con la época en la versión. El ID de CVE viene en `upstream`.
- **endoflife.date.** Responde sin clave. En Windows el ciclo depende de la edición (Home y
  Pro, o Enterprise y Education).
- **De punta a punta.** El colector corrió en un PC con Windows 11; su reporte se inscribió,
  se envió y se cruzó. Un Ubuntu 22.04 simulado con `openssl` desactualizado se cruzó contra
  OSV en línea y dio la versión de arreglo y el comando de `apt-get`.

## Límites y lo que falta

- **El reporte puede mentir.** Un equipo comprometido puede reportar versiones falsas. Es un
  límite de integridad de la fuente, no se resuelve aquí.
- **El radar no detecta compromisos.** No es un EDR.
- **Sin MSRC.** Para Windows se dice el build al que hay que llegar, no el KB que lo instala.
- **Tabla de winget curada a mano.** Un producto que no está en `WINGET`
  (`radar/equipos/remediacion.py`) no recibe comando. Los identificadores están por verificar
  con `winget show`.
- **Distribuciones cubiertas:** Ubuntu, Debian, Rocky y AlmaLinux. RHEL, Fedora y las demás
  quedan como "sin cruzar" (visible en el panel), no como "sin hallazgos".
- **Sin estado humano en los hallazgos por equipo.** Los de postura y de paquetes se
  recalculan en cada reporte; todavía no se pueden marcar como mitigados o descartados.
- **El analista no usa todavía los comandos.** El verificador ya acepta `comandos_permitidos`
  y el respaldo ya los incluye, pero `radar/agente/analista.py` está vacío: falta que el
  analista los pase al llamar a `decidir`.
- **Instaladores sin firmar y sin probar en una flota.** `instalar.ps1` e `instalar.sh` son
  de desarrollo. No se corrieron en este trabajo: registran una tarea como SYSTEM o un
  temporizador como root.
- **Apps de la Store (`appx`)** no se recogen.
- **Falsos positivos del cruce de sistema operativo** sin medir contra un escáner de
  referencia (fase 5 del plan).

## Riesgo dual

Un agente en todos los PC con el inventario completo es, en manos equivocadas, una
herramienta de reconocimiento. Por eso no tiene canal de órdenes, solo envía, y los datos
quedan en la base de la organización. Las instrucciones de remediación son de defensa
(actualizar, activar, configurar) y nunca dicen cómo explotar una falla. El código del agente
es corto y solo usa la librería estándar, para que cualquiera lo lea antes de instalarlo.


## Correcciones de la revisión del agente

Los instaladores despiertan al agente cada cinco minutos. Con `enviar --programado`,
el agente solo recoge y envía cuando vence el intervalo recibido del servidor (1 a 168
horas, 12 por defecto). El retraso aleatorio y el siguiente despertar pueden demorar el
envío; no es una hora exacta. `enviar` manual fuerza el envío. Ante una falla de red se
reintenta primero el reporte pendiente y luego se recoge el inventario actual. Un rechazo
4xx descarta el reporte rechazado; las fallas de red y 5xx lo conservan.

Windows exige Python instalado para todos los usuarios dentro de Program Files, con
propietarios y permisos de escritura reservados a SYSTEM, Administradores o TrustedInstaller.
Verifica el árbol del runtime y sus directorios antecesores, rechaza enlaces y ejecuta Python
con `-I` para ignorar PYTHONPATH y paquetes del perfil. Una instalación de Python en AppData
se rechaza antes de inscribir o crear la tarea. El instalador necesita Python 3.10 o superior.

La API autentica antes de leer el cuerpo y aplica el límite de 1 MB durante la lectura,
incluso sin Content-Length o con una longitud declarada incorrecta. En agentes, el saneado
usa la fila reservada 0 (`~f0`); los conflictos entre equipos se resuelven con su UUID.

Validación disponible: pruebas automatizadas de reintentos, intervalos y recepción por
bloques; `powershell -NoProfile -ExecutionPolicy Bypass -File tests/test_instalador_seguridad.ps1`
prueba ACL simuladas (runtime protegido, escritura por usuarios, propietario y enlaces).
La prueba de instalación real requiere una VM Windows con Python protegido y una VM Linux
con systemd, un servidor de prueba y token de inscripción. Comprobar inscripción, primer
envío, reinicio, cambio de intervalo y recuperación tras desconexión antes del piloto.

Los instaladores siguen siendo de desarrollo. Los artefactos MSI/deb/rpm firmados requieren
la infraestructura de empaquetado y las claves/certificados de firma del proyecto; no se
presentan como construidos ni validados por estas pruebas.


## Instalar con doble clic y activar con código

Como en Acronis: se instala sin escribir comandos y se activa desde la consola.

1. En el panel, sección "Equipos con agente", botón **Descargar instalador**. Baja
   `radar-agente.zip`, ya configurado con la URL del radar (`configuracion.txt`).
2. En el PC, descomprímelo y dale **doble clic a `instalar.cmd`**. Pide permiso de
   administrador. Si no hay un Python instalado para todos los usuarios, lo instala con
   winget. Copia el agente a `Program Files`, inscribe el equipo, hace el primer envío y
   registra la tarea programada.
3. Al terminar muestra una ventana con el **código de activación** (por ejemplo
   `CYNF-U89G`), que además queda copiado en el portapapeles. Lo genera el propio agente.
4. En el panel, escribe ese código en "Activar un equipo" y quién activa. Desde ese momento
   el inventario del equipo entra al cruce. Si el equipo ya había reportado, su último
   reporte se cruza en ese instante.

En Linux el mismo paquete se instala con `sudo sh instalar.sh`, que lee la URL de
`configuracion.txt` y muestra el código en la consola. Para quitar el agente en Windows:
doble clic en `desinstalar.cmd`, y luego retirar el equipo en el panel.

Mientras no se activa, el equipo aparece "por activar": reporta y TI ve su nombre, sistema,
hardware y postura, pero su software no se cruza ni genera hallazgos. Si TI no lo reconoce,
lo rechaza (se borra y su credencial deja de servir). Una inscripción que nadie activa en
7 días se borra sola, y hay un tope de 200 pendientes.

**Por qué es seguro.** El agente genera su credencial y su código; el radar guarda solo sus
huellas (SHA-256). El código solo se ve en la pantalla del equipo, así que activar exige
haberlo visto: nadie puede activar un equipo impostor copiando un nombre. El token de la
organización ya no hace falta; si el radar define `AGENTE_TOKEN_INSCRIPCION`, se exige además
y va dentro del zip (por eso la descarga pide la clave del panel). La consola activa al
equipo pero no le da órdenes: el agente sigue sin canal de órdenes.

`AGENTE_APROBACION=automatica` quita la activación (útil en pruebas). `RADAR_URL_PUBLICA`
fija la URL que va en el zip si la de la petición no sirve (detrás de un proxy). Los equipos
inscritos antes de que existiera la activación quedan activos.

**Comprobado en este PC (14 de noviembre de 2026):** se descargó el zip del panel, el agente
se inscribió desde él, mostró el código, envió 111 programas, el equipo quedó "por activar"
sin cruzarse, un código equivocado dio 404 y el correcto (escrito en minúsculas) lo activó y
cruzó las 111 filas. `instalar.cmd` no se corrió completo: instala Python para todos los
usuarios y registra una tarea como SYSTEM, y eso se prueba en una máquina virtual.
