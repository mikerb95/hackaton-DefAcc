# Agente local de inventario: plan

Creado el 14 de noviembre de 2026, durante la hackatón. Es un plan, no código: nada de esto
se ha construido ni probado.

Convención: **Verificado** (probado o leído en documentación oficial), **Propuesto** (diseño
ajustable), **Por verificar** (dato de memoria o sin probar), **Estimado** (horas a ojo).

---

## 1. Qué es

Un programa pequeño que se instala en cada PC con Windows o Linux, levanta el inventario de
software, sistema operativo, parches, hardware y postura de seguridad, y lo envía al radar.
El radar cruza ese inventario con NVD, KEV, EPSS y las fuentes de cada sistema operativo, y
el analista entrega, por equipo y por producto, qué está mal y cómo resolverlo.

Reemplaza al CSV y al RMM como fuente de inventario para quien no tiene ninguno de los dos,
que es justo el comprador objetivo del radar (TI de 50 a 200 equipos, sin equipo de
seguridad).

**Cambio de alcance frente al plan principal:** el plan principal deja fuera el sistema operativo. Este
plan lo incluye, con las precauciones de la sección 7.

## 2. Principios de diseño

1. **El agente solo recoge y envía.** No recibe órdenes, no ejecuta comandos remotos, no
   aplica parches. Las instrucciones de remediación las lee y ejecuta una persona. Un canal
   de ejecución remota convertiría al radar en un objetivo de alto valor y en una
   herramienta de ataque (riesgo dual).
2. **Solo conexiones salientes.** Ningún puerto abierto en el equipo.
3. **Corre por horario, no como demonio.** Tarea programada en Windows, temporizador de
   systemd en Linux. Menos superficie que un servicio residente.
4. **Lo que reporta el equipo es texto no confiable.** Cualquier usuario sin privilegios puede
   crear una entrada en `HKCU\...\Uninstall` con un `DisplayName` arbitrario. Eso convierte al
   agente local en un vector real de inyección indirecta contra el analista, y refuerza la
   tesis del Track 1: la misma guarda (limpieza, hooks, verificador) cubre este canal.
5. **Datos mínimos.** Ni archivos, ni historial, ni nombres de usuario, ni contenido de
   documentos. Solo lo necesario para cruzar.
6. **Determinista primero.** Cruce, postura y comandos de remediación los arma el código. El
   modelo explica y redacta, nunca inventa un comando.

## 3. Arquitectura

```
PC Windows / Linux                       Radar (lo que ya existe)
+---------------------------+            +------------------------------------+
| radar-agente              |  HTTPS     | API en Vercel                      |
|  recolectores por SO      | ---------> |  POST /api/agente/reporte (nuevo)  |
|  normaliza a ReporteEquipo|  saliente  |  valida, limita, limpia            |
|  firma con credencial     |            |  -> FilaInventario + SO + postura  |
|  tarea programada / timer |            | Núcleo: cruce apps (CPE, ya existe)|
+---------------------------+            |  + cruce SO (nuevo, sección 7)     |
                                         |  + reglas de postura (nuevo)       |
                                         | Worker: analista con remediación   |
                                         |  por plataforma y verificador      |
                                         | Panel: vista por equipo (nueva)    |
                                         +------------------------------------+
```

## 4. Qué recoge

### Windows (Propuesto; las rutas de registro son estándar)

| Dato | Fuente | Nota |
|---|---|---|
| Software instalado | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, la misma bajo `WOW6432Node`, y `HKU\<SID>\...\Uninstall` por perfil | `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`. Se descarta `SystemComponent=1` y las entradas con `ParentKeyName` (actualizaciones) |
| Lo que **no** se usa | `Win32_Product` | Dispara una reparación MSI de cada producto al consultarlo. Lección conocida, verificar en la documentación de Microsoft |
| Apps de Store | `Get-AppxPackage -AllUsers` | Opcional, en una segunda fase |
| Sistema operativo | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `ProductName`, `DisplayVersion`, `CurrentBuild`, `UBR`, `EditionID` | Build más UBR da la versión exacta (por ejemplo `10.0.22631.4317`), la que compara NVD |
| Parches | CIM `Win32_QuickFixEngineering` | Lista de KB. Incompleta para acumulativas: el UBR manda |
| Hardware | CIM `Win32_ComputerSystem`, `Win32_Processor`, `Win32_BIOS`, `Win32_BaseBoard`, `Win32_DiskDrive`, `Win32_Tpm` | Fabricante, modelo, versión de BIOS (hay CVE de firmware), TPM |
| Postura | `Get-MpComputerStatus` (Defender y firmas), `Get-NetFirewallProfile`, `Get-BitLockerVolume`, `Confirm-SecureBootUEFI`, política de Windows Update | Requiere privilegios de administrador; corre como SYSTEM |

### Linux (Propuesto)

| Dato | Fuente | Nota |
|---|---|---|
| Paquetes | `dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n'` o `rpm -qa --queryformat` | Versión del paquete de la distribución, con su sufijo (`1.2.3-1ubuntu0.4`) |
| Otros formatos | `snap list`, `flatpak list --app` | Opcional |
| Sistema operativo | `/etc/os-release` (`ID`, `VERSION_ID`, `VERSION_CODENAME`), `uname -r` | Distribución y kernel |
| Hardware | `/sys/class/dmi/id/*` (algunos campos piden root), `/proc/cpuinfo`, `/proc/meminfo`, `lsblk -J` | |
| Postura | `ufw status` o `firewall-cmd --state`, SELinux (`getenforce`) o AppArmor (`aa-status`), `unattended-upgrades` o `dnf-automatic`, cifrado (`lsblk -o TYPE` con `crypt`), Secure Boot (`mokutil --sb-state`) | Cada comprobación devuelve `si`, `no` o `desconocido`; nunca se adivina |

**Fuera de alcance:** dependencias de código (pip, npm), contenedores, máquinas virtuales
internas. Igual que en el resto del radar.

## 5. Contrato nuevo: `ReporteEquipo` (Propuesto)

```json
{
  "agente_version": "0.1.0",
  "equipo_id": "uuid estable generado en la instalación",
  "nombre_equipo": "EQUIPO-017",
  "recogido": "2026-11-14T15:00:00Z",
  "so": {
    "familia": "windows | linux",
    "nombre": "Windows 11 Pro | Ubuntu",
    "version": "23H2 | 22.04",
    "build": "10.0.22631.4317 | null",
    "kernel": "null | 6.8.0-48-generic",
    "arquitectura": "x64",
    "parches": ["KB5044285"]
  },
  "hardware": {"fabricante": "...", "modelo": "...", "bios": "...", "cpu": "...", "ram_gb": 16, "tpm": "2.0"},
  "postura": {
    "firewall": "si | no | desconocido",
    "antivirus": "si | no | desconocido",
    "firmas_al_dia": "si | no | desconocido",
    "cifrado_disco": "si | no | desconocido",
    "secure_boot": "si | no | desconocido",
    "actualizaciones_automaticas": "si | no | desconocido"
  },
  "software": [
    {"programa": "WinRAR 6.22 (32-bit)", "version": "6.22", "proveedor": "win.rar GmbH",
     "fuente": "registro | dpkg | rpm | snap | flatpak | appx", "ambito": "maquina | usuario"}
  ]
}
```

- Cada elemento de `software` se convierte en una `FilaInventario` con `fuente = "agente"`.
  Hoy el contrato admite `csv`, `excel`, `mcp` y `rmm`: agregar `agente` es un cambio del
  núcleo.
- `so`, `hardware` y `postura` van a tablas nuevas (`equipos`, `postura`), no a `inventario`.
- Topes del lado del servidor: 5000 programas por reporte, 160 caracteres por campo corto
  (los mismos de `limpieza.py`), 1 MB por reporte. Lo que exceda se recorta y se cuenta.

## 6. Envío, inscripción y autenticación (Propuesto)

1. El instalador recibe un **token de inscripción** de la organización (propiedad del MSI o
   variable al instalar el paquete).
2. En la primera corrida, el agente lo canjea en `POST /api/agente/inscribir` por una
   **credencial propia del equipo** y olvida el token. La credencial se guarda con permisos
   de solo SYSTEM o root.
3. Cada reporte va por HTTPS a `POST /api/agente/reporte`, con la credencial en una cabecera.
   El servidor puede revocar un equipo sin tocar a los demás.
4. El servidor solo devuelve `202` y, como mucho, el intervalo deseado. Nunca comandos.
5. Si no hay red, el agente guarda el último reporte y lo reintenta en la próxima corrida.

## 7. Cruce del sistema operativo

Es lo más delicado, porque comparar versiones como en las aplicaciones da muchos falsos
positivos.

### Windows

- **NVD:** las CVE de Windows vienen con CPE por edición y versión
  (`microsoft:windows_11_23h2`, `microsoft:windows_server_2022`, etc.) y rangos por build
  (`versionEndExcluding 10.0.22631.4317`). Con build más UBR, el cruce actual sirve casi sin
  cambios. Por verificar: la forma exacta de los CPE y si todas las CVE recientes traen rango.
- **MSRC (Microsoft):** la API CVRF (`api.msrc.microsoft.com/cvrf/v3.0`) dice qué KB corrige
  cada CVE por producto. Sirve para la remediación ("instalar KB5044285"). Por verificar: el
  endpoint actual y si pide clave.
- **Fin de soporte:** Windows 10 dejó de recibir parches el 14 de octubre de 2025 (salvo con
  ESU). Un equipo así es un hallazgo de postura por sí solo, aunque no empareje ninguna CVE.

### Linux

- **No se usa el CPE de NVD para paquetes de distribución.** Las distribuciones aplican
  parches de seguridad sin cambiar la versión de origen (backports): `openssl 3.0.2` en
  Ubuntu 22.04 puede estar parchado aunque NVD diga que 3.0.2 es vulnerable. Comparar contra
  NVD daría falsos positivos en masa.
- **Se usa OSV.dev**, que publica los avisos de Debian, Ubuntu, Alpine, Rocky, AlmaLinux y
  otras con la versión de paquete de cada distribución. Consulta por lote con
  `POST https://api.osv.dev/v1/querybatch` (paquete, ecosistema, versión). Gratis y sin
  clave. Por verificar: los nombres exactos de ecosistema (`Debian:12`, `Ubuntu:22.04:LTS`) y
  el comparador de versiones de cada distribución (dpkg y rpm no ordenan igual que una tupla
  de enteros: hace falta su propio comparador).
- Alternativas si OSV no cubre una distribución: Debian Security Tracker (JSON), Ubuntu OVAL o
  avisos USN, Red Hat CSAF.
- **Kernel:** igual que los paquetes, se cruza por el paquete del kernel de la distribución,
  no por `linux:linux_kernel` de NVD.
- **Fin de soporte:** la API de endoflife.date dice si la versión de la distribución sigue
  con soporte. Por verificar su uso sin clave.

### KEV y EPSS

Se aplican igual que hoy, por ID de CVE, venga del cruce de aplicaciones, de NVD para
Windows o de OSV (OSV trae el alias CVE cuando existe).

## 8. Reglas de postura (deterministas)

| Regla | Prioridad propuesta |
|---|---|
| SO sin soporte del fabricante | Inmediato |
| Antivirus apagado o firmas con más de 7 días | Inmediato |
| Firewall apagado en algún perfil | Semanal |
| Disco sin cifrar en portátil | Semanal |
| Actualizaciones automáticas apagadas | Semanal |
| Secure Boot apagado | Informativo |
| Dato `desconocido` | Cobertura, nunca hallazgo (regla 1 del radar: sin comparación no hay hallazgo) |

## 9. Remediación y el papel del analista

- **El código arma los comandos** a partir de plantillas cerradas, con el gestor de paquetes
  del equipo, el identificador del paquete y la versión objetivo que ya calcula el núcleo:
  - Windows: `winget upgrade --id RARLab.WinRAR --version 7.13`, o "instalar KB5044285" para el
    SO, o la ruta de Configuración o de directiva para la postura.
  - Debian/Ubuntu: `sudo apt-get install --only-upgrade <paquete>`.
  - RHEL y derivados: `sudo dnf upgrade <paquete>` o `dnf upgrade --advisory <ID>`.
- **El analista explica**: por qué importa, en qué orden hacerlo, qué hacer si no se puede
  actualizar ya (la mitigación temporal que diga la fuente, o la `requiredAction` de KEV), y
  redacta los comunicados por audiencia.
- **El verificador se amplía**: además de CVE, versiones y cifras, extrae del texto todo lo
  que parezca un comando y lo compara con el conjunto que armó el código. Un comando que no
  esté en ese conjunto descarta el texto y se usa el respaldo. Así una inyección en un
  `DisplayName` no puede colar un `curl ... | sh` en las instrucciones.
- **"Incidentes":** el radar no detecta compromisos (no es un EDR). Lo que sí hace: para una CVE
  en KEV sin parchar, el comunicado dice que se trate como posible compromiso y enlaza los
  pasos de verificación de la fuente. Se declara como límite.

## 10. Implementación del agente

### Recomendación

| Opción | A favor | En contra |
|---|---|---|
| **Go, binario único** (recomendada para el producto) | Un ejecutable sin dependencias por plataforma; compilación cruzada; servicio y tareas con `kardianos/service`; paquetes con `nfpm` (deb, rpm) y WiX o `go-msi` (MSI) | Lenguaje nuevo para el equipo; el registro de Windows se lee con `golang.org/x/sys/windows/registry` |
| Python empaquetado (PyInstaller o Nuitka) | El equipo ya lo usa; `winreg` viene en la librería estándar; reutiliza `limpieza.py` | Binarios de 15 a 40 MB, falsos positivos frecuentes de antivirus con PyInstaller, arranque lento |
| osquery más un emisor | Maduro, abierto, multiplataforma; tablas listas (`programs`, `deb_packages`, `rpm_packages`, `os_version`, `patches`, `bitlocker_info`) | Pesado para este caso; agrega su propia superficie y configuración; es otro producto que mantener |

Para el día del evento solo cabe un **colector en Python con librería estándar** (fase 0).
Para el producto, Go.

### Instalación

| Plataforma | Paquete | Cómo corre |
|---|---|---|
| Windows 10/11 y Server | MSI firmado (Authenticode), parámetros `TOKEN` y `URL` | Tarea programada como SYSTEM, cada 12 horas y al arrancar, con retraso aleatorio para no saturar el servidor |
| Debian, Ubuntu | `.deb` firmado, repositorio APT propio | `radar-agente.service` (oneshot) más `radar-agente.timer` |
| RHEL, Rocky, Alma, Fedora | `.rpm` firmado, repositorio propio | Igual que arriba |
| Cualquiera, para probar | El binario suelto con `--una-vez --salida reporte.json` | Manual, sin enviar nada |

Desinstalar borra la credencial y la tarea; el servidor marca el equipo como retirado.

## 11. Seguridad del propio agente

| Amenaza | Defensa |
|---|---|
| Instrucción escondida en un nombre de programa (cualquier usuario puede escribir en `HKCU`) | Mismo pipeline que hoy: limpieza con topes, herramientas que devuelven datos normalizados, hooks, verificador, comandos solo desde plantillas, aprobación humana |
| Reporte falso (un equipo comprometido miente sobre su versión) | Integridad de la fuente: límite declarado. Se mitiga comparando con otras fuentes (RMM, escaneo autorizado) |
| Robo de la credencial del equipo | Permisos de solo SYSTEM o root; credencial por equipo y revocable; solo sirve para enviar reportes de ese equipo |
| Agente o actualización suplantados | Binarios y repositorios firmados; actualización solo desde el canal firmado; SBOM del propio agente publicado |
| El servidor como objetivo | No hay canal de órdenes: tomar el servidor no da ejecución en los PC |
| Mapa de exposición | Mismo control que el resto del radar: solo lo ve la organización dueña |

## 12. Fases

| Fase | Qué | Estimado |
|---|---|---|
| 0, hoy si se decide | `colector/colector.py`, solo librería estándar: Windows con `winreg` (las tres claves Uninstall, SO desde `CurrentVersion`) y Linux con `dpkg-query`/`rpm` y `os-release`. Escribe el CSV con las columnas actuales (`equipo, programa, version, proveedor, sistema`) y lo sube a `POST /api/inventario`. Sin instalador, sin postura, sin cruce de SO. Probado solo en portátiles del equipo | 1.5 a 2 h |
| 1 | Contrato `ReporteEquipo`, `fuente = agente`, endpoints de inscripción y reporte, tablas `equipos` y `postura`, vista por equipo en el panel | 2 a 3 días |
| 2 | Cruce de SO: Windows con NVD y MSRC, Linux con OSV y comparadores dpkg y rpm, fin de soporte | 3 a 5 días |
| 3 | Agente en Go, MSI, deb y rpm firmados, tarea y timer, reintentos | 1 semana |
| 4 | Remediación con plantillas de comandos y verificador ampliado; reglas de postura | 3 días |
| 5 | Piloto con una flota real y medición de falsos positivos del cruce de SO | 2 semanas |

### Sobre la fase 0 hoy

- **A favor:** la demo gana un momento fuerte ("se corre en este portátil y aparece en el panel"),
  y muestra un vector de inyección real (una entrada de `HKCU` creada sin privilegios).
- **En contra:** el congelamiento es a las 2:15 p.m. y el frente `analista` va atrasado.
- **Si se hace:** que lo tome el frente `plugin` (dueño de la ingesta, casi libre), sin tocar
  contratos (usa el CSV actual), y solo en máquinas del equipo (regla del evento).
- **Si no:** va a la ficha como "siguiente paso" con este plan como respaldo.

## 13. Validación

- Inventario de referencia: una VM Windows 11 y una Ubuntu 22.04 con versiones conocidas
  instaladas a propósito (WinRAR 6.22, 7-Zip 24.08, un paquete Ubuntu con USN conocido).
- Métricas: programas encontrados frente a la lista instalada, exactitud de versión, falsos
  positivos del cruce de SO frente a un escáner de referencia autorizado, tiempo y tamaño del
  reporte.
- Suite de inyección ampliada: entradas de `HKCU` con instrucciones, nombres de paquete
  manipulados en un repositorio local de prueba.

## 14. Por verificar

- Que `Win32_Product` dispare reparaciones MSI (documentación de Microsoft).
- Forma de los CPE de Windows en NVD y cobertura de rangos por build.
- Endpoint y acceso de la API CVRF de MSRC.
- Ecosistemas de OSV para cada distribución y su cobertura real de Ubuntu y RHEL.
- Comparadores de versión de dpkg y rpm en Go y en Python (sin depender de las librerías del
  sistema).
- Uso de endoflife.date sin clave y sus límites.
- Firma de código: costo del certificado Authenticode (el único gasto nuevo del plan).
- Si Defender y BitLocker se consultan sin PowerShell desde Go (WMI) o hace falta lanzarlo.

## 15. Riesgo dual

- Un agente instalado en todos los PC con un inventario completo es, en manos equivocadas, una
  herramienta de reconocimiento. Por eso no tiene canal de órdenes, solo envía, y los datos
  quedan en el espacio de la organización.
- Las instrucciones de remediación son de defensa (actualizar, activar, configurar). Nunca
  incluyen cómo explotar una falla.
- El código del agente será abierto y corto para que cualquiera lo audite antes de instalarlo.
