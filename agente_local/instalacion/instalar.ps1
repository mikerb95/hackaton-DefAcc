# Instala el agente local del radar en Windows (docs/agente-local.md).
#
# Uso normal: doble clic en instalar.cmd, que pide permiso de administrador y llama a este
# guion. La URL del radar sale de configuracion.txt (viene en el paquete que se descarga
# del panel); si no está, se pregunta en una ventana.
#
#   powershell -ExecutionPolicy Bypass -File instalar.ps1 [-Url https://radar.ejemplo]
#
# Qué hace: busca un Python protegido (o lo instala con winget para todos los usuarios),
# copia el agente a Program Files, inscribe el equipo, hace el primer envío, registra una
# tarea programada como SYSTEM y muestra el código de activación para escribirlo en el panel.
# Qué no hace: no abre puertos, no instala un servicio residente y no recibe órdenes.
#
# Instalador de desarrollo sin firmar, no el MSI firmado del plan (fase 3).

[CmdletBinding()]
param(
    [string]$Url,
    [string]$Token,
    [ValidateRange(1, 168)][int]$IntervaloHoras = 12,
    [int]$RetrasoMaximoSegundos = 900,
    # Sin ventanas: para pruebas o despliegues por consola.
    [switch]$Silencioso
)

$ErrorActionPreference = 'Stop'
$destino = Join-Path $env:ProgramFiles 'RadarAgente'
$tarea = 'RadarAgente'
$titulo = 'Radar de vulnerabilidades'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic

function Avisar([string]$Texto, [string]$Icono = 'Information') {
    if ($Silencioso) { Write-Host $Texto; return }
    [void][System.Windows.Forms.MessageBox]::Show($Texto, $titulo, 'OK', $Icono)
}

function Leer-Configuracion {
    # configuracion.txt: líneas clave=valor (url, token). Lo arma el panel al descargar.
    $datos = @{}
    # Junto al instalador o en la raíz del zip (dos carpetas arriba).
    $ruta = @((Join-Path $PSScriptRoot 'configuracion.txt'),
        (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'configuracion.txt')) |
        Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($ruta) {
        foreach ($linea in Get-Content -LiteralPath $ruta -Encoding UTF8) {
            if ($linea -match '^\s*([a-z_]+)\s*=\s*(.+?)\s*$') { $datos[$Matches[1]] = $Matches[2] }
        }
    }
    return $datos
}

function Buscar-Python {
    # Candidatos: el del PATH y los instalados para todos los usuarios. Solo sirve uno que
    # ningún usuario sin privilegios pueda modificar, porque la tarea lo corre como SYSTEM.
    $candidatos = @()
    $enPath = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($enPath) { $candidatos += $enPath.Source }
    foreach ($raiz in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }) {
        $candidatos += Get-ChildItem -Path (Join-Path $raiz 'Python3*\python.exe') -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | ForEach-Object FullName
    }
    foreach ($candidato in $candidatos | Select-Object -Unique) {
        try {
            Assert-RuntimeProtegido $candidato
            $version = & $candidato -c "import sys; print(sys.version_info >= (3, 10))"
            if ($version -eq 'True') { return $candidato }
        }
        catch { continue }
    }
    return $null
}

function Instalar-Python {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if (-not $winget) {
        throw 'No hay un Python instalado para todos los usuarios y winget no está disponible. ' +
            'Instala Python 3.12 desde python.org marcando "Install Python for all users" y vuelve a correr el instalador.'
    }
    Write-Host 'Instalando Python 3.12 para todos los usuarios (winget)...'
    & $winget.Source install --id Python.Python.3.12 --exact --scope machine --silent `
        --accept-package-agreements --accept-source-agreements | Out-Host
}

try {
    $identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
    $esAdmin = ([Security.Principal.WindowsPrincipal]$identidad).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $esAdmin) { throw 'Hay que correr el instalador como administrador (doble clic en instalar.cmd).' }

    $configuracion = Leer-Configuracion
    if (-not $Url) { $Url = $configuracion['url'] }
    if (-not $Token) { $Token = $configuracion['token'] }
    if (-not $Url -and -not $Silencioso) {
        $Url = [Microsoft.VisualBasic.Interaction]::InputBox(
            'Dirección del radar (por ejemplo https://radar.ejemplo.com):', $titulo, 'https://')
    }
    if (-not $Url -or $Url -eq 'https://') { throw 'Falta la dirección del radar.' }

    . (Join-Path $PSScriptRoot 'seguridad.ps1')
    $python = Buscar-Python
    if (-not $python) {
        Instalar-Python
        $python = Buscar-Python
        if (-not $python) { throw 'Python se instaló pero no quedó en una ruta protegida de Program Files.' }
    }

    # El código del agente viene junto al instalador (paquete del panel) o en la carpeta de
    # arriba (repositorio).
    $codigoAgente = Join-Path $PSScriptRoot 'agente_local'
    if (-not (Test-Path -LiteralPath (Join-Path $codigoAgente '__main__.py'))) {
        $codigoAgente = Split-Path -Parent $PSScriptRoot
    }

    # La carpeta queda escribible solo por administradores y SYSTEM: un usuario sin
    # privilegios no puede cambiar lo que corre SYSTEM.
    New-Item -ItemType Directory -Force -Path (Join-Path $destino 'agente_local') | Out-Null
    Copy-Item -Path (Join-Path $codigoAgente '*.py') -Destination (Join-Path $destino 'agente_local') -Force
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ejecutar.py') -Destination (Join-Path $destino 'ejecutar.py') -Force
    & icacls $destino /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudieron proteger los archivos del agente.' }

    $agente = Join-Path $destino 'ejecutar.py'
    $env:PYTHONIOENCODING = 'utf-8'
    # El token, si lo hay, va por variable de entorno del proceso, no por la línea de órdenes.
    if ($Token) { $env:RADAR_AGENTE_TOKEN = $Token }
    try {
        $salida = & $python -I $agente inscribir --url $Url 2>&1 | Out-String
        Write-Host $salida
        if ($LASTEXITCODE -ne 0) { throw "La inscripción falló.`n`n$($salida.Trim())" }
    }
    finally {
        Remove-Item Env:RADAR_AGENTE_TOKEN -ErrorAction SilentlyContinue
    }
    # -cmatch distingue mayúsculas: sin eso tomaría "adar-agen" de "[radar-agente]". Se busca
    # tras "activación:" para no confundirlo con un tramo del identificador del equipo.
    if ($salida -cnotmatch 'n:\s+([A-Z0-9]{4}-[A-Z0-9]{4})\b') { throw 'El agente no devolvió un código de activación.' }
    $codigo = $Matches[1]

    # Primer envío ya mismo, para que el equipo aparezca en el panel con sus datos.
    & $python -I $agente enviar | Out-Host

    $accion = New-ScheduledTaskAction -Execute $python `
        -Argument "-I `"$agente`" enviar --programado --intervalo-horas $IntervaloHoras --retraso-maximo $RetrasoMaximoSegundos" `
        -WorkingDirectory $destino
    $cadaTanto = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
        -RepetitionInterval (New-TimeSpan -Minutes 5)
    $alArrancar = New-ScheduledTaskTrigger -AtStartup
    $quien = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    Register-ScheduledTask -TaskName $tarea -Action $accion -Trigger @($cadaTanto, $alArrancar) `
        -Principal $quien -Settings $ajustes -Force | Out-Null

    # Aviso a quien usa el equipo: corre con la cuenta de cada persona (grupo Usuarios, sin
    # privilegios) al entrar y cada dos horas. Solo lee el aviso que deja la tarea de SYSTEM
    # y muestra una notificación; no ve la credencial ni manda nada al radar.
    $pythonw = Join-Path (Split-Path -Parent $python) 'pythonw.exe'
    if (-not (Test-Path -LiteralPath $pythonw)) { $pythonw = $python }
    $usuarios = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-545').Translate(
        [Security.Principal.NTAccount]).Value
    $accionAviso = New-ScheduledTaskAction -Execute $pythonw -Argument "-I `"$agente`" aviso" `
        -WorkingDirectory $destino
    $alEntrar = New-ScheduledTaskTrigger -AtLogOn
    $cadaDosHoras = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10) `
        -RepetitionInterval (New-TimeSpan -Hours 2)
    $persona = New-ScheduledTaskPrincipal -GroupId $usuarios -RunLevel Limited
    $ajustesAviso = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName "$tarea-Aviso" -Action $accionAviso -Trigger @($alEntrar, $cadaDosHoras) `
        -Principal $persona -Settings $ajustesAviso -Force | Out-Null

    try { Set-Clipboard -Value $codigo } catch { }
    Avisar ("El agente quedó instalado en este equipo.`n`n" +
        "Código de activación:   $codigo`n`n" +
        "Escríbelo en el panel del radar, sección ""Equipos con agente"", para activar el equipo. " +
        "Ya está copiado en el portapapeles.`n`n$Url")
    exit 0
}
catch {
    Avisar ("No se pudo instalar el agente.`n`n" + $_.Exception.Message) 'Error'
    exit 1
}
