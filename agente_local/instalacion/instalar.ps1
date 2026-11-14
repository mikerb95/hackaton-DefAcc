# Instala el agente local del radar en Windows (docs/agente-local.md).
#
#   powershell -ExecutionPolicy Bypass -File instalar.ps1 -Url https://radar.ejemplo -Token <token>
#
# Qué hace: copia el agente a Program Files, canjea el token de inscripción por la
# credencial del equipo y registra una tarea programada que corre como SYSTEM cada
# 12 horas y al arrancar, con retraso aleatorio.
# Qué no hace: no abre puertos, no instala un servicio residente y no recibe órdenes.
#
# Requiere una consola de administrador y Python 3.10 o superior. Este guion no está
# firmado: es el instalador de desarrollo, no el MSI firmado del plan (fase 3).

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Url,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$IntervaloHoras = 12,
    [int]$RetrasoMaximoSegundos = 900
)

$ErrorActionPreference = 'Stop'
$destino = Join-Path $env:ProgramFiles 'RadarAgente'
$origen = Split-Path -Parent $PSScriptRoot
$tarea = 'RadarAgente'

$identidad = [Security.Principal.WindowsIdentity]::GetCurrent()
$esAdmin = ([Security.Principal.WindowsPrincipal]$identidad).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $esAdmin) { throw 'Hay que correr este guion como administrador.' }

$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $python) { throw 'No se encontró python.exe en el PATH.' }

# Copia solo el código del agente. La carpeta queda escribible únicamente por
# administradores: un usuario sin privilegios no puede cambiar lo que corre SYSTEM.
New-Item -ItemType Directory -Force -Path (Join-Path $destino 'agente_local') | Out-Null
Copy-Item -Path (Join-Path $origen '*.py') -Destination (Join-Path $destino 'agente_local') -Force
& icacls $destino /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null

# El token va por variable de entorno del proceso, no por la línea de órdenes.
$env:RADAR_AGENTE_TOKEN = $Token
try {
    Push-Location $destino
    & $python -m agente_local inscribir --url $Url
    if ($LASTEXITCODE -ne 0) { throw 'La inscripción falló.' }
}
finally {
    Pop-Location
    Remove-Item Env:RADAR_AGENTE_TOKEN -ErrorAction SilentlyContinue
}

$accion = New-ScheduledTaskAction -Execute $python `
    -Argument "-m agente_local enviar --retraso-maximo $RetrasoMaximoSegundos" `
    -WorkingDirectory $destino
$cadaTanto = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) `
    -RepetitionInterval (New-TimeSpan -Hours $IntervaloHoras)
$alArrancar = New-ScheduledTaskTrigger -AtStartup
$quien = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$ajustes = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
Register-ScheduledTask -TaskName $tarea -Action $accion -Trigger @($cadaTanto, $alArrancar) `
    -Principal $quien -Settings $ajustes -Force | Out-Null

Write-Host "Agente instalado en $destino. Tarea '$tarea' cada $IntervaloHoras horas y al arrancar."
