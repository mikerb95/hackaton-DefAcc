# Desinstala el agente local del radar en Windows: borra la tarea, la credencial y el código.
# Después hay que retirar el equipo en el radar (DELETE /api/equipos/{id}).
#
#   powershell -ExecutionPolicy Bypass -File desinstalar.ps1

$ErrorActionPreference = 'Stop'
$destino = Join-Path $env:ProgramFiles 'RadarAgente'
$datos = Join-Path $env:ProgramData 'RadarAgente'

Unregister-ScheduledTask -TaskName 'RadarAgente' -Confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'RadarAgente-Aviso' -Confirm:$false -ErrorAction SilentlyContinue
foreach ($carpeta in @($destino, $datos)) {
    if (Test-Path $carpeta) { Remove-Item -Recurse -Force $carpeta }
}
Write-Host 'Agente desinstalado. Falta retirar el equipo en el radar.'
