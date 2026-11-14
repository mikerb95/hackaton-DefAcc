$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../agente_local/instalacion/seguridad.ps1')
$script:propietario = 'S-1-5-32-544'
$script:escrituraUsuario = $false
$script:enlace = $false
function Get-Item {
    param($LiteralPath, $ErrorAction)
    [pscustomobject]@{
        FullName = $LiteralPath
        Directory = [pscustomobject]@{ FullName = "$env:ProgramFiles\PythonPrueba" }
        Parent = $null
        Attributes = $(if ($script:enlace) { [IO.FileAttributes]::ReparsePoint } else { [IO.FileAttributes]::Normal })
    }
}
function Get-ChildItem { param($LiteralPath, [switch]$Recurse, [switch]$Force, $ErrorAction) }
function Get-Acl {
    param($LiteralPath)
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetOwner([Security.Principal.SecurityIdentifier]::new($script:propietario))
    $derechos = if ($script:escrituraUsuario) { 'Modify' } else { 'ReadAndExecute' }
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'), $derechos, 'Allow'))
    return $acl
}
function Assert-Rechazado {
    $rechazado = $false
    try { Assert-RuntimeProtegido "$env:ProgramFiles\PythonPrueba\python.exe" }
    catch { $rechazado = $true }
    if (-not $rechazado) { throw 'Se acepto un runtime inseguro' }
}
Assert-RuntimeProtegido "$env:ProgramFiles\PythonPrueba\python.exe"
$script:escrituraUsuario = $true
Assert-Rechazado
$script:escrituraUsuario = $false
$script:propietario = 'S-1-5-32-545'
Assert-Rechazado
$script:propietario = 'S-1-5-32-544'
$script:enlace = $true
Assert-Rechazado
Write-Output '4 pruebas de seguridad del runtime aprobadas (ACL simuladas).'
