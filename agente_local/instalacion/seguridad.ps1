# Falla cerrado: SYSTEM solo ejecuta un runtime completo protegido contra escritura.
function Assert-RuntimeProtegido([string]$Ruta) {
    $archivo = Get-Item -LiteralPath $Ruta -ErrorAction Stop
    $raiz = $archivo.Directory.FullName
    $permitidos = @('S-1-5-18', 'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $programas = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    if (-not ($programas | Where-Object { $raiz.StartsWith($_ + '\', [StringComparison]::OrdinalIgnoreCase) })) {
        throw 'Python debe estar instalado para todos los usuarios dentro de Program Files.'
    }
    $elementos = @(Get-Item -LiteralPath $raiz) + @(Get-ChildItem -LiteralPath $raiz -Recurse -Force -ErrorAction Stop)
    $padre = (Get-Item -LiteralPath $raiz).Parent
    while ($padre -and $padre.Parent) { $elementos += $padre; $padre = $padre.Parent }
    $escritura = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($elemento in $elementos) {
        if ($elemento.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "No se permiten enlaces en el runtime: $($elemento.FullName)"
        }
        $acl = Get-Acl -LiteralPath $elemento.FullName
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $permitidos) {
            throw "Propietario no privilegiado en $($elemento.FullName)"
        }
        foreach ($regla in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($regla.AccessControlType -eq 'Allow' -and
                ($regla.FileSystemRights -band $escritura) -and
                $regla.IdentityReference.Value -notin $permitidos) {
                throw "Permisos de escritura no seguros en $($elemento.FullName)"
            }
        }
    }
}
