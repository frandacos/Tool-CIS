<#
    Motor dconf/GDM (Debian 13, 1.7.x). Solo lee/escribe archivos bajo
    /etc/dconf/db/*.d y sus locks (no usa gsettings, que exige sesion grafica).
#>

function Get-CISDconfKeyFiles {
    [CmdletBinding()]
    param([switch]$Locks)
    # Get-ChildItem <ruta inexistente> -Recurse se cuelga en PowerShell 7.6: guardar con Test-Path.
    if (-not (Test-Path '/etc/dconf/db')) { return }
    Get-ChildItem -Path '/etc/dconf/db' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\.d(/|$)' -and (($_.DirectoryName -match '/locks') -eq [bool]$Locks) }
}

function Get-CISDconfValue {
    <# Valor de <Key> dentro de la seccion [<Section>] de los keyfiles (el ultimo por orden de archivo). $null si no esta. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Section, [Parameter(Mandatory)][string]$Key)
    $value = $null
    foreach ($f in (Get-CISDconfKeyFiles | Sort-Object FullName)) {
        $in = $false
        foreach ($line in (Get-Content -Path $f.FullName -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*\[(.+)\]') { $in = ($Matches[1] -eq $Section); continue }
            if ($in -and $line -match "^\s*$([regex]::Escape($Key))\s*=\s*(.+?)\s*$") { $value = $Matches[1] }
        }
    }
    $value
}

function Test-CISDconfPathLocked {
    <# $true si algun archivo de locks lista <DconfPath> (ej. /org/gnome/desktop/session/idle-delay). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$DconfPath)
    foreach ($f in (Get-CISDconfKeyFiles -Locks)) {
        if (Get-Content -Path $f.FullName -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -eq $DconfPath }) { return $true }
    }
    $false
}

function Set-CISDconfKeyFile {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Database,           # 'gdm' o 'local'
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string[]]$KeyValueLines
    )
    $dbDir = "/etc/dconf/db/$Database.d"; $keyFile = "$dbDir/$FileName"; $profile = "/etc/dconf/profile/$Database"
    if (-not $PSCmdlet.ShouldProcess($keyFile, 'Crear/actualizar keyfile de dconf')) { return }
    if (-not (Test-Path $profile)) {
        New-Item -ItemType Directory -Path '/etc/dconf/profile' -Force | Out-Null
        $p = @('user-db:user', "system-db:$Database"); if ($Database -eq 'gdm') { $p += 'file-db:/usr/share/gdm/greeter-dconf-defaults' }
        Set-Content -Path $profile -Value $p
    }
    New-Item -ItemType Directory -Path $dbDir -Force | Out-Null
    $lines = @(); if (Test-Path $keyFile) { $lines = @(Get-Content $keyFile); Copy-Item $keyFile "$keyFile.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    if ($lines -notcontains "[$Section]") { $lines += ''; $lines += "[$Section]" }
    foreach ($kv in $KeyValueLines) {
        $key = ($kv -split '=', 2)[0]
        if ($lines -match "^\s*$([regex]::Escape($key))\s*=") { $lines = $lines | ForEach-Object { if ($_ -match "^\s*$([regex]::Escape($key))\s*=") { $kv } else { $_ } } }
        else { $i = [array]::IndexOf($lines, "[$Section]"); $lines = @($lines[0..$i]) + $kv + @($lines[($i + 1)..($lines.Count)] | Where-Object { $null -ne $_ }) }
    }
    Set-Content -Path $keyFile -Value $lines
    & dconf update 2>&1 | Out-Null
}

function Set-CISDconfLock {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Database, [Parameter(Mandatory)][string]$FileName, [Parameter(Mandatory)][string[]]$DconfPaths)
    $dir = "/etc/dconf/db/$Database.d/locks"; $file = "$dir/$FileName"
    if (-not $PSCmdlet.ShouldProcess($file, 'Crear/actualizar lock de dconf')) { return }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $lines = @(); if (Test-Path $file) { $lines = @(Get-Content $file) }
    foreach ($p in $DconfPaths) { if ($lines -notcontains $p) { $lines += $p } }
    Set-Content -Path $file -Value $lines
    & dconf update 2>&1 | Out-Null
}
