<#
    Motor de configuracion systemd con drop-ins (coredump.conf, journald.conf,
    timesyncd.conf, ...). Replica el Audit del benchmark CIS Debian 13:
    `systemd-analyze cat-config <conf>` lista los archivos en orden de lectura;
    invertido, el primero que define la opcion en el bloque es el efectivo. Si
    ninguno la define se usa el valor por defecto (linea comentada `#Opcion=X`).
#>

function Get-CISSystemdConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfName,   # ej. 'systemd/coredump.conf'
        [Parameter(Mandatory)][string]$Block,      # ej. 'Coredump'
        [Parameter(Mandatory)][string]$Option
    )
    $analyze = @('/bin/systemd-analyze', '/usr/bin/systemd-analyze') | Where-Object { Test-Path $_ } | Select-Object -First 1
    $files = @()
    if ($analyze) {
        $cat = @(& $analyze cat-config $ConfName 2>$null)
        [array]::Reverse($cat)
        $files = @($cat | Where-Object { $_ -match '^\s*#\s*(/[^#\s]+\.conf)\b' } | ForEach-Object { $Matches[1] })
    }
    foreach ($file in $files) {
        $inBlock = $false; $value = $null
        foreach ($line in (Get-Content -Path $file -ErrorAction SilentlyContinue)) {
            if ($line -match '^\s*\[(.+)\]') { $inBlock = ($Matches[1] -eq $Block); continue }
            if ($inBlock -and $line -match "^\s*$([regex]::Escape($Option))\s*=\s*(\S+)") { $value = $Matches[1] }
        }
        if ($null -ne $value) { return [pscustomobject]@{ Value = $value; File = $file; IsDefault = $false } }
    }
    # Valor por defecto (comentado) en /etc o /usr/lib.
    foreach ($file in "/etc/$ConfName", "/usr/lib/$ConfName") {
        if (-not (Test-Path $file)) { continue }
        $inBlock = $false
        foreach ($line in (Get-Content -Path $file)) {
            if ($line -match '^\s*\[(.+)\]') { $inBlock = ($Matches[1] -eq $Block); continue }
            if ($inBlock -and $line -match "^\s*#?\s*$([regex]::Escape($Option))\s*=\s*(\S+)") {
                return [pscustomobject]@{ Value = $Matches[1]; File = $file; IsDefault = $true }
            }
        }
    }
    return $null
}

function Set-CISSystemdConfigValue {
    <# Comenta <Option> con otro valor en los .conf en uso y persiste <Option>=<Value> en /etc/<ConfName>.d/60-cis.conf. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ConfName,
        [Parameter(Mandatory)][string]$Block,
        [Parameter(Mandatory)][string]$Option,
        [Parameter(Mandatory)][string]$Value
    )
    $dropIn = "/etc/$ConfName.d/60-cis.conf"
    if (-not $PSCmdlet.ShouldProcess($dropIn, "[$Block] $Option=$Value")) { return }

    $analyze = @('/bin/systemd-analyze', '/usr/bin/systemd-analyze') | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($analyze) {
        foreach ($l in @(& $analyze cat-config $ConfName 2>$null)) {
            if ($l -notmatch '^\s*#\s*(/etc/[^#\s]+\.conf)\b') { continue }
            $file = $Matches[1]
            if ($file -eq $dropIn) { continue }
            $inBlock = $false; $changed = $false
            $new = foreach ($line in (Get-Content -Path $file)) {
                if ($line -match '^\s*\[(.+)\]') { $inBlock = ($Matches[1] -eq $Block) }
                elseif ($inBlock -and $line -match "^\s*$([regex]::Escape($Option))\s*=" -and $line -notmatch "=\s*$([regex]::Escape($Value))\s*$") { $changed = $true; "# $line"; continue }
                $line
            }
            if ($changed) { Copy-Item $file "$file.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"; Set-Content -Path $file -Value $new }
        }
    }

    New-Item -ItemType Directory -Path (Split-Path $dropIn) -Force | Out-Null
    $lines = @(); if (Test-Path $dropIn) { $lines = @(Get-Content $dropIn); Copy-Item $dropIn "$dropIn.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    $out = [System.Collections.Generic.List[string]]::new(); $inBlock = $false; $done = $false; $seenBlock = $false
    foreach ($line in $lines) {
        if ($line -match '^\s*\[(.+)\]') {
            if ($inBlock -and -not $done) { $out.Add("$Option=$Value"); $done = $true }
            $inBlock = ($Matches[1] -eq $Block); if ($inBlock) { $seenBlock = $true }
        }
        elseif ($inBlock -and $line -match "^\s*$([regex]::Escape($Option))\s*=") { if (-not $done) { $out.Add("$Option=$Value"); $done = $true }; continue }
        $out.Add($line)
    }
    if (-not $done) {
        if (-not $seenBlock) { $out.Add(''); $out.Add("[$Block]") }
        $out.Add("$Option=$Value")
    }
    Set-Content -Path $dropIn -Value $out
}
