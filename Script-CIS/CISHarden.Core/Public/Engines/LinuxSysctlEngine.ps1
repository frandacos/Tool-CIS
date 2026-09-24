<#
    Motor de parametros de kernel via sysctl. Usado por ASLR/core dumps
    (1.5.x) y quedara disponible para los controles de red del Capitulo 3.
#>

function Get-CISSysctlValue {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key)
    $raw = (& sysctl -n $Key 2>$null)
    if ($LASTEXITCODE -ne 0) {
        $procPath = "/proc/sys/$($Key -replace '\.', '/')"
        if (Test-Path $procPath) {
            return (Get-Content -Path $procPath -Raw).Trim()
        }
        return $null
    }
    return $raw.Trim()
}

function Set-CISSysctlValue {
    <#
        Persiste <Key>=<Value> en /etc/sysctl.d/60-cis.conf (reemplazando
        cualquier definicion previa de esa misma clave en ese archivo) y lo
        aplica en caliente con sysctl -w.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )

    $confPath = '/etc/sysctl.d/60-cis.conf'
    if (-not $PSCmdlet.ShouldProcess($confPath, "Set $Key = $Value")) {
        return
    }

    $lines = @()
    if (Test-Path $confPath) {
        Copy-Item -Path $confPath -Destination "$confPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $lines = Get-Content -Path $confPath
    }

    $pattern = "^\s*$([regex]::Escape($Key))\s*="
    if ($lines -match $pattern) {
        $lines = $lines -replace $pattern, "$Key ="
        $lines = $lines | ForEach-Object { if ($_ -match $pattern) { "$Key = $Value" } else { $_ } }
    }
    else {
        $lines += "$Key = $Value"
    }
    Set-Content -Path $confPath -Value $lines

    & sysctl -w "$Key=$Value" *> $null
}

function Get-CISSysctlConfigFiles {
    <#
        Archivos que usa systemd-sysctl, en orden de precedencia (el primero
        gana), mas el IPT_SYSCTL de UFW y /etc/sysctl.conf, replicando el
        script de Audit del benchmark CIS Debian 13.
    #>
    [CmdletBinding()]
    param()
    $files = [System.Collections.Generic.List[string]]::new()
    if (Test-Path /etc/default/ufw) {
        $ufw = (Get-Content /etc/default/ufw | Where-Object { $_ -match '^\s*IPT_SYSCTL=' } | Select-Object -First 1)
        if ($ufw) {
            $f = ($ufw -split '=', 2)[1].Trim().Trim('"')
            if ($f -and (Test-Path $f)) { $files.Add($f) }
        }
    }
    if (Test-Path /etc/sysctl.conf) { $files.Add('/etc/sysctl.conf') }
    $bin = @('/lib/systemd/systemd-sysctl', '/usr/lib/systemd/systemd-sysctl') | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($bin) {
        $cat = @(& $bin --cat-config 2>$null)
        [array]::Reverse($cat)
        foreach ($line in $cat) {
            if ($line -match '^\s*#\s*(/[^#\s]+\.conf)\b') {
                $resolved = (Resolve-Path -LiteralPath $Matches[1] -ErrorAction SilentlyContinue).Path
                if ($resolved -and -not $files.Contains($resolved)) { $files.Add($resolved) }
            }
        }
    }
    , @($files)
}

function Get-CISSysctlPersistedValue {
    <# Valor de <Key> en cada archivo de configuracion (ultima linea de cada archivo). Devuelve @{File; Value}, en orden de precedencia. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Key)
    $grep = [regex]::Escape($Key) -replace '\\\.', '(\.|/)'
    foreach ($file in (Get-CISSysctlConfigFiles)) {
        $hit = Get-Content -Path $file -ErrorAction SilentlyContinue |
            Where-Object { $_ -match "^\s*$grep\s*=\s*\S+" } | Select-Object -Last 1
        if ($hit) { [pscustomobject]@{ File = $file; Value = (($hit -split '=', 2)[1]).Trim() } }
    }
}

function Test-CISSysctlSetting {
    <# $true si el valor en ejecucion Y el primer valor persistido (el efectivo tras un reboot) son iguales a <Value>. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string[]]$Value   # uno o varios valores aceptados (ej. 1,2,3)
    )
    $running = Get-CISSysctlValue -Key $Key
    $persisted = @(Get-CISSysctlPersistedValue -Key $Key)
    $effective = if ($persisted.Count) { $persisted[0].Value } else { $null }
    [pscustomobject]@{
        Compliant = ($Value -contains $running) -and ($Value -contains $effective)
        Running   = $running
        Persisted = $effective
        File      = if ($persisted.Count) { $persisted[0].File } else { $null }
    }
}

function Set-CISSysctlEnforced {
    <# Paso 1 del benchmark: comenta las lineas de <Key> con otro valor en los archivos en uso; luego persiste y aplica <Value>. #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value,
        [string[]]$AcceptValues = @($Value)   # valores que NO se comentan en los archivos en conflicto
    )
    if (-not $PSCmdlet.ShouldProcess($Key, "Forzar $Key = $Value (comentar valores en conflicto, persistir y aplicar)")) { return }
    $grep = [regex]::Escape($Key) -replace '\\\.', '(\.|/)'
    foreach ($file in (Get-CISSysctlConfigFiles)) {
        $lines = @(Get-Content -Path $file -ErrorAction SilentlyContinue)
        $changed = $false
        $new = foreach ($l in $lines) {
            if ($l -match "^\s*$grep\s*=" -and -not ($AcceptValues | Where-Object { $l -match "^\s*$grep\s*=\s*$([regex]::Escape($_))\s*$" })) { $changed = $true; "# $l" } else { $l }
        }
        if ($changed) {
            Copy-Item -Path $file -Destination "$file.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Set-Content -Path $file -Value $new
        }
    }
    Set-CISSysctlValue -Key $Key -Value $Value
    & sysctl --system *> $null
}
