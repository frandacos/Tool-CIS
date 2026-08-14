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
