<#
    Motor de OpenSSH server (CIS Debian 13, seccion 5.1). Audita la configuracion
    EFECTIVA (`sshd -T`, ya con los Include resueltos) y remedia con un drop-in
    /etc/ssh/sshd_config.d/00-cis-hardening.conf: sshd toma la PRIMERA ocurrencia de
    cada opcion y el sshd_config de Debian incluye sshd_config.d/*.conf al principio,
    asi que el prefijo 00- hace que gane sobre el resto. Todo cambio se valida con
    `sshd -t` y se revierte si falla; se recarga sin cortar las sesiones abiertas.
    Limitacion: `sshd -T` no evalua bloques Match (habria que pasar -C).
#>

function Get-CISSshdPath {
    @('/usr/sbin/sshd', '/sbin/sshd') | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function ConvertFrom-CISSshdOutput {
    <# Parsea la salida de `sshd -T`: @{ keyword(minuscula) = string[] valores (una entrada por linea repetida) }. #>
    [CmdletBinding()]
    param([AllowEmptyCollection()][string[]]$Lines)
    $cfg = @{}
    foreach ($l in $Lines) {
        if ($l -match '^\s*(\S+)\s*(.*)$') {
            $k = $Matches[1].ToLowerInvariant()
            if (-not $cfg.ContainsKey($k)) { $cfg[$k] = @() }
            $cfg[$k] += $Matches[2].Trim()
        }
    }
    $cfg
}

function Get-CISSshdConfig {
    <# Configuracion efectiva de sshd; $null si openssh-server no esta instalado. #>
    [CmdletBinding()]
    param([string]$Connection)   # ej. 'user=sshuser' (-C) para evaluar bloques Match
    $sshd = Get-CISSshdPath
    if (-not $sshd) { return $null }
    $sshdArgs = @('-T'); if ($Connection) { $sshdArgs += '-C', $Connection }
    ConvertFrom-CISSshdOutput -Lines @(& $sshd @sshdArgs 2>$null)
}

function Get-CISSshdVersion {
    <# Version mayor.menor de OpenSSH (ej. [version]'10.0'); $null si no se puede determinar. #>
    [CmdletBinding()]
    param()
    $sshd = Get-CISSshdPath
    if (-not $sshd) { return $null }
    $out = (& $sshd -V 2>&1) -join ' '
    if ($out -match 'openssh_(\d+)\.(\d+)') { [version]"$($Matches[1]).$($Matches[2])" }
}

function Set-CISSshdOption {
    <#
        Fija <Keyword> <Value> en el drop-in 00-cis-hardening.conf (reemplaza una
        definicion previa de la misma opcion en ese archivo), valida con `sshd -t`,
        y recarga sshd. Si la validacion falla restaura el archivo y lanza error.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][string]$Value,
        [string]$DropIn = '/etc/ssh/sshd_config.d/00-cis-hardening.conf'
    )
    if (-not $PSCmdlet.ShouldProcess($DropIn, "$Keyword $Value")) { return }
    $sshd = Get-CISSshdPath
    if (-not $sshd) { throw 'openssh-server no esta instalado.' }

    New-Item -ItemType Directory -Path (Split-Path $DropIn) -Force | Out-Null
    $had = Test-Path $DropIn
    $backup = if ($had) { "$DropIn.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    $lines = @(); if ($had) { Copy-Item $DropIn $backup; $lines = @(Get-Content $DropIn) }
    $pattern = "^\s*$([regex]::Escape($Keyword))\s"
    $found = $false
    $new = foreach ($l in $lines) { if ($l -match $pattern) { if (-not $found) { "$Keyword $Value"; $found = $true } } else { $l } }
    if (-not $found) { $new = @($new) + "$Keyword $Value" }
    Set-Content -Path $DropIn -Value $new
    & chmod 600 $DropIn; & chown root:root $DropIn

    $check = & $sshd -t 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($had) { Copy-Item $backup $DropIn -Force } else { Remove-Item $DropIn -Force }
        throw "sshd -t rechazo '$Keyword $Value' (cambio revertido): $check"
    }
    Invoke-CISSshdReload
}

function Invoke-CISSshdReload {
    # Debian usa ssh.service (sshd es alias). reload-or-restart no corta las sesiones abiertas.
    [CmdletBinding()]
    param()
    try {
        $svc = if (& systemctl cat ssh.service 2>$null) { 'ssh' } else { 'sshd' }
        & systemctl reload-or-restart $svc 2>&1 | Out-Null
    }
    catch { Write-Warning "No se pudo recargar sshd: $_" }
}
