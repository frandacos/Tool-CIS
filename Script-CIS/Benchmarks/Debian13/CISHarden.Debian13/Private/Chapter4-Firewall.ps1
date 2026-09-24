# CIS Debian Linux 13 Benchmark v1.0.0 - 4.1 Configure Uncomplicated Firewall.
# 5 controles. Fuente: cis_debian_13.md, paginas 508-520.
#
# RIESGO al remediar: habilitar ufw o cambiar sus politicas por defecto puede
# cortar la sesion SSH desde la que se administra el host. Los Set-* NO habilitan
# ufw ni cambian politicas si sshd esta activo y no existe una regla para SSH,
# salvo que se pase -AllowSsh (agrega la regla ANTES de habilitar). La politica
# de salida en deny (4.1.4) bloquea DNS/apt/NTP y exige -AcceptOutboundBlock.

function Get-Debian13UfwStatusVerbose { @(& ufw status verbose 2>$null) }
function Get-Debian13UfwRulesAdded { @(& ufw show added 2>$null) }
function Invoke-Debian13Ufw { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) & ufw @Arguments 2>&1 }

function Get-Debian13UfwDefault {
    # Politica por defecto ('deny', 'allow', 'reject', 'disabled') de incoming|outgoing|routed; $null si ufw esta inactivo.
    param([Parameter(Mandatory)][ValidateSet('incoming', 'outgoing', 'routed')][string]$Direction)
    $line = Get-Debian13UfwStatusVerbose | Where-Object { $_ -match '^Default:' } | Select-Object -First 1
    if ($line -and $line -match "(\w+)\s+\($Direction\)") { $Matches[1] } else { $null }
}

function Test-Debian13UfwSshRule {
    # Hay alguna regla de ufw que permita el puerto SSH (22 u OpenSSH)?
    [bool](Get-Debian13UfwRulesAdded | Where-Object { $_ -match '\b(allow|limit)\b' -and $_ -match '(\b22\b|OpenSSH|\bssh\b)' })
}
function Test-Debian13SshdActive { [bool](@(Get-Debian13UnitStates -Units 'ssh.service', 'sshd.service') | Where-Object { $_.ActiveState -eq 'active' }) }

function Assert-Debian13UfwSshSafe {
    # $true si se puede seguir; si no, advierte. -AllowSsh agrega la regla antes de continuar.
    param([Parameter(Mandatory)][string]$ControlId, [switch]$AllowSsh, [int]$SshPort = 22)
    if (-not (Test-Debian13SshdActive) -or (Test-Debian13UfwSshRule)) { return $true }
    if ($AllowSsh) { Invoke-Debian13Ufw allow proto tcp from any to any port $SshPort | Out-Null; return $true }
    Write-Warning "$ControlId : sshd esta activo y ufw no tiene una regla para SSH -- se omite para no perder acceso. Reintentar con -AllowSsh (permite el puerto $SshPort desde cualquier origen; restringirlo luego segun politica del sitio)."
    $false
}

function Test-CIS_Debian13_4_1_1 {
    $i = Test-CISPackageInstalled -Name 'ufw'
    New-CISResult -ControlId '4.1.1' -Title 'Ensure ufw is installed' -Status $(if ($i) { 'Pass' } else { 'Fail' }) -ExpectedValue 'ufw instalado' -ActualValue $(if ($i) { 'instalado' } else { 'no instalado' })
}
function Set-CIS_Debian13_4_1_1 { [CmdletBinding(SupportsShouldProcess)] param() if (-not (Test-CISPackageInstalled -Name 'ufw')) { Install-CISPackage -Name 'ufw' } }

function Test-CIS_Debian13_4_1_2 {
    $u = @(Get-Debian13UnitStates -Units 'ufw.service')[0]
    $active = [bool](Get-Debian13UfwStatusVerbose | Where-Object { $_ -match '^Status:\s+active' })
    $ok = ($u.UnitFileState -eq 'enabled') -and ($u.ActiveState -eq 'active') -and $active
    New-CISResult -ControlId '4.1.2' -Title 'Ensure ufw service is configured' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'ufw.service enabled y active, y ufw status: active' -ActualValue "enabled=$($u.UnitFileState); active=$($u.ActiveState); ufw status active=$active"
}
function Set-CIS_Debian13_4_1_2 {
    [CmdletBinding(SupportsShouldProcess)] param([switch]$AllowSsh, [int]$SshPort = 22)
    if (-not $PSCmdlet.ShouldProcess('ufw', '4.1.2 - regla SSH (si hace falta), unmask + enable --now y ufw --force enable')) { return }
    if (-not (Assert-Debian13UfwSshSafe -ControlId '4.1.2' -AllowSsh:$AllowSsh -SshPort $SshPort)) { return }
    Invoke-Debian13Systemctl unmask ufw.service
    Invoke-Debian13Systemctl enable --now ufw.service
    Invoke-Debian13Ufw --force enable | Out-Null
}

function Test-CIS_Debian13_4_1_3 {
    $d = Get-Debian13UfwDefault -Direction incoming
    New-CISResult -ControlId '4.1.3' -Title 'Ensure ufw incoming default is configured' -Status $(if ($d -in 'deny', 'reject') { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'incoming: deny o reject' -ActualValue $(if ($d) { $d } else { 'no determinable (ufw inactivo o no instalado)' })
}
function Set-CIS_Debian13_4_1_3 {
    [CmdletBinding(SupportsShouldProcess)] param([switch]$AllowSsh, [int]$SshPort = 22)
    if (-not $PSCmdlet.ShouldProcess('ufw', '4.1.3 - ufw default deny incoming')) { return }
    if (Assert-Debian13UfwSshSafe -ControlId '4.1.3' -AllowSsh:$AllowSsh -SshPort $SshPort) { Invoke-Debian13Ufw default deny incoming | Out-Null }
}

function Test-CIS_Debian13_4_1_4 {
    $d = Get-Debian13UfwDefault -Direction outgoing
    New-CISResult -ControlId '4.1.4' -Title 'Ensure ufw outgoing default is configured' -Status $(if ($d -in 'deny', 'reject') { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'outgoing: deny o reject' -ActualValue $(if ($d) { $d } else { 'no determinable (ufw inactivo o no instalado)' })
}
function Set-CIS_Debian13_4_1_4 {
    [CmdletBinding(SupportsShouldProcess)] param([switch]$AcceptOutboundBlock)
    if (-not $AcceptOutboundBlock) {
        Write-Warning '4.1.4: deny outgoing bloquea todo el trafico saliente sin regla explicita (DNS, apt, NTP...). Crear primero las reglas de salida necesarias y reintentar con -AcceptOutboundBlock.'; return
    }
    if ($PSCmdlet.ShouldProcess('ufw', '4.1.4 - ufw default deny outgoing')) { Invoke-Debian13Ufw default deny outgoing | Out-Null }
}

# Desviacion: el benchmark indica "ufw default disabled routed", que no es una sintaxis valida de ufw
# (allow|deny|reject); se usa "ufw default deny routed", que ufw acepta y cumple el criterio (deny).
function Test-CIS_Debian13_4_1_5 {
    $d = Get-Debian13UfwDefault -Direction routed
    New-CISResult -ControlId '4.1.5' -Title 'Ensure ufw routed default is configured' -Status $(if ($d -in 'disabled', 'deny') { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'routed: disabled o deny' -ActualValue $(if ($d) { $d } else { 'no determinable (ufw inactivo o no instalado)' })
}
function Set-CIS_Debian13_4_1_5 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('ufw', '4.1.5 - ufw default deny routed')) { Invoke-Debian13Ufw default deny routed | Out-Null }
}
