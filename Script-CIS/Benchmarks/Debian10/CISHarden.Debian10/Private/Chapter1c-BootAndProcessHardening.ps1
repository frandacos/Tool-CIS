# CIS Debian Linux 10 Benchmark v2.0.0 - Capitulo 1.4 Secure Boot Settings y
# 1.5 Additional Process Hardening. 8 controles. Fuente: cis_debian_10.md,
# paginas 143-165.

# --- 1.4.1 Ensure bootloader password is set ---------------------------------

function Test-CIS_Debian10_1_4_1 {
    [CmdletBinding()]
    param()
    $grubCfg = '/boot/grub/grub.cfg'
    $hasSuperuser = Test-CISFileContains -Path $grubCfg -Pattern '^set superusers'
    $hasPassword = Test-CISFileContains -Path $grubCfg -Pattern '^password'
    $status = if ($hasSuperuser -and $hasPassword) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.4.1' -Title 'Ensure bootloader password is set' -Status $status `
        -ExpectedValue "$grubCfg define 'set superusers' y 'password(_pbkdf2)'" `
        -ActualValue "set superusers=$hasSuperuser; password=$hasPassword"
}

function Set-CIS_Debian10_1_4_1 {
    Write-Warning "1.4.1: sin remediacion automatizada -- requiere generar un hash con 'grub-mkpasswd-pbkdf2' de forma interactiva y agregar 'set superusers'/'password_pbkdf2' a /etc/grub.d/40_custom, luego 'update-grub'."
}

# --- 1.4.2 Ensure permissions on bootloader config are configured -----------

function Test-CIS_Debian10_1_4_2 {
    [CmdletBinding()]
    param()
    $grubCfg = '/boot/grub/grub.cfg'
    $mode = Get-CISFileMode -Path $grubCfg
    $owner = Get-CISFileOwner -Path $grubCfg
    $modeOk = ($null -ne $mode) -and ([Convert]::ToInt32($mode, 8) -le [Convert]::ToInt32('600', 8))
    $ownerOk = ($owner -eq 'root:root')
    $status = if ($modeOk -and $ownerOk) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.4.2' -Title 'Ensure permissions on bootloader config are configured' -Status $status `
        -ExpectedValue 'root:root, 0600 o mas restrictivo' -ActualValue "owner=$owner; mode=$mode"
}

function Set-CIS_Debian10_1_4_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $grubCfg = '/boot/grub/grub.cfg'
    if ($PSCmdlet.ShouldProcess($grubCfg, 'chown root:root; chmod 600')) {
        Set-CISFileOwner -Path $grubCfg -Owner 'root:root'
        Set-CISFileMode -Path $grubCfg -Mode '600'
    }
}

# --- 1.4.3 Ensure authentication required for single user mode --------------

function Test-CIS_Debian10_1_4_3 {
    [CmdletBinding()]
    param()
    $hasPassword = Test-CISFileContains -Path '/etc/shadow' -Pattern '^root:\$[0-9]'
    $status = if ($hasPassword) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.4.3' -Title 'Ensure authentication required for single user mode' -Status $status `
        -ExpectedValue "/etc/shadow tiene un hash de password para 'root'" -ActualValue $(if ($hasPassword) { 'root tiene password hasheado' } else { 'root sin password (bloqueado/vacio)' })
}

function Set-CIS_Debian10_1_4_3 {
    Write-Warning "1.4.3: sin remediacion automatizada -- requiere ejecutar 'passwd root' de forma interactiva."
}

# --- 1.5.1 Ensure ASLR is enabled --------------------------------------------

function Test-CIS_Debian10_1_5_1 {
    [CmdletBinding()]
    param()
    $actual = Get-CISSysctlValue -Key 'kernel.randomize_va_space'
    $status = if ($actual -eq '2') { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.5.1' -Title 'Ensure address space layout randomization (ASLR) is enabled' -Status $status `
        -ExpectedValue '2' -ActualValue $actual
}

function Set-CIS_Debian10_1_5_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('kernel.randomize_va_space', 'Set to 2')) {
        Set-CISSysctlValue -Key 'kernel.randomize_va_space' -Value '2'
    }
}

# --- 1.5.2 Ensure ptrace_scope is restricted ---------------------------------

function Test-CIS_Debian10_1_5_2 {
    [CmdletBinding()]
    param()
    $actual = Get-CISSysctlValue -Key 'kernel.yama.ptrace_scope'
    $status = if ($actual -eq '1') { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.5.2' -Title 'Ensure ptrace_scope is restricted' -Status $status `
        -ExpectedValue '1' -ActualValue $actual
}

function Set-CIS_Debian10_1_5_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('kernel.yama.ptrace_scope', 'Set to 1')) {
        Set-CISSysctlValue -Key 'kernel.yama.ptrace_scope' -Value '1'
    }
}

# --- 1.5.3 Ensure prelink is not installed -----------------------------------

function Test-CIS_Debian10_1_5_3 {
    [CmdletBinding()]
    param()
    $installed = Test-CISPackageInstalled -Name 'prelink'
    $status = if (-not $installed) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.5.3' -Title 'Ensure prelink is not installed' -Status $status `
        -ExpectedValue 'prelink no instalado' -ActualValue $(if ($installed) { 'instalado' } else { 'no instalado' })
}

function Set-CIS_Debian10_1_5_3 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-CISPackageInstalled -Name 'prelink')) { return }
    if ($PSCmdlet.ShouldProcess('prelink', 'prelink -ua; apt-get purge -y')) {
        & prelink -ua 2>$null
        Remove-CISPackage -Name 'prelink' -Purge
    }
}

# --- 1.5.4 Ensure Automatic Error Reporting is not enabled ------------------

function Test-CIS_Debian10_1_5_4 {
    [CmdletBinding()]
    param()
    if (-not (Test-CISPackageInstalled -Name 'apport')) {
        return New-CISResult -ControlId '1.5.4' -Title 'Ensure Automatic Error Reporting is not enabled' -Status 'Pass' `
            -ExpectedValue 'apport no instalado, o enabled=0 y servicio inactivo' -ActualValue 'paquete apport no instalado'
    }
    $enabledLine = Test-CISFileContains -Path '/etc/default/apport' -Pattern '^\s*enabled\s*=\s*[^0]\b'
    $active = Test-CISServiceActive -Name 'apport.service'
    $status = if (-not $enabledLine -and -not $active) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.5.4' -Title 'Ensure Automatic Error Reporting is not enabled' -Status $status `
        -ExpectedValue 'enabled=0 en /etc/default/apport y apport.service inactivo' `
        -ActualValue "enabled!=0 presente=$enabledLine; apport.service activo=$active"
}

function Set-CIS_Debian10_1_5_4 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-CISPackageInstalled -Name 'apport')) { return }
    if ($PSCmdlet.ShouldProcess('apport', 'Set enabled=0 y detener/deshabilitar servicio')) {
        Set-CISFileLine -Path '/etc/default/apport' -Line 'enabled=0' -MatchPattern '^\s*enabled\s*='
        Disable-CISService -Name 'apport.service' -Now
    }
}

# --- 1.5.5 Ensure core dumps are restricted ----------------------------------

function Test-CIS_Debian10_1_5_5 {
    [CmdletBinding()]
    param()
    $extraLimitsFiles = @(Get-ChildItem -Path '/etc/security/limits.d' -Filter '*.conf' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $limitsFiles = @('/etc/security/limits.conf') + $extraLimitsFiles
    $hasHardCore = $false
    foreach ($f in $limitsFiles) {
        if (Test-CISFileContains -Path $f -Pattern '^(\*|\s).*hard.*core.*(\s+#.*)?$') {
            $hasHardCore = $true
            break
        }
    }
    $suidDumpable = Get-CISSysctlValue -Key 'fs.suid_dumpable'
    $status = if ($hasHardCore -and $suidDumpable -eq '0') { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.5.5' -Title 'Ensure core dumps are restricted' -Status $status `
        -ExpectedValue "'* hard core 0' en limits.conf y fs.suid_dumpable=0" `
        -ActualValue "hard core 0 presente=$hasHardCore; fs.suid_dumpable=$suidDumpable"
}

function Set-CIS_Debian10_1_5_5 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('/etc/security/limits.conf, fs.suid_dumpable', 'Restringir core dumps')) {
        Set-CISFileLine -Path '/etc/security/limits.conf' -Line '* hard core 0' -MatchPattern '^\*\s+hard\s+core\s+'
        Set-CISSysctlValue -Key 'fs.suid_dumpable' -Value '0'
    }
}
