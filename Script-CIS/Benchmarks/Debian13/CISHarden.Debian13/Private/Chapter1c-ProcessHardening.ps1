# CIS Debian Linux 13 Benchmark v1.0.0 - 1.5 Configure Additional Process
# Hardening. 13 controles. Fuente: cis_debian_13.md, paginas 159-206.

# --- sysctl (1.5.1-1.5.5, 1.5.8-1.5.10): valor en ejecucion + persistido ----

function Test-Debian13SysctlControl {
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string[]]$Accept
    )
    $r = Test-CISSysctlSetting -Key $Key -Value $Accept
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($r.Compliant) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "$Key = $($Accept -join ' | ') (en ejecucion y persistido)" `
        -ActualValue "running=$($r.Running); persisted=$($r.Persisted) ($($r.File))"
}

function Set-Debian13SysctlControl {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Value, [string[]]$Accept = @($Value))
    Set-CISSysctlEnforced -Key $Key -Value $Value -AcceptValues $Accept
}

function Test-CIS_Debian13_1_5_1 { Test-Debian13SysctlControl -ControlId '1.5.1' -Title 'Ensure fs.protected_hardlinks is configured' -Key 'fs.protected_hardlinks' -Accept '1' }
function Set-CIS_Debian13_1_5_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'fs.protected_hardlinks' -Value '1' }

function Test-CIS_Debian13_1_5_2 { Test-Debian13SysctlControl -ControlId '1.5.2' -Title 'Ensure fs.protected_symlinks is configured' -Key 'fs.protected_symlinks' -Accept '1' }
function Set-CIS_Debian13_1_5_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'fs.protected_symlinks' -Value '1' }

# 1.5.3 y 1.5.10 son dos recomendaciones distintas del benchmark sobre la misma clave (1, 2 o 3).
function Test-CIS_Debian13_1_5_3 { Test-Debian13SysctlControl -ControlId '1.5.3' -Title 'Ensure kernel.yama.ptrace_scope is configured' -Key 'kernel.yama.ptrace_scope' -Accept '1', '2', '3' }
function Set-CIS_Debian13_1_5_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'kernel.yama.ptrace_scope' -Value '1' -Accept '1', '2', '3' }

function Test-CIS_Debian13_1_5_4 { Test-Debian13SysctlControl -ControlId '1.5.4' -Title 'Ensure fs.suid_dumpable is configured' -Key 'fs.suid_dumpable' -Accept '0' }
function Set-CIS_Debian13_1_5_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'fs.suid_dumpable' -Value '0' }

function Test-CIS_Debian13_1_5_5 { Test-Debian13SysctlControl -ControlId '1.5.5' -Title 'Ensure kernel.dmesg_restrict is configured' -Key 'kernel.dmesg_restrict' -Accept '1' }
function Set-CIS_Debian13_1_5_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'kernel.dmesg_restrict' -Value '1' }

function Test-CIS_Debian13_1_5_8 { Test-Debian13SysctlControl -ControlId '1.5.8' -Title 'Ensure kernel.kptr_restrict is configured' -Key 'kernel.kptr_restrict' -Accept '1', '2' }
function Set-CIS_Debian13_1_5_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'kernel.kptr_restrict' -Value '2' -Accept '1', '2' }

function Test-CIS_Debian13_1_5_9 { Test-Debian13SysctlControl -ControlId '1.5.9' -Title 'Ensure kernel.randomize_va_space is configured' -Key 'kernel.randomize_va_space' -Accept '2' }
function Set-CIS_Debian13_1_5_9 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'kernel.randomize_va_space' -Value '2' }

function Test-CIS_Debian13_1_5_10 { Test-Debian13SysctlControl -ControlId '1.5.10' -Title 'Ensure kernel.yama.ptrace_scope is configured' -Key 'kernel.yama.ptrace_scope' -Accept '1', '2', '3' }
function Set-CIS_Debian13_1_5_10 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SysctlControl -Key 'kernel.yama.ptrace_scope' -Value '1' -Accept '1', '2', '3' }

# --- 1.5.6 prelink -------------------------------------------------------------

function Test-CIS_Debian13_1_5_6 {
    $installed = Test-CISPackageInstalled -Name 'prelink'
    New-CISResult -ControlId '1.5.6' -Title 'Ensure prelink is not installed' -Status $(if ($installed) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'prelink no instalado' -ActualValue $(if ($installed) { 'instalado' } else { 'no instalado' })
}
function Set-CIS_Debian13_1_5_6 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not (Test-CISPackageInstalled -Name 'prelink')) { return }
    if ($PSCmdlet.ShouldProcess('prelink', '1.5.6 - prelink -ua y apt purge')) {
        & prelink -ua 2>&1 | Out-Null
        Remove-CISPackage -Name 'prelink' -Purge
    }
}

# --- 1.5.7 Apport --------------------------------------------------------------

function Test-CIS_Debian13_1_5_7 {
    if (-not (Test-CISPackageInstalled -Name 'apport')) {
        return New-CISResult -ControlId '1.5.7' -Title 'Ensure Automatic Error Reporting is configured' -Status 'Pass' -ExpectedValue 'apport no instalado, o deshabilitado e inactivo' -ActualValue 'apport no instalado'
    }
    $enabled = Test-CISFileContains -Path '/etc/default/apport' -Pattern '^\s*enabled\s*=\s*[^0]\b'
    $active = Test-CISServiceActive -Name 'apport.service'
    New-CISResult -ControlId '1.5.7' -Title 'Ensure Automatic Error Reporting is configured' -Status $(if (-not $enabled -and -not $active) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'enabled=0 en /etc/default/apport y apport.service inactivo' -ActualValue "enabled!=0: $enabled; service activo: $active"
}
function Set-CIS_Debian13_1_5_7 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not (Test-CISPackageInstalled -Name 'apport')) { return }
    if ($PSCmdlet.ShouldProcess('apport', '1.5.7 - enabled=0, detener y enmascarar apport.service')) {
        Backup-CISFile -Path '/etc/default/apport' | Out-Null
        Set-CISFileLine -Path '/etc/default/apport' -Line 'enabled=0' -MatchPattern '^\s*enabled\s*='
        & systemctl stop apport.service 2>&1 | Out-Null
        Set-CISServiceMasked -Name 'apport.service'
    }
}

# --- 1.5.11 core file size (limits.conf) ---------------------------------------

function Get-Debian13CoreLimitLines {
    # Lineas "* hard core <valor>" de limits.conf y limits.d/*: @{File; Value}
    $files = @('/etc/security/limits.conf') + @(Get-ChildItem '/etc/security/limits.d' -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
    foreach ($f in $files) {
        foreach ($l in (Get-Content -Path $f -ErrorAction SilentlyContinue)) {
            if ($l -match '^\s*\*\s+hard\s+core\s+(\S+)') { [pscustomobject]@{ File = $f; Value = $Matches[1] } }
        }
    }
}
function Test-CIS_Debian13_1_5_11 {
    $lines = @(Get-Debian13CoreLimitLines)
    $bad = @($lines | Where-Object { $_.Value -ne '0' })
    $ok = ($lines.Count -gt 0) -and ($bad.Count -eq 0)
    New-CISResult -ControlId '1.5.11' -Title 'Ensure core file size is configured' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue '* hard core 0 y ninguna linea con valor mayor a 0' `
        -ActualValue $(if ($lines.Count) { ($lines | ForEach-Object { "$($_.File): $($_.Value)" }) -join '; ' } else { 'sin limite definido' })
}
function Set-CIS_Debian13_1_5_11 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('/etc/security/limits.d/60-limits.conf', '1.5.11 - comentar core>0 y agregar "* hard core 0"')) { return }
    foreach ($f in (@(Get-Debian13CoreLimitLines) | Where-Object { $_.Value -ne '0' } | ForEach-Object File | Select-Object -Unique)) {
        Backup-CISFile -Path $f | Out-Null
        (Get-Content $f) | ForEach-Object { if ($_ -match '^\s*[^#\s]+\s+hard\s+core\s+([1-9][0-9]*)') { "# $_" } else { $_ } } | Set-Content $f
    }
    if (-not (@(Get-Debian13CoreLimitLines) | Where-Object { $_.Value -eq '0' })) {
        New-Item -ItemType Directory -Path '/etc/security/limits.d' -Force | Out-Null
        Add-Content -Path '/etc/security/limits.d/60-limits.conf' -Value @('', '* hard core 0')
    }
}

# --- 1.5.12 / 1.5.13 systemd-coredump ------------------------------------------

function Test-Debian13CoredumpControl {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Option, [Parameter(Mandatory)][string]$Expected)
    if (-not (Test-CISPackageInstalled -Name 'systemd-coredump')) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue "$Option=$Expected, o systemd-coredump no instalado" -ActualValue 'systemd-coredump no instalado'
    }
    $r = Get-CISSystemdConfigValue -ConfName 'systemd/coredump.conf' -Block 'Coredump' -Option $Option
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($r -and $r.Value -eq $Expected) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "$Option=$Expected" -ActualValue $(if ($r) { "$($r.Value) ($($r.File)$(if ($r.IsDefault) { ', valor por defecto' }))" } else { 'no definido' })
}
function Set-Debian13CoredumpControl {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Option, [Parameter(Mandatory)][string]$Value)
    if (-not (Test-CISPackageInstalled -Name 'systemd-coredump')) { return }
    Set-CISSystemdConfigValue -ConfName 'systemd/coredump.conf' -Block 'Coredump' -Option $Option -Value $Value
}
function Test-CIS_Debian13_1_5_12 { Test-Debian13CoredumpControl -ControlId '1.5.12' -Title 'Ensure systemd-coredump ProcessSizeMax is configured' -Option 'ProcessSizeMax' -Expected '0' }
function Set-CIS_Debian13_1_5_12 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CoredumpControl -Option 'ProcessSizeMax' -Value '0' }
function Test-CIS_Debian13_1_5_13 { Test-Debian13CoredumpControl -ControlId '1.5.13' -Title 'Ensure systemd-coredump Storage is configured' -Option 'Storage' -Expected 'none' }
function Set-CIS_Debian13_1_5_13 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CoredumpControl -Option 'Storage' -Value 'none' }
