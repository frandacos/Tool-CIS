# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 1 Account Policies
# 10 controles (1.1.1-1.1.7 Password Policy, 1.2.1-1.2.4 Account Lockout Policy).
# Fuente: cis2025.md, paginas 37-59. Todo Level 1, aplica a DC y MS salvo 1.1.6
# (Member Server only, backed por registro segun el propio Audit Procedure del
# benchmark) y 1.2.3 (Member Server only, Manual).

# --- 1.1.1 Enforce password history: 24 or more password(s) --------------

function Test-CIS_1_1_1 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['PasswordHistorySize']
    $status = if ($actual -ge 24) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.1' -Title "Ensure 'Enforce password history' is set to '24 or more password(s)'" `
        -Status $status -ExpectedValue '>= 24' -ActualValue $actual
}

function Set-CIS_1_1_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 24)
    if ($PSCmdlet.ShouldProcess('1.1.1 Enforce password history', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'PasswordHistorySize' -Value $Value
    }
}

# --- 1.1.2 Maximum password age: 365 or fewer days, but not 0 ------------

function Test-CIS_1_1_2 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['MaximumPasswordAge']
    $status = if ($actual -gt 0 -and $actual -le 365) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.2' -Title "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'" `
        -Status $status -ExpectedValue '1-365' -ActualValue $actual
}

function Set-CIS_1_1_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 365)
    if ($PSCmdlet.ShouldProcess('1.1.2 Maximum password age', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'MaximumPasswordAge' -Value $Value
    }
}

# --- 1.1.3 Minimum password age: 1 or more day(s) ------------------------

function Test-CIS_1_1_3 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['MinimumPasswordAge']
    $status = if ($actual -ge 1) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.3' -Title "Ensure 'Minimum password age' is set to '1 or more day(s)'" `
        -Status $status -ExpectedValue '>= 1' -ActualValue $actual
}

function Set-CIS_1_1_3 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 1)
    if ($PSCmdlet.ShouldProcess('1.1.3 Minimum password age', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'MinimumPasswordAge' -Value $Value
    }
}

# --- 1.1.4 Minimum password length: 14 or more character(s) --------------

function Test-CIS_1_1_4 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['MinimumPasswordLength']
    $status = if ($actual -ge 14) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.4' -Title "Ensure 'Minimum password length' is set to '14 or more character(s)'" `
        -Status $status -ExpectedValue '>= 14' -ActualValue $actual
}

function Set-CIS_1_1_4 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 14)
    if ($PSCmdlet.ShouldProcess('1.1.4 Minimum password length', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'MinimumPasswordLength' -Value $Value
    }
}

# --- 1.1.5 Password must meet complexity requirements: Enabled ----------

function Test-CIS_1_1_5 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['PasswordComplexity']
    $status = if ($actual -eq 1) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.5' -Title "Ensure 'Password must meet complexity requirements' is set to 'Enabled'" `
        -Status $status -ExpectedValue '1 (Enabled)' -ActualValue $actual
}

function Set-CIS_1_1_5 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('1.1.5 Password must meet complexity requirements', 'Set to Enabled')) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'PasswordComplexity' -Value 1
    }
}

# --- 1.1.6 Relax minimum password length limits: Enabled (MS only) ------
# Backed por registro segun el propio benchmark (Audit Procedure, pag. 47):
# HKLM\System\CurrentControlSet\Control\SAM:RelaxMinimumPasswordLengthLimits

function Test-CIS_1_1_6 {
    [CmdletBinding()]
    param()
    if ((Get-CISServerRole) -eq 'DC') {
        return New-CISResult -ControlId '1.1.6' -Title "Ensure 'Relax minimum password length limits' is set to 'Enabled' (MS only)" `
            -Status 'NotApplicable' -Notes 'Control marcado (MS only) en el benchmark; este equipo es Domain Controller.'
    }

    $path = 'HKLM:\System\CurrentControlSet\Control\SAM'
    $prop = Get-ItemProperty -Path $path -Name 'RelaxMinimumPasswordLengthLimits' -ErrorAction SilentlyContinue
    $actual = if ($null -ne $prop) { $prop.RelaxMinimumPasswordLengthLimits } else { 0 }
    $status = if ($actual -eq 1) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.6' -Title "Ensure 'Relax minimum password length limits' is set to 'Enabled' (MS only)" `
        -Status $status -ExpectedValue '1 (Enabled)' -ActualValue $actual
}

function Set-CIS_1_1_6 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ((Get-CISServerRole) -eq 'DC') {
        Write-Warning '1.1.6 es (MS only): no se aplica en un Domain Controller.'
        return
    }
    $path = 'HKLM:\System\CurrentControlSet\Control\SAM'
    if ($PSCmdlet.ShouldProcess($path, 'Set RelaxMinimumPasswordLengthLimits = 1')) {
        reg export 'HKLM\System\CurrentControlSet\Control\SAM' `
            (Join-Path (Split-Path (Backup-CISSecurityPolicy) -Parent) "SAM_backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg") 2>$null
        New-ItemProperty -Path $path -Name 'RelaxMinimumPasswordLengthLimits' -PropertyType DWord -Value 1 -Force | Out-Null
    }
}

# --- 1.1.7 Store passwords using reversible encryption: Disabled ---------

function Test-CIS_1_1_7 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['ClearTextPassword']
    $status = if ($actual -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.1.7' -Title "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'" `
        -Status $status -ExpectedValue '0 (Disabled)' -ActualValue $actual
}

function Set-CIS_1_1_7 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('1.1.7 Store passwords using reversible encryption', 'Set to Disabled')) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'ClearTextPassword' -Value 0
    }
}

# --- 1.2.1 Account lockout duration: 15 or more minute(s) ----------------

function Test-CIS_1_2_1 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['LockoutDuration']
    $status = if ($actual -ge 15) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.2.1' -Title "Ensure 'Account lockout duration' is set to '15 or more minute(s)'" `
        -Status $status -ExpectedValue '>= 15' -ActualValue $actual
}

function Set-CIS_1_2_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 15)
    if ($PSCmdlet.ShouldProcess('1.2.1 Account lockout duration', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'LockoutDuration' -Value $Value
    }
}

# --- 1.2.2 Account lockout threshold: 5 or fewer invalid logon attempt(s), but not 0

function Test-CIS_1_2_2 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['LockoutBadCount']
    $status = if ($actual -ge 1 -and $actual -le 5) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.2.2' -Title "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'" `
        -Status $status -ExpectedValue '1-5' -ActualValue $actual
}

function Set-CIS_1_2_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 5)
    if ($PSCmdlet.ShouldProcess('1.2.2 Account lockout threshold', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'LockoutBadCount' -Value $Value
    }
}

# --- 1.2.3 Allow Administrator account lockout: Enabled (MS only) (Manual)
# El benchmark no documenta una ruta de registro/secedit para este control
# (solo UI Path de GPO); por regla del system prompt esto es Manual Review,
# no se inventa una heuristica de auditoria.

function Test-CIS_1_2_3 {
    [CmdletBinding()]
    param()
    if ((Get-CISServerRole) -eq 'DC') {
        return New-CISResult -ControlId '1.2.3' -Title "Ensure 'Allow Administrator account lockout' is set to 'Enabled' (MS only)" `
            -Status 'NotApplicable' -Notes 'Control marcado (MS only) en el benchmark; este equipo es Domain Controller.'
    }
    New-CISResult -ControlId '1.2.3' -Title "Ensure 'Allow Administrator account lockout' is set to 'Enabled' (MS only)" `
        -Status 'ManualReviewRequired' `
        -Notes 'El benchmark (pag. 57) solo define UI Path de GPO (Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Account Lockout Policies\Allow Administrator account lockout), sin backing de registro/secedit documentado. Verificar manualmente via gpresult/RSOP o Local Security Policy. Requiere build patchado a partir de KB5020282 (11-oct-2022).'
}

function Set-CIS_1_2_3 {
    [CmdletBinding()]
    param()
    Write-Warning '1.2.3 es (Manual): este benchmark no define un mecanismo de remediacion automatizable via registro/secedit. Aplicar manualmente el UI Path indicado en Test-CIS_1_2_3 via GPO.'
}

# --- 1.2.4 Reset account lockout counter after: 15 or more minute(s) -----

function Test-CIS_1_2_4 {
    [CmdletBinding()]
    param()
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['ResetLockoutCount']
    $status = if ($actual -ge 15) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.2.4' -Title "Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'" `
        -Status $status -ExpectedValue '>= 15' -ActualValue $actual
}

function Set-CIS_1_2_4 {
    [CmdletBinding(SupportsShouldProcess)]
    param([int]$Value = 15)
    if ($PSCmdlet.ShouldProcess('1.2.4 Reset account lockout counter after', "Set to $Value")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-CISSecurityPolicyValue -Key 'ResetLockoutCount' -Value $Value
    }
}
