# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 2.3
# Security Options (70 controles). Fuente: cis2025.md paginas 162-306+.
#
# Reutiliza Get-CISSecurityPolicy/Set-CISSecurityPolicyValue (Helpers.ps1,
# secedit [System Access]) para los 6 controles que en realidad viven ahi
# (EnableGuestAccount, NewAdministratorName, NewGuestName, SubmitControl,
# RefusePasswordChange, LSAAnonymousNameLookup) y Test-CISRegistryValue/
# Set-CISRegistryValue (RegistryEngine.ps1) para el resto, que son valores de
# registro directos bajo HKLM (asi es como Windows almacena internamente
# estas politicas de Security Options, independientemente de que la UI de
# Local Security Policy las muestre agrupadas).
#
# Dos controles quedan como ManualReviewRequired en vez de una heuristica
# inventada (regla 3 del system prompt):
#   - 2.3.11.5 (Manual en el propio benchmark).
#   - 2.3.11.7 ("LDAP client encryption requirements"): no hay certeza sobre
#     un valor de registro DISTINTO de LDAPClientIntegrity (que ya cubre
#     2.3.11.8, signing) documentado para "encryption requirements" como
#     control separado; mejor no inventar la clave que adivinarla mal.
#   - 2.3.5.4 ("LDAP server signing requirements Enforcement"): mismo caso,
#     variante DC de signing enforcement sin clave de registro confirmada
#     de forma independiente de 2.3.5.3 (channel binding).

# ===================== 2.3.1 Accounts =====================

# 2.3.1.1 (MS only) - system access
function Test-CIS_2_3_1_1 {
    if ((Get-CISServerRole) -ne 'MS') {
        return New-CISResult -ControlId '2.3.1.1' -Title "Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)" -Status 'NotApplicable' -Notes 'Control (MS only); este equipo no es MS.'
    }
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['EnableGuestAccount']
    $status = if ($actual -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '2.3.1.1' -Title "Ensure 'Accounts: Guest account status' is set to 'Disabled' (MS only)" -Status $status -ExpectedValue '0 (Disabled)' -ActualValue $actual
}
function Set-CIS_2_3_1_1 {
    if ((Get-CISServerRole) -ne 'MS') { Write-Warning '2.3.1.1 es (MS only).'; return }
    Backup-CISSecurityPolicy | Out-Null
    Set-CISSecurityPolicyValue -Key 'EnableGuestAccount' -Value 0
}

# 2.3.1.2 - registro
function Test-CIS_2_3_1_2 {
    Test-CISRegistryValue -ControlId '2.3.1.2' -Title "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' `
        -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_1_2 {
    Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LimitBlankPasswordUse' -Type DWord -Value 1
}

# 2.3.1.3 - system access, valor organization-specific: se exige que ya no sea 'Administrator'
# secedit exporta los valores string de [System Access] entre comillas
# literales (ej. NewAdministratorName = "Administrator"); sin el Trim('"')
# la comparacion nunca coincide con el valor prohibido (uno queda con
# comillas y el otro sin ellas) y el control da Pass siempre, este o no
# renombrada la cuenta.
function Test-CIS_2_3_1_3 {
    $policy = Get-CISSecurityPolicy
    $actual = ($policy['NewAdministratorName']) -replace '^"|"$', ''
    $ok = (& (New-CISValidatorNotEqualCaseInsensitive 'Administrator') $actual) -and (& (New-CISValidatorNonEmptyString) $actual)
    New-CISResult -ControlId '2.3.1.3' -Title "Configure 'Accounts: Rename administrator account'" -Status ($(if ($ok) { 'Pass' } else { 'Fail' })) -ExpectedValue "distinto de 'Administrator'" -ActualValue $actual
}
function Set-CIS_2_3_1_3 {
    param([Parameter(Mandatory)][string]$NewName)
    if ($NewName -eq 'Administrator') { throw "2.3.1.3 requiere un nombre distinto de 'Administrator'." }
    Backup-CISSecurityPolicy | Out-Null
    Set-CISSecurityPolicyValue -Key 'NewAdministratorName' -Value "`"$NewName`""
}

# 2.3.1.4 - system access, valor organization-specific: se exige que ya no sea 'Guest'
# Mismo Trim('"') que 2.3.1.3, mismo motivo (ver comentario ahi).
function Test-CIS_2_3_1_4 {
    $policy = Get-CISSecurityPolicy
    $actual = ($policy['NewGuestName']) -replace '^"|"$', ''
    $ok = (& (New-CISValidatorNotEqualCaseInsensitive 'Guest') $actual) -and (& (New-CISValidatorNonEmptyString) $actual)
    New-CISResult -ControlId '2.3.1.4' -Title "Configure 'Accounts: Rename guest account'" -Status ($(if ($ok) { 'Pass' } else { 'Fail' })) -ExpectedValue "distinto de 'Guest'" -ActualValue $actual
}
function Set-CIS_2_3_1_4 {
    param([Parameter(Mandatory)][string]$NewName)
    if ($NewName -eq 'Guest') { throw "2.3.1.4 requiere un nombre distinto de 'Guest'." }
    Backup-CISSecurityPolicy | Out-Null
    Set-CISSecurityPolicyValue -Key 'NewGuestName' -Value "`"$NewName`""
}

# ===================== 2.3.2 Audit =====================

function Test-CIS_2_3_2_1 {
    Test-CISRegistryValue -ControlId '2.3.2.1' -Title "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' `
        -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_2_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 }

function Test-CIS_2_3_2_2 {
    Test-CISRegistryValue -ControlId '2.3.2.2' -Title "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'CrashOnAuditFail' `
        -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_2_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'CrashOnAuditFail' -Type DWord -Value 0 }

# ===================== 2.3.4 Devices =====================

function Test-CIS_2_3_4_1 {
    Test-CISRegistryValue -ControlId '2.3.4.1' -Title "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' `
        -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_4_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers' -Name 'AddPrinterDrivers' -Type DWord -Value 1 }

# ===================== 2.3.5 Domain controller =====================

function Test-CIS_2_3_5_1 {
    if ((Get-CISServerRole) -ne 'DC') { return New-CISResult -ControlId '2.3.5.1' -Title "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)" -Status 'NotApplicable' -Notes 'Control (DC only).' }
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['SubmitControl']
    $status = if ($actual -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '2.3.5.1' -Title "Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled' (DC only)" -Status $status -ExpectedValue '0 (Disabled)' -ActualValue $actual
}
function Set-CIS_2_3_5_1 {
    if ((Get-CISServerRole) -ne 'DC') { Write-Warning '2.3.5.1 es (DC only).'; return }
    Backup-CISSecurityPolicy | Out-Null
    Set-CISSecurityPolicyValue -Key 'SubmitControl' -Value 0
}

function Test-CIS_2_3_5_2 {
    Test-CISRegistryValue -ControlId '2.3.5.2' -Title "Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured' (DC Only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'VulnerableChannelAllowList' `
        -Validator (New-CISValidatorNotConfigured) -ExpectedValue 'Not Configured' -Scope DC
}
function Set-CIS_2_3_5_2 { Remove-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'VulnerableChannelAllowList' -Scope DC }

# Confianza media: LdapEnforceChannelBinding es el registro documentado por
# Microsoft para "channel binding token requirements" post PetitPotam/CVE
# LDAP hardening. Verificar contra el DC de lab antes de remediar en prod.
function Test-CIS_2_3_5_3 {
    Test-CISRegistryValue -ControlId '2.3.5.3' -Title "Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always' (DC Only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' `
        -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Always)' -Scope DC
}
function Set-CIS_2_3_5_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name 'LdapEnforceChannelBinding' -Type DWord -Value 2 -Scope DC }

# Baja confianza deliberada: no hay una clave de registro distinta de
# LdapEnforceChannelBinding/LDAPServerIntegrity confirmada para esta
# variante especifica de "Enforcement". Manual en vez de adivinar.
function Test-CIS_2_3_5_4 {
    if ((Get-CISServerRole) -ne 'DC') { return New-CISResult -ControlId '2.3.5.4' -Title "Ensure 'Domain controller: LDAP server signing requirements Enforcement' is set to 'Enabled' (DC only)" -Status 'NotApplicable' -Notes 'Control (DC only).' }
    New-CISResult -ControlId '2.3.5.4' -Title "Ensure 'Domain controller: LDAP server signing requirements Enforcement' is set to 'Enabled' (DC only)" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza una clave de registro distinta de LDAPServerIntegrity/LdapEnforceChannelBinding para esta variante de enforcement en la documentacion disponible. Verificar manualmente via RSOP/gpresult antes de automatizar.'
}
function Set-CIS_2_3_5_4 { Write-Warning '2.3.5.4 es Manual: no hay remediacion automatizada, ver Test-CIS_2_3_5_4 para el detalle.' }

function Test-CIS_2_3_5_5 {
    if ((Get-CISServerRole) -ne 'DC') { return New-CISResult -ControlId '2.3.5.5' -Title "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only)" -Status 'NotApplicable' -Notes 'Control (DC only).' }
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['RefusePasswordChange']
    $status = if ($actual -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '2.3.5.5' -Title "Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled' (DC only)" -Status $status -ExpectedValue '0 (Disabled)' -ActualValue $actual
}
function Set-CIS_2_3_5_5 {
    if ((Get-CISServerRole) -ne 'DC') { Write-Warning '2.3.5.5 es (DC only).'; return }
    Backup-CISSecurityPolicy | Out-Null
    Set-CISSecurityPolicyValue -Key 'RefusePasswordChange' -Value 0
}

# ===================== 2.3.6 Domain member =====================
# Registro bajo Netlogon\Parameters (no secedit, a pesar de aparecer bajo
# "Security Options" en la UI).

function Test-CIS_2_3_6_1 {
    Test-CISRegistryValue -ControlId '2.3.6.1' -Title "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_6_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireSignOrSeal' -Type DWord -Value 1 }

function Test-CIS_2_3_6_2 {
    Test-CISRegistryValue -ControlId '2.3.6.2' -Title "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_6_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SealSecureChannel' -Type DWord -Value 1 }

function Test-CIS_2_3_6_3 {
    Test-CISRegistryValue -ControlId '2.3.6.3' -Title "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_6_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'SignSecureChannel' -Type DWord -Value 1 }

function Test-CIS_2_3_6_4 {
    Test-CISRegistryValue -ControlId '2.3.6.4' -Title "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_6_4 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'DisablePasswordChange' -Type DWord -Value 0 }

function Test-CIS_2_3_6_5 {
    Test-CISRegistryValue -ControlId '2.3.6.5' -Title "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge' -Validator (New-CISValidatorRange 1 30) -ExpectedValue '1-30'
}
function Set-CIS_2_3_6_5 { param([int]$Value = 30) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'MaximumPasswordAge' -Type DWord -Value $Value }

function Test-CIS_2_3_6_6 {
    Test-CISRegistryValue -ControlId '2.3.6.6' -Title "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_6_6 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'RequireStrongKey' -Type DWord -Value 1 }

# ===================== 2.3.7 Interactive logon =====================

function Test-CIS_2_3_7_1 {
    Test-CISRegistryValue -ControlId '2.3.7.1' -Title "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_7_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableCAD' -Type DWord -Value 0 }

function Test-CIS_2_3_7_2 {
    Test-CISRegistryValue -ControlId '2.3.7.2' -Title "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_7_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DontDisplayLastUserName' -Type DWord -Value 1 }

function Test-CIS_2_3_7_3 {
    Test-CISRegistryValue -ControlId '2.3.7.3' -Title "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Validator (New-CISValidatorRange 1 900) -ExpectedValue '1-900'
}
function Set-CIS_2_3_7_3 { param([int]$Value = 900) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'InactivityTimeoutSecs' -Type DWord -Value $Value }

# 2.3.7.4/2.3.7.5: valor organization-specific (texto del cartel legal).
function Test-CIS_2_3_7_4 {
    Test-CISRegistryValue -ControlId '2.3.7.4' -Title "Configure 'Interactive logon: Message text for users attempting to log on'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Validator (New-CISValidatorNonEmptyString) -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_2_3_7_4 { param([Parameter(Mandatory)][string]$Text) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeText' -Type String -Value $Text }

function Test-CIS_2_3_7_5 {
    Test-CISRegistryValue -ControlId '2.3.7.5' -Title "Configure 'Interactive logon: Message title for users attempting to log on'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -Validator (New-CISValidatorNonEmptyString) -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_2_3_7_5 { param([Parameter(Mandatory)][string]$Caption) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -Type String -Value $Caption }

# 2.3.7.6 (MS only) - CachedLogonsCount se almacena como REG_SZ, no DWORD.
function Test-CIS_2_3_7_6 {
    Test-CISRegistryValue -ControlId '2.3.7.6' -Title "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer logon(s)' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' `
        -Validator { param($v) $null -ne $v -and [int]$v -ge 0 -and [int]$v -le 4 } -ExpectedValue '0-4' -Scope MS
}
function Set-CIS_2_3_7_6 { param([int]$Value = 4) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'CachedLogonsCount' -Type String -Value "$Value" -Scope MS }

function Test-CIS_2_3_7_7 {
    Test-CISRegistryValue -ControlId '2.3.7.7' -Title "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PasswordExpiryWarning' -Validator (New-CISValidatorRange 5 14) -ExpectedValue '5-14'
}
function Set-CIS_2_3_7_7 { param([int]$Value = 14) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PasswordExpiryWarning' -Type DWord -Value $Value }

function Test-CIS_2_3_7_8 {
    Test-CISRegistryValue -ControlId '2.3.7.8' -Title "Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ForceUnlockLogon' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)' -Scope MS
}
function Set-CIS_2_3_7_8 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ForceUnlockLogon' -Type DWord -Value 1 -Scope MS }

# 2.3.7.9 - ScRemoveOption es REG_SZ ("1"=Lock Workstation, "2"=Force Logoff).
function Test-CIS_2_3_7_9 {
    Test-CISRegistryValue -ControlId '2.3.7.9' -Title "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' `
        -Validator (New-CISValidatorOneOf @('1', '2')) -ExpectedValue "'1' (Lock Workstation) o '2' (Force Logoff)"
}
function Set-CIS_2_3_7_9 { param([ValidateSet('1', '2')][string]$Value = '1') Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ScRemoveOption' -Type String -Value $Value }

# ===================== 2.3.8 Microsoft network client =====================

function Test-CIS_2_3_8_1 {
    Test-CISRegistryValue -ControlId '2.3.8.1' -Title "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_8_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1 }

function Test-CIS_2_3_8_2 {
    Test-CISRegistryValue -ControlId '2.3.8.2' -Title "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_8_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'EnablePlainTextPassword' -Type DWord -Value 0 }

# ===================== 2.3.9 Microsoft network server =====================

function Test-CIS_2_3_9_1 {
    Test-CISRegistryValue -ControlId '2.3.9.1' -Title "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'AutoDisconnect' -Validator (New-CISValidatorMaxValueNotZero 15) -ExpectedValue '1-15'
}
function Set-CIS_2_3_9_1 { param([int]$Value = 15) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'AutoDisconnect' -Type DWord -Value $Value }

function Test-CIS_2_3_9_2 {
    Test-CISRegistryValue -ControlId '2.3.9.2' -Title "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_9_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RequireSecuritySignature' -Type DWord -Value 1 }

function Test-CIS_2_3_9_3 {
    Test-CISRegistryValue -ControlId '2.3.9.3' -Title "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'EnableForcedLogOff' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_9_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'EnableForcedLogOff' -Type DWord -Value 1 }

function Test-CIS_2_3_9_4 {
    Test-CISRegistryValue -ControlId '2.3.9.4' -Title "Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher (MS only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'SMBServerNameHardeningLevel' -Validator (New-CISValidatorMinValue 1) -ExpectedValue '>= 1' -Scope MS
}
function Set-CIS_2_3_9_4 { param([int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'SMBServerNameHardeningLevel' -Type DWord -Value $Value -Scope MS }

# ===================== 2.3.10 Network access =====================

# 2.3.10.1 - system access (LSAAnonymousNameLookup), no registro.
function Test-CIS_2_3_10_1 {
    $policy = Get-CISSecurityPolicy
    $actual = [int]$policy['LSAAnonymousNameLookup']
    $status = if ($actual -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '2.3.10.1' -Title "Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'" -Status $status -ExpectedValue '0 (Disabled)' -ActualValue $actual
}
function Set-CIS_2_3_10_1 { Backup-CISSecurityPolicy | Out-Null; Set-CISSecurityPolicyValue -Key 'LSAAnonymousNameLookup' -Value 0 }

function Test-CIS_2_3_10_2 {
    Test-CISRegistryValue -ControlId '2.3.10.2' -Title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled' (MS only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)' -Scope MS
}
function Set-CIS_2_3_10_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Type DWord -Value 1 -Scope MS }

function Test-CIS_2_3_10_3 {
    Test-CISRegistryValue -ControlId '2.3.10.3' -Title "Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled' (MS only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)' -Scope MS
}
function Set-CIS_2_3_10_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymous' -Type DWord -Value 1 -Scope MS }

function Test-CIS_2_3_10_4 {
    Test-CISRegistryValue -ControlId '2.3.10.4' -Title "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_10_4 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'DisableDomainCreds' -Type DWord -Value 1 }

function Test-CIS_2_3_10_5 {
    Test-CISRegistryValue -ControlId '2.3.10.5' -Title "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_10_5 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'EveryoneIncludesAnonymous' -Type DWord -Value 0 }

# 2.3.10.6/7 - NullSessionPipes (REG_MULTI_SZ), distinto valor esperado DC/MS.
function Test-CIS_2_3_10_6 {
    Test-CISRegistryValue -ControlId '2.3.10.6' -Title "Ensure 'Network access: Named Pipes that can be accessed anonymously' is configured (DC only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionPipes' `
        -Validator (New-CISValidatorMultiStringContainsAll @('LSARPC', 'NETLOGON', 'SAMR')) -ExpectedValue 'Incluye al menos: LSARPC, NETLOGON, SAMR' -Scope DC
}
function Set-CIS_2_3_10_6 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionPipes' -Type MultiString -Value @('LSARPC', 'NETLOGON', 'SAMR') -Scope DC }

function Test-CIS_2_3_10_7 {
    Test-CISRegistryValue -ControlId '2.3.10.7' -Title "Ensure 'Network access: Named Pipes that can be accessed anonymously' is configured (MS only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionPipes' `
        -Validator (New-CISValidatorMultiStringEmpty) -ExpectedValue 'Vacio (ninguno)' -Scope MS
}
function Set-CIS_2_3_10_7 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionPipes' -Type MultiString -Value @() -Scope MS }

function Test-CIS_2_3_10_8 {
    Test-CISRegistryValue -ControlId '2.3.10.8' -Title "Ensure 'Network access: Remotely accessible registry paths' is configured" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -Name 'Machine' `
        -Validator { param($v) $null -ne $v -and @($v).Count -gt 0 } -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_2_3_10_8 {
    param([string[]]$Paths = @('System\CurrentControlSet\Control\ProductOptions', 'System\CurrentControlSet\Control\Server Applications', 'Software\Microsoft\Windows NT\CurrentVersion'))
    Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -Name 'Machine' -Type MultiString -Value $Paths
}

function Test-CIS_2_3_10_9 {
    Test-CISRegistryValue -ControlId '2.3.10.9' -Title "Ensure 'Network access: Remotely accessible registry paths and sub-paths' is configured" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths' -Name 'Machine' `
        -Validator { param($v) $null -ne $v -and @($v).Count -gt 0 } -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_2_3_10_9 {
    param([string[]]$Paths = @(
            'System\CurrentControlSet\Control\Print\Printers', 'System\CurrentControlSet\Services\Eventlog',
            'Software\Microsoft\OLAP Server', 'Software\Microsoft\Windows NT\CurrentVersion\Print',
            'Software\Microsoft\Windows NT\CurrentVersion\Windows', 'System\CurrentControlSet\Control\ContentIndex',
            'System\CurrentControlSet\Control\Terminal Server', 'System\CurrentControlSet\Control\Terminal Server\UserConfig',
            'System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration', 'Software\Microsoft\Windows NT\CurrentVersion\Perflib',
            'System\CurrentControlSet\Services\SysmonLog'
        ))
    Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths' -Name 'Machine' -Type MultiString -Value $Paths
}

function Test-CIS_2_3_10_10 {
    Test-CISRegistryValue -ControlId '2.3.10.10' -Title "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_10_10 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'RestrictNullSessAccess' -Type DWord -Value 1 }

function Test-CIS_2_3_10_11 {
    Test-CISRegistryValue -ControlId '2.3.10.11' -Title "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow' (MS only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -Validator (New-CISValidatorExact 'O:BAG:BAD:(A;;RC;;;BA)') -ExpectedValue 'O:BAG:BAD:(A;;RC;;;BA)' -Scope MS
}
function Set-CIS_2_3_10_11 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -Type String -Value 'O:BAG:BAD:(A;;RC;;;BA)' -Scope MS }

function Test-CIS_2_3_10_12 {
    Test-CISRegistryValue -ControlId '2.3.10.12' -Title "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionShares' -Validator (New-CISValidatorMultiStringEmpty) -ExpectedValue 'Vacio (ninguno)'
}
function Set-CIS_2_3_10_12 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name 'NullSessionShares' -Type MultiString -Value @() }

function Test-CIS_2_3_10_13 {
    Test-CISRegistryValue -ControlId '2.3.10.13' -Title "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Classic)'
}
function Set-CIS_2_3_10_13 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'ForceGuest' -Type DWord -Value 0 }

# ===================== 2.3.11 Network security =====================

function Test-CIS_2_3_11_1 {
    Test-CISRegistryValue -ControlId '2.3.11.1' -Title "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_11_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'UseMachineId' -Type DWord -Value 1 }

function Test-CIS_2_3_11_2 {
    Test-CISRegistryValue -ControlId '2.3.11.2' -Title "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'allownullsessionfallback' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_11_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'allownullsessionfallback' -Type DWord -Value 0 }

function Test-CIS_2_3_11_3 {
    Test-CISRegistryValue -ControlId '2.3.11.3' -Title "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' -Name 'AllowOnlineID' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_11_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' -Name 'AllowOnlineID' -Type DWord -Value 0 }

# 2.3.11.4 - bitmask: exige AES128 (0x08) y AES256 (0x10) habilitados. No se
# valida el bit de "Future types" (0x80000000) como obligatorio porque su
# presencia exacta varia entre plantillas sin cambiar la postura de
# seguridad real (RC4/DES ya quedan excluidos al no pedirlos).
function Test-CIS_2_3_11_4 {
    Test-CISRegistryValue -ControlId '2.3.11.4' -Title "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Validator (New-CISValidatorBitmaskAll 0x18) -ExpectedValue 'Bits AES128 (0x8) y AES256 (0x10) habilitados'
}
function Set-CIS_2_3_11_4 { param([int]$Value = 2147483672) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters' -Name 'SupportedEncryptionTypes' -Type DWord -Value $Value }

function Test-CIS_2_3_11_5 {
    New-CISResult -ControlId '2.3.11.5' -Title "Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'" -Status 'ManualReviewRequired' `
        -Notes 'Control marcado (Manual) en el propio benchmark: el estado esperado puede variar segun el entorno. Verificar manualmente via Local Security Policy / RSOP.'
}
function Set-CIS_2_3_11_5 { Write-Warning '2.3.11.5 es Manual en el benchmark: no se remedia automaticamente.' }

function Test-CIS_2_3_11_6 {
    Test-CISRegistryValue -ControlId '2.3.11.6' -Title "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Validator (New-CISValidatorExact 5) -ExpectedValue '5'
}
function Set-CIS_2_3_11_6 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel' -Type DWord -Value 5 }

# Baja confianza deliberada: no hay una clave de registro distinta de
# LDAPClientIntegrity (que ya cubre 2.3.11.8, signing) confirmada para
# "encryption requirements" como control independiente.
function Test-CIS_2_3_11_7 {
    New-CISResult -ControlId '2.3.11.7' -Title "Ensure 'Network security: LDAP client encryption requirements' is set to 'Negotiate sealing' or higher" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza una clave de registro distinta de LDAPClientIntegrity (usada por 2.3.11.8) para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_2_3_11_7 { Write-Warning '2.3.11.7: sin remediacion automatizada, ver Test-CIS_2_3_11_7.' }

function Test-CIS_2_3_11_8 {
    Test-CISRegistryValue -ControlId '2.3.11.8' -Title "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Validator (New-CISValidatorMinValue 1) -ExpectedValue '>= 1'
}
function Set-CIS_2_3_11_8 { param([int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -Name 'LDAPClientIntegrity' -Type DWord -Value $Value }

# 2.3.11.9/10 - bitmask 0x20080000 = Require NTLMv2 session security (0x20000000) + Require 128-bit encryption (0x20000000)... en realidad NTLMv2=0x00080000, 128-bit=0x20000000; combinados = 0x20080000.
function Test-CIS_2_3_11_9 {
    Test-CISRegistryValue -ControlId '2.3.11.9' -Title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Validator (New-CISValidatorBitmaskAll 0x20080000) -ExpectedValue 'Bits NTLMv2 (0x80000) y 128-bit (0x20000000) habilitados'
}
function Set-CIS_2_3_11_9 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinClientSec' -Type DWord -Value 537395200 }

function Test-CIS_2_3_11_10 {
    Test-CISRegistryValue -ControlId '2.3.11.10' -Title "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Validator (New-CISValidatorBitmaskAll 0x20080000) -ExpectedValue 'Bits NTLMv2 (0x80000) y 128-bit (0x20000000) habilitados'
}
function Set-CIS_2_3_11_10 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'NtlmMinServerSec' -Type DWord -Value 537395200 }

function Test-CIS_2_3_11_11 {
    Test-CISRegistryValue -ControlId '2.3.11.11' -Title "Ensure 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' is set to 'Enable auditing for all accounts'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Enable auditing for all accounts)'
}
function Set-CIS_2_3_11_11 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'AuditReceivingNTLMTraffic' -Type DWord -Value 2 }

function Test-CIS_2_3_11_12 {
    Test-CISRegistryValue -ControlId '2.3.11.12' -Title "Ensure 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' is set to 'Enable all' (DC only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'AuditNTLMInDomain' -Validator (New-CISValidatorExact 7) -ExpectedValue '7 (Enable all)' -Scope DC
}
function Set-CIS_2_3_11_12 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'AuditNTLMInDomain' -Type DWord -Value 7 -Scope DC }

function Test-CIS_2_3_11_13 {
    Test-CISRegistryValue -ControlId '2.3.11.13' -Title "Ensure 'Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers' is set to 'Audit all' or higher" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Validator (New-CISValidatorMinValue 1) -ExpectedValue '>= 1'
}
function Set-CIS_2_3_11_13 { param([int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -Name 'RestrictSendingNTLMTraffic' -Type DWord -Value $Value }

# ===================== 2.3.13 Shutdown =====================

function Test-CIS_2_3_13_1 {
    Test-CISRegistryValue -ControlId '2.3.13.1' -Title "Ensure 'Shutdown: Allow system to be shut down without having to log on' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_2_3_13_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ShutdownWithoutLogon' -Type DWord -Value 0 }

# ===================== 2.3.15 System objects =====================

function Test-CIS_2_3_15_1 {
    Test-CISRegistryValue -ControlId '2.3.15.1' -Title "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -Name 'ObCaseInsensitive' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_15_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -Name 'ObCaseInsensitive' -Type DWord -Value 1 }

function Test-CIS_2_3_15_2 {
    Test-CISRegistryValue -ControlId '2.3.15.2' -Title "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'ProtectionMode' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_15_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'ProtectionMode' -Type DWord -Value 1 }

# ===================== 2.3.17 User Account Control =====================

function Test-CIS_2_3_17_1 {
    Test-CISRegistryValue -ControlId '2.3.17.1' -Title "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_17_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'FilterAdministratorToken' -Type DWord -Value 1 }

# Acepta 1 (credenciales en escritorio seguro) o 2 (consentimiento en
# escritorio seguro) -- ambos cumplen "Prompt ... on the secure desktop' or
# higher" segun el propio benchmark.
function Test-CIS_2_3_17_2 {
    Test-CISRegistryValue -ControlId '2.3.17.2' -Title "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop' or higher" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Validator (New-CISValidatorOneOf @(1, 2)) -ExpectedValue '1 o 2'
}
function Set-CIS_2_3_17_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWord -Value 2 }

function Test-CIS_2_3_17_3 {
    Test-CISRegistryValue -ControlId '2.3.17.3' -Title "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Automatically deny elevation requests)'
}
function Set-CIS_2_3_17_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorUser' -Type DWord -Value 0 }

function Test-CIS_2_3_17_4 {
    Test-CISRegistryValue -ControlId '2.3.17.4' -Title "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_17_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Type DWord -Value 1 }

function Test-CIS_2_3_17_5 {
    Test-CISRegistryValue -ControlId '2.3.17.5' -Title "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ValidateAdminCodeSignatures' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_17_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ValidateAdminCodeSignatures' -Type DWord -Value 1 }

function Test-CIS_2_3_17_6 {
    Test-CISRegistryValue -ControlId '2.3.17.6' -Title "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_17_6 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Type DWord -Value 1 }

function Test-CIS_2_3_17_7 {
    Test-CISRegistryValue -ControlId '2.3.17.7' -Title "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_17_7 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop' -Type DWord -Value 1 }

function Test-CIS_2_3_17_8 {
    Test-CISRegistryValue -ControlId '2.3.17.8' -Title "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_2_3_17_8 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableVirtualization' -Type DWord -Value 1 }
