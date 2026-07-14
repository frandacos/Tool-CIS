# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 18.9 System
# (68 controles). Fuente: cis2025.md paginas 631-816.
#
# 62 controles via registro (RegistryEngine.ps1), incluyendo bloques bien
# documentados desde hace anios (Remote Assistance, RPC, NTP, power
# management, logon options, la tanda "Internet Communication settings" de
# 18.9.20.1.x) y bloques mas recientes pero ya extensamente documentados
# (Device Guard/VBS, Credential Guard, Windows LAPS, Kernel DMA Protection,
# LSASS protected process).
#
# 6 controles quedan ManualReviewRequired por incertidumbre genuina sobre la
# clave de registro exacta (features 2022+ poco documentadas o con
# variantes que no pude confirmar con certeza): 18.9.17.1, 18.9.23.1,
# 18.9.31.1.1, 18.9.41.1, 18.9.41.2, 18.9.41.3.

# ===================== 18.9.3 Audit Process Creation =====================

function Test-CIS_18_9_3_1 {
    Test-CISRegistryValue -ControlId '18.9.3.1' -Title "Ensure 'Include command line in process creation events' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_3_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name 'ProcessCreationIncludeCmdLine_Enabled' -Type DWord -Value 1 }

# ===================== 18.9.4 Credentials Delegation =====================

function Test-CIS_18_9_4_1 {
    Test-CISRegistryValue -ControlId '18.9.4.1' -Title "Ensure 'Encryption Oracle Remediation' is set to 'Enabled: Force Updated Clients'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Force Updated Clients)'
}
function Set-CIS_18_9_4_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Type DWord -Value 0 }

function Test-CIS_18_9_4_2 {
    Test-CISRegistryValue -ControlId '18.9.4.2' -Title "Ensure 'Remote host allows delegation of non-exportable credentials' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_4_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name 'AllowProtectedCreds' -Type DWord -Value 1 }

# ===================== 18.9.5 Device Guard / VBS / Credential Guard =====================
# Confianza media-alta: esquema estable desde Windows 10 1607/Server 2016,
# documentado en CIS Server 2019/2022, pero con capas de registro (Policy
# vs Scenario vs LSA) que ameritan doble chequeo en el server de lab.

function Test-CIS_18_9_5_1 {
    Test-CISRegistryValue -ControlId '18.9.5.1' -Title "Ensure 'Turn On Virtualization Based Security' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_5_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'EnableVirtualizationBasedSecurity' -Type DWord -Value 1 }

function Test-CIS_18_9_5_2 {
    Test-CISRegistryValue -ControlId '18.9.5.2' -Title "Ensure 'Turn On Virtualization Based Security: Select Platform Security Level' is set to 'Secure Boot' or higher" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Validator (New-CISValidatorMinValue 1) -ExpectedValue '>= 1 (Secure Boot)'
}
function Set-CIS_18_9_5_2 { param([int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'RequirePlatformSecurityFeatures' -Type DWord -Value $Value }

function Test-CIS_18_9_5_3 {
    Test-CISRegistryValue -ControlId '18.9.5.3' -Title "Ensure 'Turn On Virtualization Based Security: Virtualization Based Protection of Code Integrity' is set to 'Enabled with UEFI lock'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Enabled with UEFI lock)'
}
function Set-CIS_18_9_5_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HypervisorEnforcedCodeIntegrity' -Type DWord -Value 2 }

function Test-CIS_18_9_5_4 {
    Test-CISRegistryValue -ControlId '18.9.5.4' -Title "Ensure 'Turn On Virtualization Based Security: Require UEFI Memory Attributes Table' is set to 'True (checked)'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HVCIMATRequired' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (True)'
}
function Set-CIS_18_9_5_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'HVCIMATRequired' -Type DWord -Value 1 }

function Test-CIS_18_9_5_5 {
    Test-CISRegistryValue -ControlId '18.9.5.5' -Title "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Enabled with UEFI lock' (MS Only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LsaCfgFlags' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled with UEFI lock)' -Scope MS
}
function Set-CIS_18_9_5_5 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LsaCfgFlags' -Type DWord -Value 1 -Scope MS }

function Test-CIS_18_9_5_6 {
    Test-CISRegistryValue -ControlId '18.9.5.6' -Title "Ensure 'Turn On Virtualization Based Security: Credential Guard Configuration' is set to 'Disabled' (DC Only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LsaCfgFlags' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)' -Scope DC
}
function Set-CIS_18_9_5_6 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA' -Name 'LsaCfgFlags' -Type DWord -Value 0 -Scope DC }

function Test-CIS_18_9_5_7 {
    Test-CISRegistryValue -ControlId '18.9.5.7' -Title "Ensure 'Turn On Virtualization Based Security: Secure Launch Configuration' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'ConfigureSystemGuardLaunch' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_5_7 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard' -Name 'ConfigureSystemGuardLaunch' -Type DWord -Value 1 }

# ===================== 18.9.7 Device Installation =====================

function Test-CIS_18_9_7_2 {
    Test-CISRegistryValue -ControlId '18.9.7.2' -Title "Ensure 'Prevent automatic download of applications associated with device metadata' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_7_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata' -Name 'PreventDeviceMetadataFromNetwork' -Type DWord -Value 1 }

# ===================== 18.9.13 Early Launch Antimalware =====================

function Test-CIS_18_9_13_1 {
    Test-CISRegistryValue -ControlId '18.9.13.1' -Title "Ensure 'Boot-Start Driver Initialization Policy' is set to 'Enabled: Good, unknown and bad but critical'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Validator (New-CISValidatorExact 3) -ExpectedValue '3'
}
function Set-CIS_18_9_13_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -Name 'DriverLoadPolicy' -Type DWord -Value 3 }

# ===================== 18.9.17 File Share Shadow Copy Provider (CLFS) =====================
# Baja confianza: control nuevo, no confirme la clave de registro con certeza.

function Test-CIS_18_9_17_1 {
    New-CISResult -ControlId '18.9.17.1' -Title "Ensure 'Enable / disable CLFS logfile authentication' is set to 'Enabled'" -Status 'ManualReviewRequired' `
        -Notes 'Control nuevo; no se identifico con certeza la clave de registro. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_9_17_1 { Write-Warning '18.9.17.1: sin remediacion automatizada.' }

# ===================== 18.9.19 Group Policy =====================

function Test-CIS_18_9_19_2 {
    Test-CISRegistryValue -ControlId '18.9.19.2' -Title "Ensure 'Configure security policy processing: Do not apply during periodic background processing' is set to 'Enabled: FALSE'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoBackgroundPolicy' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (FALSE)'
}
function Set-CIS_18_9_19_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoBackgroundPolicy' -Type DWord -Value 0 }

function Test-CIS_18_9_19_3 {
    Test-CISRegistryValue -ControlId '18.9.19.3' -Title "Ensure 'Configure security policy processing: Process even if the Group Policy objects have not changed' is set to 'Enabled: TRUE'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoGPOListChanges' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (TRUE, procesa siempre)'
}
function Set-CIS_18_9_19_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{827D319E-6EAC-11D2-A4EA-00C04F79F83A}' -Name 'NoGPOListChanges' -Type DWord -Value 0 }

function Test-CIS_18_9_19_4 {
    Test-CISRegistryValue -ControlId '18.9.19.4' -Title "Ensure 'Continue experiences on this device' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableCdp' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_19_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableCdp' -Type DWord -Value 0 }

function Test-CIS_18_9_19_5 {
    Test-CISRegistryValue -ControlId '18.9.19.5' -Title "Ensure 'Turn off background refresh of Group Policy' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableBkGndGroupPolicy' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_19_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableBkGndGroupPolicy' -Type DWord -Value 0 }

# ===================== 18.9.20.1 Internet Communication settings =====================
# Bloque clasico, estable desde Windows Vista/Server 2008, documentado en
# todos los CIS Windows benchmarks desde hace mas de una decada.

function Test-CIS_18_9_20_1_1 {
    Test-CISRegistryValue -ControlId '18.9.20.1.1' -Title "Ensure 'Turn off downloading of print drivers over HTTP' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableWebPnPDownload' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_2 {
    Test-CISRegistryValue -ControlId '18.9.20.1.2' -Title "Ensure 'Turn off handwriting personalization data sharing' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC' -Name 'PreventHandwritingDataSharing' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_3 {
    Test-CISRegistryValue -ControlId '18.9.20.1.3' -Title "Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports' -Name 'PreventHandwritingErrorReports' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_4 {
    Test-CISRegistryValue -ControlId '18.9.20.1.4' -Title "Ensure 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' -Name 'ExitOnMSICW' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard' -Name 'ExitOnMSICW' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_5 {
    Test-CISRegistryValue -ControlId '18.9.20.1.5' -Title "Ensure 'Turn off Internet download for Web publishing and online ordering wizards' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoWebServices' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoWebServices' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_6 {
    Test-CISRegistryValue -ControlId '18.9.20.1.6' -Title "Ensure 'Turn off printing over HTTP' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_6 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'DisableHTTPPrinting' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_7 {
    Test-CISRegistryValue -ControlId '18.9.20.1.7' -Title "Ensure 'Turn off Registration if URL connection is referring to Microsoft.com' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' -Name 'NoRegistration' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_7 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control' -Name 'NoRegistration' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_8 {
    Test-CISRegistryValue -ControlId '18.9.20.1.8' -Title "Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_8 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_9 {
    Test-CISRegistryValue -ControlId '18.9.20.1.9' -Title "Ensure 'Turn off the ''Order Prints'' picture task' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoOnlinePrintsWizard' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_9 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoOnlinePrintsWizard' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_10 {
    Test-CISRegistryValue -ControlId '18.9.20.1.10' -Title "Ensure 'Turn off the ''Publish to Web'' task for files and folders' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoPublishingWizard' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_20_1_10 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoPublishingWizard' -Type DWord -Value 1 }

function Test-CIS_18_9_20_1_11 {
    Test-CISRegistryValue -ControlId '18.9.20.1.11' -Title "Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' -Name 'CEIP' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Enabled)'
}
function Set-CIS_18_9_20_1_11 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' -Name 'CEIP' -Type DWord -Value 2 }

function Test-CIS_18_9_20_1_12 {
    Test-CISRegistryValue -ControlId '18.9.20.1.12' -Title "Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (apagado)'
}
function Set-CIS_18_9_20_1_12 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows' -Name 'CEIPEnable' -Type DWord -Value 0 }

function Test-CIS_18_9_20_1_13 {
    Test-CISRegistryValue -ControlId '18.9.20.1.13' -Title "Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled = WER apagado)'
}
function Set-CIS_18_9_20_1_13 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name 'Disabled' -Type DWord -Value 1 }

# ===================== 18.9.23 Kerberos =====================
# Baja confianza: no confirme el nombre exacto de la clave.

function Test-CIS_18_9_23_1 {
    New-CISResult -ControlId '18.9.23.1' -Title "Ensure 'Support device authentication using certificate' is set to 'Enabled: Automatic'" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_9_23_1 { Write-Warning '18.9.23.1: sin remediacion automatizada.' }

# ===================== 18.9.24 Kernel DMA Protection =====================

function Test-CIS_18_9_24_1 {
    Test-CISRegistryValue -ControlId '18.9.24.1' -Title "Ensure 'Enumeration policy for external devices incompatible with Kernel DMA Protection' is set to 'Enabled: Block All'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name 'DeviceEnumerationPolicy' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Block All)'
}
function Set-CIS_18_9_24_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name 'DeviceEnumerationPolicy' -Type DWord -Value 0 }

# ===================== 18.9.26 Local Administrator Password Solution (Windows LAPS) =====================
# Confianza alta: esquema de Windows LAPS (2022+), muy documentado, mismo
# usado en CIS Windows Server 2022 v3+ y este benchmark de 2025.

function Test-CIS_18_9_26_1 {
    Test-CISRegistryValue -ControlId '18.9.26.1' -Title "Ensure 'Configure password backup directory' is set to 'Enabled: Active Directory' or 'Enabled: Azure Active Directory'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory' -Validator (New-CISValidatorOneOf @(1, 2)) -ExpectedValue '1 (AD) o 2 (Azure AD)'
}
function Set-CIS_18_9_26_1 { param([ValidateSet(1, 2)][int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'BackupDirectory' -Type DWord -Value $Value }

function Test-CIS_18_9_26_2 {
    Test-CISRegistryValue -ControlId '18.9.26.2' -Title "Ensure 'Do not allow password expiration time longer than required by policy' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordExpirationProtectionEnabled' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_26_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordExpirationProtectionEnabled' -Type DWord -Value 1 }

function Test-CIS_18_9_26_3 {
    Test-CISRegistryValue -ControlId '18.9.26.3' -Title "Ensure 'Enable password encryption' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'ADPasswordEncryptionEnabled' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_26_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'ADPasswordEncryptionEnabled' -Type DWord -Value 1 }

function Test-CIS_18_9_26_4 {
    Test-CISRegistryValue -ControlId '18.9.26.4' -Title "Ensure 'Password Settings: Password Complexity' is set to 'Enabled: Large letters + small letters + numbers + special characters' or 'Passphrase'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordComplexity' -Validator (New-CISValidatorMinValue 4) -ExpectedValue '>= 4'
}
function Set-CIS_18_9_26_4 { param([int]$Value = 4) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordComplexity' -Type DWord -Value $Value }

function Test-CIS_18_9_26_5 {
    Test-CISRegistryValue -ControlId '18.9.26.5' -Title "Ensure 'Password Settings: Password Length' is set to 'Enabled: 15 or more'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordLength' -Validator (New-CISValidatorMinValue 15) -ExpectedValue '>= 15'
}
function Set-CIS_18_9_26_5 { param([int]$Value = 15) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordLength' -Type DWord -Value $Value }

function Test-CIS_18_9_26_6 {
    Test-CISRegistryValue -ControlId '18.9.26.6' -Title "Ensure 'Password Settings: Password Age (Days)' is set to 'Enabled: 30 or fewer'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordAgeDays' -Validator (New-CISValidatorMaxValueNotZero 30) -ExpectedValue '1-30'
}
function Set-CIS_18_9_26_6 { param([int]$Value = 30) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PasswordAgeDays' -Type DWord -Value $Value }

function Test-CIS_18_9_26_7 {
    Test-CISRegistryValue -ControlId '18.9.26.7' -Title "Ensure 'Post-authentication actions: Grace period (hours)' is set to 'Enabled: 8 or fewer hours, but not 0'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PostAuthenticationResetDelay' -Validator (New-CISValidatorMaxValueNotZero 8) -ExpectedValue '1-8'
}
function Set-CIS_18_9_26_7 { param([int]$Value = 8) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PostAuthenticationResetDelay' -Type DWord -Value $Value }

function Test-CIS_18_9_26_8 {
    Test-CISRegistryValue -ControlId '18.9.26.8' -Title "Ensure 'Post-authentication actions: Actions' is set to 'Enabled: Reset the password and logoff the managed account' or higher" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PostAuthenticationActions' -Validator (New-CISValidatorMinValue 3) -ExpectedValue '>= 3'
}
function Set-CIS_18_9_26_8 { param([int]$Value = 3) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -Name 'PostAuthenticationActions' -Type DWord -Value $Value }

# ===================== 18.9.27 Local Security Authority =====================

function Test-CIS_18_9_27_1 {
    Test-CISRegistryValue -ControlId '18.9.27.1' -Title "Ensure 'Allow Custom SSPs and APs to be loaded into LSASS' is set to 'Disabled' (DC only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'AllowCustomSSPsAPs' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)' -Scope DC
}
function Set-CIS_18_9_27_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'AllowCustomSSPsAPs' -Type DWord -Value 0 -Scope DC }

function Test-CIS_18_9_27_2 {
    Test-CISRegistryValue -ControlId '18.9.27.2' -Title "Ensure 'Configures LSASS to run as a protected process' is set to 'Enabled: Enabled with UEFI Lock'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Enabled with UEFI Lock)'
}
function Set-CIS_18_9_27_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Type DWord -Value 2 }

# ===================== 18.9.28 Locale Services =====================

function Test-CIS_18_9_28_1 {
    Test-CISRegistryValue -ControlId '18.9.28.1' -Title "Ensure 'Disallow copying of user input methods to the system account for sign-in' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\International' -Name 'BlockUserInputMethodsForSignIn' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_28_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\International' -Name 'BlockUserInputMethodsForSignIn' -Type DWord -Value 1 }

# ===================== 18.9.29 Logon =====================

function Test-CIS_18_9_29_1 {
    Test-CISRegistryValue -ControlId '18.9.29.1' -Title "Ensure 'Block user from showing account details on sign-in' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'BlockUserFromShowingAccountDetailsOnSignin' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_29_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'BlockUserFromShowingAccountDetailsOnSignin' -Type DWord -Value 1 }

function Test-CIS_18_9_29_2 {
    Test-CISRegistryValue -ControlId '18.9.29.2' -Title "Ensure 'Do not display network selection UI' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_29_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontDisplayNetworkSelectionUI' -Type DWord -Value 1 }

function Test-CIS_18_9_29_3 {
    Test-CISRegistryValue -ControlId '18.9.29.3' -Title "Ensure 'Do not enumerate connected users on domain-joined computers' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontEnumerateConnectedUsers' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_29_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DontEnumerateConnectedUsers' -Type DWord -Value 1 }

function Test-CIS_18_9_29_4 {
    Test-CISRegistryValue -ControlId '18.9.29.4' -Title "Ensure 'Enumerate local users on domain-joined computers' is set to 'Disabled' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)' -Scope MS
}
function Set-CIS_18_9_29_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnumerateLocalUsers' -Type DWord -Value 0 -Scope MS }

function Test-CIS_18_9_29_5 {
    Test-CISRegistryValue -ControlId '18.9.29.5' -Title "Ensure 'Turn off app notifications on the lock screen' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLockScreenAppNotifications' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_29_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLockScreenAppNotifications' -Type DWord -Value 1 }

function Test-CIS_18_9_29_6 {
    Test-CISRegistryValue -ControlId '18.9.29.6' -Title "Ensure 'Turn on convenience PIN sign-in' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowDomainPINLogon' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_29_6 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowDomainPINLogon' -Type DWord -Value 0 }

# ===================== 18.9.31 Net Logon =====================
# Baja confianza: no confirme la clave de registro con certeza.

function Test-CIS_18_9_31_1_1 {
    New-CISResult -ControlId '18.9.31.1.1' -Title "Ensure 'Block NetBIOS-based discovery for domain controller location' is set to 'Enabled'" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_9_31_1_1 { Write-Warning '18.9.31.1.1: sin remediacion automatizada.' }

# ===================== 18.9.33 OS Policies =====================

function Test-CIS_18_9_33_1 {
    Test-CISRegistryValue -ControlId '18.9.33.1' -Title "Ensure 'Allow Clipboard synchronization across devices' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowCrossDeviceClipboard' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_33_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'AllowCrossDeviceClipboard' -Type DWord -Value 0 }

function Test-CIS_18_9_33_2 {
    Test-CISRegistryValue -ControlId '18.9.33.2' -Title "Ensure 'Allow upload of User Activities' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_33_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Type DWord -Value 0 }

# ===================== 18.9.35 Power Management =====================
# Confianza media: GUIDs de power settings estables desde Server 2016, pero
# se recomienda doble chequeo (powercfg /q) antes de confiar ciegamente.

function Test-CIS_18_9_35_6_1 {
    Test-CISRegistryValue -ControlId '18.9.35.6.1' -Title "Ensure 'Allow network connectivity during connected-standby (on battery)' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' -Name 'DCSettingIndex' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_35_6_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' -Name 'DCSettingIndex' -Type DWord -Value 0 }

function Test-CIS_18_9_35_6_2 {
    Test-CISRegistryValue -ControlId '18.9.35.6.2' -Title "Ensure 'Allow network connectivity during connected-standby (plugged in)' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' -Name 'ACSettingIndex' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_35_6_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9' -Name 'ACSettingIndex' -Type DWord -Value 0 }

function Test-CIS_18_9_35_6_3 {
    Test-CISRegistryValue -ControlId '18.9.35.6.3' -Title "Ensure 'Require a password when a computer wakes (on battery)' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_35_6_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'DCSettingIndex' -Type DWord -Value 1 }

function Test-CIS_18_9_35_6_4 {
    Test-CISRegistryValue -ControlId '18.9.35.6.4' -Title "Ensure 'Require a password when a computer wakes (plugged in)' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_35_6_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Name 'ACSettingIndex' -Type DWord -Value 1 }

# ===================== 18.9.37 Remote Assistance =====================

function Test-CIS_18_9_37_1 {
    Test-CISRegistryValue -ControlId '18.9.37.1' -Title "Ensure 'Configure Offer Remote Assistance' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowUnsolicited' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_37_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowUnsolicited' -Type DWord -Value 0 }

function Test-CIS_18_9_37_2 {
    Test-CISRegistryValue -ControlId '18.9.37.2' -Title "Ensure 'Configure Solicited Remote Assistance' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_37_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fAllowToGetHelp' -Type DWord -Value 0 }

# ===================== 18.9.38 RPC =====================

function Test-CIS_18_9_38_1 {
    Test-CISRegistryValue -ControlId '18.9.38.1' -Title "Ensure 'Enable RPC Endpoint Mapper Client Authentication' is set to 'Enabled' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'EnableAuthEpResolution' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)' -Scope MS
}
function Set-CIS_18_9_38_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'EnableAuthEpResolution' -Type DWord -Value 1 -Scope MS }

function Test-CIS_18_9_38_2 {
    Test-CISRegistryValue -ControlId '18.9.38.2' -Title "Ensure 'Restrict Unauthenticated RPC clients' is set to 'Enabled: Authenticated' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'RestrictRemoteClients' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Authenticated)' -Scope MS
}
function Set-CIS_18_9_38_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -Name 'RestrictRemoteClients' -Type DWord -Value 1 -Scope MS }

# ===================== 18.9.41 Security Account Manager =====================
# Baja confianza: 3 controles nuevos (2022+ hardening ROCA/SAM RPC), no
# confirme las claves de registro con certeza.

function Test-CIS_18_9_41_1 {
    if ((Get-CISServerRole) -ne 'DC') { return New-CISResult -ControlId '18.9.41.1' -Title "Ensure 'Configure validation of ROCA-vulnerable WHfB keys during authentication' is set to 'Enabled: Block' (DC only)" -Status 'NotApplicable' -Notes 'Control (DC only).' }
    New-CISResult -ControlId '18.9.41.1' -Title "Ensure 'Configure validation of ROCA-vulnerable WHfB keys during authentication' is set to 'Enabled: Block' (DC only)" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_9_41_1 { Write-Warning '18.9.41.1: sin remediacion automatizada.' }

function Test-CIS_18_9_41_2 {
    if ((Get-CISServerRole) -ne 'DC') { return New-CISResult -ControlId '18.9.41.2' -Title "Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Allow strong encryption change password RPC method only' (DC only)" -Status 'NotApplicable' -Notes 'Control (DC only).' }
    New-CISResult -ControlId '18.9.41.2' -Title "Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Allow strong encryption change password RPC method only' (DC only)" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_9_41_2 { Write-Warning '18.9.41.2: sin remediacion automatizada.' }

function Test-CIS_18_9_41_3 {
    if ((Get-CISServerRole) -ne 'MS') { return New-CISResult -ControlId '18.9.41.3' -Title "Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Block all change password RPC methods' (MS only)" -Status 'NotApplicable' -Notes 'Control (MS only).' }
    New-CISResult -ControlId '18.9.41.3' -Title "Ensure 'Configure SAM change password RPC methods policy' is set to 'Enabled: Block all change password RPC methods' (MS only)" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_9_41_3 { Write-Warning '18.9.41.3: sin remediacion automatizada.' }

# ===================== 18.9.49 Troubleshooting and Diagnostics =====================

function Test-CIS_18_9_49_5_1 {
    Test-CISRegistryValue -ControlId '18.9.49.5.1' -Title "Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' -Name 'DisableQueryRemoteServer' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_9_49_5_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy' -Name 'DisableQueryRemoteServer' -Type DWord -Value 0 }

function Test-CIS_18_9_49_11_1 {
    Test-CISRegistryValue -ControlId '18.9.49.11.1' -Title "Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisablePerfTrack' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (PerfTrack deshabilitado)'
}
function Set-CIS_18_9_49_11_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisablePerfTrack' -Type DWord -Value 1 }

# ===================== 18.9.51 User Profiles =====================

function Test-CIS_18_9_51_1 {
    Test-CISRegistryValue -ControlId '18.9.51.1' -Title "Ensure 'Turn off the advertising ID' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_51_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' -Name 'DisabledByGroupPolicy' -Type DWord -Value 1 }

# ===================== 18.9.53 Windows Time Service =====================

function Test-CIS_18_9_53_1_1 {
    Test-CISRegistryValue -ControlId '18.9.53.1.1' -Title "Ensure 'Enable Windows NTP Client' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient' -Name 'Enabled' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_9_53_1_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient' -Name 'Enabled' -Type DWord -Value 1 }

function Test-CIS_18_9_53_1_2 {
    Test-CISRegistryValue -ControlId '18.9.53.1.2' -Title "Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer' -Name 'Enabled' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)' -Scope MS
}
function Set-CIS_18_9_53_1_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpServer' -Name 'Enabled' -Type DWord -Value 0 -Scope MS }
