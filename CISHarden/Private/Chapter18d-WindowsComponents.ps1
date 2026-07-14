# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 18.10
# Windows Components (114 controles, el bloque mas grande del benchmark).
# Fuente: cis2025.md paginas 816-1137.
#
# ~103 controles via registro (RegistryEngine.ps1): bloques clasicos muy
# documentados desde hace 10-20 anios (Remote Desktop Services/Terminal
# Services, Windows Installer, Winlogon, Event Log, AutoPlay, WinRM, Windows
# Update, RSS, Software Protection Platform) y bloques de Microsoft Defender
# Antivirus ya bien establecidos (MAPS, Attack Surface Reduction, Network
# Protection, Real-time Protection classicas, exclusiones/PUA).
#
# ~11 controles quedan ManualReviewRequired: features de Microsoft Defender
# 2023-2025 (EDR block mode, Brute-Force Protection, Remote Encryption
# Protection/anti-ransomware, "Convert warn verdict to block") y un par mas
# donde no confirme la clave/seccion con certeza suficiente. No se inventan
# (regla 3 del system prompt).

# ===================== 18.10.4 App Package Deployment =====================

function Test-CIS_18_10_4_1 {
    Test-CISRegistryValue -ControlId '18.10.4.1' -Title "Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsSyncWithDevices' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Force Deny)'
}
function Set-CIS_18_10_4_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -Name 'LetAppsSyncWithDevices' -Type DWord -Value 2 }

function Test-CIS_18_10_4_2 {
    Test-CISRegistryValue -ControlId '18.10.4.2' -Title "Ensure 'Not allow per-user unsigned packages to install by default (requires explicitly allow per install)' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx' -Name 'AllowAllTrustedApps' -Validator (New-CISValidatorExact 0) -ExpectedValue '0'
}
function Set-CIS_18_10_4_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx' -Name 'AllowAllTrustedApps' -Type DWord -Value 0 }

# ===================== 18.10.6 App runtime =====================

function Test-CIS_18_10_6_1 {
    Test-CISRegistryValue -ControlId '18.10.6.1' -Title "Ensure 'Allow Microsoft accounts to be optional' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\MicrosoftAccount' -Name 'MSAOptional' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_6_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\MicrosoftAccount' -Name 'MSAOptional' -Type DWord -Value 1 }

# ===================== 18.10.8 AutoPlay Policies =====================

function Test-CIS_18_10_8_1 {
    Test-CISRegistryValue -ControlId '18.10.8.1' -Title "Ensure 'Disallow Autoplay for non-volume devices' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_8_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutoplayfornonVolume' -Type DWord -Value 1 }

function Test-CIS_18_10_8_2 {
    Test-CISRegistryValue -ControlId '18.10.8.2' -Title "Ensure 'Set the default behavior for AutoRun' is set to 'Enabled: Do not execute any autorun commands'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutorun' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_8_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoAutorun' -Type DWord -Value 1 }

function Test-CIS_18_10_8_3 {
    Test-CISRegistryValue -ControlId '18.10.8.3' -Title "Ensure 'Turn off Autoplay' is set to 'Enabled: All drives'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDriveTypeAutoRun' -Validator (New-CISValidatorExact 255) -ExpectedValue '255 (All drives)'
}
function Set-CIS_18_10_8_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDriveTypeAutoRun' -Type DWord -Value 255 }

# ===================== 18.10.9 Biometrics =====================

function Test-CIS_18_10_9_1_1 {
    Test-CISRegistryValue -ControlId '18.10.9.1.1' -Title "Ensure 'Configure enhanced anti-spoofing' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_9_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -Name 'EnhancedAntiSpoofing' -Type DWord -Value 1 }

# ===================== 18.10.11 Camera =====================

function Test-CIS_18_10_11_1 {
    Test-CISRegistryValue -ControlId '18.10.11.1' -Title "Ensure 'Allow Use of Camera' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -Name 'AllowCamera' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_11_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Camera' -Name 'AllowCamera' -Type DWord -Value 0 }

# ===================== 18.10.13 Cloud Content =====================

function Test-CIS_18_10_13_1 {
    Test-CISRegistryValue -ControlId '18.10.13.1' -Title "Ensure 'Turn off cloud consumer account state content' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableConsumerAccountStateContent' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_13_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableConsumerAccountStateContent' -Type DWord -Value 1 }

function Test-CIS_18_10_13_2 {
    Test-CISRegistryValue -ControlId '18.10.13.2' -Title "Ensure 'Turn off cloud optimized content' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableCloudOptimizedContent' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_13_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableCloudOptimizedContent' -Type DWord -Value 1 }

# ===================== 18.10.14 Connect =====================

function Test-CIS_18_10_14_1 {
    Test-CISRegistryValue -ControlId '18.10.14.1' -Title "Ensure 'Require pin for pairing' is set to 'Enabled: First Time' OR 'Enabled: Always'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect' -Name 'RequirePinForPairing' -Validator (New-CISValidatorOneOf @(1, 2)) -ExpectedValue '1 (First Time) o 2 (Always)'
}
function Set-CIS_18_10_14_1 { param([ValidateSet(1, 2)][int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect' -Name 'RequirePinForPairing' -Type DWord -Value $Value }

# ===================== 18.10.15 Credential User Interface =====================

function Test-CIS_18_10_15_1 {
    Test-CISRegistryValue -ControlId '18.10.15.1' -Title "Ensure 'Do not display the password reveal button' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_15_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'DisablePasswordReveal' -Type DWord -Value 1 }

function Test-CIS_18_10_15_2 {
    Test-CISRegistryValue -ControlId '18.10.15.2' -Title "Ensure 'Enumerate administrator accounts on elevation' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'EnumerateAdministrators' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_15_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI' -Name 'EnumerateAdministrators' -Type DWord -Value 0 }

# ===================== 18.10.16 Data Collection and Preview Builds =====================

function Test-CIS_18_10_16_1 {
    Test-CISRegistryValue -ControlId '18.10.16.1' -Title "Ensure 'Allow Diagnostic Data' is set to 'Enabled: Diagnostic data off (not recommended)' or 'Enabled: Send required diagnostic data'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Validator (New-CISValidatorOneOf @(0, 1)) -ExpectedValue '0 o 1'
}
function Set-CIS_18_10_16_1 { param([ValidateSet(0, 1)][int]$Value = 1) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value $Value }

function Test-CIS_18_10_16_2 {
    Test-CISRegistryValue -ControlId '18.10.16.2' -Title "Ensure 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service' is set to 'Enabled: Disable Authenticated Proxy usage'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DisableEnterpriseAuthProxy' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_16_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DisableEnterpriseAuthProxy' -Type DWord -Value 1 }

function Test-CIS_18_10_16_3 {
    Test-CISRegistryValue -ControlId '18.10.16.3' -Title "Ensure 'Do not show feedback notifications' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_16_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'DoNotShowFeedbackNotifications' -Type DWord -Value 1 }

function Test-CIS_18_10_16_4 { New-CISResult -ControlId '18.10.16.4' -Title "Ensure 'Enable OneSettings Auditing' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Control nuevo; no se identifico con certeza la clave de registro. Verificar manualmente antes de automatizar.' }
function Set-CIS_18_10_16_4 { Write-Warning '18.10.16.4: sin remediacion automatizada.' }

function Test-CIS_18_10_16_5 {
    Test-CISRegistryValue -ControlId '18.10.16.5' -Title "Ensure 'Limit Diagnostic Log Collection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitDiagnosticLogCollection' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_16_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitDiagnosticLogCollection' -Type DWord -Value 1 }

function Test-CIS_18_10_16_6 {
    Test-CISRegistryValue -ControlId '18.10.16.6' -Title "Ensure 'Limit Dump Collection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitDumpCollection' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_16_6 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'LimitDumpCollection' -Type DWord -Value 1 }

# ===================== 18.10.18 App Installer =====================
# Confianza media: ADMX relativamente nuevo (2023+) pero con nombres de
# clave que siguen la convencion estandar (nombre de politica -> nombre de
# valor), igual se recomienda doble chequeo en el server de lab.

function Test-CIS_18_10_18_1 {
    Test-CISRegistryValue -ControlId '18.10.18.1' -Title "Ensure 'Enable App Installer' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableAppInstaller' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableAppInstaller' -Type DWord -Value 0 }

function Test-CIS_18_10_18_2 {
    Test-CISRegistryValue -ControlId '18.10.18.2' -Title "Ensure 'Enable App Installer Experimental Features' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableExperimentalFeatures' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableExperimentalFeatures' -Type DWord -Value 0 }

function Test-CIS_18_10_18_3 {
    Test-CISRegistryValue -ControlId '18.10.18.3' -Title "Ensure 'Enable App Installer Hash Override' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableHashOverride' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableHashOverride' -Type DWord -Value 0 }

function Test-CIS_18_10_18_4 {
    Test-CISRegistryValue -ControlId '18.10.18.4' -Title "Ensure 'Enable App Installer Local Archive Malware Scan Override' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableLocalArchiveMalwareScanOverride' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableLocalArchiveMalwareScanOverride' -Type DWord -Value 0 }

function Test-CIS_18_10_18_5 {
    Test-CISRegistryValue -ControlId '18.10.18.5' -Title "Ensure 'Enable App Installer ms-appinstaller protocol' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableMSAppInstallerProtocol' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableMSAppInstallerProtocol' -Type DWord -Value 0 }

function Test-CIS_18_10_18_6 {
    Test-CISRegistryValue -ControlId '18.10.18.6' -Title "Ensure 'Enable App Installer Microsoft Store Source Certificate Validation Bypass' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableMicrosoftStoreSourceCertificateValidationBypass' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_6 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableMicrosoftStoreSourceCertificateValidationBypass' -Type DWord -Value 0 }

function Test-CIS_18_10_18_7 {
    Test-CISRegistryValue -ControlId '18.10.18.7' -Title "Ensure 'Enable Windows Package Manager command line interfaces' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableWindowsPackageManagerCommandLineInterfaces' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_18_7 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller' -Name 'EnableWindowsPackageManagerCommandLineInterfaces' -Type DWord -Value 0 }

# ===================== 18.10.26 Event Log Service =====================
# Clasico, estable desde Windows Vista/Server 2008.

function Test-CIS_18_10_26_1_1 {
    Test-CISRegistryValue -ControlId '18.10.26.1.1' -Title "Ensure 'Application: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'Retention' -Validator (New-CISValidatorExact '0') -ExpectedValue "'0' (Disabled)"
}
function Set-CIS_18_10_26_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'Retention' -Type String -Value '0' }

function Test-CIS_18_10_26_1_2 {
    Test-CISRegistryValue -ControlId '18.10.26.1.2' -Title "Ensure 'Application: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Validator (New-CISValidatorMinValue 32768) -ExpectedValue '>= 32768'
}
function Set-CIS_18_10_26_1_2 { param([int]$Value = 32768) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -Name 'MaxSize' -Type DWord -Value $Value }

function Test-CIS_18_10_26_2_1 {
    Test-CISRegistryValue -ControlId '18.10.26.2.1' -Title "Ensure 'Security: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Validator (New-CISValidatorExact '0') -ExpectedValue "'0' (Disabled)"
}
function Set-CIS_18_10_26_2_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'Retention' -Type String -Value '0' }

function Test-CIS_18_10_26_2_2 {
    Test-CISRegistryValue -ControlId '18.10.26.2.2' -Title "Ensure 'Security: Specify the maximum log file size (KB)' is set to 'Enabled: 196,608 or greater'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Validator (New-CISValidatorMinValue 196608) -ExpectedValue '>= 196608'
}
function Set-CIS_18_10_26_2_2 { param([int]$Value = 196608) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' -Name 'MaxSize' -Type DWord -Value $Value }

function Test-CIS_18_10_26_3_1 {
    Test-CISRegistryValue -ControlId '18.10.26.3.1' -Title "Ensure 'Setup: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' -Name 'Retention' -Validator (New-CISValidatorExact '0') -ExpectedValue "'0' (Disabled)"
}
function Set-CIS_18_10_26_3_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' -Name 'Retention' -Type String -Value '0' }

function Test-CIS_18_10_26_3_2 {
    Test-CISRegistryValue -ControlId '18.10.26.3.2' -Title "Ensure 'Setup: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' -Name 'MaxSize' -Validator (New-CISValidatorMinValue 32768) -ExpectedValue '>= 32768'
}
function Set-CIS_18_10_26_3_2 { param([int]$Value = 32768) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup' -Name 'MaxSize' -Type DWord -Value $Value }

function Test-CIS_18_10_26_4_1 {
    Test-CISRegistryValue -ControlId '18.10.26.4.1' -Title "Ensure 'System: Control Event Log behavior when the log file reaches its maximum size' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'Retention' -Validator (New-CISValidatorExact '0') -ExpectedValue "'0' (Disabled)"
}
function Set-CIS_18_10_26_4_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'Retention' -Type String -Value '0' }

function Test-CIS_18_10_26_4_2 {
    Test-CISRegistryValue -ControlId '18.10.26.4.2' -Title "Ensure 'System: Specify the maximum log file size (KB)' is set to 'Enabled: 32,768 or greater'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Validator (New-CISValidatorMinValue 32768) -ExpectedValue '>= 32768'
}
function Set-CIS_18_10_26_4_2 { param([int]$Value = 32768) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System' -Name 'MaxSize' -Type DWord -Value $Value }

# ===================== 18.10.29 File Explorer =====================

function Test-CIS_18_10_29_2 { New-CISResult -ControlId '18.10.29.2' -Title "Ensure 'Do not apply the Mark of the Web tag to files copied from insecure sources' is set to 'Disabled'" -Status 'ManualReviewRequired' -Notes 'Control nuevo, distinto del clasico SaveZoneInformation; no se identifico con certeza la clave de registro. Verificar manualmente antes de automatizar.' }
function Set-CIS_18_10_29_2 { Write-Warning '18.10.29.2: sin remediacion automatizada.' }

function Test-CIS_18_10_29_3 {
    Test-CISRegistryValue -ControlId '18.10.29.3' -Title "Ensure 'Turn off Data Execution Prevention for Explorer' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled = DEP activo)'
}
function Set-CIS_18_10_29_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoDataExecutionPrevention' -Type DWord -Value 0 }

function Test-CIS_18_10_29_4 {
    Test-CISRegistryValue -ControlId '18.10.29.4' -Title "Ensure 'Turn off heap termination on corruption' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoHeapTerminationOnCorruption' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_29_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'NoHeapTerminationOnCorruption' -Type DWord -Value 0 }

function Test-CIS_18_10_29_5 {
    Test-CISRegistryValue -ControlId '18.10.29.5' -Title "Ensure 'Turn off shell protocol protected mode' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_29_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name 'PreXPSP2ShellProtocolBehavior' -Type DWord -Value 0 }

# ===================== 18.10.36 Location and Sensors =====================

function Test-CIS_18_10_36_1 {
    Test-CISRegistryValue -ControlId '18.10.36.1' -Title "Ensure 'Turn off location' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_36_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors' -Name 'DisableLocation' -Type DWord -Value 1 }

# ===================== 18.10.40 Messaging =====================

function Test-CIS_18_10_40_1 {
    Test-CISRegistryValue -ControlId '18.10.40.1' -Title "Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging' -Name 'AllowMessageSync' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_40_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging' -Name 'AllowMessageSync' -Type DWord -Value 0 }

# ===================== 18.10.41 Microsoft Account =====================

function Test-CIS_18_10_41_1 {
    Test-CISRegistryValue -ControlId '18.10.41.1' -Title "Ensure 'Block all consumer Microsoft account user authentication' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\MicrosoftAccount' -Name 'DisableUserAuth' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_41_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\MicrosoftAccount' -Name 'DisableUserAuth' -Type DWord -Value 1 }

# ===================== 18.10.42 Microsoft Defender Antivirus =====================

function Test-CIS_18_10_42_4_1 { New-CISResult -ControlId '18.10.42.4.1' -Title "Ensure 'Enable EDR in block mode' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Feature de Microsoft Defender for Endpoint (2023+); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_10_42_4_1 { Write-Warning '18.10.42.4.1: sin remediacion automatizada.' }

function Test-CIS_18_10_42_5_1 {
    Test-CISRegistryValue -ControlId '18.10.42.5.1' -Title "Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'LocalSettingOverrideSpynetReporting' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_42_5_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'LocalSettingOverrideSpynetReporting' -Type DWord -Value 0 }

function Test-CIS_18_10_42_5_2 {
    Test-CISRegistryValue -ControlId '18.10.42.5.2' -Title "Ensure 'Join Microsoft MAPS' is set to 'Enabled: Advanced'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Advanced)'
}
function Set-CIS_18_10_42_5_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name 'SpynetReporting' -Type DWord -Value 2 }

function Test-CIS_18_10_42_6_1_1 {
    Test-CISRegistryValue -ControlId '18.10.42.6.1.1' -Title "Ensure 'Configure Attack Surface Reduction rules' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' -Name 'ExploitGuard_ASR_Rules' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_42_6_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR' -Name 'ExploitGuard_ASR_Rules' -Type DWord -Value 1 }

function Test-CIS_18_10_42_6_1_2 {
    Test-CISRegistryValue -ControlId '18.10.42.6.1.2' -Title "Ensure 'Configure Attack Surface Reduction rules: Set the state for each ASR rule' is configured" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' -Name 'Rules' -Validator { param($v) $null -ne $v } -ExpectedValue 'Configurado (al menos una regla ASR definida)'
}
function Set-CIS_18_10_42_6_1_2 { Write-Warning '18.10.42.6.1.2 requiere configurar cada GUID de regla ASR individualmente bajo HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules -- no se aplica un valor generico automatico.' }

function Test-CIS_18_10_42_6_3_1 {
    Test-CISRegistryValue -ControlId '18.10.42.6.3.1' -Title "Ensure 'Prevent users and apps from accessing dangerous websites' is set to 'Enabled: Block'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' -Name 'EnableNetworkProtection' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Block)'
}
function Set-CIS_18_10_42_6_3_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection' -Name 'EnableNetworkProtection' -Type DWord -Value 1 }

function Test-CIS_18_10_42_7_1 {
    Test-CISRegistryValue -ControlId '18.10.42.7.1' -Title "Ensure 'Enable file hash computation feature' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' -Name 'EnableFileHashComputation' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_42_7_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine' -Name 'EnableFileHashComputation' -Type DWord -Value 1 }

function Test-CIS_18_10_42_8_1 { New-CISResult -ControlId '18.10.42.8.1' -Title "Ensure 'Convert warn verdict to block' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Feature reciente de Microsoft Defender; no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_10_42_8_1 { Write-Warning '18.10.42.8.1: sin remediacion automatizada.' }

function Test-CIS_18_10_42_10_1 { New-CISResult -ControlId '18.10.42.10.1' -Title "Ensure 'Configure real-time protection and Security Intelligence Updates during OOBE' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Control especifico de OOBE; no se identifico con certeza la clave de registro distinta de la proteccion en tiempo real clasica. Verificar manualmente.' }
function Set-CIS_18_10_42_10_1 { Write-Warning '18.10.42.10.1: sin remediacion automatizada.' }

function Test-CIS_18_10_42_10_2 {
    Test-CISRegistryValue -ControlId '18.10.42.10.2' -Title "Ensure 'Scan all downloaded files and attachments' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableIOAVProtection' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled)'
}
function Set-CIS_18_10_42_10_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableIOAVProtection' -Type DWord -Value 0 }

function Test-CIS_18_10_42_10_3 {
    Test-CISRegistryValue -ControlId '18.10.42.10.3' -Title "Ensure 'Turn off real-time protection' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled = proteccion activa)'
}
function Set-CIS_18_10_42_10_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableRealtimeMonitoring' -Type DWord -Value 0 }

function Test-CIS_18_10_42_10_4 {
    Test-CISRegistryValue -ControlId '18.10.42.10.4' -Title "Ensure 'Turn on behavior monitoring' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableBehaviorMonitoring' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled)'
}
function Set-CIS_18_10_42_10_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableBehaviorMonitoring' -Type DWord -Value 0 }

function Test-CIS_18_10_42_10_5 {
    Test-CISRegistryValue -ControlId '18.10.42.10.5' -Title "Ensure 'Turn on script scanning' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableScriptScanning' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled)'
}
function Set-CIS_18_10_42_10_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' -Name 'DisableScriptScanning' -Type DWord -Value 0 }

# 18.10.42.11.1.x - Brute-Force / Remote Encryption Protection: features
# antiransomware de Defender 2024-2025, sin documentacion suficiente.
function Test-CIS_18_10_42_11_1_1_1 { New-CISResult -ControlId '18.10.42.11.1.1.1' -Title "Ensure 'Configure Brute-Force Protection aggressiveness' is set to 'Enabled: Medium' or higher" -Status 'ManualReviewRequired' -Notes 'Feature nueva de Defender (2024-2025, Brute-Force Protection); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_10_42_11_1_1_1 { Write-Warning '18.10.42.11.1.1.1: sin remediacion automatizada.' }
function Test-CIS_18_10_42_11_1_1_2 { New-CISResult -ControlId '18.10.42.11.1.1.2' -Title "Ensure 'Configure Remote Encryption Protection Mode' is set to 'Enabled: Audit' or higher" -Status 'ManualReviewRequired' -Notes 'Feature nueva de Defender (2024-2025, anti-ransomware); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_10_42_11_1_1_2 { Write-Warning '18.10.42.11.1.1.2: sin remediacion automatizada.' }
function Test-CIS_18_10_42_11_1_2_1 { New-CISResult -ControlId '18.10.42.11.1.2.1' -Title "Ensure 'Configure how aggressively Remote Encryption Protection blocks threats' is set to 'Enabled: Medium' or higher" -Status 'ManualReviewRequired' -Notes 'Feature nueva de Defender (2024-2025, anti-ransomware); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_10_42_11_1_2_1 { Write-Warning '18.10.42.11.1.2.1: sin remediacion automatizada.' }

function Test-CIS_18_10_42_12_1 {
    Test-CISRegistryValue -ControlId '18.10.42.12.1' -Title "Ensure 'Configure Watson events' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' -Name 'DisableGenericRePorts' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Disabled)'
}
function Set-CIS_18_10_42_12_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' -Name 'DisableGenericRePorts' -Type DWord -Value 1 }

function Test-CIS_18_10_42_13_1 { New-CISResult -ControlId '18.10.42.13.1' -Title "Ensure 'Scan excluded files and directories during quick scans' is set to 'Enabled: 1'" -Status 'ManualReviewRequired' -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.' }
function Set-CIS_18_10_42_13_1 { Write-Warning '18.10.42.13.1: sin remediacion automatizada.' }

function Test-CIS_18_10_42_13_2 {
    Test-CISRegistryValue -ControlId '18.10.42.13.2' -Title "Ensure 'Scan packed executables' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisablePackedExeScanning' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled)'
}
function Set-CIS_18_10_42_13_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisablePackedExeScanning' -Type DWord -Value 0 }

function Test-CIS_18_10_42_13_3 {
    Test-CISRegistryValue -ControlId '18.10.42.13.3' -Title "Ensure 'Scan removable drives' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisableRemovableDriveScanning' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled)'
}
function Set-CIS_18_10_42_13_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisableRemovableDriveScanning' -Type DWord -Value 0 }

function Test-CIS_18_10_42_13_4 { New-CISResult -ControlId '18.10.42.13.4' -Title "Ensure 'Trigger a quick scan after X days without any scans' is set to 'Enabled: 7'" -Status 'ManualReviewRequired' -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.' }
function Set-CIS_18_10_42_13_4 { Write-Warning '18.10.42.13.4: sin remediacion automatizada.' }

function Test-CIS_18_10_42_13_5 {
    Test-CISRegistryValue -ControlId '18.10.42.13.5' -Title "Ensure 'Turn on e-mail scanning' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisableEmailScanning' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled)'
}
function Set-CIS_18_10_42_13_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -Name 'DisableEmailScanning' -Type DWord -Value 0 }

function Test-CIS_18_10_42_16 {
    Test-CISRegistryValue -ControlId '18.10.42.16' -Title "Ensure 'Configure detection for potentially unwanted applications' is set to 'Enabled: Block'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'PUAProtection' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Block)'
}
function Set-CIS_18_10_42_16 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name 'PUAProtection' -Type DWord -Value 1 }

function Test-CIS_18_10_42_17 {
    Test-CISRegistryValue -ControlId '18.10.42.17' -Title "Ensure 'Control whether exclusions are visible to local users' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Configuration' -Name 'HideExclusionsFromLocalAdmins' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_42_17 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Configuration' -Name 'HideExclusionsFromLocalAdmins' -Type DWord -Value 1 }

# ===================== 18.10.56 Push To Install =====================

function Test-CIS_18_10_56_1 {
    Test-CISRegistryValue -ControlId '18.10.56.1' -Title "Ensure 'Turn off Push To Install service' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall' -Name 'DisablePushToInstall' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_56_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PushToInstall' -Name 'DisablePushToInstall' -Type DWord -Value 1 }

# ===================== 18.10.57 Remote Desktop Services =====================
# Clasico, estable desde Windows Server 2003/2008 (Terminal Services).

function Test-CIS_18_10_57_2_2 {
    Test-CISRegistryValue -ControlId '18.10.57.2.2' -Title "Ensure 'Do not allow passwords to be saved' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_2_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DisablePasswordSaving' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_2_1 {
    Test-CISRegistryValue -ControlId '18.10.57.3.2.1' -Title "Ensure 'Restrict Remote Desktop Services users to a single Remote Desktop Services session' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fSingleSessionPerUser' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_2_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fSingleSessionPerUser' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_3_1 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.1' -Title "Ensure 'Allow UI Automation redirection' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEnableUiaRedirection' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_57_3_3_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEnableUiaRedirection' -Type DWord -Value 0 }

function Test-CIS_18_10_57_3_3_2 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.2' -Title "Ensure 'Do not allow COM port redirection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCcm' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_3_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCcm' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_3_3 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.3' -Title "Ensure 'Do not allow drive redirection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_3_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableCdm' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_3_4 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.4' -Title "Ensure 'Do not allow location redirection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableLocationRedir' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_3_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableLocationRedir' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_3_5 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.5' -Title "Ensure 'Do not allow LPT port redirection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableLPT' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_3_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableLPT' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_3_6 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.6' -Title "Ensure 'Do not allow supported Plug and Play device redirection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisablePNPRedir' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_3_6 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisablePNPRedir' -Type DWord -Value 1 }

# Confianza media: adiciones mas recientes al mismo bloque clasico de TS.
function Test-CIS_18_10_57_3_3_7 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.7' -Title "Ensure 'Do not allow WebAuthn redirection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableWebAuthnRedirection' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_3_7 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableWebAuthnRedirection' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_3_8 {
    Test-CISRegistryValue -ControlId '18.10.57.3.3.8' -Title "Ensure 'Restrict clipboard transfer from server to client' is set to 'Enabled: Disable clipboard transfers from server to client'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'RestrictClipboardTransfer' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Disable)'
}
function Set-CIS_18_10_57_3_3_8 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'RestrictClipboardTransfer' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_9_1 {
    Test-CISRegistryValue -ControlId '18.10.57.3.9.1' -Title "Ensure 'Always prompt for password upon connection' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_9_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fPromptForPassword' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_9_2 {
    Test-CISRegistryValue -ControlId '18.10.57.3.9.2' -Title "Ensure 'Require secure RPC communication' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_9_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_9_3 {
    Test-CISRegistryValue -ControlId '18.10.57.3.9.3' -Title "Ensure 'Require use of specific security layer for remote (RDP) connections' is set to 'Enabled: SSL'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'SecurityLayer' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (SSL)'
}
function Set-CIS_18_10_57_3_9_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'SecurityLayer' -Type DWord -Value 2 }

function Test-CIS_18_10_57_3_9_4 {
    Test-CISRegistryValue -ControlId '18.10.57.3.9.4' -Title "Ensure 'Require user authentication for remote connections by using Network Level Authentication' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'UserAuthentication' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_57_3_9_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'UserAuthentication' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_9_5 {
    Test-CISRegistryValue -ControlId '18.10.57.3.9.5' -Title "Ensure 'Set client connection encryption level' is set to 'Enabled: High Level'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Validator (New-CISValidatorExact 3) -ExpectedValue '3 (High Level)'
}
function Set-CIS_18_10_57_3_9_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel' -Type DWord -Value 3 }

function Test-CIS_18_10_57_3_10_1 {
    Test-CISRegistryValue -ControlId '18.10.57.3.10.1' -Title "Ensure 'Set time limit for active but idle Remote Desktop Services sessions' is set to 'Enabled: 15 minutes or less'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxIdleTime' -Validator (New-CISValidatorMaxValueNotZero 900000) -ExpectedValue '1-900000 ms (<=15 min)'
}
function Set-CIS_18_10_57_3_10_1 { param([int]$Value = 900000) Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxIdleTime' -Type DWord -Value $Value }

function Test-CIS_18_10_57_3_10_2 {
    Test-CISRegistryValue -ControlId '18.10.57.3.10.2' -Title "Ensure 'Set time limit for disconnected sessions' is set to 'Enabled: 1 minute'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxDisconnectionTime' -Validator (New-CISValidatorExact 60000) -ExpectedValue '60000 ms (1 min)'
}
function Set-CIS_18_10_57_3_10_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MaxDisconnectionTime' -Type DWord -Value 60000 }

function Test-CIS_18_10_57_3_11_1 {
    Test-CISRegistryValue -ControlId '18.10.57.3.11.1' -Title "Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DeleteTempDirsOnExit' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (se eliminan al salir)'
}
function Set-CIS_18_10_57_3_11_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'DeleteTempDirsOnExit' -Type DWord -Value 1 }

function Test-CIS_18_10_57_3_11_2 {
    Test-CISRegistryValue -ControlId '18.10.57.3.11.2' -Title "Ensure 'Do not use temporary folders per session' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'PerSessionTempDir' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (usa carpetas por sesion)'
}
function Set-CIS_18_10_57_3_11_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'PerSessionTempDir' -Type DWord -Value 1 }

# ===================== 18.10.58 RSS Feeds =====================

function Test-CIS_18_10_58_1 {
    Test-CISRegistryValue -ControlId '18.10.58.1' -Title "Ensure 'Prevent downloading of enclosures' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_58_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name 'DisableEnclosureDownload' -Type DWord -Value 1 }

# ===================== 18.10.59 Search =====================

function Test-CIS_18_10_59_2 {
    Test-CISRegistryValue -ControlId '18.10.59.2' -Title "Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disable Cloud Search)'
}
function Set-CIS_18_10_59_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCloudSearch' -Type DWord -Value 0 }

function Test-CIS_18_10_59_3 {
    Test-CISRegistryValue -ControlId '18.10.59.3' -Title "Ensure 'Allow indexing of encrypted files' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_59_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowIndexingEncryptedStoresOrItems' -Type DWord -Value 0 }

function Test-CIS_18_10_59_4 {
    Test-CISRegistryValue -ControlId '18.10.59.4' -Title "Ensure 'Allow search highlights' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'EnableDynamicContentInWSB' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_59_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'EnableDynamicContentInWSB' -Type DWord -Value 0 }

# ===================== 18.10.63 Software Protection Platform =====================

function Test-CIS_18_10_63_1 {
    Test-CISRegistryValue -ControlId '18.10.63.1' -Title "Ensure 'Turn off KMS Client Online AVS Validation' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -Name 'NoGenTicket' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_63_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform' -Name 'NoGenTicket' -Type DWord -Value 1 }

# ===================== 18.10.77 Windows Defender SmartScreen =====================

function Test-CIS_18_10_77_2_1 {
    Test-CISRegistryValue -ControlId '18.10.77.2.1' -Title "Ensure 'Configure Windows Defender SmartScreen' is set to 'Enabled: Warn and prevent bypass'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_77_2_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen' -Type DWord -Value 1 }

# ===================== 18.10.81 Windows Ink Workspace =====================

function Test-CIS_18_10_81_1 {
    Test-CISRegistryValue -ControlId '18.10.81.1' -Title "Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowSuggestedAppsInWindowsInkWorkspace' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_81_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowSuggestedAppsInWindowsInkWorkspace' -Type DWord -Value 0 }

function Test-CIS_18_10_81_2 {
    Test-CISRegistryValue -ControlId '18.10.81.2' -Title "Ensure 'Allow Windows Ink Workspace' is set to 'Enabled: On, but disallow access above lock'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowWindowsInkWorkspace' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (On, but disallow access above lock)'
}
function Set-CIS_18_10_81_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -Name 'AllowWindowsInkWorkspace' -Type DWord -Value 1 }

# ===================== 18.10.82 Windows Installer =====================

function Test-CIS_18_10_82_1 {
    Test-CISRegistryValue -ControlId '18.10.82.1' -Title "Ensure 'Allow user control over installs' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_82_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'EnableUserControl' -Type DWord -Value 0 }

function Test-CIS_18_10_82_2 {
    Test-CISRegistryValue -ControlId '18.10.82.2' -Title "Ensure 'Always install with elevated privileges' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_82_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Type DWord -Value 0 }

function Test-CIS_18_10_82_3 {
    Test-CISRegistryValue -ControlId '18.10.82.3' -Title "Ensure 'Prevent Internet Explorer security prompt for Windows Installer scripts' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_82_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'SafeForScripting' -Type DWord -Value 0 }

# ===================== 18.10.83 Winlogon =====================

function Test-CIS_18_10_83_1 {
    Test-CISRegistryValue -ControlId '18.10.83.1' -Title "Ensure 'Configure the transmission of the user's password in the content of MPR notifications sent by winlogon.' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'PlainTextPassword' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_83_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'PlainTextPassword' -Type DWord -Value 0 }

function Test-CIS_18_10_83_2 {
    Test-CISRegistryValue -ControlId '18.10.83.2' -Title "Ensure 'Sign-in and lock last interactive user automatically after a restart' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Disabled = sin auto sign-on)'
}
function Set-CIS_18_10_83_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'DisableAutomaticRestartSignOn' -Type DWord -Value 1 }

# ===================== 18.10.88 Windows PowerShell =====================

function Test-CIS_18_10_88_1 {
    Test-CISRegistryValue -ControlId '18.10.88.1' -Title "Ensure 'Turn on PowerShell Script Block Logging' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_88_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Type DWord -Value 1 }

function Test-CIS_18_10_88_2 {
    Test-CISRegistryValue -ControlId '18.10.88.2' -Title "Ensure 'Turn on PowerShell Transcription' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_88_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription' -Name 'EnableTranscripting' -Type DWord -Value 1 }

# ===================== 18.10.90 Windows Remote Management (WinRM) =====================

function Test-CIS_18_10_90_1_1 {
    Test-CISRegistryValue -ControlId '18.10.90.1.1' -Title "Ensure 'Allow Basic authentication' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_90_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowBasic' -Type DWord -Value 0 }

function Test-CIS_18_10_90_1_2 {
    Test-CISRegistryValue -ControlId '18.10.90.1.2' -Title "Ensure 'Allow unencrypted traffic' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_90_1_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0 }

function Test-CIS_18_10_90_1_3 {
    Test-CISRegistryValue -ControlId '18.10.90.1.3' -Title "Ensure 'Disallow Digest authentication' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Digest no permitido)'
}
function Set-CIS_18_10_90_1_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -Name 'AllowDigest' -Type DWord -Value 0 }

function Test-CIS_18_10_90_2_1 {
    Test-CISRegistryValue -ControlId '18.10.90.2.1' -Title "Ensure 'Allow Basic authentication' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_90_2_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic' -Type DWord -Value 0 }

function Test-CIS_18_10_90_2_2 {
    Test-CISRegistryValue -ControlId '18.10.90.2.2' -Title "Ensure 'Allow remote server management through WinRM' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowAutoConfig' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_90_2_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowAutoConfig' -Type DWord -Value 0 }

function Test-CIS_18_10_90_2_3 {
    Test-CISRegistryValue -ControlId '18.10.90.2.3' -Title "Ensure 'Allow unencrypted traffic' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_90_2_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencryptedTraffic' -Type DWord -Value 0 }

function Test-CIS_18_10_90_2_4 {
    Test-CISRegistryValue -ControlId '18.10.90.2.4' -Title "Ensure 'Disallow WinRM from storing RunAs credentials' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_10_90_2_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'DisableRunAs' -Type DWord -Value 1 }

# ===================== 18.10.91 Windows Remote Shell (WinRS) =====================

function Test-CIS_18_10_91_1 {
    Test-CISRegistryValue -ControlId '18.10.91.1' -Title "Ensure 'Allow Remote Shell Access' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' -Name 'AllowRemoteShellAccess' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_91_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS' -Name 'AllowRemoteShellAccess' -Type DWord -Value 0 }

# ===================== 18.10.93 (seccion sin identificar con certeza) =====================

function Test-CIS_18_10_93_2_1 { New-CISResult -ControlId '18.10.93.2.1' -Title "Ensure 'Prevent users from modifying settings' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'No se identifico con certeza la seccion/clave de registro para este control (ambiguo entre varias plantillas ADMX). Verificar manualmente antes de automatizar.' }
function Set-CIS_18_10_93_2_1 { Write-Warning '18.10.93.2.1: sin remediacion automatizada.' }

# ===================== 18.10.94 Windows Update =====================
# Clasico, estable desde Windows Vista/Server 2008 (WUAU/AU).

function Test-CIS_18_10_94_1_1 {
    Test-CISRegistryValue -ControlId '18.10.94.1.1' -Title "Ensure 'No auto-restart with logged on users for scheduled automatic updates installations' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_94_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoRebootWithLoggedOnUsers' -Type DWord -Value 0 }

function Test-CIS_18_10_94_2_1 {
    Test-CISRegistryValue -ControlId '18.10.94.2.1' -Title "Ensure 'Configure Automatic Updates' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Enabled = auto update activo)'
}
function Set-CIS_18_10_94_2_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWord -Value 0 }

function Test-CIS_18_10_94_2_2 {
    Test-CISRegistryValue -ControlId '18.10.94.2.2' -Title "Ensure 'Configure Automatic Updates: Scheduled install day' is set to '0 - Every day'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Every day)'
}
function Set-CIS_18_10_94_2_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'ScheduledInstallDay' -Type DWord -Value 0 }

function Test-CIS_18_10_94_4_1 {
    Test-CISRegistryValue -ControlId '18.10.94.4.1' -Title "Ensure 'Manage preview builds' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ManagePreviewBuilds' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_10_94_4_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ManagePreviewBuilds' -Type DWord -Value 0 }

function Test-CIS_18_10_94_4_2 {
    Test-CISRegistryValue -ControlId '18.10.94.4.2' -Title "Ensure 'Select when Quality Updates are received' is set to 'Enabled: 0 days'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferQualityUpdatesPeriodInDays' -Validator (New-CISValidatorExact 0) -ExpectedValue '0'
}
function Set-CIS_18_10_94_4_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DeferQualityUpdatesPeriodInDays' -Type DWord -Value 0 }
