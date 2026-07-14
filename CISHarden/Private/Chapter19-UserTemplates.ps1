# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 19
# Administrative Templates (User) (11 controles). Fuente: cis2025.md
# paginas 1144-1178. Reusa RegistryEngine.ps1.
#
# LIMITACION IMPORTANTE: estos son "User Configuration" GPO settings, que
# Windows aplica bajo HKCU para la sesion de CADA usuario que inicia
# sesion, no bajo HKLM. Este modulo corre como el usuario/servicio que
# ejecuta el audit (tipicamente un administrador con sesion interactiva o
# PSRemoting), asi que Test-CIS_19_* audita el HKCU de ESA sesion, no de
# "todos los usuarios del servidor". Es el mismo enfoque que usan la
# mayoria de las herramientas de hardening publicas para este tipo de
# control, pero la auditoria definitiva de que la GPO efectivamente llega a
# los usuarios reales sigue siendo `gpresult /h reporte.html` corrido desde
# una sesion de un usuario representativo, o revisar la GPO en el DC
# directamente. Documentado tambien en README.md.

function Test-CIS_19_5_1_1 {
    Test-CISRegistryValue -ControlId '19.5.1.1' -Title "Ensure 'Turn off toast notifications on the lock screen' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_5_1_1 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1 }

function Test-CIS_19_6_6_1_1 {
    Test-CISRegistryValue -ControlId '19.6.6.1.1' -Title "Ensure 'Turn off Help Experience Improvement Program' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0' -Name 'NoImplicitFeedback' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_6_6_1_1 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0' -Name 'NoImplicitFeedback' -Type DWord -Value 1 }

# Clasico "Mark of the Web" de adjuntos (distinto del control nuevo 18.10.29.2).
function Test-CIS_19_7_5_1 {
    Test-CISRegistryValue -ControlId '19.7.5.1' -Title "Ensure 'Do not preserve zone information in file attachments' is set to 'Disabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Attachments' -Name 'SaveZoneInformation' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (se preserva la zona)'
}
function Set-CIS_19_7_5_1 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Attachments' -Name 'SaveZoneInformation' -Type DWord -Value 2 }

function Test-CIS_19_7_5_2 {
    Test-CISRegistryValue -ControlId '19.7.5.2' -Title "Ensure 'Notify antivirus programs when opening attachments' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Attachments' -Name 'ScanWithAntiVirus' -Validator (New-CISValidatorExact 3) -ExpectedValue '3 (forzar escaneo)'
}
function Set-CIS_19_7_5_2 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Attachments' -Name 'ScanWithAntiVirus' -Type DWord -Value 3 }

function Test-CIS_19_7_8_1 {
    Test-CISRegistryValue -ControlId '19.7.8.1' -Title "Ensure 'Configure Windows spotlight on lock screen' is set to 'Disabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'ConfigureWindowsSpotlight' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Disabled)'
}
function Set-CIS_19_7_8_1 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'ConfigureWindowsSpotlight' -Type DWord -Value 2 }

function Test-CIS_19_7_8_2 {
    Test-CISRegistryValue -ControlId '19.7.8.2' -Title "Ensure 'Do not suggest third-party content in Windows spotlight' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableThirdPartySuggestions' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_7_8_2 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableThirdPartySuggestions' -Type DWord -Value 1 }

function Test-CIS_19_7_8_3 {
    Test-CISRegistryValue -ControlId '19.7.8.3' -Title "Ensure 'Do not use diagnostic data for tailored experiences' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_7_8_3 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableTailoredExperiencesWithDiagnosticData' -Type DWord -Value 1 }

function Test-CIS_19_7_8_4 {
    Test-CISRegistryValue -ControlId '19.7.8.4' -Title "Ensure 'Turn off all Windows spotlight features' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_7_8_4 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableWindowsSpotlightFeatures' -Type DWord -Value 1 }

function Test-CIS_19_7_8_5 {
    Test-CISRegistryValue -ControlId '19.7.8.5' -Title "Ensure 'Turn off Spotlight collection on Desktop' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSpotlightCollectionOnDesktop' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_7_8_5 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'DisableSpotlightCollectionOnDesktop' -Type DWord -Value 1 }

function Test-CIS_19_7_26_1 {
    Test-CISRegistryValue -ControlId '19.7.26.1' -Title "Ensure 'Prevent users from sharing files within their profile.' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoInplaceSharing' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_7_26_1 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoInplaceSharing' -Type DWord -Value 1 }

function Test-CIS_19_7_46_2_1 {
    Test-CISRegistryValue -ControlId '19.7.46.2.1' -Title "Ensure 'Prevent Codec Download' is set to 'Enabled'" `
        -Path 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer' -Name 'PreventCodecDownload' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_19_7_46_2_1 { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer' -Name 'PreventCodecDownload' -Type DWord -Value 1 }
