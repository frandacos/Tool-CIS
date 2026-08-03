# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 9
# Windows Defender Firewall with Advanced Security (23 controles: 9.1 Domain,
# 9.2 Private, 9.3 Public). Fuente: cis2025.md paginas ~330-378.
#
# Todo via registro bajo HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\
# <Perfil>Profile (EnableFirewall, DefaultInboundAction, DisableNotifications,
# AllowLocalPolicyMerge, AllowLocalIPsecPolicyMerge) y su subclave \Logging
# (LogFilePath, LogFileSize, LogDroppedPackets, LogSuccessfulConnections).
# Este es el esquema de registro oficial que usa el ADMX WindowsFirewall.admx
# de Microsoft para las 3 GPO de perfil de firewall, reutiliza el mismo motor
# generico de Chapter2-SecurityOptions.ps1 (RegistryEngine.ps1).

$script:CISFirewallProfilePaths = @{
    Domain  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
    Private = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
    Public  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
}

function Get-CISFirewallLoggingPath {
    param([Parameter(Mandatory)][ValidateSet('Domain', 'Private', 'Public')][string]$Profile)
    Join-Path $script:CISFirewallProfilePaths[$Profile] 'Logging'
}

# ===================== 9.1 Domain Profile =====================

function Test-CIS_WS2025_9_1_1 {
    Test-CISRegistryValue -ControlId '9.1.1' -Title "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'" `
        -Path $script:CISFirewallProfilePaths.Domain -Name 'EnableFirewall' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (On)'
}
function Set-CIS_WS2025_9_1_1 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Domain -Name 'EnableFirewall' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_1_2 {
    Test-CISRegistryValue -ControlId '9.1.2' -Title "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'" `
        -Path $script:CISFirewallProfilePaths.Domain -Name 'DefaultInboundAction' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Block)'
}
function Set-CIS_WS2025_9_1_2 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Domain -Name 'DefaultInboundAction' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_1_3 {
    Test-CISRegistryValue -ControlId '9.1.3' -Title "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'" `
        -Path $script:CISFirewallProfilePaths.Domain -Name 'DisableNotifications' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (No mostrar notificacion)'
}
function Set-CIS_WS2025_9_1_3 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Domain -Name 'DisableNotifications' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_1_4 {
    Test-CISRegistryValue -ControlId '9.1.4' -Title "Ensure 'Windows Firewall: Domain: Logging: Name' is configured" `
        -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogFilePath' -Validator (New-CISValidatorNonEmptyString) -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_WS2025_9_1_4 { param([string]$Path = '%SystemRoot%\System32\logfiles\firewall\domainfw.log') Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogFilePath' -Type String -Value $Path }

function Test-CIS_WS2025_9_1_5 {
    Test-CISRegistryValue -ControlId '9.1.5' -Title "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'" `
        -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogFileSize' -Validator (New-CISValidatorMinValue 16384) -ExpectedValue '>= 16384'
}
function Set-CIS_WS2025_9_1_5 { param([int]$Value = 16384) Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogFileSize' -Type DWord -Value $Value }

function Test-CIS_WS2025_9_1_6 {
    Test-CISRegistryValue -ControlId '9.1.6' -Title "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'" `
        -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogDroppedPackets' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Yes)'
}
function Set-CIS_WS2025_9_1_6 { Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogDroppedPackets' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_1_7 {
    Test-CISRegistryValue -ControlId '9.1.7' -Title "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'" `
        -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogSuccessfulConnections' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Yes)'
}
function Set-CIS_WS2025_9_1_7 { Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Domain) -Name 'LogSuccessfulConnections' -Type DWord -Value 1 }

# ===================== 9.2 Private Profile =====================

function Test-CIS_WS2025_9_2_1 {
    Test-CISRegistryValue -ControlId '9.2.1' -Title "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'" `
        -Path $script:CISFirewallProfilePaths.Private -Name 'EnableFirewall' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (On)'
}
function Set-CIS_WS2025_9_2_1 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Private -Name 'EnableFirewall' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_2_2 {
    Test-CISRegistryValue -ControlId '9.2.2' -Title "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'" `
        -Path $script:CISFirewallProfilePaths.Private -Name 'DefaultInboundAction' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Block)'
}
function Set-CIS_WS2025_9_2_2 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Private -Name 'DefaultInboundAction' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_2_3 {
    Test-CISRegistryValue -ControlId '9.2.3' -Title "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'" `
        -Path $script:CISFirewallProfilePaths.Private -Name 'DisableNotifications' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (No mostrar notificacion)'
}
function Set-CIS_WS2025_9_2_3 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Private -Name 'DisableNotifications' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_2_4 {
    Test-CISRegistryValue -ControlId '9.2.4' -Title "Ensure 'Windows Firewall: Private: Logging: Name' is configured" `
        -Path (Get-CISFirewallLoggingPath Private) -Name 'LogFilePath' -Validator (New-CISValidatorNonEmptyString) -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_WS2025_9_2_4 { param([string]$Path = '%SystemRoot%\System32\logfiles\firewall\privatefw.log') Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Private) -Name 'LogFilePath' -Type String -Value $Path }

function Test-CIS_WS2025_9_2_5 {
    Test-CISRegistryValue -ControlId '9.2.5' -Title "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'" `
        -Path (Get-CISFirewallLoggingPath Private) -Name 'LogFileSize' -Validator (New-CISValidatorMinValue 16384) -ExpectedValue '>= 16384'
}
function Set-CIS_WS2025_9_2_5 { param([int]$Value = 16384) Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Private) -Name 'LogFileSize' -Type DWord -Value $Value }

function Test-CIS_WS2025_9_2_6 {
    Test-CISRegistryValue -ControlId '9.2.6' -Title "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'" `
        -Path (Get-CISFirewallLoggingPath Private) -Name 'LogDroppedPackets' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Yes)'
}
function Set-CIS_WS2025_9_2_6 { Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Private) -Name 'LogDroppedPackets' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_2_7 {
    Test-CISRegistryValue -ControlId '9.2.7' -Title "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'" `
        -Path (Get-CISFirewallLoggingPath Private) -Name 'LogSuccessfulConnections' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Yes)'
}
function Set-CIS_WS2025_9_2_7 { Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Private) -Name 'LogSuccessfulConnections' -Type DWord -Value 1 }

# ===================== 9.3 Public Profile =====================

function Test-CIS_WS2025_9_3_1 {
    Test-CISRegistryValue -ControlId '9.3.1' -Title "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'" `
        -Path $script:CISFirewallProfilePaths.Public -Name 'EnableFirewall' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (On)'
}
function Set-CIS_WS2025_9_3_1 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Public -Name 'EnableFirewall' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_3_2 {
    Test-CISRegistryValue -ControlId '9.3.2' -Title "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'" `
        -Path $script:CISFirewallProfilePaths.Public -Name 'DefaultInboundAction' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Block)'
}
function Set-CIS_WS2025_9_3_2 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Public -Name 'DefaultInboundAction' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_3_3 {
    Test-CISRegistryValue -ControlId '9.3.3' -Title "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'" `
        -Path $script:CISFirewallProfilePaths.Public -Name 'DisableNotifications' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (No mostrar notificacion)'
}
function Set-CIS_WS2025_9_3_3 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Public -Name 'DisableNotifications' -Type DWord -Value 1 }

# 9.3.4/9.3.5 - unicos del perfil Public (no existen para Domain/Private).
function Test-CIS_WS2025_9_3_4 {
    Test-CISRegistryValue -ControlId '9.3.4' -Title "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'" `
        -Path $script:CISFirewallProfilePaths.Public -Name 'AllowLocalPolicyMerge' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (No)'
}
function Set-CIS_WS2025_9_3_4 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Public -Name 'AllowLocalPolicyMerge' -Type DWord -Value 0 }

function Test-CIS_WS2025_9_3_5 {
    Test-CISRegistryValue -ControlId '9.3.5' -Title "Ensure 'Windows Firewall: Public: Settings: Apply local connection security rules' is set to 'No'" `
        -Path $script:CISFirewallProfilePaths.Public -Name 'AllowLocalIPsecPolicyMerge' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (No)'
}
function Set-CIS_WS2025_9_3_5 { Set-CISRegistryValue -Path $script:CISFirewallProfilePaths.Public -Name 'AllowLocalIPsecPolicyMerge' -Type DWord -Value 0 }

function Test-CIS_WS2025_9_3_6 {
    Test-CISRegistryValue -ControlId '9.3.6' -Title "Ensure 'Windows Firewall: Public: Logging: Name' is configured" `
        -Path (Get-CISFirewallLoggingPath Public) -Name 'LogFilePath' -Validator (New-CISValidatorNonEmptyString) -ExpectedValue 'Configurado (no vacio)'
}
function Set-CIS_WS2025_9_3_6 { param([string]$Path = '%SystemRoot%\System32\logfiles\firewall\publicfw.log') Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Public) -Name 'LogFilePath' -Type String -Value $Path }

function Test-CIS_WS2025_9_3_7 {
    Test-CISRegistryValue -ControlId '9.3.7' -Title "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'" `
        -Path (Get-CISFirewallLoggingPath Public) -Name 'LogFileSize' -Validator (New-CISValidatorMinValue 16384) -ExpectedValue '>= 16384'
}
function Set-CIS_WS2025_9_3_7 { param([int]$Value = 16384) Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Public) -Name 'LogFileSize' -Type DWord -Value $Value }

function Test-CIS_WS2025_9_3_8 {
    Test-CISRegistryValue -ControlId '9.3.8' -Title "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'" `
        -Path (Get-CISFirewallLoggingPath Public) -Name 'LogDroppedPackets' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Yes)'
}
function Set-CIS_WS2025_9_3_8 { Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Public) -Name 'LogDroppedPackets' -Type DWord -Value 1 }

function Test-CIS_WS2025_9_3_9 {
    Test-CISRegistryValue -ControlId '9.3.9' -Title "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'" `
        -Path (Get-CISFirewallLoggingPath Public) -Name 'LogSuccessfulConnections' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Yes)'
}
function Set-CIS_WS2025_9_3_9 { Set-CISRegistryValue -Path (Get-CISFirewallLoggingPath Public) -Name 'LogSuccessfulConnections' -Type DWord -Value 1 }
