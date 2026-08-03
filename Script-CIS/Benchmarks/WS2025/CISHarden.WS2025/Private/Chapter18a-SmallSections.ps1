# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 18, primer
# bloque de sub-etapas chicas: 18.1 Control Panel (4), 18.4 MS Security Guide
# (6), 18.5 MSS (Legacy) (11), 18.8 Start Menu and Taskbar (1), 18.11 Custom
# Settings (2) = 24 controles. Fuente: cis2025.md paginas 459-486, 631,
# 1137-1141. Todo via registro (Administrative Templates = ADMX -> HKLM),
# reutiliza RegistryEngine.ps1.
#
# 18.11.2 queda ManualReviewRequired: no encontre con certeza la clave de
# registro para "Disable proxy authentication over loopback interfaces" (es
# un "Custom Setting" del benchmark, sin ADMX oficial de Microsoft detras) --
# mejor no inventarla (regla 3 del system prompt).

# ===================== 18.1 Control Panel =====================

function Test-CIS_WS2025_18_1_1_1 {
    Test-CISRegistryValue -ControlId '18.1.1.1' -Title "Ensure 'Prevent enabling lock screen camera' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_1_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenCamera' -Type DWord -Value 1 }

function Test-CIS_WS2025_18_1_1_2 {
    Test-CISRegistryValue -ControlId '18.1.1.2' -Title "Ensure 'Prevent enabling lock screen slide show' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_1_1_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -Name 'NoLockScreenSlideshow' -Type DWord -Value 1 }

function Test-CIS_WS2025_18_1_2_2 {
    Test-CISRegistryValue -ControlId '18.1.2.2' -Title "Ensure 'Allow users to enable online speech recognition services' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'AllowInputPersonalization' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_WS2025_18_1_2_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization' -Name 'AllowInputPersonalization' -Type DWord -Value 0 }

function Test-CIS_WS2025_18_1_3 {
    Test-CISRegistryValue -ControlId '18.1.3' -Title "Ensure 'Allow Online Tips' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'AllowOnlineTips' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_WS2025_18_1_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -Name 'AllowOnlineTips' -Type DWord -Value 0 }

# ===================== 18.4 MS Security Guide =====================

# LocalAccountTokenFilterPolicy=0 es la restriccion UAC remota "activa"
# (recomendada); el nombre de la clave es contraintuitivo pero es el
# esquema oficial de Microsoft.
function Test-CIS_WS2025_18_4_1 {
    Test-CISRegistryValue -ControlId '18.4.1' -Title "Ensure 'Apply UAC restrictions to local accounts on network logons' is set to 'Enabled' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (restriccion activa)' -Scope MS
}
function Set-CIS_WS2025_18_4_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -Type DWord -Value 0 -Scope MS }

function Test-CIS_WS2025_18_4_2 {
    Test-CISRegistryValue -ControlId '18.4.2' -Title "Ensure 'Configure SMB v1 client driver' is set to 'Enabled: Disable driver (recommended)'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Validator (New-CISValidatorExact 4) -ExpectedValue '4 (Disabled)'
}
function Set-CIS_WS2025_18_4_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Type DWord -Value 4 }

function Test-CIS_WS2025_18_4_3 {
    Test-CISRegistryValue -ControlId '18.4.3' -Title "Ensure 'Configure SMB v1 server' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_WS2025_18_4_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Type DWord -Value 0 }

function Test-CIS_WS2025_18_4_4 {
    Test-CISRegistryValue -ControlId '18.4.4' -Title "Ensure 'Enable Certificate Padding' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_4_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config' -Name 'EnableCertPaddingCheck' -Type DWord -Value 1 }

# DisableExceptionChainValidation=0 significa que la validacion SEHOP NO
# esta deshabilitada, es decir, SEHOP esta Enabled.
function Test-CIS_WS2025_18_4_5 {
    Test-CISRegistryValue -ControlId '18.4.5' -Title "Ensure 'Enable Structured Exception Handling Overwrite Protection (SEHOP)' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'DisableExceptionChainValidation' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (SEHOP Enabled)'
}
function Set-CIS_WS2025_18_4_5 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'DisableExceptionChainValidation' -Type DWord -Value 0 }

function Test-CIS_WS2025_18_4_6 {
    Test-CISRegistryValue -ControlId '18.4.6' -Title "Ensure 'NetBT NodeType configuration' is set to 'Enabled: P-node (recommended)'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (P-node)'
}
function Set-CIS_WS2025_18_4_6 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'NodeType' -Type DWord -Value 2 }

# ===================== 18.5 MSS (Legacy) =====================

function Test-CIS_WS2025_18_5_1 {
    Test-CISRegistryValue -ControlId '18.5.1' -Title "Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Validator (New-CISValidatorExact '0') -ExpectedValue "'0' (Disabled)"
}
function Set-CIS_WS2025_18_5_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon' -Type String -Value '0' }

function Test-CIS_WS2025_18_5_2 {
    Test-CISRegistryValue -ControlId '18.5.2' -Title "Ensure 'MSS: (DisableIPSourceRouting IPv6) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Highest protection)'
}
function Set-CIS_WS2025_18_5_2 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2 }

function Test-CIS_WS2025_18_5_3 {
    Test-CISRegistryValue -ControlId '18.5.3' -Title "Ensure 'MSS: (DisableIPSourceRouting) IP source routing protection level' is set to 'Enabled: Highest protection, source routing is completely disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Highest protection)'
}
function Set-CIS_WS2025_18_5_3 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'DisableIPSourceRouting' -Type DWord -Value 2 }

function Test-CIS_WS2025_18_5_4 {
    Test-CISRegistryValue -ControlId '18.5.4' -Title "Ensure 'MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_WS2025_18_5_4 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'EnableICMPRedirect' -Type DWord -Value 0 }

function Test-CIS_WS2025_18_5_5 {
    Test-CISRegistryValue -ControlId '18.5.5' -Title "Ensure 'MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds' is set to 'Enabled: 300,000 or 5 minutes (recommended)'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Validator (New-CISValidatorExact 300000) -ExpectedValue '300000'
}
function Set-CIS_WS2025_18_5_5 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'KeepAliveTime' -Type DWord -Value 300000 }

function Test-CIS_WS2025_18_5_6 {
    Test-CISRegistryValue -ControlId '18.5.6' -Title "Ensure 'MSS: (NoNameReleaseOnDemand) Allow the computer to ignore NetBIOS name release requests except from WINS servers' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -Name 'NoNameReleaseOnDemand' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_5_6 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters' -Name 'NoNameReleaseOnDemand' -Type DWord -Value 1 }

function Test-CIS_WS2025_18_5_7 {
    Test-CISRegistryValue -ControlId '18.5.7' -Title "Ensure 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses' is set to 'Disabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'PerformRouterDiscovery' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_WS2025_18_5_7 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'PerformRouterDiscovery' -Type DWord -Value 0 }

function Test-CIS_WS2025_18_5_8 {
    Test-CISRegistryValue -ControlId '18.5.8' -Title "Ensure 'MSS: (SafeDllSearchMode) Enable Safe DLL search mode' is set to 'Enabled'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_5_8 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'SafeDllSearchMode' -Type DWord -Value 1 }

function Test-CIS_WS2025_18_5_9 {
    Test-CISRegistryValue -ControlId '18.5.9' -Title "Ensure 'MSS: (TcpMaxDataRetransmissions IPv6) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'TcpMaxDataRetransmissions' -Validator (New-CISValidatorExact 3) -ExpectedValue '3'
}
function Set-CIS_WS2025_18_5_9 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 }

function Test-CIS_WS2025_18_5_10 {
    Test-CISRegistryValue -ControlId '18.5.10' -Title "Ensure 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted' is set to 'Enabled: 3'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'TcpMaxDataRetransmissions' -Validator (New-CISValidatorExact 3) -ExpectedValue '3'
}
function Set-CIS_WS2025_18_5_10 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'TcpMaxDataRetransmissions' -Type DWord -Value 3 }

function Test-CIS_WS2025_18_5_11 {
    Test-CISRegistryValue -ControlId '18.5.11' -Title "Ensure 'MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning' is set to 'Enabled: 90% or less'" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'WarningLevel' -Validator (New-CISValidatorRange 0 90) -ExpectedValue '0-90'
}
function Set-CIS_WS2025_18_5_11 { param([int]$Value = 90) Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security' -Name 'WarningLevel' -Type DWord -Value $Value }

# ===================== 18.8 Start Menu and Taskbar =====================

function Test-CIS_WS2025_18_8_1_1 {
    Test-CISRegistryValue -ControlId '18.8.1.1' -Title "Ensure 'Turn off notifications network usage' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoCloudApplicationNotification' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_8_1_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoCloudApplicationNotification' -Type DWord -Value 1 }

# ===================== 18.11 Custom Settings =====================

function Test-CIS_WS2025_18_11_1 {
    Test-CISRegistryValue -ControlId '18.11.1' -Title "Ensure 'Disable HTTP proxy features: Disable WPAD' is set to 'Enabled: Checked'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinHttpAutoProxySvc' -Name 'DisableWpad' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_WS2025_18_11_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinHttpAutoProxySvc' -Name 'DisableWpad' -Type DWord -Value 1 }

# Baja confianza deliberada: "Custom Setting" del benchmark sin ADMX oficial
# de Microsoft detras; no encontre con certeza la clave de registro para
# "Disable proxy authentication over loopback interfaces". Manual en vez de
# adivinar (regla 3 del system prompt).
function Test-CIS_WS2025_18_11_2 {
    New-CISResult -ControlId '18.11.2' -Title "Ensure 'Disable HTTP proxy features: Disable proxy authentication' is set to 'Enabled: Disable authentication over loopback interfaces' or higher" -Status 'ManualReviewRequired' `
        -Notes 'Custom Setting del benchmark sin ADMX oficial de Microsoft detras; no se identifico con certeza la clave de registro. Verificar manualmente antes de automatizar.'
}
function Set-CIS_WS2025_18_11_2 { Write-Warning '18.11.2: sin remediacion automatizada, ver Test-CIS_WS2025_18_11_2.' }
