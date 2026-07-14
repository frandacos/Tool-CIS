# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 18.6/18.7
# (Network + Printers, 49 controles: 31+18). Fuente: cis2025.md paginas
# 509-627.
#
# 20 controles son configuraciones clasicas de Administrative Templates
# (LLTD, P2P Networking, Network Bridge, ICS, Hardened UNC Paths, IPv6
# disable, WCN, minimizar conexiones simultaneas, Point and Print
# Restrictions, limite de instalacion de drivers, mDNS/NetBIOS/LLMNR, Font
# Providers) con mapeo de registro estable y bien documentado desde hace
# años -- se implementan con RegistryEngine.ps1 igual que los capitulos
# anteriores.
#
# 29 controles quedan ManualReviewRequired: son funcionalidades NUEVAS de
# Windows Server 2025 (hardening SMB client/server 2024-2025, Redirection
# Guard, Windows Protected Print, politicas TLS/SSL para IPP, y varios del
# bloque RPC del Print Spooler cuyo mapeo/semantica exacta no pude confirmar
# con certeza suficiente). No se inventan las claves de registro (regla 3
# del system prompt) -- requieren verificacion manual contra
# C:\Windows\PolicyDefinitions o RSOP en un DC/MS real antes de automatizar.

# ===================== 18.6.4 DNS Client =====================

function Test-CIS_18_6_4_1 {
    Test-CISRegistryValue -ControlId '18.6.4.1' -Title "Ensure 'Configure multicast DNS (mDNS) protocol' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMDNS' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_6_4_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMDNS' -Type DWord -Value 0 }

function Test-CIS_18_6_4_2 {
    Test-CISRegistryValue -ControlId '18.6.4.2' -Title "Ensure 'Configure NetBIOS settings' is set to 'Enabled: Disable NetBIOS name resolution on public networks'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableNetbios' -Validator (New-CISValidatorExact 2) -ExpectedValue '2'
}
function Set-CIS_18_6_4_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableNetbios' -Type DWord -Value 2 }

function Test-CIS_18_6_4_3 {
    New-CISResult -ControlId '18.6.4.3' -Title "Ensure 'Turn off default IPv6 DNS Servers' is set to 'Enabled'" -Status 'ManualReviewRequired' `
        -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.'
}
function Set-CIS_18_6_4_3 { Write-Warning '18.6.4.3: sin remediacion automatizada, ver Test-CIS_18_6_4_3.' }

function Test-CIS_18_6_4_4 {
    Test-CISRegistryValue -ControlId '18.6.4.4' -Title "Ensure 'Turn off multicast name resolution' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (LLMNR deshabilitado)'
}
function Set-CIS_18_6_4_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Type DWord -Value 0 }

# ===================== 18.6.5 Fonts =====================

function Test-CIS_18_6_5_1 {
    Test-CISRegistryValue -ControlId '18.6.5.1' -Title "Ensure 'Enable Font Providers' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableFontProviders' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_6_5_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableFontProviders' -Type DWord -Value 0 }

# ===================== 18.6.7 Lanman Workstation (SMB Client) =====================
# Hardening SMB client/server nuevo de Windows Server 2025 (KB/24H2):
# auditoria de cifrado/firma no soportados, rate limiter de autenticacion,
# remote mailslots, version minima de SMB. No confirme con certeza los
# nombres de valor de registro exactos para estos 7 -- Manual.

function Test-CIS_18_6_7_1 { New-CISResult -ControlId '18.6.7.1' -Title "Ensure 'Audit client does not support encryption' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_1 { Write-Warning '18.6.7.1: sin remediacion automatizada.' }
function Test-CIS_18_6_7_2 { New-CISResult -ControlId '18.6.7.2' -Title "Ensure 'Audit client does not support signing' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_2 { Write-Warning '18.6.7.2: sin remediacion automatizada.' }
function Test-CIS_18_6_7_3 { New-CISResult -ControlId '18.6.7.3' -Title "Ensure 'Audit insecure guest logon' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_3 { Write-Warning '18.6.7.3: sin remediacion automatizada.' }
function Test-CIS_18_6_7_4 { New-CISResult -ControlId '18.6.7.4' -Title "Ensure 'Enable authentication rate limiter' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_4 { Write-Warning '18.6.7.4: sin remediacion automatizada.' }
function Test-CIS_18_6_7_5 { New-CISResult -ControlId '18.6.7.5' -Title "Ensure 'Enable remote mailslots' is set to 'Disabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_5 { Write-Warning '18.6.7.5: sin remediacion automatizada.' }
function Test-CIS_18_6_7_6 { New-CISResult -ControlId '18.6.7.6' -Title "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_6 { Write-Warning '18.6.7.6: sin remediacion automatizada.' }
function Test-CIS_18_6_7_7 { New-CISResult -ControlId '18.6.7.7' -Title "Ensure 'Set authentication rate limiter delay (milliseconds)' is set to 'Enabled: 2000' or more" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_7_7 { Write-Warning '18.6.7.7: sin remediacion automatizada.' }

# ===================== 18.6.8 Lanman Server (SMB Server) =====================
# Mismo motivo que 18.6.7 -- hardening SMB server nuevo, Manual.

function Test-CIS_18_6_8_1 { New-CISResult -ControlId '18.6.8.1' -Title "Ensure 'Audit insecure guest logon' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_1 { Write-Warning '18.6.8.1: sin remediacion automatizada.' }
function Test-CIS_18_6_8_2 { New-CISResult -ControlId '18.6.8.2' -Title "Ensure 'Audit server does not support encryption' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_2 { Write-Warning '18.6.8.2: sin remediacion automatizada.' }
function Test-CIS_18_6_8_3 { New-CISResult -ControlId '18.6.8.3' -Title "Ensure 'Audit server does not support signing' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_3 { Write-Warning '18.6.8.3: sin remediacion automatizada.' }
function Test-CIS_18_6_8_4 { New-CISResult -ControlId '18.6.8.4' -Title "Ensure 'Enable insecure guest logons' is set to 'Disabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_4 { Write-Warning '18.6.8.4: sin remediacion automatizada.' }
function Test-CIS_18_6_8_5 { New-CISResult -ControlId '18.6.8.5' -Title "Ensure 'Enable remote mailslots' is set to 'Disabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_5 { Write-Warning '18.6.8.5: sin remediacion automatizada.' }
function Test-CIS_18_6_8_6 { New-CISResult -ControlId '18.6.8.6' -Title "Ensure 'Mandate the minimum version of SMB' is set to 'Enabled: 3.1.1'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_6 { Write-Warning '18.6.8.6: sin remediacion automatizada.' }
function Test-CIS_18_6_8_7 { New-CISResult -ControlId '18.6.8.7' -Title "Ensure 'Require Encryption' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de hardening SMB server (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_6_8_7 { Write-Warning '18.6.8.7: sin remediacion automatizada.' }

# ===================== 18.6.9 Link-Layer Topology Discovery =====================

function Test-CIS_18_6_9_1 {
    Test-CISRegistryValue -ControlId '18.6.9.1' -Title "Ensure 'Turn on Mapper I/O (LLTDIO) driver' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableLLTDIO' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_6_9_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableLLTDIO' -Type DWord -Value 0 }

function Test-CIS_18_6_9_2 {
    Test-CISRegistryValue -ControlId '18.6.9.2' -Title "Ensure 'Turn on Responder (RSPNDR) driver' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableRspndr' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_6_9_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LLTD' -Name 'EnableRspndr' -Type DWord -Value 0 }

# ===================== 18.6.10 Microsoft Peer-to-Peer Networking Services =====================

function Test-CIS_18_6_10_2 {
    Test-CISRegistryValue -ControlId '18.6.10.2' -Title "Ensure 'Turn off Microsoft Peer-to-Peer Networking Services' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled = P2P apagado)'
}
function Set-CIS_18_6_10_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Peernet' -Name 'Disabled' -Type DWord -Value 1 }

# ===================== 18.6.11 Network Connections =====================

function Test-CIS_18_6_11_2 {
    Test-CISRegistryValue -ControlId '18.6.11.2' -Title "Ensure 'Prohibit installation and configuration of Network Bridge on your DNS domain network' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Network Connections' -Name 'NC_AllowNetBridge_NLA' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (prohibido)'
}
function Set-CIS_18_6_11_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Network Connections' -Name 'NC_AllowNetBridge_NLA' -Type DWord -Value 0 }

function Test-CIS_18_6_11_3 {
    Test-CISRegistryValue -ControlId '18.6.11.3' -Title "Ensure 'Prohibit use of Internet Connection Sharing on your DNS domain network' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Network Connections' -Name 'NC_ShowSharedAccessUI' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (prohibido)'
}
function Set-CIS_18_6_11_3 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Network Connections' -Name 'NC_ShowSharedAccessUI' -Type DWord -Value 0 }

function Test-CIS_18_6_11_4 {
    Test-CISRegistryValue -ControlId '18.6.11.4' -Title "Ensure 'Require domain users to elevate when setting a network's location' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Network Connections' -Name 'NC_StdDomainUserSetLocation' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_6_11_4 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Network Connections' -Name 'NC_StdDomainUserSetLocation' -Type DWord -Value 1 }

# ===================== 18.6.14 Network Provider =====================
# Hardened UNC Paths: no es un unico Name/Value, son 2 entradas (NETLOGON y
# SYSVOL) bajo la misma clave. Validacion/remediacion a medida, no usa el
# motor generico de un solo valor.

function Test-CIS_18_6_14_1 {
    [CmdletBinding()]
    param()
    $title = "Ensure 'Hardened UNC Paths' is set to 'Enabled, with 'Require Mutual Authentication' and 'Require Integrity' set for all NETLOGON and SYSVOL shares'"
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
    $prop = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
    $required = @('\\*\NETLOGON', '\\*\SYSVOL')
    $missing = @()
    foreach ($r in $required) {
        $val = if ($prop) { $prop.$r } else { $null }
        if (-not $val -or $val -notmatch 'RequireMutualAuthentication=1' -or $val -notmatch 'RequireIntegrity=1') {
            $missing += $r
        }
    }
    $status = if ($missing.Count -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '18.6.14.1' -Title $title -Status $status `
        -ExpectedValue 'NETLOGON y SYSVOL con RequireMutualAuthentication=1,RequireIntegrity=1' `
        -ActualValue ("faltan/incompletos: {0}" -f ($missing -join ', '))
}
function Set-CIS_18_6_14_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
    if ($PSCmdlet.ShouldProcess($path, 'Configurar Hardened UNC Paths para NETLOGON y SYSVOL')) {
        Set-CISRegistryValue -Path $path -Name '\\*\NETLOGON' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1'
        Set-CISRegistryValue -Path $path -Name '\\*\SYSVOL' -Type String -Value 'RequireMutualAuthentication=1,RequireIntegrity=1'
    }
}

# ===================== 18.6.19 TCPIP Settings (IPv6) =====================

function Test-CIS_18_6_19_2_1 {
    Test-CISRegistryValue -ControlId '18.6.19.2.1' -Title "Disable IPv6 (Ensure TCPIP6 Parameter 'DisabledComponents' is set to '0xff (255)')" `
        -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Validator (New-CISValidatorExact 255) -ExpectedValue '255 (0xff)'
}
function Set-CIS_18_6_19_2_1 { Set-CISRegistryValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisabledComponents' -Type DWord -Value 255 }

# ===================== 18.6.20 Windows Connect Now =====================

function Test-CIS_18_6_20_1 {
    Test-CISRegistryValue -ControlId '18.6.20.1' -Title "Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'EnableRegistrars' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Disabled)'
}
function Set-CIS_18_6_20_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars' -Name 'EnableRegistrars' -Type DWord -Value 0 }

function Test-CIS_18_6_20_2 {
    Test-CISRegistryValue -ControlId '18.6.20.2' -Title "Ensure 'Prohibit access of the Windows Connect Now wizards' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_6_20_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI' -Name 'DisableWcnUi' -Type DWord -Value 1 }

# ===================== 18.6.21 Windows Connection Manager =====================

function Test-CIS_18_6_21_1 {
    Test-CISRegistryValue -ControlId '18.6.21.1' -Title "Ensure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' is set to 'Enabled: 3 = Prevent Wi-Fi when on Ethernet'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Validator (New-CISValidatorExact 3) -ExpectedValue '3'
}
function Set-CIS_18_6_21_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fMinimizeConnections' -Type DWord -Value 3 }

function Test-CIS_18_6_21_2 {
    Test-CISRegistryValue -ControlId '18.6.21.2' -Title "Ensure 'Prohibit connection to non-domain networks when connected to domain authenticated network' is set to 'Enabled' (MS only)" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)' -Scope MS
}
function Set-CIS_18_6_21_2 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -Name 'fBlockNonDomain' -Type DWord -Value 1 -Scope MS }

# ===================== 18.7 Printers =====================

# 18.7.1 - mitigacion PrintNightmare (CVE-2021-34527), bien documentada.
function Test-CIS_18_7_1 {
    Test-CISRegistryValue -ControlId '18.7.1' -Title "Ensure 'Allow Print Spooler to accept client connections' is set to 'Disabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint' -Validator (New-CISValidatorExact 2) -ExpectedValue '2 (Disabled)'
}
function Set-CIS_18_7_1 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -Name 'RegisterSpoolerRemoteRpcEndPoint' -Type DWord -Value 2 }

function Test-CIS_18_7_2 { New-CISResult -ControlId '18.7.2' -Title "Ensure 'Configure Redirection Guard' is set to 'Enabled: Redirection Guard Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de Print Spooler (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_2 { Write-Warning '18.7.2: sin remediacion automatizada.' }

function Test-CIS_18_7_3 { New-CISResult -ControlId '18.7.3' -Title "Ensure 'Configure RPC connection settings: Protocol to use for outgoing RPC connections' is set to 'Enabled: RPC over TCP'" -Status 'ManualReviewRequired' -Notes 'Bloque RPC del Print Spooler; no se confirmo la semantica exacta de valores con suficiente certeza.' }
function Set-CIS_18_7_3 { Write-Warning '18.7.3: sin remediacion automatizada.' }
function Test-CIS_18_7_4 { New-CISResult -ControlId '18.7.4' -Title "Ensure 'Configure RPC connection settings: Use authentication for outgoing RPC connections' is set to 'Enabled: Default'" -Status 'ManualReviewRequired' -Notes 'Bloque RPC del Print Spooler; no se confirmo la semantica exacta de valores con suficiente certeza.' }
function Set-CIS_18_7_4 { Write-Warning '18.7.4: sin remediacion automatizada.' }
function Test-CIS_18_7_5 { New-CISResult -ControlId '18.7.5' -Title "Ensure 'Configure RPC listener settings: Protocols to allow for incoming RPC connections' is set to 'Enabled: RPC over TCP'" -Status 'ManualReviewRequired' -Notes 'Bloque RPC del Print Spooler; no se confirmo la semantica exacta de valores con suficiente certeza.' }
function Set-CIS_18_7_5 { Write-Warning '18.7.5: sin remediacion automatizada.' }
function Test-CIS_18_7_6 { New-CISResult -ControlId '18.7.6' -Title "Ensure 'Configure RPC listener settings: Authentication protocol to use for incoming RPC connections:' is set to 'Enabled: Negotiate' or higher" -Status 'ManualReviewRequired' -Notes 'Bloque RPC del Print Spooler; no se confirmo la semantica exacta de valores con suficiente certeza.' }
function Set-CIS_18_7_6 { Write-Warning '18.7.6: sin remediacion automatizada.' }
function Test-CIS_18_7_7 { New-CISResult -ControlId '18.7.7' -Title "Ensure 'Configure RPC over TCP port' is set to 'Enabled: 0'" -Status 'ManualReviewRequired' -Notes 'Bloque RPC del Print Spooler; no se confirmo la semantica exacta de valores con suficiente certeza.' }
function Set-CIS_18_7_7 { Write-Warning '18.7.7: sin remediacion automatizada.' }
function Test-CIS_18_7_8 { New-CISResult -ControlId '18.7.8' -Title "Ensure 'Configure RPC packet level privacy setting for incoming connections' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Bloque RPC del Print Spooler; no se confirmo la semantica exacta de valores con suficiente certeza.' }
function Set-CIS_18_7_8 { Write-Warning '18.7.8: sin remediacion automatizada.' }

function Test-CIS_18_7_9 { New-CISResult -ControlId '18.7.9' -Title "Ensure 'Configure Windows protected print' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de Server 2025 (Windows Protected Print Mode); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_9 { Write-Warning '18.7.9: sin remediacion automatizada.' }

# 18.7.10 y 18.7.12/18.7.13 - mitigaciones PrintNightmare clasicas (KB5005010), bien documentadas.
function Test-CIS_18_7_10 {
    Test-CISRegistryValue -ControlId '18.7.10' -Title "Ensure 'Limits print driver installation to Administrators' is set to 'Enabled'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Validator (New-CISValidatorExact 1) -ExpectedValue '1 (Enabled)'
}
function Set-CIS_18_7_10 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Type DWord -Value 1 }

function Test-CIS_18_7_11 { New-CISResult -ControlId '18.7.11' -Title "Ensure 'Manage processing of Queue-specific files' is set to 'Enabled: Limit Queue- specific files to Color profiles'" -Status 'ManualReviewRequired' -Notes 'No se identifico con certeza la clave de registro para este control. Verificar manualmente antes de automatizar.' }
function Set-CIS_18_7_11 { Write-Warning '18.7.11: sin remediacion automatizada.' }

function Test-CIS_18_7_12 {
    Test-CISRegistryValue -ControlId '18.7.12' -Title "Ensure 'Point and Print Restrictions: When installing drivers for a new connection' is set to 'Enabled: Show warning and elevation prompt'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Show warning and elevation prompt)'
}
function Set-CIS_18_7_12 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'NoWarningNoElevationOnInstall' -Type DWord -Value 0 }

function Test-CIS_18_7_13 {
    Test-CISRegistryValue -ControlId '18.7.13' -Title "Ensure 'Point and Print Restrictions: When updating drivers for an existing connection' is set to 'Enabled: Show warning and elevation prompt'" `
        -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'UpdatePromptSettings' -Validator (New-CISValidatorExact 0) -ExpectedValue '0 (Show warning and elevation prompt)'
}
function Set-CIS_18_7_13 { Set-CISRegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'UpdatePromptSettings' -Type DWord -Value 0 }

function Test-CIS_18_7_14 { New-CISResult -ControlId '18.7.14' -Title "Ensure 'Require IPPS for IPP printers' is set to 'Enabled'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de impresion IPP sobre TLS (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_14 { Write-Warning '18.7.14: sin remediacion automatizada.' }

function Test-CIS_18_7_15 { New-CISResult -ControlId '18.7.15' -Title "Ensure 'Set TLS/SSL security policy for IPP printers: Disallow invalid certificate authority' is set to 'Enabled: Checked'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de impresion IPP sobre TLS (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_15 { Write-Warning '18.7.15: sin remediacion automatizada.' }
function Test-CIS_18_7_16 { New-CISResult -ControlId '18.7.16' -Title "Ensure 'Set TLS/SSL security policy for IPP printers: Disallow non-server certificates' is set to 'Enabled: Checked'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de impresion IPP sobre TLS (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_16 { Write-Warning '18.7.16: sin remediacion automatizada.' }
function Test-CIS_18_7_17 { New-CISResult -ControlId '18.7.17' -Title "Ensure 'Set TLS/SSL security policy for IPP printers: Disallow invalid certificate common name' is set to 'Enabled: Checked'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de impresion IPP sobre TLS (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_17 { Write-Warning '18.7.17: sin remediacion automatizada.' }
function Test-CIS_18_7_18 { New-CISResult -ControlId '18.7.18' -Title "Ensure 'Set TLS/SSL security policy for IPP printers: Disallow invalid certificate date' is set to 'Enabled: Checked'" -Status 'ManualReviewRequired' -Notes 'Funcionalidad nueva de impresion IPP sobre TLS (Server 2025); no se confirmo la clave de registro con certeza.' }
function Set-CIS_18_7_18 { Write-Warning '18.7.18: sin remediacion automatizada.' }
