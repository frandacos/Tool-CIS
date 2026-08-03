# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 2.2
# User Rights Assignment (48 controles). Fuente: cis2025.md paginas 63-158.
# Todos via secedit /areas USER_RIGHTS ([Privilege Rights]); constantes
# SeXxxPrivilege/SeXxxLogonRight son las oficiales de Microsoft (estables,
# usadas por el propio benchmark). Los principals esperados vienen textuales
# del titulo de cada recomendacion (ya validados 1 a 1 contra el inventario
# de 454 controles) y se resuelven a SID en tiempo de ejecucion contra el
# servidor real -- nunca se hardcodea un SID.
#
# Helper interno para no repetir el chequeo de rol DC/MS en las 48 funciones.

function Test-CISScopedUserRight {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$RightConstant,
        [string[]]$ExpectedPrincipals = @(),
        [switch]$MustInclude,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )
    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'NotApplicable' `
            -Notes "Control marcado ($Scope only) en el benchmark; este equipo no es $Scope."
    }
    Test-CISUserRight -ControlId $ControlId -Title $Title -RightConstant $RightConstant `
        -ExpectedPrincipals $ExpectedPrincipals -MustInclude:$MustInclude
}

function Set-CISScopedUserRight {
    param(
        [Parameter(Mandatory)][string]$RightConstant,
        [string[]]$ExpectedPrincipals = @(),
        [switch]$MustInclude,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )
    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        Write-Warning "$RightConstant es ($Scope only): no se aplica en este equipo."
        return
    }
    Set-CISUserRight -RightConstant $RightConstant -ExpectedPrincipals $ExpectedPrincipals -MustInclude:$MustInclude
}

# 2.2.1
function Test-CIS_WS2025_2_2_1 { Test-CISScopedUserRight -ControlId '2.2.1' -Title "Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -RightConstant 'SeTrustedCredManAccessPrivilege' }
function Set-CIS_WS2025_2_2_1  { Set-CISScopedUserRight -RightConstant 'SeTrustedCredManAccessPrivilege' }

# 2.2.2 (DC only)
function Test-CIS_WS2025_2_2_2 { Test-CISScopedUserRight -ControlId '2.2.2' -Title "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS' (DC only)" -RightConstant 'SeNetworkLogonRight' -ExpectedPrincipals 'Administrators', 'Authenticated Users', 'ENTERPRISE DOMAIN CONTROLLERS' -Scope DC }
function Set-CIS_WS2025_2_2_2  { Set-CISScopedUserRight -RightConstant 'SeNetworkLogonRight' -ExpectedPrincipals 'Administrators', 'Authenticated Users', 'ENTERPRISE DOMAIN CONTROLLERS' -Scope DC }

# 2.2.3 (MS only)
function Test-CIS_WS2025_2_2_3 { Test-CISScopedUserRight -ControlId '2.2.3' -Title "Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users' (MS only)" -RightConstant 'SeNetworkLogonRight' -ExpectedPrincipals 'Administrators', 'Authenticated Users' -Scope MS }
function Set-CIS_WS2025_2_2_3  { Set-CISScopedUserRight -RightConstant 'SeNetworkLogonRight' -ExpectedPrincipals 'Administrators', 'Authenticated Users' -Scope MS }

# 2.2.4
function Test-CIS_WS2025_2_2_4 { Test-CISScopedUserRight -ControlId '2.2.4' -Title "Ensure 'Act as part of the operating system' is set to 'No One'" -RightConstant 'SeTcbPrivilege' }
function Set-CIS_WS2025_2_2_4  { Set-CISScopedUserRight -RightConstant 'SeTcbPrivilege' }

# 2.2.5 (DC only)
function Test-CIS_WS2025_2_2_5 { Test-CISScopedUserRight -ControlId '2.2.5' -Title "Ensure 'Add workstations to domain' is set to 'Administrators' (DC only)" -RightConstant 'SeMachineAccountPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }
function Set-CIS_WS2025_2_2_5  { Set-CISScopedUserRight -RightConstant 'SeMachineAccountPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }

# 2.2.6
function Test-CIS_WS2025_2_2_6 { Test-CISScopedUserRight -ControlId '2.2.6' -Title "Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'" -RightConstant 'SeIncreaseQuotaPrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE' }
function Set-CIS_WS2025_2_2_6  { Set-CISScopedUserRight -RightConstant 'SeIncreaseQuotaPrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE' }

# 2.2.7 (DC only)
function Test-CIS_WS2025_2_2_7 { Test-CISScopedUserRight -ControlId '2.2.7' -Title "Ensure 'Allow log on locally' is set to 'Administrators, ENTERPRISE DOMAIN CONTROLLERS' (DC only)" -RightConstant 'SeInteractiveLogonRight' -ExpectedPrincipals 'Administrators', 'ENTERPRISE DOMAIN CONTROLLERS' -Scope DC }
function Set-CIS_WS2025_2_2_7  { Set-CISScopedUserRight -RightConstant 'SeInteractiveLogonRight' -ExpectedPrincipals 'Administrators', 'ENTERPRISE DOMAIN CONTROLLERS' -Scope DC }

# 2.2.8 (MS only)
function Test-CIS_WS2025_2_2_8 { Test-CISScopedUserRight -ControlId '2.2.8' -Title "Ensure 'Allow log on locally' is set to 'Administrators' (MS only)" -RightConstant 'SeInteractiveLogonRight' -ExpectedPrincipals 'Administrators' -Scope MS }
function Set-CIS_WS2025_2_2_8  { Set-CISScopedUserRight -RightConstant 'SeInteractiveLogonRight' -ExpectedPrincipals 'Administrators' -Scope MS }

# 2.2.9 (DC only)
function Test-CIS_WS2025_2_2_9 { Test-CISScopedUserRight -ControlId '2.2.9' -Title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators' (DC only)" -RightConstant 'SeRemoteInteractiveLogonRight' -ExpectedPrincipals 'Administrators' -Scope DC }
function Set-CIS_WS2025_2_2_9  { Set-CISScopedUserRight -RightConstant 'SeRemoteInteractiveLogonRight' -ExpectedPrincipals 'Administrators' -Scope DC }

# 2.2.10 (MS only)
function Test-CIS_WS2025_2_2_10 { Test-CISScopedUserRight -ControlId '2.2.10' -Title "Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users' (MS only)" -RightConstant 'SeRemoteInteractiveLogonRight' -ExpectedPrincipals 'Administrators', 'Remote Desktop Users' -Scope MS }
function Set-CIS_WS2025_2_2_10  { Set-CISScopedUserRight -RightConstant 'SeRemoteInteractiveLogonRight' -ExpectedPrincipals 'Administrators', 'Remote Desktop Users' -Scope MS }

# 2.2.11
function Test-CIS_WS2025_2_2_11 { Test-CISScopedUserRight -ControlId '2.2.11' -Title "Ensure 'Back up files and directories' is set to 'Administrators'" -RightConstant 'SeBackupPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_11  { Set-CISScopedUserRight -RightConstant 'SeBackupPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.12
function Test-CIS_WS2025_2_2_12 { Test-CISScopedUserRight -ControlId '2.2.12' -Title "Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" -RightConstant 'SeSystemtimePrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE' }
function Set-CIS_WS2025_2_2_12  { Set-CISScopedUserRight -RightConstant 'SeSystemtimePrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE' }

# 2.2.13
function Test-CIS_WS2025_2_2_13 { Test-CISScopedUserRight -ControlId '2.2.13' -Title "Ensure 'Create a pagefile' is set to 'Administrators'" -RightConstant 'SeCreatePagefilePrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_13  { Set-CISScopedUserRight -RightConstant 'SeCreatePagefilePrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.14
function Test-CIS_WS2025_2_2_14 { Test-CISScopedUserRight -ControlId '2.2.14' -Title "Ensure 'Create a token object' is set to 'No One'" -RightConstant 'SeCreateTokenPrivilege' }
function Set-CIS_WS2025_2_2_14  { Set-CISScopedUserRight -RightConstant 'SeCreateTokenPrivilege' }

# 2.2.15
function Test-CIS_WS2025_2_2_15 { Test-CISScopedUserRight -ControlId '2.2.15' -Title "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -RightConstant 'SeCreateGlobalPrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE' }
function Set-CIS_WS2025_2_2_15  { Set-CISScopedUserRight -RightConstant 'SeCreateGlobalPrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE' }

# 2.2.16
function Test-CIS_WS2025_2_2_16 { Test-CISScopedUserRight -ControlId '2.2.16' -Title "Ensure 'Create permanent shared objects' is set to 'No One'" -RightConstant 'SeCreatePermanentPrivilege' }
function Set-CIS_WS2025_2_2_16  { Set-CISScopedUserRight -RightConstant 'SeCreatePermanentPrivilege' }

# 2.2.17 (DC only)
function Test-CIS_WS2025_2_2_17 { Test-CISScopedUserRight -ControlId '2.2.17' -Title "Ensure 'Create symbolic links' is set to 'Administrators' (DC only)" -RightConstant 'SeCreateSymbolicLinkPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }
function Set-CIS_WS2025_2_2_17  { Set-CISScopedUserRight -RightConstant 'SeCreateSymbolicLinkPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }

# 2.2.18 (MS only)
function Test-CIS_WS2025_2_2_18 { Test-CISScopedUserRight -ControlId '2.2.18' -Title "Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines' (MS only)" -RightConstant 'SeCreateSymbolicLinkPrivilege' -ExpectedPrincipals 'Administrators', 'NT VIRTUAL MACHINE\Virtual Machines' -Scope MS }
function Set-CIS_WS2025_2_2_18  { Set-CISScopedUserRight -RightConstant 'SeCreateSymbolicLinkPrivilege' -ExpectedPrincipals 'Administrators', 'NT VIRTUAL MACHINE\Virtual Machines' -Scope MS }

# 2.2.19
function Test-CIS_WS2025_2_2_19 { Test-CISScopedUserRight -ControlId '2.2.19' -Title "Ensure 'Debug programs' is set to 'Administrators'" -RightConstant 'SeDebugPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_19  { Set-CISScopedUserRight -RightConstant 'SeDebugPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.20 (DC only) - Deny right: must include
function Test-CIS_WS2025_2_2_20 { Test-CISScopedUserRight -ControlId '2.2.20' -Title "Ensure 'Deny access to this computer from the network' to include 'Guests' (DC only)" -RightConstant 'SeDenyNetworkLogonRight' -ExpectedPrincipals 'Guests' -MustInclude -Scope DC }
function Set-CIS_WS2025_2_2_20  { Set-CISScopedUserRight -RightConstant 'SeDenyNetworkLogonRight' -ExpectedPrincipals 'Guests' -MustInclude -Scope DC }

# 2.2.21 (MS only) - Deny right: must include
function Test-CIS_WS2025_2_2_21 { Test-CISScopedUserRight -ControlId '2.2.21' -Title "Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group' (MS only)" -RightConstant 'SeDenyNetworkLogonRight' -ExpectedPrincipals 'Guests', 'Local account and member of Administrators group' -MustInclude -Scope MS }
function Set-CIS_WS2025_2_2_21  { Set-CISScopedUserRight -RightConstant 'SeDenyNetworkLogonRight' -ExpectedPrincipals 'Guests', 'Local account and member of Administrators group' -MustInclude -Scope MS }

# 2.2.22 - Deny right: must include
function Test-CIS_WS2025_2_2_22 { Test-CISScopedUserRight -ControlId '2.2.22' -Title "Ensure 'Deny log on as a batch job' to include 'Guests'" -RightConstant 'SeDenyBatchLogonRight' -ExpectedPrincipals 'Guests' -MustInclude }
function Set-CIS_WS2025_2_2_22  { Set-CISScopedUserRight -RightConstant 'SeDenyBatchLogonRight' -ExpectedPrincipals 'Guests' -MustInclude }

# 2.2.23 - Deny right: must include
function Test-CIS_WS2025_2_2_23 { Test-CISScopedUserRight -ControlId '2.2.23' -Title "Ensure 'Deny log on as a service' to include 'Guests'" -RightConstant 'SeDenyServiceLogonRight' -ExpectedPrincipals 'Guests' -MustInclude }
function Set-CIS_WS2025_2_2_23  { Set-CISScopedUserRight -RightConstant 'SeDenyServiceLogonRight' -ExpectedPrincipals 'Guests' -MustInclude }

# 2.2.24 - Deny right: must include
function Test-CIS_WS2025_2_2_24 { Test-CISScopedUserRight -ControlId '2.2.24' -Title "Ensure 'Deny log on locally' to include 'Guests'" -RightConstant 'SeDenyInteractiveLogonRight' -ExpectedPrincipals 'Guests' -MustInclude }
function Set-CIS_WS2025_2_2_24  { Set-CISScopedUserRight -RightConstant 'SeDenyInteractiveLogonRight' -ExpectedPrincipals 'Guests' -MustInclude }

# 2.2.25 (DC only) - Deny right: must include
function Test-CIS_WS2025_2_2_25 { Test-CISScopedUserRight -ControlId '2.2.25' -Title "Ensure 'Deny log on through Remote Desktop Services' to include 'Guests' (DC only)" -RightConstant 'SeDenyRemoteInteractiveLogonRight' -ExpectedPrincipals 'Guests' -MustInclude -Scope DC }
function Set-CIS_WS2025_2_2_25  { Set-CISScopedUserRight -RightConstant 'SeDenyRemoteInteractiveLogonRight' -ExpectedPrincipals 'Guests' -MustInclude -Scope DC }

# 2.2.26 (MS only) - Deny right: must include
function Test-CIS_WS2025_2_2_26 { Test-CISScopedUserRight -ControlId '2.2.26' -Title "Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account' (MS only)" -RightConstant 'SeDenyRemoteInteractiveLogonRight' -ExpectedPrincipals 'Guests', 'Local account' -MustInclude -Scope MS }
function Set-CIS_WS2025_2_2_26  { Set-CISScopedUserRight -RightConstant 'SeDenyRemoteInteractiveLogonRight' -ExpectedPrincipals 'Guests', 'Local account' -MustInclude -Scope MS }

# 2.2.27 (DC only)
function Test-CIS_WS2025_2_2_27 { Test-CISScopedUserRight -ControlId '2.2.27' -Title "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators' (DC only)" -RightConstant 'SeEnableDelegationPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }
function Set-CIS_WS2025_2_2_27  { Set-CISScopedUserRight -RightConstant 'SeEnableDelegationPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }

# 2.2.28 (MS only) - recuperado del bug de parseo (form-feed en el TOC)
function Test-CIS_WS2025_2_2_28 { Test-CISScopedUserRight -ControlId '2.2.28' -Title "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One' (MS only)" -RightConstant 'SeEnableDelegationPrivilege' -Scope MS }
function Set-CIS_WS2025_2_2_28  { Set-CISScopedUserRight -RightConstant 'SeEnableDelegationPrivilege' -Scope MS }

# 2.2.29
function Test-CIS_WS2025_2_2_29 { Test-CISScopedUserRight -ControlId '2.2.29' -Title "Ensure 'Force shutdown from a remote system' is set to 'Administrators'" -RightConstant 'SeRemoteShutdownPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_29  { Set-CISScopedUserRight -RightConstant 'SeRemoteShutdownPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.30
function Test-CIS_WS2025_2_2_30 { Test-CISScopedUserRight -ControlId '2.2.30' -Title "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE, RESTRICTED SERVICES\PrintSpoolerService'" -RightConstant 'SeAuditPrivilege' -ExpectedPrincipals 'LOCAL SERVICE', 'NETWORK SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService' }
function Set-CIS_WS2025_2_2_30  { Set-CISScopedUserRight -RightConstant 'SeAuditPrivilege' -ExpectedPrincipals 'LOCAL SERVICE', 'NETWORK SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService' }

# 2.2.31 (DC only)
function Test-CIS_WS2025_2_2_31 { Test-CISScopedUserRight -ControlId '2.2.31' -Title "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\PrintSpoolerService' (DC only)" -RightConstant 'SeImpersonatePrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService' -Scope DC }
function Set-CIS_WS2025_2_2_31  { Set-CISScopedUserRight -RightConstant 'SeImpersonatePrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService' -Scope DC }

# 2.2.32 (MS only)
function Test-CIS_WS2025_2_2_32 { Test-CISScopedUserRight -ControlId '2.2.32' -Title "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE, RESTRICTED SERVICES\PrintSpoolerService, IIS_IUSRS' (MS only)" -RightConstant 'SeImpersonatePrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService', 'IIS_IUSRS' -Scope MS }
function Set-CIS_WS2025_2_2_32  { Set-CISScopedUserRight -RightConstant 'SeImpersonatePrivilege' -ExpectedPrincipals 'Administrators', 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE', 'RESTRICTED SERVICES\PrintSpoolerService', 'IIS_IUSRS' -Scope MS }

# 2.2.33
function Test-CIS_WS2025_2_2_33 { Test-CISScopedUserRight -ControlId '2.2.33' -Title "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'" -RightConstant 'SeIncreaseBasePriorityPrivilege' -ExpectedPrincipals 'Administrators', 'Window Manager\Window Manager Group' }
function Set-CIS_WS2025_2_2_33  { Set-CISScopedUserRight -RightConstant 'SeIncreaseBasePriorityPrivilege' -ExpectedPrincipals 'Administrators', 'Window Manager\Window Manager Group' }

# 2.2.34
function Test-CIS_WS2025_2_2_34 { Test-CISScopedUserRight -ControlId '2.2.34' -Title "Ensure 'Load and unload device drivers' is set to 'Administrators'" -RightConstant 'SeLoadDriverPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_34  { Set-CISScopedUserRight -RightConstant 'SeLoadDriverPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.35
function Test-CIS_WS2025_2_2_35 { Test-CISScopedUserRight -ControlId '2.2.35' -Title "Ensure 'Lock pages in memory' is set to 'No One'" -RightConstant 'SeLockMemoryPrivilege' }
function Set-CIS_WS2025_2_2_35  { Set-CISScopedUserRight -RightConstant 'SeLockMemoryPrivilege' }

# 2.2.36 (DC only)
function Test-CIS_WS2025_2_2_36 { Test-CISScopedUserRight -ControlId '2.2.36' -Title "Ensure 'Log on as a batch job' is set to 'Administrators' (DC Only)" -RightConstant 'SeBatchLogonRight' -ExpectedPrincipals 'Administrators' -Scope DC }
function Set-CIS_WS2025_2_2_36  { Set-CISScopedUserRight -RightConstant 'SeBatchLogonRight' -ExpectedPrincipals 'Administrators' -Scope DC }

# 2.2.37 (DC only)
function Test-CIS_WS2025_2_2_37 { Test-CISScopedUserRight -ControlId '2.2.37' -Title "Ensure 'Manage auditing and security log' is set to 'Administrators' (DC only)" -RightConstant 'SeSecurityPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }
function Set-CIS_WS2025_2_2_37  { Set-CISScopedUserRight -RightConstant 'SeSecurityPrivilege' -ExpectedPrincipals 'Administrators' -Scope DC }

# 2.2.38 (MS only)
function Test-CIS_WS2025_2_2_38 { Test-CISScopedUserRight -ControlId '2.2.38' -Title "Ensure 'Manage auditing and security log' is set to 'Administrators' (MS only)" -RightConstant 'SeSecurityPrivilege' -ExpectedPrincipals 'Administrators' -Scope MS }
function Set-CIS_WS2025_2_2_38  { Set-CISScopedUserRight -RightConstant 'SeSecurityPrivilege' -ExpectedPrincipals 'Administrators' -Scope MS }

# 2.2.39
function Test-CIS_WS2025_2_2_39 { Test-CISScopedUserRight -ControlId '2.2.39' -Title "Ensure 'Modify an object label' is set to 'No One'" -RightConstant 'SeRelabelPrivilege' }
function Set-CIS_WS2025_2_2_39  { Set-CISScopedUserRight -RightConstant 'SeRelabelPrivilege' }

# 2.2.40
function Test-CIS_WS2025_2_2_40 { Test-CISScopedUserRight -ControlId '2.2.40' -Title "Ensure 'Modify firmware environment values' is set to 'Administrators'" -RightConstant 'SeSystemEnvironmentPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_40  { Set-CISScopedUserRight -RightConstant 'SeSystemEnvironmentPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.41
function Test-CIS_WS2025_2_2_41 { Test-CISScopedUserRight -ControlId '2.2.41' -Title "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'" -RightConstant 'SeManageVolumePrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_41  { Set-CISScopedUserRight -RightConstant 'SeManageVolumePrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.42
function Test-CIS_WS2025_2_2_42 { Test-CISScopedUserRight -ControlId '2.2.42' -Title "Ensure 'Profile single process' is set to 'Administrators'" -RightConstant 'SeProfileSingleProcessPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_42  { Set-CISScopedUserRight -RightConstant 'SeProfileSingleProcessPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.43
function Test-CIS_WS2025_2_2_43 { Test-CISScopedUserRight -ControlId '2.2.43' -Title "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'" -RightConstant 'SeSystemProfilePrivilege' -ExpectedPrincipals 'Administrators', 'NT SERVICE\WdiServiceHost' }
function Set-CIS_WS2025_2_2_43  { Set-CISScopedUserRight -RightConstant 'SeSystemProfilePrivilege' -ExpectedPrincipals 'Administrators', 'NT SERVICE\WdiServiceHost' }

# 2.2.44
function Test-CIS_WS2025_2_2_44 { Test-CISScopedUserRight -ControlId '2.2.44' -Title "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -RightConstant 'SeAssignPrimaryTokenPrivilege' -ExpectedPrincipals 'LOCAL SERVICE', 'NETWORK SERVICE' }
function Set-CIS_WS2025_2_2_44  { Set-CISScopedUserRight -RightConstant 'SeAssignPrimaryTokenPrivilege' -ExpectedPrincipals 'LOCAL SERVICE', 'NETWORK SERVICE' }

# 2.2.45
function Test-CIS_WS2025_2_2_45 { Test-CISScopedUserRight -ControlId '2.2.45' -Title "Ensure 'Restore files and directories' is set to 'Administrators'" -RightConstant 'SeRestorePrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_45  { Set-CISScopedUserRight -RightConstant 'SeRestorePrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.46
function Test-CIS_WS2025_2_2_46 { Test-CISScopedUserRight -ControlId '2.2.46' -Title "Ensure 'Shut down the system' is set to 'Administrators'" -RightConstant 'SeShutdownPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_46  { Set-CISScopedUserRight -RightConstant 'SeShutdownPrivilege' -ExpectedPrincipals 'Administrators' }

# 2.2.47 (DC only)
function Test-CIS_WS2025_2_2_47 { Test-CISScopedUserRight -ControlId '2.2.47' -Title "Ensure 'Synchronize directory service data' is set to 'No One' (DC only)" -RightConstant 'SeSyncAgentPrivilege' -Scope DC }
function Set-CIS_WS2025_2_2_47  { Set-CISScopedUserRight -RightConstant 'SeSyncAgentPrivilege' -Scope DC }

# 2.2.48
function Test-CIS_WS2025_2_2_48 { Test-CISScopedUserRight -ControlId '2.2.48' -Title "Ensure 'Take ownership of files or other objects' is set to 'Administrators'" -RightConstant 'SeTakeOwnershipPrivilege' -ExpectedPrincipals 'Administrators' }
function Set-CIS_WS2025_2_2_48  { Set-CISScopedUserRight -RightConstant 'SeTakeOwnershipPrivilege' -ExpectedPrincipals 'Administrators' }
