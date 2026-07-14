#Requires -Modules Pester
<#
    Tests de Etapa 2a (User Rights Assignment, 48 controles). Mockean
    Get-CISPrivilegeRights (secedit) y Resolve-CISPrincipalToSid (traduccion
    de nombre->SID) para validar la logica de Test-CIS_2_2_* sin depender de
    un Windows Server real. La validacion real en lab sigue el procedimiento
    de PLAN.md.

    IMPORTANTE: igual que en Chapter1.Tests.ps1, todo corre dentro de
    InModuleScope 'CISHarden' porque Test-CIS_2_2_*/Get-CISPrivilegeRights/
    Resolve-CISPrincipalToSid son funciones privadas del modulo -- sin esto
    los mocks no interceptan nada.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'CISHarden.psd1') -Force

    # SIDs de ejemplo fijos para no depender de traducciones reales del SO
    $Sids = @{
        'Administrators'                                     = 'S-1-5-32-544'
        'Authenticated Users'                                = 'S-1-5-11'
        'ENTERPRISE DOMAIN CONTROLLERS'                      = 'S-1-5-9'
        'Guests'                                              = 'S-1-5-32-546'
        'LOCAL SERVICE'                                       = 'S-1-5-19'
        'NETWORK SERVICE'                                     = 'S-1-5-20'
        'SERVICE'                                              = 'S-1-5-6'
        'Remote Desktop Users'                                = 'S-1-5-32-555'
        'NT VIRTUAL MACHINE\Virtual Machines'                 = 'S-1-5-83-0'
        'Local account'                                       = 'S-1-5-113'
        'Local account and member of Administrators group'    = 'S-1-5-114'
        'Window Manager\Window Manager Group'                 = 'S-1-5-90-0'
        'NT SERVICE\WdiServiceHost'                            = 'S-1-5-80-3139157870'
        'RESTRICTED SERVICES\PrintSpoolerService'              = 'S-1-5-90-1'
        'IIS_IUSRS'                                            = 'S-1-5-32-568'
    }
}

Describe 'Chapter 2.2 - User Rights Assignment' {
    InModuleScope 'CISHarden' {

        Context 'Caso simple: right exclusivo de Administrators (2.2.11 Back up files and directories)' {
            It 'Pass cuando el right tiene exactamente Administrators' {
                Mock Get-CISServerRole { 'MS' }
                Mock Resolve-CISPrincipalToSid { $Sids[$Name] }
                Mock Get-CISPrivilegeRights { @{ SeBackupPrivilege = @($Sids['Administrators']) } }
                (Test-CIS_2_2_11).Status | Should -Be 'Pass'
            }
            It 'Fail cuando el right tiene un principal de mas' {
                Mock Get-CISServerRole { 'MS' }
                Mock Resolve-CISPrincipalToSid { $Sids[$Name] }
                Mock Get-CISPrivilegeRights { @{ SeBackupPrivilege = @($Sids['Administrators'], $Sids['Guests']) } }
                (Test-CIS_2_2_11).Status | Should -Be 'Fail'
            }
        }

        Context 'Caso "No One" (2.2.4 Act as part of the operating system)' {
            It 'Pass cuando el right esta vacio' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISPrivilegeRights { @{ SeTcbPrivilege = @() } }
                (Test-CIS_2_2_4).Status | Should -Be 'Pass'
            }
            It 'Fail cuando el right tiene algun principal asignado' {
                Mock Get-CISServerRole { 'MS' }
                Mock Resolve-CISPrincipalToSid { $Sids[$Name] }
                Mock Get-CISPrivilegeRights { @{ SeTcbPrivilege = @($Sids['Administrators']) } }
                (Test-CIS_2_2_4).Status | Should -Be 'Fail'
            }
        }

        Context 'Alcance DC/MS (2.2.2 vs 2.2.3 Access this computer from the network)' {
            It '2.2.2 (DC only) es NotApplicable en un Member Server' {
                Mock Get-CISServerRole { 'MS' }
                (Test-CIS_2_2_2).Status | Should -Be 'NotApplicable'
            }
            It '2.2.3 (MS only) es NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_2_2_3).Status | Should -Be 'NotApplicable'
            }
            It '2.2.3 (MS only) hace Pass en un Member Server bien configurado' {
                Mock Get-CISServerRole { 'MS' }
                Mock Resolve-CISPrincipalToSid { $Sids[$Name] }
                Mock Get-CISPrivilegeRights { @{ SeNetworkLogonRight = @($Sids['Administrators'], $Sids['Authenticated Users']) } }
                (Test-CIS_2_2_3).Status | Should -Be 'Pass'
            }
        }

        Context 'Deny rights con semantica "to include" (2.2.20 Deny access to this computer from the network, DC only)' {
            It 'Pass cuando Guests esta incluido aunque haya otros principals' {
                Mock Get-CISServerRole { 'DC' }
                Mock Resolve-CISPrincipalToSid { $Sids[$Name] }
                Mock Get-CISPrivilegeRights { @{ SeDenyNetworkLogonRight = @($Sids['Guests'], $Sids['Administrators']) } }
                (Test-CIS_2_2_20).Status | Should -Be 'Pass'
            }
            It 'Fail cuando Guests no esta incluido' {
                Mock Get-CISServerRole { 'DC' }
                Mock Resolve-CISPrincipalToSid { $Sids[$Name] }
                Mock Get-CISPrivilegeRights { @{ SeDenyNetworkLogonRight = @($Sids['Administrators']) } }
                (Test-CIS_2_2_20).Status | Should -Be 'Fail'
            }
        }

        Context 'Principal no resoluble en este servidor (2.2.32 Impersonate..., incluye IIS_IUSRS)' {
            It 'Devuelve Error con nota clara si IIS_IUSRS no existe en el equipo' {
                Mock Get-CISServerRole { 'MS' }
                Mock Resolve-CISPrincipalToSid {
                    if ($Name -eq 'IIS_IUSRS') { return $null }
                    return $Sids[$Name]
                }
                Mock Get-CISPrivilegeRights { @{ SeImpersonatePrivilege = @($Sids['Administrators']) } }
                $result = Test-CIS_2_2_32
                $result.Status | Should -Be 'Error'
                $result.Notes | Should -Match 'IIS_IUSRS'
            }
        }

        Context 'Control recuperado del bug de parseo (2.2.28, MS only)' {
            It 'Pass cuando el right esta vacio en un Member Server' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISPrivilegeRights { @{ SeEnableDelegationPrivilege = @() } }
                (Test-CIS_2_2_28).Status | Should -Be 'Pass'
            }
            It 'NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_2_2_28).Status | Should -Be 'NotApplicable'
            }
        }

        Context 'Cobertura de la sub-etapa 2a' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 48 filas 2.2.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^2\.2\.' }
                $inventory.Count | Should -Be 48
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
