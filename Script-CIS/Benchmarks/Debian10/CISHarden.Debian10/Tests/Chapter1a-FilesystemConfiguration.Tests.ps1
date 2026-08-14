#Requires -Modules Pester
<#
    Tests de 1.1.x (Filesystem Configuration). Igual que en CISHarden.WS2025,
    se mockean los motores de CISHarden.Core (Test-CISKernelModuleDisabled,
    Test-CISPartitionExists, Test-CISMountOption) en vez de los binarios Unix
    de mas bajo nivel (modprobe/lsmod/findmnt) -- eso valida la logica de
    cada Test-CIS_Debian10_* (umbrales, Pass/Fail) sin necesitar una Debian
    10 real. La validacion contra un servidor real queda pendiente (ver
    PLAN.md / README.md).

    IMPORTANTE: Test-CIS_Debian10_*/Set-CIS_Debian10_* son funciones
    PRIVADAS del modulo (no exportadas), por eso todo corre dentro de
    InModuleScope 'CISHarden.Debian10'.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian10.psd1') -Force
}

Describe 'Chapter 1.1 - Filesystem Configuration' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.1.1.1 Disable cramfs' {
            It 'Pass cuando el modulo esta deshabilitado' {
                Mock Test-CISKernelModuleDisabled { [pscustomobject]@{ Disabled = $true; Loadable = $false; Loaded = $false; Blacklisted = $true; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian10_1_1_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando el modulo sigue cargable' {
                Mock Test-CISKernelModuleDisabled { [pscustomobject]@{ Disabled = $false; Loadable = $true; Loaded = $false; Blacklisted = $false; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian10_1_1_1_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.1.10 Disable USB Storage' {
            It 'Usa Type=drivers para usb-storage' {
                Mock Test-CISKernelModuleDisabled { param($Module, $Type) [pscustomobject]@{ Disabled = ($Type -eq 'drivers'); Loadable = $false; Loaded = $false; Blacklisted = $true; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian10_1_1_10).Status | Should -Be 'Pass'
            }
        }

        Context '1.1.2.1 /tmp separate partition' {
            It 'Pass cuando /tmp es un mount point propio' {
                Mock Test-CISPartitionExists { $true }
                (Test-CIS_Debian10_1_1_2_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando /tmp no es un mount point propio' {
                Mock Test-CISPartitionExists { $false }
                (Test-CIS_Debian10_1_1_2_1).Status | Should -Be 'Fail'
            }
            It 'Set-CIS_Debian10_1_1_2_1 solo advierte (no automatizable)' {
                { Set-CIS_Debian10_1_1_2_1 -WarningAction SilentlyContinue } | Should -Not -Throw
            }
        }

        Context '1.1.2.2 nodev en /tmp' {
            It 'Pass cuando nodev esta seteado' {
                Mock Test-CISMountOption { $true }
                Mock Test-CISPartitionExists { $true }
                (Test-CIS_Debian10_1_1_2_2).Status | Should -Be 'Pass'
            }
            It 'Fail cuando nodev no esta seteado' {
                Mock Test-CISMountOption { $false }
                Mock Test-CISPartitionExists { $true }
                (Test-CIS_Debian10_1_1_2_2).Status | Should -Be 'Fail'
            }
        }

        Context '1.1.9 Disable Automounting' {
            It 'Pass cuando autofs no esta instalado' {
                Mock Test-CISPackageInstalled { $false }
                (Test-CIS_Debian10_1_1_9).Status | Should -Be 'Pass'
            }
            It 'Fail cuando autofs esta instalado y habilitado' {
                Mock Test-CISPackageInstalled { $true }
                Mock Test-CISServiceEnabled { $true }
                (Test-CIS_Debian10_1_1_9).Status | Should -Be 'Fail'
            }
            It 'Pass cuando autofs esta instalado pero deshabilitado' {
                Mock Test-CISPackageInstalled { $true }
                Mock Test-CISServiceEnabled { $false }
                (Test-CIS_Debian10_1_1_9).Status | Should -Be 'Pass'
            }
        }
    }
}
