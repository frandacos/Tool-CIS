#Requires -Modules Pester
<#
    Tests de 1.1.x (Filesystem, Debian 13). Se mockean los motores de Core
    (Test-CISKernelModuleDisabled, Test-CISPartitionExists, Test-CISMountOption)
    para validar la logica Pass/Fail sin una Debian real. Las funciones
    Test-CIS_Debian13_* son privadas del modulo: todo corre en InModuleScope.
#>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 1.1 - Filesystem (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {

        Context '1.1.1.x kernel modules' {
            It 'Pass cuando el modulo esta deshabilitado' {
                Mock Test-CISKernelModuleDisabled { [pscustomobject]@{ Disabled = $true; Loadable = $false; Loaded = $false; Blacklisted = $true; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian13_1_1_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando el modulo sigue cargable' {
                Mock Test-CISKernelModuleDisabled { [pscustomobject]@{ Disabled = $false; Loadable = $true; Loaded = $false; Blacklisted = $false; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian13_1_1_1_1).Status | Should -Be 'Fail'
            }
            It 'overlay usa DirName overlayfs' {
                Mock Test-CISKernelModuleDisabled { [pscustomobject]@{ Disabled = ($Module -eq 'overlay' -and $DirName -eq 'overlayfs'); Loadable = $false; Loaded = $false; Blacklisted = $true; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian13_1_1_1_6).Status | Should -Be 'Pass'
            }
            It 'firewire-core y usb-storage usan Type=drivers' {
                Mock Test-CISKernelModuleDisabled { [pscustomobject]@{ Disabled = ($Type -eq 'drivers'); Loadable = $false; Loaded = $false; Blacklisted = $true; ExistsInRunningKernel = $true } }
                (Test-CIS_Debian13_1_1_1_9).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_1_1_1_10).Status | Should -Be 'Pass'
            }
            It '1.1.1.11 es ManualReviewRequired' {
                (Test-CIS_Debian13_1_1_1_11).Status | Should -Be 'ManualReviewRequired'
            }
        }

        Context '1.1.2.1.1 /tmp' {
            It 'Pass si /tmp esta montado y tmp.mount no esta masked' {
                Mock Test-CISPartitionExists { $true }
                Mock Get-Debian13TmpMountUnitState { 'generated' }
                (Test-CIS_Debian13_1_1_2_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail si tmp.mount esta masked' {
                Mock Test-CISPartitionExists { $true }
                Mock Get-Debian13TmpMountUnitState { 'masked' }
                (Test-CIS_Debian13_1_1_2_1_1).Status | Should -Be 'Fail'
            }
            It 'Fail si /tmp no esta montado' {
                Mock Test-CISPartitionExists { $false }
                Mock Get-Debian13TmpMountUnitState { 'generated' }
                (Test-CIS_Debian13_1_1_2_1_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Particiones separadas y opciones de montaje' {
            It 'Pass/Fail de particion separada (/home)' {
                Mock Test-CISPartitionExists { $true }
                (Test-CIS_Debian13_1_1_2_3_1).Status | Should -Be 'Pass'
                Mock Test-CISPartitionExists { $false }
                (Test-CIS_Debian13_1_1_2_3_1).Status | Should -Be 'Fail'
            }
            It 'Mapea cada control de opcion al mount point y opcion correctos' {
                $expected = @{
                    '1.1.2.1.2' = '/tmp|nodev'; '1.1.2.1.4' = '/tmp|noexec'; '1.1.2.2.3' = '/dev/shm|nosuid'
                    '1.1.2.3.3' = '/home|nosuid'; '1.1.2.4.2' = '/var|nodev'; '1.1.2.5.4' = '/var/tmp|noexec'
                    '1.1.2.6.2' = '/var/log|nodev'; '1.1.2.7.4' = '/var/log/audit|noexec'
                }
                Mock Test-CISPartitionExists { $true }
                foreach ($id in $expected.Keys) {
                    $mp, $opt = $expected[$id] -split '\|'
                    $script:seen = $null
                    Mock Test-CISMountOption { $script:seen = "$Path|$Option"; $true }
                    $fn = "Test-CIS_Debian13_$($id -replace '\.', '_')"
                    (& $fn).Status | Should -Be 'Pass'
                    $script:seen | Should -Be "$mp|$opt" -Because $id
                }
            }
            It 'Fail cuando falta la opcion' {
                Mock Test-CISPartitionExists { $true }
                Mock Test-CISMountOption { $false }
                (Test-CIS_Debian13_1_1_2_1_3).Status | Should -Be 'Fail'
            }
        }
    }
}
