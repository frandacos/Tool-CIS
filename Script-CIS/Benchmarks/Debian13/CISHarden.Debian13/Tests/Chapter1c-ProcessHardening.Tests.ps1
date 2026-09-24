#Requires -Modules Pester
<# Tests de 1.5 Process Hardening (Debian 13). Motores de Core y helpers privados mockeados. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 1.5 - Process Hardening (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {

        Context 'sysctl' {
            It 'Cada control usa la clave y los valores aceptados del benchmark' {
                $expected = @{
                    '1_5_1' = 'fs.protected_hardlinks|1'; '1_5_2' = 'fs.protected_symlinks|1'; '1_5_3' = 'kernel.yama.ptrace_scope|1,2,3'
                    '1_5_4' = 'fs.suid_dumpable|0'; '1_5_5' = 'kernel.dmesg_restrict|1'; '1_5_8' = 'kernel.kptr_restrict|1,2'
                    '1_5_9' = 'kernel.randomize_va_space|2'; '1_5_10' = 'kernel.yama.ptrace_scope|1,2,3'
                }
                foreach ($id in $expected.Keys) {
                    $script:seen = $null
                    Mock Test-CISSysctlSetting { $script:seen = "$Key|$($Value -join ',')"; [pscustomobject]@{ Compliant = $true; Running = '1'; Persisted = '1'; File = 'f' } }
                    (& "Test-CIS_Debian13_$id").Status | Should -Be 'Pass'
                    $script:seen | Should -Be $expected[$id] -Because $id
                }
            }
            It 'Fail cuando no cumple (ejecucion o persistencia)' {
                Mock Test-CISSysctlSetting { [pscustomobject]@{ Compliant = $false; Running = '1'; Persisted = $null; File = $null } }
                (Test-CIS_Debian13_1_5_9).Status | Should -Be 'Fail'
            }
            It 'Set usa Set-CISSysctlEnforced con el valor de remediacion' {
                Mock Set-CISSysctlEnforced { }
                Set-CIS_Debian13_1_5_8
                Should -Invoke Set-CISSysctlEnforced -ParameterFilter { $Key -eq 'kernel.kptr_restrict' -and $Value -eq '2' -and $AcceptValues -contains '1' }
            }
        }

        Context '1.5.6 prelink / 1.5.7 apport' {
            It 'prelink instalado = Fail' {
                Mock Test-CISPackageInstalled { $true }; (Test-CIS_Debian13_1_5_6).Status | Should -Be 'Fail'
                Mock Test-CISPackageInstalled { $false }; (Test-CIS_Debian13_1_5_6).Status | Should -Be 'Pass'
            }
            It 'apport no instalado = Pass' {
                Mock Test-CISPackageInstalled { $false }; (Test-CIS_Debian13_1_5_7).Status | Should -Be 'Pass'
            }
            It 'apport instalado: Fail si enabled!=0 o servicio activo' {
                Mock Test-CISPackageInstalled { $true }
                Mock Test-CISFileContains { $true }; Mock Test-CISServiceActive { $false }
                (Test-CIS_Debian13_1_5_7).Status | Should -Be 'Fail'
                Mock Test-CISFileContains { $false }; Mock Test-CISServiceActive { $true }
                (Test-CIS_Debian13_1_5_7).Status | Should -Be 'Fail'
                Mock Test-CISServiceActive { $false }
                (Test-CIS_Debian13_1_5_7).Status | Should -Be 'Pass'
            }
        }

        Context '1.5.11 core file size' {
            It 'Pass con * hard core 0 y sin valores mayores' {
                Mock Get-Debian13CoreLimitLines { [pscustomobject]@{ File = 'a'; Value = '0' } }
                (Test-CIS_Debian13_1_5_11).Status | Should -Be 'Pass'
            }
            It 'Fail sin limite o con valor > 0' {
                Mock Get-Debian13CoreLimitLines { }
                (Test-CIS_Debian13_1_5_11).Status | Should -Be 'Fail'
                Mock Get-Debian13CoreLimitLines { [pscustomobject]@{ File = 'a'; Value = '0' }; [pscustomobject]@{ File = 'b'; Value = '1000' } }
                (Test-CIS_Debian13_1_5_11).Status | Should -Be 'Fail'
            }
        }

        Context '1.5.12 / 1.5.13 systemd-coredump' {
            It 'Pass si el paquete no esta instalado' {
                Mock Test-CISPackageInstalled { $false }
                (Test-CIS_Debian13_1_5_12).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_1_5_13).Status | Should -Be 'Pass'
            }
            It 'Valida ProcessSizeMax=0 y Storage=none' {
                Mock Test-CISPackageInstalled { $true }
                Mock Get-CISSystemdConfigValue { [pscustomobject]@{ Value = $(if ($Option -eq 'Storage') { 'none' } else { '0' }); File = 'f'; IsDefault = $false } }
                (Test-CIS_Debian13_1_5_12).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_1_5_13).Status | Should -Be 'Pass'
                Mock Get-CISSystemdConfigValue { [pscustomobject]@{ Value = 'external'; File = 'f'; IsDefault = $true } }
                (Test-CIS_Debian13_1_5_13).Status | Should -Be 'Fail'
                Mock Get-CISSystemdConfigValue { $null }
                (Test-CIS_Debian13_1_5_12).Status | Should -Be 'Fail'
            }
        }
    }
}
