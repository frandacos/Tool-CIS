#Requires -Modules Pester
<# Tests de 1.4.x (Secure Boot Settings) y 1.5.x (Additional Process Hardening). Ver Chapter1a-*.Tests.ps1 para la nota sobre mockeo de motores de Core. #>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian10.psd1') -Force
}

Describe 'Chapter 1.4 - Secure Boot Settings' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.4.1 Bootloader password' {
            It 'Pass cuando superusers y password estan definidos' {
                Mock Test-CISFileContains { $true }
                (Test-CIS_Debian10_1_4_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta alguno' {
                Mock Test-CISFileContains { param($Path, $Pattern) $Pattern -eq '^set superusers' }
                (Test-CIS_Debian10_1_4_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.4.2 Permisos de grub.cfg' {
            It 'Pass con 0600 root:root' {
                Mock Get-CISFileMode { '600' }
                Mock Get-CISFileOwner { 'root:root' }
                (Test-CIS_Debian10_1_4_2).Status | Should -Be 'Pass'
            }
            It 'Fail con permisos mas laxos' {
                Mock Get-CISFileMode { '644' }
                Mock Get-CISFileOwner { 'root:root' }
                (Test-CIS_Debian10_1_4_2).Status | Should -Be 'Fail'
            }
        }

        Context '1.4.3 Password requerido en single user mode' {
            It 'Pass cuando root tiene hash de password' {
                Mock Test-CISFileContains { $true }
                (Test-CIS_Debian10_1_4_3).Status | Should -Be 'Pass'
            }
            It 'Fail cuando root no tiene password' {
                Mock Test-CISFileContains { $false }
                (Test-CIS_Debian10_1_4_3).Status | Should -Be 'Fail'
            }
        }
    }
}

Describe 'Chapter 1.5 - Additional Process Hardening' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.5.1 ASLR' {
            It 'Pass cuando kernel.randomize_va_space = 2' {
                Mock Get-CISSysctlValue { '2' }
                (Test-CIS_Debian10_1_5_1).Status | Should -Be 'Pass'
            }
            It 'Fail con cualquier otro valor' {
                Mock Get-CISSysctlValue { '0' }
                (Test-CIS_Debian10_1_5_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.5.2 ptrace_scope' {
            It 'Pass cuando kernel.yama.ptrace_scope = 1' {
                Mock Get-CISSysctlValue { '1' }
                (Test-CIS_Debian10_1_5_2).Status | Should -Be 'Pass'
            }
            It 'Fail con 0' {
                Mock Get-CISSysctlValue { '0' }
                (Test-CIS_Debian10_1_5_2).Status | Should -Be 'Fail'
            }
        }

        Context '1.5.3 prelink no instalado' {
            It 'Pass cuando prelink no esta instalado' {
                Mock Test-CISPackageInstalled { $false }
                (Test-CIS_Debian10_1_5_3).Status | Should -Be 'Pass'
            }
            It 'Fail cuando prelink esta instalado' {
                Mock Test-CISPackageInstalled { $true }
                (Test-CIS_Debian10_1_5_3).Status | Should -Be 'Fail'
            }
        }

        Context '1.5.4 Automatic Error Reporting (apport)' {
            It 'Pass cuando apport no esta instalado' {
                Mock Test-CISPackageInstalled { $false }
                (Test-CIS_Debian10_1_5_4).Status | Should -Be 'Pass'
            }
            It 'Fail cuando apport esta instalado, habilitado y activo' {
                Mock Test-CISPackageInstalled { $true }
                Mock Test-CISFileContains { $true }
                Mock Test-CISServiceActive { $true }
                (Test-CIS_Debian10_1_5_4).Status | Should -Be 'Fail'
            }
            It 'Pass cuando apport esta instalado pero deshabilitado e inactivo' {
                Mock Test-CISPackageInstalled { $true }
                Mock Test-CISFileContains { $false }
                Mock Test-CISServiceActive { $false }
                (Test-CIS_Debian10_1_5_4).Status | Should -Be 'Pass'
            }
        }

        Context '1.5.5 Core dumps restringidos' {
            It 'Pass cuando hard core 0 esta seteado y fs.suid_dumpable = 0' {
                Mock Get-ChildItem { @() }
                Mock Test-CISFileContains { $true }
                Mock Get-CISSysctlValue { '0' }
                (Test-CIS_Debian10_1_5_5).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta la linea en limits.conf' {
                Mock Get-ChildItem { @() }
                Mock Test-CISFileContains { $false }
                Mock Get-CISSysctlValue { '0' }
                (Test-CIS_Debian10_1_5_5).Status | Should -Be 'Fail'
            }
        }
    }
}
