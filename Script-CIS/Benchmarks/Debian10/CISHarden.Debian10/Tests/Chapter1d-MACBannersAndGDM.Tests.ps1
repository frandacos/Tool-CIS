#Requires -Modules Pester
<# Tests de 1.6.1.x (AppArmor), 1.7.x (Banners) y 1.8.x (GDM). Ver Chapter1a-*.Tests.ps1 para la nota sobre mockeo de motores de Core. #>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian10.psd1') -Force
}

Describe 'Chapter 1.6.1 - AppArmor' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.6.1.1 AppArmor installed' {
            It 'Pass cuando apparmor y apparmor-utils estan instalados' {
                Mock Test-CISPackageInstalled { $true }
                (Test-CIS_Debian10_1_6_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta apparmor-utils' {
                Mock Test-CISPackageInstalled { param($Name) $Name -eq 'apparmor' }
                (Test-CIS_Debian10_1_6_1_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.6.1.2 AppArmor en el bootloader' {
            It 'Pass cuando todas las lineas linux tienen ambos parametros' {
                Mock Test-Path { $true }
                Mock Select-String { @([pscustomobject]@{ Line = 'linux /boot/vmlinuz apparmor=1 security=apparmor' }) }
                (Test-CIS_Debian10_1_6_1_2).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta un parametro' {
                Mock Test-Path { $true }
                Mock Select-String { @([pscustomobject]@{ Line = 'linux /boot/vmlinuz apparmor=1' }) }
                (Test-CIS_Debian10_1_6_1_2).Status | Should -Be 'Fail'
            }
        }

        Context '1.6.1.3 / 1.6.1.4 Perfiles AppArmor' {
            It '1.6.1.3 Pass cuando todos los perfiles estan en enforce o complain y nada unconfined' {
                Mock Get-Debian10AppArmorStatus { [pscustomobject]@{ Success = $true; ProfilesLoaded = 10; ProfilesEnforce = 8; ProfilesComplain = 2; ProcessesUnconf = 0 } }
                (Test-CIS_Debian10_1_6_1_3).Status | Should -Be 'Pass'
            }
            It '1.6.1.4 Fail cuando hay perfiles en complain (deben estar todos enforce)' {
                Mock Get-Debian10AppArmorStatus { [pscustomobject]@{ Success = $true; ProfilesLoaded = 10; ProfilesEnforce = 8; ProfilesComplain = 2; ProcessesUnconf = 0 } }
                (Test-CIS_Debian10_1_6_1_4).Status | Should -Be 'Fail'
            }
            It '1.6.1.4 Pass cuando todos los perfiles estan enforce' {
                Mock Get-Debian10AppArmorStatus { [pscustomobject]@{ Success = $true; ProfilesLoaded = 10; ProfilesEnforce = 10; ProfilesComplain = 0; ProcessesUnconf = 0 } }
                (Test-CIS_Debian10_1_6_1_4).Status | Should -Be 'Pass'
            }
        }
    }
}

Describe 'Chapter 1.7 - Command Line Warning Banners' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.7.1 motd sin info de SO' {
            It 'Pass cuando no hay escapes de info de SO' {
                Mock Test-CISFileContains { $false }
                (Test-CIS_Debian10_1_7_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando el motd filtra info de SO' {
                Mock Test-CISFileContains { $true }
                (Test-CIS_Debian10_1_7_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.7.2 / 1.7.3 son revision manual' {
            It '1.7.2 es ManualReviewRequired' { (Test-CIS_Debian10_1_7_2).Status | Should -Be 'ManualReviewRequired' }
            It '1.7.3 es ManualReviewRequired' { (Test-CIS_Debian10_1_7_3).Status | Should -Be 'ManualReviewRequired' }
        }

        Context '1.7.4-1.7.6 Permisos de banners' {
            It '1.7.4 Pass cuando /etc/motd no existe' {
                Mock Test-Path { $false }
                (Test-CIS_Debian10_1_7_4).Status | Should -Be 'Pass'
            }
            It '1.7.5 Pass con 0644 root:root' {
                Mock Test-Path { $true }
                Mock Get-CISFileMode { '644' }
                Mock Get-CISFileOwner { 'root:root' }
                (Test-CIS_Debian10_1_7_5).Status | Should -Be 'Pass'
            }
            It '1.7.6 Fail con owner incorrecto' {
                Mock Test-Path { $true }
                Mock Get-CISFileMode { '644' }
                Mock Get-CISFileOwner { 'user:user' }
                (Test-CIS_Debian10_1_7_6).Status | Should -Be 'Fail'
            }
        }
    }
}

Describe 'Chapter 1.8 - GNOME Display Manager' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.8.1 GDM removido (Level 2, Server only)' {
            It 'NotApplicable en una Workstation' {
                Mock Get-CISLinuxProfile { 'Workstation' }
                (Test-CIS_Debian10_1_8_1).Status | Should -Be 'NotApplicable'
            }
            It 'Pass en un Server sin gdm3 instalado' {
                Mock Get-CISLinuxProfile { 'Server' }
                Mock Test-CISPackageInstalled { $false }
                (Test-CIS_Debian10_1_8_1).Status | Should -Be 'Pass'
            }
            It 'Fail en un Server con gdm3 instalado' {
                Mock Get-CISLinuxProfile { 'Server' }
                Mock Test-CISPackageInstalled { $true }
                (Test-CIS_Debian10_1_8_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.8.2-1.8.9 son Pass cuando GDM no esta instalado' {
            BeforeEach { Mock Test-Debian10GdmInstalled { $false } }
            It '1.8.2' { (Test-CIS_Debian10_1_8_2).Status | Should -Be 'Pass' }
            It '1.8.3' { (Test-CIS_Debian10_1_8_3).Status | Should -Be 'Pass' }
            It '1.8.4' { (Test-CIS_Debian10_1_8_4).Status | Should -Be 'Pass' }
            It '1.8.5' { (Test-CIS_Debian10_1_8_5).Status | Should -Be 'Pass' }
            It '1.8.6' { (Test-CIS_Debian10_1_8_6).Status | Should -Be 'Pass' }
            It '1.8.7' { (Test-CIS_Debian10_1_8_7).Status | Should -Be 'Pass' }
            It '1.8.8' { (Test-CIS_Debian10_1_8_8).Status | Should -Be 'Pass' }
            It '1.8.9' { (Test-CIS_Debian10_1_8_9).Status | Should -Be 'Pass' }
        }

        Context '1.8.3 disable-user-list con GDM instalado' {
            It 'Pass cuando la clave esta seteada' {
                Mock Test-Debian10GdmInstalled { $true }
                Mock Test-Debian10DconfKeySet { $true }
                (Test-CIS_Debian10_1_8_3).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no esta seteada' {
                Mock Test-Debian10GdmInstalled { $true }
                Mock Test-Debian10DconfKeySet { $false }
                (Test-CIS_Debian10_1_8_3).Status | Should -Be 'Fail'
            }
        }

        Context '1.8.9 autorun-never bloqueado con GDM instalado' {
            It 'Pass cuando el path esta lockeado' {
                Mock Test-Debian10GdmInstalled { $true }
                Mock Test-Debian10DconfPathLocked { $true }
                (Test-CIS_Debian10_1_8_9).Status | Should -Be 'Pass'
            }
            It 'Fail cuando no esta lockeado' {
                Mock Test-Debian10GdmInstalled { $true }
                Mock Test-Debian10DconfPathLocked { $false }
                (Test-CIS_Debian10_1_8_9).Status | Should -Be 'Fail'
            }
        }

        Context '1.8.10 XDMCP no habilitado' {
            It 'Pass cuando no hay Enable=true' {
                Mock Test-CISFileContains { $false }
                (Test-CIS_Debian10_1_8_10).Status | Should -Be 'Pass'
            }
            It 'Fail cuando Enable=true esta presente' {
                Mock Test-CISFileContains { $true }
                (Test-CIS_Debian10_1_8_10).Status | Should -Be 'Fail'
            }
        }
    }
}
