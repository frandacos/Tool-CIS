#Requires -Modules Pester
<# Tests de 1.2 Package Management, 1.3 AppArmor y 1.4 Bootloader (Debian 13). Motores de Core y helpers privados mockeados. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 1.2-1.4 (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {

        Context '1.2.1.x' {
            It 'Manuales: 1.2.1.1 y 1.2.2.1' {
                (Test-CIS_Debian13_1_2_1_1).Status | Should -Be 'ManualReviewRequired'
                (Test-CIS_Debian13_1_2_2_1).Status | Should -Be 'ManualReviewRequired'
            }
            It '1.2.1.2 Pass con Recommends y Suggests en 0' {
                Mock Get-Debian13AptConfigDump { 'APT::Install-Recommends "0";', 'APT::Install-Suggests "0";' }
                (Test-CIS_Debian13_1_2_1_2).Status | Should -Be 'Pass'
            }
            It '1.2.1.2 Fail con Recommends en 1 o sin salida' {
                Mock Get-Debian13AptConfigDump { 'APT::Install-Recommends "1";', 'APT::Install-Suggests "0";' }
                (Test-CIS_Debian13_1_2_1_2).Status | Should -Be 'Fail'
                Mock Get-Debian13AptConfigDump { @() }
                (Test-CIS_Debian13_1_2_1_2).Status | Should -Be 'Fail'
            }
            It 'Directorios: Pass conforme, Fail no conforme' {
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '755'; Owner = 'root:root' } }
                foreach ($id in '4', '5', '7', '8') { (& "Test-CIS_Debian13_1_2_1_$id").Status | Should -Be 'Pass' }
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $false; Mode = '777'; Owner = 'root:root' } }
                foreach ($id in '4', '5', '7', '8') { (& "Test-CIS_Debian13_1_2_1_$id").Status | Should -Be 'Fail' }
            }
            It 'Directorios: usan el path y modo del benchmark' {
                $script:seen = @{}
                Mock Test-CISPathAccess { $script:seen[$Path] = $MaxMode; [pscustomobject]@{ Path = $Path; Exists = $false; Compliant = $true; Mode = $null; Owner = $null } }
                Test-CIS_Debian13_1_2_1_4 | Out-Null; Test-CIS_Debian13_1_2_1_7 | Out-Null; Test-CIS_Debian13_1_4_2 | Out-Null
                $script:seen['/etc/apt/trusted.gpg.d'] | Should -Be '755'
                $script:seen['/usr/share/keyrings'] | Should -Be '755'
                $script:seen['/boot/grub/grub.cfg'] | Should -Be '600'
            }
            It 'Archivos: Fail si alguno no cumple, Pass si la lista esta vacia' {
                Mock Get-Debian13FilesIn { @('/etc/apt/sources.list.d/a.sources') }
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $false; Mode = '666'; Owner = 'root:root' } }
                (Test-CIS_Debian13_1_2_1_9).Status | Should -Be 'Fail'
                Mock Get-Debian13FilesIn { @() }
                (Test-CIS_Debian13_1_2_1_9).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_1_2_1_6).Status | Should -Be 'Pass'
            }
            It '1.2.1.3 revisa keyrings y sources con Signed-By' {
                Mock Get-Debian13GpgKeyFiles { @('/usr/share/keyrings/k.gpg') }
                Mock Get-Debian13SignedByFiles { @('/etc/apt/sources.list.d/d.sources') }
                $script:paths = @()
                Mock Test-CISPathAccess { $script:paths += $Path; [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '644'; Owner = 'root:root' } }
                (Test-CIS_Debian13_1_2_1_3).Status | Should -Be 'Pass'
                $script:paths | Should -Be @('/usr/share/keyrings/k.gpg', '/etc/apt/sources.list.d/d.sources')
            }
        }

        Context '1.3.1.x AppArmor' {
            It '1.3.1.1 requiere apparmor y apparmor-utils' {
                Mock Test-CISPackageInstalled { $true }
                (Test-CIS_Debian13_1_3_1_1).Status | Should -Be 'Pass'
                Mock Test-CISPackageInstalled { $Name -eq 'apparmor' }
                (Test-CIS_Debian13_1_3_1_1).Status | Should -Be 'Fail'
            }
            It '1.3.1.2 Pass/Fail/Error segun grub.cfg' {
                Mock Test-Debian13GrubCfgExists { $true }
                Mock Get-Debian13GrubApparmorOff { @() }
                (Test-CIS_Debian13_1_3_1_2).Status | Should -Be 'Pass'
                Mock Get-Debian13GrubApparmorOff { @('linux /vmlinuz apparmor=0') }
                (Test-CIS_Debian13_1_3_1_2).Status | Should -Be 'Fail'
                Mock Test-Debian13GrubCfgExists { $false }
                (Test-CIS_Debian13_1_3_1_2).Status | Should -Be 'Error'
            }
            It '1.3.1.3 Pass con todo en enforce' {
                Mock Get-Debian13AppArmorStatus { '34 profiles are loaded.', '34 profiles are in enforce mode.', '0 profiles are in complain mode.', '2 processes have profiles defined.', '0 processes are unconfined but have a profile defined.' }
                (Test-CIS_Debian13_1_3_1_3).Status | Should -Be 'Pass'
            }
            It '1.3.1.3 Fail con perfiles en complain, procesos sin confinar o sin perfiles' {
                Mock Get-Debian13AppArmorStatus { '34 profiles are loaded.', '30 profiles are in enforce mode.', '4 profiles are in complain mode.', '0 processes are unconfined but have a profile defined.' }
                (Test-CIS_Debian13_1_3_1_3).Status | Should -Be 'Fail'
                Mock Get-Debian13AppArmorStatus { '34 profiles are loaded.', '34 profiles are in enforce mode.', '0 profiles are in complain mode.', '1 processes are unconfined but have a profile defined.' }
                (Test-CIS_Debian13_1_3_1_3).Status | Should -Be 'Fail'
                Mock Get-Debian13AppArmorStatus { @() }
                (Test-CIS_Debian13_1_3_1_3).Status | Should -Be 'Fail'
            }
            It '1.3.1.4 exige valor en ejecucion Y persistido' {
                Mock Test-CISSysctlSetting { [pscustomobject]@{ Compliant = $true; Running = '1'; Persisted = '1'; File = '/etc/sysctl.d/x.conf' } }
                (Test-CIS_Debian13_1_3_1_4).Status | Should -Be 'Pass'
                Mock Test-CISSysctlSetting { [pscustomobject]@{ Compliant = $false; Running = '1'; Persisted = $null; File = $null } }
                (Test-CIS_Debian13_1_3_1_4).Status | Should -Be 'Fail'
            }
        }

        Context '1.4 Bootloader' {
            It '1.4.1 requiere set superusers y password_pbkdf2' {
                Mock Test-CISFileContains { $true }
                (Test-CIS_Debian13_1_4_1).Status | Should -Be 'Pass'
                Mock Test-CISFileContains { $Pattern -like '*superusers*' }
                (Test-CIS_Debian13_1_4_1).Status | Should -Be 'Fail'
            }
        }
    }
}
