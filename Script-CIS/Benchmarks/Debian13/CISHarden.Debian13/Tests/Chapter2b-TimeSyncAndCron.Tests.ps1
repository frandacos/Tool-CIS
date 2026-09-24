#Requires -Modules Pester
<# Tests de 2.3 Time Synchronization y 2.4 Job Schedulers (Debian 13). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 2.3 Time synchronization (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeAll {
            function script:St { param($tE = $false, $tA = $false, $cE = $false, $cA = $false)
                [pscustomobject]@{ TimesyncdEnabled = $tE; TimesyncdActive = $tA; TimesyncdInUse = ($tE -or $tA); ChronyEnabled = $cE; ChronyActive = $cA; ChronyInUse = ($cE -or $cA) } }
        }
        It '2.3.1.1: Pass con exactamente un daemon en uso; Fail con ninguno o con dos' {
            Mock Get-Debian13TimeSyncState { St -tE $true -tA $true }; (Test-CIS_Debian13_2_3_1_1).Status | Should -Be 'Pass'
            Mock Get-Debian13TimeSyncState { St -cA $true }; (Test-CIS_Debian13_2_3_1_1).Status | Should -Be 'Pass'
            Mock Get-Debian13TimeSyncState { St }; (Test-CIS_Debian13_2_3_1_1).Status | Should -Be 'Fail'
            Mock Get-Debian13TimeSyncState { St -tE $true -cE $true }; (Test-CIS_Debian13_2_3_1_1).Status | Should -Be 'Fail'
        }
        It '2.3.1.1 Set: con dos daemons enmascara timesyncd y conserva chrony' {
            Mock Get-Debian13TimeSyncState { St -tE $true -cE $true }
            Mock Invoke-Debian13Systemctl { }
            Set-CIS_Debian13_2_3_1_1
            Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments[0] -eq 'mask' -and $Arguments -contains 'systemd-timesyncd.service' } -Times 1
            Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments -contains 'chrony.service' } -Times 0
        }
        It '2.3.2.1: Pass si NTP/FallbackNTP explicitos; Fail si solo el default; Pass si timesyncd no esta en uso' {
            Mock Get-Debian13TimeSyncState { St -tA $true }
            Mock Get-CISSystemdConfigValue { if ($Option -eq 'NTP') { [pscustomobject]@{ Value = 'time.nist.gov'; File = 'f'; IsDefault = $false } } }
            (Test-CIS_Debian13_2_3_2_1).Status | Should -Be 'Pass'
            Mock Get-CISSystemdConfigValue { }
            (Test-CIS_Debian13_2_3_2_1).Status | Should -Be 'Fail'
            Mock Get-CISSystemdConfigValue { [pscustomobject]@{ Value = 'x'; File = 'f'; IsDefault = $true } }
            (Test-CIS_Debian13_2_3_2_1).Status | Should -Be 'Fail'
            Mock Get-Debian13TimeSyncState { St -cE $true -cA $true }
            (Test-CIS_Debian13_2_3_2_1).Status | Should -Be 'Pass'
        }
        It '2.3.2.1 Set sin servidores no inventa nada' {
            Mock Set-CISSystemdConfigValue { }
            Set-CIS_Debian13_2_3_2_1 -WarningAction SilentlyContinue
            Should -Invoke Set-CISSystemdConfigValue -Times 0
        }
        It '2.3.2.2: enabled y active requeridos si chrony no esta en uso' {
            Mock Get-Debian13TimeSyncState { St -tE $true -tA $true }; (Test-CIS_Debian13_2_3_2_2).Status | Should -Be 'Pass'
            Mock Get-Debian13TimeSyncState { St -tE $true }; (Test-CIS_Debian13_2_3_2_2).Status | Should -Be 'Fail'
            Mock Get-Debian13TimeSyncState { St -cE $true -cA $true }; (Test-CIS_Debian13_2_3_2_2).Status | Should -Be 'Pass'
        }
        It '2.3.3.1: Pass con server/pool, Fail sin ellos, Pass si chrony no esta en uso' {
            Mock Get-Debian13TimeSyncState { St -cA $true }
            Mock Get-Debian13ChronySourceLines { '/etc/chrony/chrony.conf: pool time.nist.gov iburst' }; (Test-CIS_Debian13_2_3_3_1).Status | Should -Be 'Pass'
            Mock Get-Debian13ChronySourceLines { }; (Test-CIS_Debian13_2_3_3_1).Status | Should -Be 'Fail'
            Mock Get-Debian13TimeSyncState { St -tA $true }; (Test-CIS_Debian13_2_3_3_1).Status | Should -Be 'Pass'
        }
        It '2.3.3.2: Fail si chronyd corre como otro usuario' {
            Mock Get-Debian13ChronydUsers { '_chrony', '_chrony' }; (Test-CIS_Debian13_2_3_3_2).Status | Should -Be 'Pass'
            Mock Get-Debian13ChronydUsers { 'root' }; (Test-CIS_Debian13_2_3_3_2).Status | Should -Be 'Fail'
            Mock Get-Debian13ChronydUsers { }; (Test-CIS_Debian13_2_3_3_2).Status | Should -Be 'Pass'
        }
        It '2.3.3.3: enabled y active requeridos si chrony esta en uso' {
            Mock Get-Debian13TimeSyncState { St -cE $true -cA $true }; (Test-CIS_Debian13_2_3_3_3).Status | Should -Be 'Pass'
            Mock Get-Debian13TimeSyncState { St -cE $true }; (Test-CIS_Debian13_2_3_3_3).Status | Should -Be 'Fail'
            Mock Get-Debian13TimeSyncState { St -tE $true -tA $true }; (Test-CIS_Debian13_2_3_3_3).Status | Should -Be 'Pass'
        }
    }
}

Describe 'Chapter 2.4 Job schedulers (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        It 'Sin cron instalado, todos los controles de cron dan Pass' {
            Mock Test-CISPackageInstalled { $false }
            foreach ($n in 1..9) { (& "Test-CIS_Debian13_2_4_1_$n").Status | Should -Be 'Pass' -Because "2.4.1.$n" }
        }
        It '2.4.1.1 requiere enabled y active' {
            Mock Test-CISPackageInstalled { $true }
            Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'cron.service'; UnitFileState = 'enabled'; ActiveState = 'active' } }
            (Test-CIS_Debian13_2_4_1_1).Status | Should -Be 'Pass'
            Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'cron.service'; UnitFileState = 'enabled'; ActiveState = 'inactive' } }
            (Test-CIS_Debian13_2_4_1_1).Status | Should -Be 'Fail'
        }
        It '2.4.1.2-8 usan la ruta y el modo maximo del benchmark' {
            Mock Test-CISPackageInstalled { $true }
            $script:seen = @{}
            Mock Test-CISPathAccess { $script:seen[$Path] = $MaxMode; [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '600'; Owner = 'root:root' } }
            foreach ($n in 2..8) { (& "Test-CIS_Debian13_2_4_1_$n").Status | Should -Be 'Pass' }
            $script:seen['/etc/crontab'] | Should -Be '600'
            foreach ($d in 'hourly', 'daily', 'weekly', 'monthly', 'yearly', 'd') { $script:seen["/etc/cron.$d"] | Should -Be '700' -Because $d }
        }
        It '2.4.1.2 Fail si el archivo tiene permisos de grupo/otros' {
            Mock Test-CISPackageInstalled { $true }
            Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $false; Mode = '644'; Owner = 'root:root' } }
            (Test-CIS_Debian13_2_4_1_2).Status | Should -Be 'Fail'
        }
        Context 'cron.allow / at.allow' {
            BeforeEach { Mock Test-CISPackageInstalled { $true } }
            It 'Pass con allow conforme y deny inexistente' {
                Mock Test-CISPathAccess { if ($Path -like '*.allow') { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '640'; Owner = 'root:crontab' } } else { [pscustomobject]@{ Path = $Path; Exists = $false; Compliant = $true; Mode = $null; Owner = $null } } }
                (Test-CIS_Debian13_2_4_1_9).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_2_4_2_1).Status | Should -Be 'Pass'
            }
            It 'Fail si allow no existe' {
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $false; Compliant = $true; Mode = $null; Owner = $null } }
                (Test-CIS_Debian13_2_4_1_9).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_2_4_2_1).Status | Should -Be 'Fail'
            }
            It 'Fail si deny existe y no es conforme' {
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = ($Path -like '*.allow'); Mode = '644'; Owner = 'root:root' } }
                (Test-CIS_Debian13_2_4_1_9).Status | Should -Be 'Fail'
            }
            It 'Grupos aceptados: crontab/root para cron, daemon/root para at' {
                $script:owners = @{}
                Mock Test-CISPathAccess { $script:owners[$Path] = $Owner -join ','; [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '640'; Owner = 'root:root' } }
                Test-CIS_Debian13_2_4_1_9 | Out-Null; Test-CIS_Debian13_2_4_2_1 | Out-Null
                $script:owners['/etc/cron.allow'] | Should -Be 'root:root,root:crontab'
                $script:owners['/etc/at.allow'] | Should -Be 'root:daemon,root:root'
            }
        }
    }
}

Describe 'Test-CISPathAccess con varios owners' {
    InModuleScope 'CISHarden.Core' {
        It 'acepta cualquiera de los owner:group indicados' {
            Mock Get-CISFileMode { '640' }; Mock Get-CISFileOwner { 'root:crontab' }
            (Test-CISPathAccess -Path /x -MaxMode 640 -Owner 'root:root', 'root:crontab').Compliant | Should -BeTrue
            (Test-CISPathAccess -Path /x -MaxMode 640 -Owner 'root:root').Compliant | Should -BeFalse
        }
    }
}
