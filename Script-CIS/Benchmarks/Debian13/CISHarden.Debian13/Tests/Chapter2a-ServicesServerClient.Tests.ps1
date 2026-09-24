#Requires -Modules Pester
<# Tests de 2.1 Server Services y 2.2 Client Services (Debian 13). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 2.1 / 2.2 Services (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        $script:svcIds = 1..20 | ForEach-Object { "2_1_$_" }

        Context '2.1.1-2.1.20 servicios no en uso' {
            It 'Pass si el paquete no esta instalado' {
                Mock Get-Debian13InstalledPackages { }
                foreach ($id in $script:svcIds) { (& "Test-CIS_Debian13_$id").Status | Should -Be 'Pass' -Because $id }
            }
            It 'Pass si esta instalado pero sin servicios enabled/active' {
                Mock Get-Debian13InstalledPackages { 'x' }
                Mock Get-Debian13UnitStates { foreach ($u in $Units) { [pscustomobject]@{ Unit = $u; UnitFileState = 'masked'; ActiveState = 'inactive' } } }
                foreach ($id in $script:svcIds) { (& "Test-CIS_Debian13_$id").Status | Should -Be 'Pass' -Because $id }
            }
            It 'Fail si algun servicio esta enabled o active' {
                Mock Get-Debian13InstalledPackages { 'x' }
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = $Units[0]; UnitFileState = 'enabled'; ActiveState = 'inactive' } }
                foreach ($id in $script:svcIds) { (& "Test-CIS_Debian13_$id").Status | Should -Be 'Fail' -Because $id }
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = $Units[0]; UnitFileState = 'disabled'; ActiveState = 'active' } }
                (Test-CIS_Debian13_2_1_9).Status | Should -Be 'Fail'
            }
            It 'Cada control usa los paquetes y unidades del benchmark' {
                $script:seenP = $null; $script:seenU = $null
                Mock Get-Debian13InstalledPackages { $script:seenP = $Patterns -join ','; 'x' }
                Mock Get-Debian13UnitStates { $script:seenU = $Units -join ','; @() }
                Test-CIS_Debian13_2_1_19 | Out-Null
                $script:seenP | Should -Be 'apache2,nginx'
                $script:seenU | Should -Be 'apache2.socket,apache2.service,nginx.service'
                Test-CIS_Debian13_2_1_14 | Out-Null
                $script:seenU | Should -Be 'smbd.service'
                Test-CIS_Debian13_2_1_3 | Out-Null
                $script:seenU | Should -Match 'kea-dhcp6-server.service'
            }
            It 'Set: -WhatIf no toca nada; sin -Purge enmascara sin desinstalar; con -Purge desinstala' {
                Mock Get-Debian13InstalledPackages { 'autofs' }
                Mock Remove-CISPackage { }
                Mock Invoke-Debian13Systemctl { }
                Set-CIS_Debian13_2_1_1 -WhatIf
                Should -Invoke Invoke-Debian13Systemctl -Times 0
                Set-CIS_Debian13_2_1_1
                Should -Invoke Invoke-Debian13Systemctl -Times 1 -ParameterFilter { $Arguments[0] -eq 'stop' -and $Arguments -contains 'autofs.service' }
                Should -Invoke Invoke-Debian13Systemctl -Times 1 -ParameterFilter { $Arguments[0] -eq 'mask' -and $Arguments -contains 'autofs.service' }
                Should -Invoke Remove-CISPackage -Times 0
                Set-CIS_Debian13_2_1_1 -Purge
                Should -Invoke Remove-CISPackage -Times 1 -ParameterFilter { $Name -eq 'autofs' -and $Purge }
            }
            It 'Set no hace nada si el paquete no esta instalado' {
                Mock Get-Debian13InstalledPackages { }
                Mock Invoke-Debian13Systemctl { }
                Set-CIS_Debian13_2_1_1
                Should -Invoke Invoke-Debian13Systemctl -Times 0
            }
        }

        Context '2.1.21 X server' {
            It 'NotApplicable en Workstation; Fail/Pass segun xserver-common en Server' {
                Mock Get-CISLinuxProfile { 'Workstation' }; (Test-CIS_Debian13_2_1_21).Status | Should -Be 'NotApplicable'
                Mock Get-CISLinuxProfile { 'Server' }
                Mock Get-Debian13InstalledPackages { 'xserver-common' }; (Test-CIS_Debian13_2_1_21).Status | Should -Be 'Fail'
                Mock Get-Debian13InstalledPackages { }; (Test-CIS_Debian13_2_1_21).Status | Should -Be 'Pass'
            }
        }

        Context '2.1.22 MTA local-only' {
            It 'Pass sin MTA' {
                Mock Get-Debian13SsListening { 'tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*' }; Mock Get-Debian13MtaInterfaces { $null }
                (Test-CIS_Debian13_2_1_22).Status | Should -Be 'Pass'
            }
            It 'Pass con postfix en loopback-only y puerto 25 solo en 127.0.0.1' {
                Mock Get-Debian13SsListening { 'tcp LISTEN 0 100 127.0.0.1:25 0.0.0.0:* users:(("master"))', 'tcp LISTEN 0 100 [::1]:25 [::]:*' }
                Mock Get-Debian13MtaInterfaces { 'inet_interfaces = loopback-only' }
                (Test-CIS_Debian13_2_1_22).Status | Should -Be 'Pass'
            }
            It 'Fail con puerto 25 en todas las interfaces' {
                Mock Get-Debian13SsListening { 'tcp LISTEN 0 100 0.0.0.0:25 0.0.0.0:*' }; Mock Get-Debian13MtaInterfaces { $null }
                (Test-CIS_Debian13_2_1_22).Status | Should -Be 'Fail'
            }
            It 'Fail con inet_interfaces = all o 0.0.0.0 o una IP publica' {
                Mock Get-Debian13SsListening { @() }
                foreach ($v in 'inet_interfaces = all', 'inet_interfaces = 0.0.0.0', 'inet_interfaces = 10.0.0.5') {
                    Mock Get-Debian13MtaInterfaces { $v }.GetNewClosure()
                    (Test-CIS_Debian13_2_1_22).Status | Should -Be 'Fail' -Because $v
                }
            }
        }

        It '2.1.23 es Manual' { (Test-CIS_Debian13_2_1_23).Status | Should -Be 'ManualReviewRequired' }

        Context '2.2.x clientes' {
            It 'Pass sin paquetes, Fail con paquetes' {
                Mock Get-Debian13InstalledPackages { }
                foreach ($n in 1..6) { (& "Test-CIS_Debian13_2_2_$n").Status | Should -Be 'Pass' }
                Mock Get-Debian13InstalledPackages { 'x' }
                foreach ($n in 1..6) { (& "Test-CIS_Debian13_2_2_$n").Status | Should -Be 'Fail' }
            }
            It 'Paquetes del benchmark (telnet, ftp)' {
                $script:seen = $null
                Mock Get-Debian13InstalledPackages { $script:seen = $Patterns -join ','; }
                Test-CIS_Debian13_2_2_4 | Out-Null; $script:seen | Should -Be 'telnet,inetutils-telnet'
                Test-CIS_Debian13_2_2_6 | Out-Null; $script:seen | Should -Be 'ftp,tnftp'
                Test-CIS_Debian13_2_2_5 | Out-Null; $script:seen | Should -Be 'ldap-utils'
            }
        }
    }
}
