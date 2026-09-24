#Requires -Modules Pester
<# Tests de 3.1-3.3 Network (Debian 13). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 3 Network (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {

        Context '3.1' {
            It '3.1.1 es Manual' { Mock Test-Debian13Ipv6Enabled { $true }; (Test-CIS_Debian13_3_1_1).Status | Should -Be 'ManualReviewRequired' }
            It '3.1.2 Pass sin interfaces wireless' {
                Mock Get-Debian13WirelessDriverModules { }
                (Test-CIS_Debian13_3_1_2).Status | Should -Be 'Pass'
            }
            It '3.1.2 Fail si el driver esta cargado, es cargable o no esta en denylist; Pass si esta deshabilitado' {
                Mock Get-Debian13WirelessDriverModules { 'iwlwifi' }
                Mock Get-Debian13ModuleState { [pscustomobject]@{ Module = $Name; Loadable = $false; Loaded = $false; Blacklisted = $true } }
                (Test-CIS_Debian13_3_1_2).Status | Should -Be 'Pass'
                Mock Get-Debian13ModuleState { [pscustomobject]@{ Module = $Name; Loadable = $false; Loaded = $true; Blacklisted = $true } }
                (Test-CIS_Debian13_3_1_2).Status | Should -Be 'Fail'
                Mock Get-Debian13ModuleState { [pscustomobject]@{ Module = $Name; Loadable = $true; Loaded = $false; Blacklisted = $true } }
                (Test-CIS_Debian13_3_1_2).Status | Should -Be 'Fail'
                Mock Get-Debian13ModuleState { [pscustomobject]@{ Module = $Name; Loadable = $false; Loaded = $false; Blacklisted = $false } }
                (Test-CIS_Debian13_3_1_2).Status | Should -Be 'Fail'
            }
            It '3.1.3 bluetooth usa bluez y bluetooth.service' {
                $script:seen = $null
                Mock Get-Debian13InstalledPackages { $script:seen = $Patterns -join ','; 'bluez' }
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'bluetooth.service'; UnitFileState = 'enabled'; ActiveState = 'active' } }
                (Test-CIS_Debian13_3_1_3).Status | Should -Be 'Fail'
                $script:seen | Should -Be 'bluez'
                Mock Get-Debian13InstalledPackages { }
                (Test-CIS_Debian13_3_1_3).Status | Should -Be 'Pass'
            }
        }

        Context '3.2 modulos de kernel de red' {
            It 'Cada control usa su modulo con Type=net' {
                $expected = @{ '3_2_1' = 'atm'; '3_2_2' = 'can'; '3_2_3' = 'dccp'; '3_2_4' = 'rds'; '3_2_5' = 'sctp'; '3_2_6' = 'tipc' }
                foreach ($id in $expected.Keys) {
                    $script:seen = $null
                    Mock Test-CISKernelModuleDisabled { $script:seen = "$Module|$Type"; [pscustomobject]@{ Disabled = $true; Loadable = $false; Loaded = $false; Blacklisted = $true; ExistsInRunningKernel = $true } }
                    (& "Test-CIS_Debian13_$id").Status | Should -Be 'Pass'
                    $script:seen | Should -Be "$($expected[$id])|net" -Because $id
                }
            }
        }

        Context '3.3 sysctl' {
            It 'Cada control usa la clave y el valor del benchmark (24 controles + ip_forward)' {
                $expected = [ordered]@{
                    '3_3_1_1' = 'net.ipv4.ip_forward|0'; '3_3_1_2' = 'net.ipv4.conf.all.forwarding|0'; '3_3_1_3' = 'net.ipv4.conf.default.forwarding|0'
                    '3_3_1_4' = 'net.ipv4.conf.all.send_redirects|0'; '3_3_1_5' = 'net.ipv4.conf.default.send_redirects|0'
                    '3_3_1_6' = 'net.ipv4.icmp_ignore_bogus_error_responses|1'; '3_3_1_7' = 'net.ipv4.icmp_echo_ignore_broadcasts|1'
                    '3_3_1_8' = 'net.ipv4.conf.all.accept_redirects|0'; '3_3_1_9' = 'net.ipv4.conf.default.accept_redirects|0'
                    '3_3_1_10' = 'net.ipv4.conf.all.secure_redirects|0'; '3_3_1_11' = 'net.ipv4.conf.default.secure_redirects|0'
                    '3_3_1_12' = 'net.ipv4.conf.all.rp_filter|1'; '3_3_1_13' = 'net.ipv4.conf.default.rp_filter|1'
                    '3_3_1_14' = 'net.ipv4.conf.all.accept_source_route|0'; '3_3_1_15' = 'net.ipv4.conf.default.accept_source_route|0'
                    '3_3_1_16' = 'net.ipv4.conf.all.log_martians|1'; '3_3_1_17' = 'net.ipv4.conf.default.log_martians|1'; '3_3_1_18' = 'net.ipv4.tcp_syncookies|1'
                    '3_3_2_1' = 'net.ipv6.conf.all.forwarding|0'; '3_3_2_2' = 'net.ipv6.conf.default.forwarding|0'
                    '3_3_2_3' = 'net.ipv6.conf.all.accept_redirects|0'; '3_3_2_4' = 'net.ipv6.conf.default.accept_redirects|0'
                    '3_3_2_5' = 'net.ipv6.conf.all.accept_source_route|0'; '3_3_2_6' = 'net.ipv6.conf.default.accept_source_route|0'
                    '3_3_2_7' = 'net.ipv6.conf.all.accept_ra|0'; '3_3_2_8' = 'net.ipv6.conf.default.accept_ra|0'
                }
                Mock Test-Debian13Ipv6Enabled { $true }
                foreach ($id in $expected.Keys) {
                    $script:seen = $null
                    Mock Test-CISSysctlSetting { $script:seen = "$Key|$($Value -join ',')"; [pscustomobject]@{ Compliant = $true; Running = 'x'; Persisted = 'x'; File = 'f' } }
                    (& "Test-CIS_Debian13_$id").Status | Should -Be 'Pass' -Because $id
                    $script:seen | Should -Be $expected[$id] -Because $id
                }
                $expected.Count | Should -Be 26
            }
            It 'Fail cuando no cumple' {
                Mock Test-Debian13Ipv6Enabled { $true }
                Mock Test-CISSysctlSetting { [pscustomobject]@{ Compliant = $false; Running = '1'; Persisted = $null; File = $null } }
                (Test-CIS_Debian13_3_3_1_2).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_3_3_2_7).Status | Should -Be 'Fail'
            }
            It 'IPv6 deshabilitado: 3.3.2.x son NotApplicable y su Set no hace nada' {
                Mock Test-Debian13Ipv6Enabled { $false }
                Mock Set-CISSysctlEnforced { }
                foreach ($n in 1..8) { (& "Test-CIS_Debian13_3_3_2_$n").Status | Should -Be 'NotApplicable' }
                Set-CIS_Debian13_3_3_2_7
                Should -Invoke Set-CISSysctlEnforced -Times 0
            }
            It 'Set IPv4 fuerza el valor del benchmark' {
                Mock Set-CISSysctlEnforced { }
                Set-CIS_Debian13_3_3_1_16
                Should -Invoke Set-CISSysctlEnforced -ParameterFilter { $Key -eq 'net.ipv4.conf.all.log_martians' -and $Value -eq '1' } -Times 1
            }
            It '3.3.1.1: Pass por omision si forwarding all/default ya estan en 0' {
                Mock Test-CISSysctlSetting {
                    if ($Key -eq 'net.ipv4.ip_forward') { [pscustomobject]@{ Compliant = $false; Running = '1'; Persisted = $null; File = $null } }
                    else { [pscustomobject]@{ Compliant = $true; Running = '0'; Persisted = '0'; File = 'f' } }
                }
                (Test-CIS_Debian13_3_3_1_1).Status | Should -Be 'Pass'
                Mock Test-CISSysctlSetting { [pscustomobject]@{ Compliant = $false; Running = '1'; Persisted = $null; File = $null } }
                (Test-CIS_Debian13_3_3_1_1).Status | Should -Be 'Fail'
            }
        }
    }
}
