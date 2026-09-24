#Requires -Modules Pester
<# Tests de 4.1 UFW (Debian 13). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 4.1 UFW (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeAll {
            $script:active = 'Status: active', 'Logging: on (low)', 'Default: deny (incoming), allow (outgoing), disabled (routed)', 'New profiles: skip'
        }
        It '4.1.1 ufw instalado' {
            Mock Test-CISPackageInstalled { $true }; (Test-CIS_Debian13_4_1_1).Status | Should -Be 'Pass'
            Mock Test-CISPackageInstalled { $false }; (Test-CIS_Debian13_4_1_1).Status | Should -Be 'Fail'
        }
        It '4.1.2 requiere enabled, active y Status: active' {
            Mock Get-Debian13UfwStatusVerbose { $script:active }
            Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'ufw.service'; UnitFileState = 'enabled'; ActiveState = 'active' } }
            (Test-CIS_Debian13_4_1_2).Status | Should -Be 'Pass'
            Mock Get-Debian13UfwStatusVerbose { 'Status: inactive' }
            (Test-CIS_Debian13_4_1_2).Status | Should -Be 'Fail'
            Mock Get-Debian13UfwStatusVerbose { $script:active }
            Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'ufw.service'; UnitFileState = 'masked'; ActiveState = 'inactive' } }
            (Test-CIS_Debian13_4_1_2).Status | Should -Be 'Fail'
        }
        It 'Politicas por defecto: incoming/outgoing/routed' {
            Mock Get-Debian13UfwStatusVerbose { $script:active }
            (Test-CIS_Debian13_4_1_3).Status | Should -Be 'Pass'
            (Test-CIS_Debian13_4_1_4).Status | Should -Be 'Fail'   # outgoing = allow
            (Test-CIS_Debian13_4_1_5).Status | Should -Be 'Pass'   # routed = disabled
            Mock Get-Debian13UfwStatusVerbose { 'Status: active', 'Default: reject (incoming), deny (outgoing), deny (routed)' }
            (Test-CIS_Debian13_4_1_3).Status | Should -Be 'Pass'
            (Test-CIS_Debian13_4_1_4).Status | Should -Be 'Pass'
            (Test-CIS_Debian13_4_1_5).Status | Should -Be 'Pass'
            Mock Get-Debian13UfwStatusVerbose { 'Status: active', 'Default: allow (incoming), allow (outgoing), allow (routed)' }
            (Test-CIS_Debian13_4_1_3).Status | Should -Be 'Fail'
            (Test-CIS_Debian13_4_1_5).Status | Should -Be 'Fail'
        }
        It 'ufw inactivo: las politicas no son determinables (Fail)' {
            Mock Get-Debian13UfwStatusVerbose { 'Status: inactive' }
            foreach ($n in 3, 4, 5) { (& "Test-CIS_Debian13_4_1_$n").Status | Should -Be 'Fail' }
        }
        Context 'Seguridad SSH de los Set-*' {
            BeforeEach { Mock Invoke-Debian13Ufw { }; Mock Invoke-Debian13Systemctl { } }
            It '4.1.2: con sshd activo y sin regla SSH no habilita ufw' {
                Mock Test-Debian13SshdActive { $true }; Mock Test-Debian13UfwSshRule { $false }
                Set-CIS_Debian13_4_1_2 -WarningAction SilentlyContinue
                Should -Invoke Invoke-Debian13Ufw -Times 0
                Should -Invoke Invoke-Debian13Systemctl -Times 0
            }
            It '4.1.2: con -AllowSsh agrega la regla ANTES de habilitar' {
                Mock Test-Debian13SshdActive { $true }; Mock Test-Debian13UfwSshRule { $false }
                $script:order = @()
                Mock Invoke-Debian13Ufw { $script:order += ($Arguments -join ' ') }
                Set-CIS_Debian13_4_1_2 -AllowSsh -SshPort 2222
                $script:order[0] | Should -Be 'allow proto tcp from any to any port 2222'
                $script:order[-1] | Should -Be '--force enable'
            }
            It '4.1.2: con regla SSH existente habilita sin agregar reglas' {
                Mock Test-Debian13SshdActive { $true }; Mock Test-Debian13UfwSshRule { $true }
                Set-CIS_Debian13_4_1_2
                Should -Invoke Invoke-Debian13Ufw -Times 1 -ParameterFilter { $Arguments -contains '--force' }
                Should -Invoke Invoke-Debian13Ufw -Times 0 -ParameterFilter { $Arguments -contains 'allow' }
            }
            It '4.1.2: sin sshd activo habilita directamente; -WhatIf no ejecuta nada' {
                Mock Test-Debian13SshdActive { $false }
                Set-CIS_Debian13_4_1_2 -WhatIf
                Should -Invoke Invoke-Debian13Ufw -Times 0
                Set-CIS_Debian13_4_1_2
                Should -Invoke Invoke-Debian13Ufw -Times 1
            }
            It '4.1.3: sin regla SSH no cambia la politica; con regla si' {
                Mock Test-Debian13SshdActive { $true }; Mock Test-Debian13UfwSshRule { $false }
                Set-CIS_Debian13_4_1_3 -WarningAction SilentlyContinue
                Should -Invoke Invoke-Debian13Ufw -Times 0
                Mock Test-Debian13UfwSshRule { $true }
                Set-CIS_Debian13_4_1_3
                Should -Invoke Invoke-Debian13Ufw -Times 1 -ParameterFilter { ($Arguments -join ' ') -eq 'default deny incoming' }
            }
            It '4.1.4 exige -AcceptOutboundBlock' {
                Set-CIS_Debian13_4_1_4 -WarningAction SilentlyContinue
                Should -Invoke Invoke-Debian13Ufw -Times 0
                Set-CIS_Debian13_4_1_4 -AcceptOutboundBlock
                Should -Invoke Invoke-Debian13Ufw -Times 1 -ParameterFilter { ($Arguments -join ' ') -eq 'default deny outgoing' }
            }
            It '4.1.5 usa la sintaxis valida deny routed' {
                Set-CIS_Debian13_4_1_5
                Should -Invoke Invoke-Debian13Ufw -Times 1 -ParameterFilter { ($Arguments -join ' ') -eq 'default deny routed' }
            }
        }
        It 'Test-Debian13UfwSshRule reconoce reglas allow de SSH' {
            Mock Get-Debian13UfwRulesAdded { 'Added user rules (see ufw status for running firewall):', 'ufw allow 22/tcp' }
            Test-Debian13UfwSshRule | Should -BeTrue
            Mock Get-Debian13UfwRulesAdded { 'ufw allow 443/tcp', 'ufw deny 22/tcp' }
            Test-Debian13UfwSshRule | Should -BeFalse
            Mock Get-Debian13UfwRulesAdded { 'ufw allow OpenSSH' }
            Test-Debian13UfwSshRule | Should -BeTrue
        }
    }
}
