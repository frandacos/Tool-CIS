#Requires -Modules Pester
<# Tests de 5.2 sudo/su (Debian 13). Los Set-* de sudoers se prueban con archivos temporales reales y visudo mockeado. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 5.2 privilege escalation (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeAll {
            function script:L { param($f, $l) [pscustomobject]@{ File = $f; Line = $l } }
        }
        It '5.2.1 sudo, sudo-ldap o libsss-sudo+sssd' {
            Mock Get-Debian13InstalledPackages { 'sudo' }; (Test-CIS_Debian13_5_2_1).Status | Should -Be 'Pass'
            Mock Get-Debian13InstalledPackages { if ($Patterns -contains 'libsss-sudo' -or $Patterns -contains 'sssd') { 'x' } }; (Test-CIS_Debian13_5_2_1).Status | Should -Be 'Pass'
            Mock Get-Debian13InstalledPackages { }; (Test-CIS_Debian13_5_2_1).Status | Should -Be 'Fail'
            Mock Get-Debian13InstalledPackages { if ($Patterns -contains 'libsss-sudo') { 'libsss-sudo' } }; (Test-CIS_Debian13_5_2_1).Status | Should -Be 'Fail'
        }
        It '5.2.2 requiere use_pty y ausencia de !use_pty' {
            Mock Get-Debian13SudoersLines { if ($Pattern -like '*!use_pty*') { } else { L '/etc/sudoers' 'Defaults use_pty' } }
            (Test-CIS_Debian13_5_2_2).Status | Should -Be 'Pass'
            Mock Get-Debian13SudoersLines { L '/etc/sudoers' 'Defaults use_pty' }   # ambos patrones devuelven algo
            (Test-CIS_Debian13_5_2_2).Status | Should -Be 'Fail'
            Mock Get-Debian13SudoersLines { }
            (Test-CIS_Debian13_5_2_2).Status | Should -Be 'Fail'
        }
        It '5.2.3 logfile / 5.2.4 NOPASSWD / 5.2.5 !authenticate' {
            Mock Get-Debian13SudoersLines { L 'f' 'Defaults logfile="/var/log/sudo.log"' }; (Test-CIS_Debian13_5_2_3).Status | Should -Be 'Pass'
            Mock Get-Debian13SudoersLines { }; (Test-CIS_Debian13_5_2_3).Status | Should -Be 'Fail'
            (Test-CIS_Debian13_5_2_4).Status | Should -Be 'Pass'; (Test-CIS_Debian13_5_2_5).Status | Should -Be 'Pass'
            Mock Get-Debian13SudoersLines { L 'f' 'admin ALL=(ALL) NOPASSWD: ALL' }
            (Test-CIS_Debian13_5_2_4).Status | Should -Be 'Fail'
            Mock Get-Debian13SudoersLines { L 'f' 'Defaults !authenticate' }
            (Test-CIS_Debian13_5_2_5).Status | Should -Be 'Fail'
        }
        It '5.2.6 timestamp_timeout: 15 ok, 16 o negativo Fail, sin definir usa el default de sudo -V' {
            Mock Get-Debian13SudoersLines { L 'f' 'Defaults timestamp_timeout=15' }; (Test-CIS_Debian13_5_2_6).Status | Should -Be 'Pass'
            Mock Get-Debian13SudoersLines { L 'f' 'Defaults env_reset, timestamp_timeout=20' }; (Test-CIS_Debian13_5_2_6).Status | Should -Be 'Fail'
            Mock Get-Debian13SudoersLines { L 'f' 'Defaults timestamp_timeout=-1' }; (Test-CIS_Debian13_5_2_6).Status | Should -Be 'Fail'
            Mock Get-Debian13SudoersLines { }
            Mock Get-Debian13SudoDefaultTimeout { 15.0 }; (Test-CIS_Debian13_5_2_6).Status | Should -Be 'Pass'
            Mock Get-Debian13SudoDefaultTimeout { -1.0 }; (Test-CIS_Debian13_5_2_6).Status | Should -Be 'Fail'
            Mock Get-Debian13SudoDefaultTimeout { $null }; (Test-CIS_Debian13_5_2_6).Status | Should -Be 'Fail'
        }
        Context '5.2.7 su' {
            It 'Pass con pam_wheel use_uid y grupo vacio' {
                Mock Get-Debian13PamSuLines { 'auth required pam_wheel.so use_uid group=sugroup' }
                Mock Test-Debian13GroupExists { $true }
                Mock Get-Debian13GroupMembers { @() }
                (Test-CIS_Debian13_5_2_7).Status | Should -Be 'Pass'
            }
            It 'Fail si el grupo tiene miembros, no existe, o falta la linea/comentada' {
                Mock Get-Debian13PamSuLines { 'auth required pam_wheel.so use_uid group=sugroup' }
                Mock Test-Debian13GroupExists { $true }
                Mock Get-Debian13GroupMembers { @('alice') }; (Test-CIS_Debian13_5_2_7).Status | Should -Be 'Fail'
                Mock Test-Debian13GroupExists { $false }; Mock Get-Debian13GroupMembers { }; (Test-CIS_Debian13_5_2_7).Status | Should -Be 'Fail'
                Mock Test-Debian13GroupExists { $true }
                Mock Get-Debian13PamSuLines { '# auth required pam_wheel.so use_uid group=sugroup' }; (Test-CIS_Debian13_5_2_7).Status | Should -Be 'Fail'
                Mock Get-Debian13PamSuLines { 'auth required pam_wheel.so' }; (Test-CIS_Debian13_5_2_7).Status | Should -Be 'Fail'
            }
        }

        Context 'Set-* sobre sudoers (archivos temporales, visudo mockeado)' {
            BeforeEach {
                $script:dir = Join-Path ([IO.Path]::GetTempPath()) "cis13-sudo-$([guid]::NewGuid())"; New-Item -ItemType Directory $script:dir | Out-Null
                $script:cis = Join-Path $script:dir '60-cis'; $script:main = Join-Path $script:dir 'sudoers'
                $script:Debian13SudoersCisFile = $script:cis
                Mock Test-Debian13SudoersSyntax { $true }
            }
            AfterEach { Remove-Item $script:dir -Recurse -Force }

            It 'Update-Debian13SudoersFile: sin cambios devuelve $false y no toca el archivo' {
                Set-Content $script:main 'Defaults env_reset'
                (Update-Debian13SudoersFile -File $script:main -Transform { param($l) $l }) | Should -BeFalse
                @(Get-ChildItem $script:dir -Filter '*.bak*').Count | Should -Be 0
            }
            It 'Update-Debian13SudoersFile: si visudo rechaza, restaura el original y lanza error' {
                Set-Content $script:main 'Defaults env_reset'
                Mock Test-Debian13SudoersSyntax { $false }
                { Update-Debian13SudoersFile -File $script:main -Transform { param($l) $l + 'basura' } } | Should -Throw '*revertido*'
                @(Get-Content $script:main) | Should -Be @('Defaults env_reset')
            }
            It 'Update-Debian13SudoersFile: archivo nuevo rechazado no queda creado' {
                Mock Test-Debian13SudoersSyntax { $false }
                { Update-Debian13SudoersFile -File $script:cis -Transform { param($l) 'x' } } | Should -Throw
                Test-Path $script:cis | Should -BeFalse
            }
            It '5.2.2 Set: agrega use_pty al archivo CIS y comenta !use_pty en el original' {
                Set-Content $script:main @('Defaults env_reset', 'Defaults !use_pty')
                Mock Get-Debian13SudoersLines { if ($Pattern -like '*!use_pty*') { L $script:main 'Defaults !use_pty' } }
                Set-CIS_Debian13_5_2_2
                @(Get-Content $script:main) | Should -Be @('Defaults env_reset', '# Defaults !use_pty')
                @(Get-Content $script:cis) | Should -Be @('Defaults use_pty')
            }
            It '5.2.3 Set: logfile, reemplaza una definicion previa del archivo CIS' {
                Set-CIS_Debian13_5_2_3
                Set-CIS_Debian13_5_2_3 -LogFile '/var/log/sudo2.log'
                @(Get-Content $script:cis) | Should -Be @('Defaults logfile="/var/log/sudo2.log"')
            }
            It '5.2.4 Set exige -RemoveNoPasswd y solo quita la etiqueta (conserva la regla)' {
                Set-Content $script:main @('root ALL=(ALL:ALL) ALL', 'admin ALL=(ALL) NOPASSWD: ALL', '# ops ALL=(ALL) NOPASSWD: ALL')
                Mock Get-Debian13SudoersLines { L $script:main 'admin ALL=(ALL) NOPASSWD: ALL' }
                Set-CIS_Debian13_5_2_4 -WarningAction SilentlyContinue
                (Get-Content $script:main -Raw) | Should -Match 'NOPASSWD: ALL'
                Set-CIS_Debian13_5_2_4 -RemoveNoPasswd
                $l = @(Get-Content $script:main)
                $l[1] | Should -Be 'admin ALL=(ALL) ALL'
                $l[2] | Should -Be '# ops ALL=(ALL) NOPASSWD: ALL'
            }
            It '5.2.5 Set: quita !authenticate; una linea Defaults que queda vacia se comenta' {
                Set-Content $script:main @('Defaults !authenticate', 'ops ALL=(ALL) !authenticate ALL')
                Mock Get-Debian13SudoersLines { L $script:main 'x' }
                Set-CIS_Debian13_5_2_5
                $l = @(Get-Content $script:main)
                $l[0] | Should -Be '# Defaults !authenticate'
                $l[1] | Should -Not -Match '!authenticate'
                $l[1] | Should -Match '^ops ALL=\(ALL\)\s+ALL$'
            }
            It '5.2.6 Set: corrige valores > 15 en su archivo y agrega el default en el archivo CIS' {
                Set-Content $script:main @('Defaults env_reset, timestamp_timeout=60')
                Mock Get-Debian13SudoersLines { L $script:main 'Defaults env_reset, timestamp_timeout=60' }
                Set-CIS_Debian13_5_2_6
                @(Get-Content $script:main) | Should -Be @('Defaults env_reset, timestamp_timeout=15')
                @(Get-Content $script:cis) | Should -Be @('Defaults timestamp_timeout=15')
            }
        }
    }
}
