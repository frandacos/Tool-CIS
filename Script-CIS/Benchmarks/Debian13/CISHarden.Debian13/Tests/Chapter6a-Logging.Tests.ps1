#Requires -Modules Pester
<# Tests de 6.1 System Logging (Debian 13). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 6.1 logging (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeEach {
            $script:root = Join-Path ([IO.Path]::GetTempPath()) "cis13-log-$([guid]::NewGuid())"
            $script:etc = Join-Path $script:root 'etc'; New-Item -ItemType Directory $script:etc, (Join-Path $script:etc 'rsyslog.d') | Out-Null
            $script:Debian13EtcDir = $script:etc
            Mock Invoke-Debian13Systemctl { }
        }
        AfterEach { Remove-Item $script:root -Recurse -Force }

        It 'Manuales (7): journald 6.1.1.1.2/.3, upload auth 6.1.1.2.2, rsyslog 6.1.2.5/.6/.8/.11' {
            foreach ($id in '6_1_1_1_2', '6_1_1_1_3', '6_1_1_2_2', '6_1_2_5', '6_1_2_6', '6_1_2_8', '6_1_2_11') { (& "Test-CIS_Debian13_$id").Status | Should -Be 'ManualReviewRequired' -Because $id }
        }

        Context 'journald' {
            It '6.1.1.1.1 journald activo' {
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'systemd-journald.service'; UnitFileState = 'static'; ActiveState = 'active' } }; (Test-CIS_Debian13_6_1_1_1_1).Status | Should -Be 'Pass'
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'systemd-journald.service'; UnitFileState = 'masked'; ActiveState = 'inactive' } }; (Test-CIS_Debian13_6_1_1_1_1).Status | Should -Be 'Fail'
            }
            It 'Storage / Compress / ForwardToSyslog (metodo journald)' {
                Mock Test-Debian13RsyslogInUse { $false }
                $script:cfg = @{}
                Mock Get-CISSystemdConfigValue { if ($script:cfg.ContainsKey($Option)) { [pscustomobject]@{ Value = $script:cfg[$Option]; File = 'f'; IsDefault = $false } } }
                $script:cfg = @{ Storage = 'persistent'; Compress = 'yes'; ForwardToSyslog = 'no' }
                foreach ($n in 4, 5, 6) { (& "Test-CIS_Debian13_6_1_1_1_$n").Status | Should -Be 'Pass' -Because $n }
                $script:cfg = @{ Storage = 'auto'; Compress = 'no'; ForwardToSyslog = 'yes' }
                foreach ($n in 4, 5, 6) { (& "Test-CIS_Debian13_6_1_1_1_$n").Status | Should -Be 'Fail' -Because $n }
                $script:cfg = @{}
                (Test-CIS_Debian13_6_1_1_1_5).Status | Should -Be 'Fail'
            }
            It 'ForwardToSyslog no aplica con rsyslog en uso y es obligatorio (yes) en 6.1.2.3' {
                Mock Test-Debian13RsyslogInUse { $true }
                Mock Get-CISSystemdConfigValue { [pscustomobject]@{ Value = 'yes'; File = 'f'; IsDefault = $false } }
                (Test-CIS_Debian13_6_1_1_1_4).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_6_1_2_3).Status | Should -Be 'Pass'
                Mock Get-CISSystemdConfigValue { [pscustomobject]@{ Value = 'no'; File = 'f'; IsDefault = $true } }
                (Test-CIS_Debian13_6_1_2_3).Status | Should -Be 'Fail'
                Mock Test-Debian13RsyslogInUse { $false }
                (Test-CIS_Debian13_6_1_2_3).Status | Should -Be 'Pass'
            }
            It 'Set journald escribe con el motor y reinicia el servicio; -WhatIf no hace nada' {
                Mock Set-CISSystemdConfigValue { }
                Set-CIS_Debian13_6_1_1_1_5
                Should -Invoke Set-CISSystemdConfigValue -ParameterFilter { $ConfName -eq 'systemd/journald.conf' -and $Block -eq 'Journal' -and $Option -eq 'Storage' -and $Value -eq 'persistent' } -Times 1
                Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments[0] -eq 'restart' -and $Arguments -contains 'systemd-journald' } -Times 1
                Set-CIS_Debian13_6_1_1_1_6 -WhatIf
                Should -Invoke Set-CISSystemdConfigValue -Times 1
            }
        }

        Context 'journal-remote / upload' {
            It '6.1.1.2.1 y .3 aplican solo con journald; .4 siempre' {
                Mock Test-Debian13RsyslogInUse { $true }
                (Test-CIS_Debian13_6_1_1_2_1).Status | Should -Be 'Pass'; (Test-CIS_Debian13_6_1_1_2_3).Status | Should -Be 'Pass'
                Mock Test-Debian13RsyslogInUse { $false }
                Mock Get-Debian13InstalledPackages { }
                (Test-CIS_Debian13_6_1_1_2_1).Status | Should -Be 'Fail'
                Mock Get-Debian13InstalledPackages { 'systemd-journal-remote' }
                (Test-CIS_Debian13_6_1_1_2_1).Status | Should -Be 'Pass'
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'systemd-journal-upload.service'; UnitFileState = 'enabled'; ActiveState = 'active' } }
                (Test-CIS_Debian13_6_1_1_2_3).Status | Should -Be 'Pass'
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'systemd-journal-upload.service'; UnitFileState = 'disabled'; ActiveState = 'inactive' } }
                (Test-CIS_Debian13_6_1_1_2_3).Status | Should -Be 'Fail'
            }
            It '6.1.1.2.4 remote no debe estar enabled ni active' {
                Mock Get-Debian13UnitStates { foreach ($u in $Units) { [pscustomobject]@{ Unit = $u; UnitFileState = 'masked'; ActiveState = 'inactive' } } }
                (Test-CIS_Debian13_6_1_1_2_4).Status | Should -Be 'Pass'
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'systemd-journal-remote.socket'; UnitFileState = 'enabled'; ActiveState = 'inactive' } }
                (Test-CIS_Debian13_6_1_1_2_4).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_1_1_2_4
                Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments[0] -eq 'mask' } -Times 1
            }
        }

        Context 'rsyslog' {
            It 'Sin rsyslog instalado, los controles 6.1.2.x dan Pass (no aplica)' {
                Mock Get-Debian13InstalledPackages { }
                foreach ($id in '6_1_2_1', '6_1_2_2', '6_1_2_4', '6_1_2_7', '6_1_2_10') { (& "Test-CIS_Debian13_$id").Status | Should -Be 'Pass' -Because $id }
                (Test-CIS_Debian13_6_1_2_9).Status | Should -Be 'Fail'
            }
            It '6.1.2.2 enabled y active' {
                Mock Test-Debian13RsyslogInUse { $true }
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'rsyslog.service'; UnitFileState = 'enabled'; ActiveState = 'active' } }; (Test-CIS_Debian13_6_1_2_2).Status | Should -Be 'Pass'
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'rsyslog.service'; UnitFileState = 'enabled'; ActiveState = 'inactive' } }; (Test-CIS_Debian13_6_1_2_2).Status | Should -Be 'Fail'
            }
            It '6.1.2.4 FileCreateMode 0640 o mas restrictivo y Set' {
                Mock Test-Debian13RsyslogInUse { $true }
                Set-Content (Join-Path $script:etc 'rsyslog.conf') @('$ModLoad imuxsock', '$FileCreateMode 0644')
                (Test-CIS_Debian13_6_1_2_4).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_1_2_4
                (Test-CIS_Debian13_6_1_2_4).Status | Should -Be 'Pass'
                Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments -contains 'rsyslog' } -Times 1
                foreach ($m in '0600', '0640', '0400', '0440') { Set-Content (Join-Path $script:etc 'rsyslog.conf') "`$FileCreateMode $m"; Remove-Item (Join-Path $script:etc 'rsyslog.d/50-cis-filecreatemode.conf') -ErrorAction SilentlyContinue; (Test-CIS_Debian13_6_1_2_4).Status | Should -Be 'Pass' -Because $m }
                foreach ($m in '0660', '0644', '0666') { Set-Content (Join-Path $script:etc 'rsyslog.conf') "`$FileCreateMode $m"; (Test-CIS_Debian13_6_1_2_4).Status | Should -Be 'Fail' -Because $m }
            }
            It '6.1.2.7 recepcion remota (imtcp) en formato avanzado y legacy; Set la comenta' {
                Mock Test-Debian13RsyslogInUse { $true }
                Mock Backup-CISFile { }
                (Test-CIS_Debian13_6_1_2_7).Status | Should -Be 'Pass'
                $f = Join-Path $script:etc 'rsyslog.d/10-recv.conf'
                foreach ($line in 'module(load="imtcp")', 'input(type="imtcp" port="514")', '$ModLoad imtcp', '$InputTCPServerRun 514') {
                    Set-Content $f @('# nada', $line); (Test-CIS_Debian13_6_1_2_7).Status | Should -Be 'Fail' -Because $line
                }
                Set-Content $f @('module(load="imtcp")', 'input(type="imtcp" port="514")', 'auth.* /var/log/auth.log')
                Set-CIS_Debian13_6_1_2_7
                @(Get-Content $f) | Should -Be @('# module(load="imtcp")', '# input(type="imtcp" port="514")', 'auth.* /var/log/auth.log')
                (Test-CIS_Debian13_6_1_2_7).Status | Should -Be 'Pass'
            }
            It '6.1.2.10 requiere StreamDriver="gtls" con rsyslog en uso' {
                Mock Test-Debian13RsyslogInUse { $true }
                (Test-CIS_Debian13_6_1_2_10).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:etc 'rsyslog.d/40-forward.conf') 'action(type="omfwd" target="s" StreamDriver="gtls" StreamDriverMode="1")'
                (Test-CIS_Debian13_6_1_2_10).Status | Should -Be 'Pass'
            }
        }

        Context '6.1.3.1 archivos de log' {
            BeforeEach { Mock Get-Debian13ValidShells { '/bin/bash', '/bin/sh' } }
            It 'sin candidatos = Pass; reglas por nombre de archivo' {
                Mock Get-Debian13LogFileCandidates { }
                (Test-CIS_Debian13_6_1_3_1).Status | Should -Be 'Pass'
                function script:F { param($p, $m, $u, $g) [pscustomobject]@{ Path = $p; Mode = [Convert]::ToInt32($m, 8); User = $u; Group = $g } }
                $cases = @(
                    @('/var/log/syslog', '0640', 'root', 'adm', $false), @('/var/log/syslog', '0644', 'root', 'adm', $true), @('/var/log/auth.log', '0640', 'syslog', 'adm', $false),
                    @('/var/log/auth.log', '0640', 'bob', 'adm', $true), @('/var/log/wtmp', '0664', 'root', 'utmp', $false), @('/var/log/wtmp', '0666', 'root', 'utmp', $true),
                    @('/var/log/btmp', '0660', 'root', 'utmp', $false), @('/var/log/apt/history.log', '0644', 'root', 'root', $false), @('/var/log/apt/history.log', '0664', 'root', 'root', $true),
                    @('/var/log/journal/x/system.journal', '0640', 'root', 'systemd-journal', $false), @('/var/log/journal/x/system.journal', '0640', 'root', 'adm', $true),
                    @('/var/log/lastlog', '0664', 'root', 'utmp', $false), @('/var/log/cloud-init.log', '0640', 'syslog', 'adm', $false), @('/var/log/other.log', '0640', 'root', 'adm', $false),
                    @('/var/log/other.log', '0600', 'syslog', 'adm', $false), @('/var/log/other.log', '0660', 'root', 'adm', $true), @('/var/log/other.log', '0640', 'nobody', 'adm', $false)
                )
                foreach ($c in $cases) {
                    $file = F $c[0] $c[1] $c[2] $c[3]
                    Mock Get-Debian13LogFileCandidates { $file }.GetNewClosure()
                    $script:Debian13LogShellLookup = { param($u) '/usr/sbin/nologin' }
                    $exp = if ($c[4]) { 'Fail' } else { 'Pass' }
                    (Test-CIS_Debian13_6_1_3_1).Status | Should -Be $exp -Because "$($c[0]) $($c[1]) $($c[2]):$($c[3])"
                }
            }
            It 'un archivo de un usuario con shell valido y owner ajeno = Fail; de cuenta de servicio (nologin) = Pass' {
                $file = [pscustomobject]@{ Path = '/var/log/app.log'; Mode = 416; User = 'bob'; Group = 'bob' }   # 0640
                Mock Get-Debian13LogFileCandidates { $file }
                $script:Debian13LogShellLookup = { param($u) '/bin/bash' }; (Test-CIS_Debian13_6_1_3_1).Status | Should -Be 'Fail'
                $script:Debian13LogShellLookup = { param($u) '/usr/sbin/nologin' }; (Test-CIS_Debian13_6_1_3_1).Status | Should -Be 'Pass'
            }
        }
    }
}
