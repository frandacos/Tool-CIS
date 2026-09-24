#Requires -Modules Pester
<# Tests de 6.2.1/6.2.2/6.2.4 (auditd) y 6.3 (AIDE), Debian 13. Archivos temporales reales para auditd.conf; el resto mockeado. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 6.2/6.3 auditd y AIDE (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeEach {
            $script:root = Join-Path ([IO.Path]::GetTempPath()) "cis13-aud-$([guid]::NewGuid())"
            $script:aud = Join-Path $script:root 'audit'; $script:sbin = Join-Path $script:root 'sbin'; $script:logd = Join-Path $script:root 'varlog'
            New-Item -ItemType Directory $script:aud, (Join-Path $script:aud 'rules.d'), $script:sbin, $script:logd | Out-Null
            $script:Debian13AuditDir = $script:aud; $script:Debian13SbinDir = $script:sbin; $script:Debian13GrubDropInDir = Join-Path $script:root 'grub.d'
            Set-Content (Join-Path $script:aud 'auditd.conf') @("log_file = $(Join-Path $script:logd 'audit.log')", 'log_group = adm', 'max_log_file = 8', 'max_log_file_action = ROTATE', 'space_left_action = SYSLOG', 'admin_space_left_action = SUSPEND', 'disk_full_action = SUSPEND', 'disk_error_action = SUSPEND')
            Mock Invoke-Debian13Systemctl { }
        }
        AfterEach { Remove-Item $script:root -Recurse -Force }

        It '6.2.1.1 auditd y audispd-plugins' {
            Mock Get-Debian13InstalledPackages { 'x' }; (Test-CIS_Debian13_6_2_1_1).Status | Should -Be 'Pass'
            Mock Get-Debian13InstalledPackages { if ($Patterns -contains 'auditd') { 'auditd' } }; (Test-CIS_Debian13_6_2_1_1).Status | Should -Be 'Fail'
        }
        It '6.2.1.2 enabled y active' {
            Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'auditd.service'; UnitFileState = 'enabled'; ActiveState = 'active' } }; (Test-CIS_Debian13_6_2_1_2).Status | Should -Be 'Pass'
            Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'auditd.service'; UnitFileState = 'enabled'; ActiveState = 'inactive' } }; (Test-CIS_Debian13_6_2_1_2).Status | Should -Be 'Fail'
        }
        Context 'GRUB audit=1 y audit_backlog_limit' {
            It 'Pass/Fail/Error segun las lineas linux' {
                Mock Get-Debian13GrubLinuxLines { 'linux /vmlinuz root=/dev/sda1 quiet audit=1 audit_backlog_limit=8192' }
                (Test-CIS_Debian13_6_2_1_3).Status | Should -Be 'Pass'; (Test-CIS_Debian13_6_2_1_4).Status | Should -Be 'Pass'
                Mock Get-Debian13GrubLinuxLines { 'linux /vmlinuz quiet audit=1', 'linux /vmlinuz-old quiet' }
                (Test-CIS_Debian13_6_2_1_3).Status | Should -Be 'Fail'; (Test-CIS_Debian13_6_2_1_4).Status | Should -Be 'Fail'
                Mock Get-Debian13GrubLinuxLines { }
                (Test-CIS_Debian13_6_2_1_3).Status | Should -Be 'Error'
            }
            It 'Set anexa el parametro (no reemplaza GRUB_CMDLINE_LINUX) y ejecuta update-grub' {
                Mock Invoke-Debian13UpdateGrub { }
                Set-CIS_Debian13_6_2_1_3 -WarningAction SilentlyContinue
                Should -Invoke Invoke-Debian13UpdateGrub -Times 1
                $c = Get-Content (Join-Path $script:Debian13GrubDropInDir '40-cis-audit.cfg') -Raw
                $c | Should -Match 'GRUB_CMDLINE_LINUX="\$GRUB_CMDLINE_LINUX audit=1"'
            }
        }
        Context '6.2.2 auditd.conf' {
            It 'valores por defecto de Debian: 6.2.2.2/.3/.4 Fail; max_log_file numerico Pass' {
                (Test-CIS_Debian13_6_2_2_1).Status | Should -Be 'Pass'
                foreach ($n in 2, 3, 4) { (& "Test-CIS_Debian13_6_2_2_$n").Status | Should -Be 'Fail' -Because $n }
            }
            It 'Set 6.2.2.x escribe los valores del benchmark, es idempotente y reinicia auditd' {
                Set-CIS_Debian13_6_2_2_2; Set-CIS_Debian13_6_2_2_3; Set-CIS_Debian13_6_2_2_4 -SpaceLeftAction single -WarningAction SilentlyContinue
                Set-CIS_Debian13_6_2_2_2
                foreach ($n in 2, 3, 4) { (& "Test-CIS_Debian13_6_2_2_$n").Status | Should -Be 'Pass' -Because $n }
                $c = @(Get-Content (Join-Path $script:aud 'auditd.conf'))
                @($c | Where-Object { $_ -match '^max_log_file_action' }).Count | Should -Be 1
                ($c -join "`n") | Should -Match 'disk_full_action = halt'
                Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments -contains 'auditd' -and $Arguments[0] -eq 'restart' } -Times 4
            }
            It 'valores no permitidos Fail (disk_full_action=ignore, admin_space_left_action=email)' {
                Set-Content (Join-Path $script:aud 'auditd.conf') @('disk_full_action = ignore', 'disk_error_action = syslog', 'space_left_action = email', 'admin_space_left_action = email')
                (Test-CIS_Debian13_6_2_2_3).Status | Should -Be 'Fail'; (Test-CIS_Debian13_6_2_2_4).Status | Should -Be 'Fail'
            }
            It '6.2.2.1: Set sin -SizeMB no inventa; con -SizeMB escribe' {
                Set-CIS_Debian13_6_2_2_1 -WarningAction SilentlyContinue
                (Get-Debian13AuditdConfValue -Key 'max_log_file') | Should -Be '8'
                Set-CIS_Debian13_6_2_2_1 -SizeMB 64
                (Get-Debian13AuditdConfValue -Key 'max_log_file') | Should -Be '64'
                Remove-Item (Join-Path $script:aud 'auditd.conf'); (Test-CIS_Debian13_6_2_2_1).Status | Should -Be 'Fail'
            }
            It 'valor comentado no cuenta' {
                Set-Content (Join-Path $script:aud 'auditd.conf') '#max_log_file_action = keep_logs'
                (Test-CIS_Debian13_6_2_2_2).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_2_2_2
                (Test-CIS_Debian13_6_2_2_2).Status | Should -Be 'Pass'
            }
        }
        Context '6.2.4 acceso' {
            BeforeEach { Set-Content (Join-Path $script:logd 'audit.log') 'x'; Set-Content (Join-Path $script:aud 'rules.d/audit.rules') 'x'; Set-Content (Join-Path $script:sbin 'auditctl') 'x' }
            It 'Todo conforme = Pass' {
                Mock Get-CISFileMode { '640' }; Mock Get-CISFileOwner { 'root:adm' }
                foreach ($n in 1, 2, 3, 5, 6) { (& "Test-CIS_Debian13_6_2_4_$n").Status | Should -Be 'Pass' -Because $n }
                Mock Get-CISFileMode { '750' }; (Test-CIS_Debian13_6_2_4_4).Status | Should -Be 'Pass'
                Mock Get-CISFileMode { '755' }; Mock Get-CISFileOwner { 'root:root' }
                foreach ($n in 7, 8, 9, 10) { (& "Test-CIS_Debian13_6_2_4_$n").Status | Should -Be 'Pass' -Because $n }
            }
            It 'Modos: logs > 0640, directorio > 0750, config > 0640, tools > 0755 = Fail' {
                Mock Get-CISFileOwner { 'root:root' }
                Mock Get-CISFileMode { '644' }; (Test-CIS_Debian13_6_2_4_1).Status | Should -Be 'Fail'; (Test-CIS_Debian13_6_2_4_5).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '755' }; (Test-CIS_Debian13_6_2_4_4).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '775' }; (Test-CIS_Debian13_6_2_4_8).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '400' }; foreach ($n in 1, 4, 5, 8) { (& "Test-CIS_Debian13_6_2_4_$n").Status | Should -Be 'Pass' -Because $n }
                Mock Get-CISFileMode { '740' }; (Test-CIS_Debian13_6_2_4_5).Status | Should -Be 'Fail'   # x de owner
            }
            It 'Owner y grupo' {
                Mock Get-CISFileMode { '640' }
                Mock Get-CISFileOwner { 'bob:root' }
                foreach ($n in 2, 6, 9) { (& "Test-CIS_Debian13_6_2_4_$n").Status | Should -Be 'Fail' -Because $n }
                Mock Get-CISFileOwner { 'root:staff' }
                foreach ($n in 3, 7, 10) { (& "Test-CIS_Debian13_6_2_4_$n").Status | Should -Be 'Fail' -Because $n }
                Mock Get-CISFileOwner { 'root:adm' }; (Test-CIS_Debian13_6_2_4_3).Status | Should -Be 'Pass'; (Test-CIS_Debian13_6_2_4_7).Status | Should -Be 'Fail'
            }
            It '6.2.4.3 Fail si log_group no es adm/root' {
                Mock Get-CISFileMode { '640' }; Mock Get-CISFileOwner { 'root:adm' }
                Set-Content (Join-Path $script:aud 'auditd.conf') @("log_file = $(Join-Path $script:logd 'audit.log')", 'log_group = staff')
                (Test-CIS_Debian13_6_2_4_3).Status | Should -Be 'Fail'
            }
            It 'Sin auditd.conf: los controles de logs dan Fail' {
                Remove-Item (Join-Path $script:aud 'auditd.conf')
                foreach ($n in 1..4) { (& "Test-CIS_Debian13_6_2_4_$n").Status | Should -Be 'Fail' -Because $n }
            }
            It 'Set usa chmod/chown/chgrp solo donde hace falta y respeta -WhatIf' {
                Mock Set-Debian13FileAttr { }
                Mock Get-CISFileMode { '664' }; Mock Get-CISFileOwner { 'bob:staff' }
                Set-CIS_Debian13_6_2_4_1; Set-CIS_Debian13_6_2_4_2; Set-CIS_Debian13_6_2_4_3
                Should -Invoke Set-Debian13FileAttr -ParameterFilter { $Chmod -eq 'u-x,g-wx,o-rwx' } -Times 1
                Should -Invoke Set-Debian13FileAttr -ParameterFilter { $Chown -eq 'root' } -Times 1
                Should -Invoke Set-Debian13FileAttr -ParameterFilter { $Chgrp -eq 'adm' } -Times 1
                Set-CIS_Debian13_6_2_4_8 -WhatIf
                Should -Invoke Set-Debian13FileAttr -ParameterFilter { $Chmod -eq 'go-w' } -Times 0
                Set-CIS_Debian13_6_2_4_8
                Should -Invoke Set-Debian13FileAttr -ParameterFilter { $Chmod -eq 'go-w' } -Times 1
            }
        }
        Context '6.3 AIDE' {
            It '6.3.1 aide y aide-common' {
                Mock Get-Debian13InstalledPackages { 'x' }; (Test-CIS_Debian13_6_3_1).Status | Should -Be 'Pass'
                Mock Get-Debian13InstalledPackages { if ($Patterns -contains 'aide') { 'aide' } }
                Mock Get-Debian13InstalledPackages { if ($Patterns -eq 'aide') { 'aide' } }; (Test-CIS_Debian13_6_3_1).Status | Should -Be 'Fail'
            }
            It '6.3.2 timer enabled+active y service static/enabled' {
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'dailyaidecheck.timer'; UnitFileState = 'enabled'; ActiveState = 'active' }; [pscustomobject]@{ Unit = 'dailyaidecheck.service'; UnitFileState = 'static'; ActiveState = 'inactive' } }
                (Test-CIS_Debian13_6_3_2).Status | Should -Be 'Pass'
                Mock Get-Debian13UnitStates { [pscustomobject]@{ Unit = 'dailyaidecheck.timer'; UnitFileState = 'disabled'; ActiveState = 'inactive' }; [pscustomobject]@{ Unit = 'dailyaidecheck.service'; UnitFileState = 'static'; ActiveState = 'inactive' } }
                (Test-CIS_Debian13_6_3_2).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_3_2
                Should -Invoke Invoke-Debian13Systemctl -ParameterFilter { $Arguments -contains '--now' -and $Arguments -contains 'dailyaidecheck.timer' } -Times 1
            }
            It '6.3.3 reglas de aide.conf para las 5 herramientas con todas las opciones' {
                Mock Get-Debian13InstalledPackages { 'aide' }
                Mock Resolve-Debian13AuditToolRealPath { "/usr/sbin/$Tool" }
                $conf = Join-Path $script:root 'aide.conf'; Mock Get-Debian13AideConfFiles { $conf }.GetNewClosure()
                $opts = 'p+i+n+u+g+s+b+acl+xattrs+sha512'
                Set-Content $conf (@('# Audit Tools') + @('auditctl', 'auditd', 'ausearch', 'aureport', 'augenrules' | ForEach-Object { "/usr/sbin/$_ $opts" }))
                (Test-CIS_Debian13_6_3_3).Status | Should -Be 'Pass'
                Set-Content $conf (@('auditctl', 'auditd', 'ausearch', 'aureport' | ForEach-Object { "/usr/sbin/$_ $opts" }))
                (Test-CIS_Debian13_6_3_3).Status | Should -Be 'Fail'   # falta augenrules
                Set-Content $conf (@('auditctl', 'auditd', 'ausearch', 'aureport', 'augenrules' | ForEach-Object { "/usr/sbin/$_ p+i+n+u+g+s+b+acl+xattrs+sha256" }))
                (Test-CIS_Debian13_6_3_3).Status | Should -Be 'Fail'   # sha256 en lugar de sha512
                Mock Get-Debian13InstalledPackages { }
                (Test-CIS_Debian13_6_3_3).Status | Should -Be 'Fail'
            }
        }
    }
}
