#Requires -Modules Pester
<# Tests de 6.2.3 reglas de auditd (Debian 13): motor de comparacion semantica y Test/Set con un rules.d temporal real. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 6.2.3 auditd rules (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeEach {
            $script:root = Join-Path ([IO.Path]::GetTempPath()) "cis13-rules-$([guid]::NewGuid())"
            $script:aud = Join-Path $script:root 'audit'; New-Item -ItemType Directory $script:aud, (Join-Path $script:aud 'rules.d') | Out-Null
            $script:Debian13AuditDir = $script:aud
            Mock Get-Debian13AuditArch { 'b64' }; Mock Get-Debian13UidMin { '1000' }
            Mock Invoke-Debian13AugenrulesLoad { }
        }
        AfterEach { Remove-Item $script:root -Recurse -Force }

        Context 'Motor de comparacion' {
            BeforeAll {
                function script:M { param($e, $a) Test-Debian13AuditRuleMatch -Expected (ConvertTo-Debian13AuditRule $e) -Actual (ConvertTo-Debian13AuditRule $a) }
            }
            It 'Regla de disco = regla de auditctl -l (reescrituras de auditctl)' {
                M '-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access' '-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-13 -F auid>=1000 -F auid!=-1 -F key=access' | Should -BeTrue
                M '-a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change' '-a always,exit -F arch=b64 -S clock_settime -F a0=0 -F key=time-change' | Should -BeTrue
                M '-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation' '-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=-1 -F key=user_emulation' | Should -BeTrue
            }
            It 'Reglas de path/dir: equivalentes a -w (deprecado), con perm suficiente y sin arch' {
                $e = '-a always,exit -F arch=b64 -S all -F path=/etc/sudoers -F perm=wa -k scope'
                M $e '-a always,exit -F arch=b64 -S all -F path=/etc/sudoers -F perm=wa -k scope' | Should -BeTrue
                M $e '-a always,exit -S all -F path=/etc/sudoers -F perm=wa -F key=scope' | Should -BeTrue
                M $e '-w /etc/sudoers -p wa -k scope' | Should -BeTrue
                M $e '-w /etc/sudoers -p rwxa -k scope' | Should -BeTrue
                M $e '-w /etc/sudoers -p w -k scope' | Should -BeFalse
                M $e '-w /etc/sudoers.d -p wa -k scope' | Should -BeFalse
                M '-a always,exit -F arch=b64 -S all -F dir=/etc/sudoers.d -F perm=wa -k scope' '-w /etc/sudoers.d/ -p wa -k scope' | Should -BeTrue
            }
            It 'Rechaza reglas distintas: syscall faltante, campo faltante, arch distinta, auid distinto' {
                $e = '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=unset -k perm_mod'
                M $e '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=-1 -F key=perm_mod' | Should -BeTrue
                M $e '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1' | Should -BeFalse
                M $e '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2' | Should -BeFalse
                M $e '-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=-1' | Should -BeFalse
                M $e '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=500 -F auid!=-1' | Should -BeFalse
                M $e '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2,chown -F auid>=1000 -F auid!=-1' | Should -BeTrue   # superconjunto de syscalls
                M $e '-a never,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1000 -F auid!=-1' | Should -BeFalse
            }
            It 'ConvertTo-Debian13AuditRule ignora lineas que no son reglas' {
                ConvertTo-Debian13AuditRule '-e 2' | Should -BeNullOrEmpty; ConvertTo-Debian13AuditRule '-c' | Should -BeNullOrEmpty
            }
        }

        Context 'Test-* con reglas en disco y cargadas' {
            It 'Sin reglas en disco: Fail; en disco y cargadas: Pass; solo en disco (no cargadas): Fail' {
                Mock Get-Debian13AuditctlList { }
                (Test-CIS_Debian13_6_2_3_2).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:aud 'rules.d/50-user_emulation.rules') '-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation'
                (Test-CIS_Debian13_6_2_3_2).Status | Should -Be 'Fail'
                Mock Get-Debian13AuditctlList { '-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=-1 -F key=user_emulation' }
                (Test-CIS_Debian13_6_2_3_2).Status | Should -Be 'Pass'
            }
            It 'Vigilancia de una ruta inexistente: exige la regla en disco pero no cargada' {
                $missing = Join-Path $script:root 'no-existe'
                Mock Test-Path { $false } -ParameterFilter { $Path -eq '/var/log/sudo.log' }
                Mock Get-Debian13AuditctlList { }
                Set-Content (Join-Path $script:aud 'rules.d/50-sudo.rules') '-a always,exit -F arch=b64 -S all -F path=/var/log/sudo.log -F perm=wa -k sudo_log_file'
                (Test-CIS_Debian13_6_2_3_3).Status | Should -Be 'Pass'
                Remove-Item (Join-Path $script:aud 'rules.d/50-sudo.rules')
                (Test-CIS_Debian13_6_2_3_3).Status | Should -Be 'Fail'
            }
            It 'Reglas -w antiguas en disco cuentan (estado passing del benchmark)' {
                Mock Test-Path { $true } -ParameterFilter { $Path -like '/etc/sudoers*' }
                Set-Content (Join-Path $script:aud 'rules.d/50-scope.rules') @('-w /etc/sudoers -p wa -k scope', '-w /etc/sudoers.d/ -p wa -k scope')
                Mock Get-Debian13AuditctlList { '-w /etc/sudoers -p wa -k scope', '-w /etc/sudoers.d -p wa -k scope' }
                (Test-CIS_Debian13_6_2_3_1).Status | Should -Be 'Pass'
            }
            It 'La regla puede estar en cualquier archivo .rules; los comentados no cuentan' {
                Mock Get-Debian13AuditctlList { '-a always,exit -F arch=b64 -S execve -C euid!=uid -F auid!=-1 -F key=x' }
                Set-Content (Join-Path $script:aud 'rules.d/10-otro.rules') '# -a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k x'
                (Test-CIS_Debian13_6_2_3_2).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:aud 'rules.d/99-mio.rules') '-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k mio'
                (Test-CIS_Debian13_6_2_3_2).Status | Should -Be 'Pass'
            }
        }

        Context 'Cobertura de las funciones generadas' {
            It 'Existen Test/Set para los 37 controles 6.2.3.x y las reglas del JSON se analizan' {
                foreach ($n in 1..37) {
                    Get-Command "Test-CIS_Debian13_6_2_3_$n" -ErrorAction Stop | Out-Null; Get-Command "Set-CIS_Debian13_6_2_3_$n" -ErrorAction Stop | Out-Null
                }
                $data = Get-Debian13AuditRulesData
                $n = 0
                foreach ($id in $data.PSObject.Properties.Name) { foreach ($b in $data.$id) { foreach ($r in $b.rules) { (ConvertTo-Debian13AuditRule (Expand-Debian13AuditRuleText $r)) | Should -Not -BeNullOrEmpty -Because "$id : $r"; $n++ } } }
                $n | Should -Be 47
            }
            It 'Cada control del JSON usa el titulo del inventario' {
                Mock Get-Debian13AuditctlList { }; (Test-CIS_Debian13_6_2_3_12).Title | Should -Match 'group'
            }
        }

        Context 'Set-* sobre un rules.d temporal' {
            It 'Escribe las reglas del benchmark con UID_MIN y arch sustituidos, en el archivo indicado, y es idempotente' {
                Mock Get-Debian13UidMin { '1500' }
                Set-CIS_Debian13_6_2_3_18
                $f = Join-Path $script:aud 'rules.d/50-perm_mod.rules'
                (Get-Content $f) | Should -Contain '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1500 -F auid!=unset -k perm_mod'
                Set-CIS_Debian13_6_2_3_18
                @(Get-Content $f | Where-Object { $_ -match 'chmod' }).Count | Should -Be 1
                Should -Invoke Invoke-Debian13AugenrulesLoad -Times 1
                Set-CIS_Debian13_6_2_3_19; Set-CIS_Debian13_6_2_3_20
                @(Get-Content $f | Where-Object { $_ -match '^-a' }).Count | Should -Be 3
                Mock Get-Debian13AuditctlList { '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,fchmodat2 -F auid>=1500 -F auid!=-1 -F key=perm_mod' }
                (Test-CIS_Debian13_6_2_3_18).Status | Should -Be 'Pass'
            }
            It 'arch b32 en sistemas de 32 bits' {
                Mock Get-Debian13AuditArch { 'b32' }
                Set-CIS_Debian13_6_2_3_5
                (Get-Content (Join-Path $script:aud 'rules.d/50-system_locale.rules') -Raw) | Should -Match 'arch=b32'
            }
            It '-WhatIf no escribe ni carga' {
                Set-CIS_Debian13_6_2_3_5 -WhatIf
                Test-Path (Join-Path $script:aud 'rules.d/50-system_locale.rules') | Should -BeFalse
                Should -Invoke Invoke-Debian13AugenrulesLoad -Times 0
            }
            It 'Set conserva reglas ya existentes en el archivo (agrega sin reemplazar)' {
                $f = Join-Path $script:aud 'rules.d/50-identity.rules'
                Set-Content $f '-w /etc/custom -p wa -k mio'
                Set-CIS_Debian13_6_2_3_12; Set-CIS_Debian13_6_2_3_13
                $c = Get-Content $f
                $c | Should -Contain '-w /etc/custom -p wa -k mio'
                @($c | Where-Object { $_ -match '/etc/group|/etc/passwd' }).Count | Should -Be 2
            }
        }

        Context '6.2.3.10 / 35 / 36 / 37' {
            It '6.2.3.10 genera una regla por binario setuid/setgid' {
                Mock Get-Debian13PrivilegedFiles { '/usr/bin/sudo', '/usr/bin/passwd' }
                Mock Get-Debian13AuditctlList { }
                (Test-CIS_Debian13_6_2_3_10).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_2_3_10
                $c = Get-Content (Join-Path $script:aud 'rules.d/50-privileged.rules')
                $c | Should -Contain '-a always,exit -F arch=b64 -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged'
                Mock Test-Path { $true } -ParameterFilter { $Path -like '/usr/bin/*' }
                Mock Get-Debian13AuditctlList { '-a always,exit -S all -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged', '-a always,exit -S all -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged' }
                (Test-CIS_Debian13_6_2_3_10).Status | Should -Be 'Pass'
                Mock Get-Debian13PrivilegedFiles { }
                (Test-CIS_Debian13_6_2_3_10).Status | Should -Be 'Pass'
            }
            It '6.2.3.35 -c en disco' {
                (Test-CIS_Debian13_6_2_3_35).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_2_3_35
                (Test-CIS_Debian13_6_2_3_35).Status | Should -Be 'Pass'
                (Get-Content (Join-Path $script:aud 'rules.d/01-initialize.rules')) | Should -Contain '-c'
            }
            It '6.2.3.36 -e 2: la ultima directiva -e decide; el Set exige -AcceptImmutable' {
                (Test-CIS_Debian13_6_2_3_36).Status | Should -Be 'Fail'
                Set-CIS_Debian13_6_2_3_36 -WarningAction SilentlyContinue
                Test-Path (Join-Path $script:aud 'rules.d/99-finalize.rules') | Should -BeFalse
                Set-CIS_Debian13_6_2_3_36 -AcceptImmutable
                (Test-CIS_Debian13_6_2_3_36).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:aud 'rules.d/999-later.rules') '-e 1'
                (Test-CIS_Debian13_6_2_3_36).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:aud 'rules.d/999-later.rules') '# -e 1'
                (Test-CIS_Debian13_6_2_3_36).Status | Should -Be 'Pass'
            }
            It '6.2.3.37 es Manual' { (Test-CIS_Debian13_6_2_3_37).Status | Should -Be 'ManualReviewRequired' }
        }
    }
}
