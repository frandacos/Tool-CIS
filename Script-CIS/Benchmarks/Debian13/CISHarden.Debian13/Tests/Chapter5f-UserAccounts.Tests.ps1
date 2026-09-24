#Requires -Modules Pester
<# Tests de 5.4 User Accounts and Environment (Debian 13) con un /etc temporal real; chage/usermod/useradd/passwd mockeados. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 5.4 User accounts and environment (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeEach {
            $script:root = Join-Path ([IO.Path]::GetTempPath()) "cis13-acct-$([guid]::NewGuid())"
            $script:etc = Join-Path $script:root 'etc'; $script:rh = Join-Path $script:root 'root'
            New-Item -ItemType Directory $script:etc, (Join-Path $script:etc 'profile.d'), $script:rh | Out-Null
            $script:Debian13EtcDir = $script:etc; $script:Debian13RootHome = $script:rh
            Set-Content (Join-Path $script:etc 'passwd') @('root:x:0:0:root:/root:/bin/bash', 'daemon:x:1:1:d:/usr/sbin:/usr/sbin/nologin', 'alice:x:1000:1000::/home/alice:/bin/bash', 'sync:x:4:0::/bin:/bin/sync')
            Set-Content (Join-Path $script:etc 'group') @('root:x:0:', 'daemon:x:1:', 'alice:x:1000:')
            Set-Content (Join-Path $script:etc 'shells') @('# shells', '/bin/sh', '/bin/bash', '/usr/sbin/nologin')
            Set-Content (Join-Path $script:etc 'login.defs') @('# defs', 'PASS_MAX_DAYS   99999', 'PASS_MIN_DAYS   0', 'PASS_WARN_AGE   7', 'UID_MIN 1000', 'UMASK 022', 'ENCRYPT_METHOD YESCRYPT')
            # shadow: user, hash, lastchg, min, max, warn, inactive
            Set-Content (Join-Path $script:etc 'shadow') @('root:$y$j9T$abc$def:19000:0:99999:7:::', 'alice:$y$j9T$abc$def:19000:1:90:7:30::', 'daemon:*:19000:0:99999:7:::')
            Mock Invoke-Debian13Chage { }; Mock Invoke-Debian13Usermod { }; Mock Set-Debian13UseraddDefaultInactive { }
        }
        AfterEach { Remove-Item $script:root -Recurse -Force }

        Context '5.4.1' {
            It '5.4.1.1: Fail si login.defs o algun usuario supera 365 / es < 1; Pass conforme' {
                (Test-CIS_Debian13_5_4_1_1).Status | Should -Be 'Fail'   # login.defs 99999 y root 99999
                Set-Content (Join-Path $script:etc 'login.defs') @('PASS_MAX_DAYS 365')
                Set-Content (Join-Path $script:etc 'shadow') @('root:$6$a$b:19000:0:365:7:::', 'alice:$6$a$b:19000:1:90:7:30::')
                (Test-CIS_Debian13_5_4_1_1).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:etc 'shadow') @('alice:$6$a$b:19000:1:0:7:30::')
                (Test-CIS_Debian13_5_4_1_1).Status | Should -Be 'Fail'
            }
            It '5.4.1.1 Set: login.defs, chage por usuario fuera de norma y omite cuentas sin fecha de cambio' {
                Set-Content (Join-Path $script:etc 'shadow') @('root:$6$a$b:19000:0:99999:7:::', 'bob:$6$a$b::0:99999:7:::', 'alice:$6$a$b:19000:1:90:7:30::')
                Set-CIS_Debian13_5_4_1_1 -WarningAction SilentlyContinue
                (Get-Debian13LoginDefs -Key 'PASS_MAX_DAYS') | Should -Be '365'
                Should -Invoke Invoke-Debian13Chage -Times 1 -ParameterFilter { $Arguments -contains '--maxdays' -and $Arguments -contains 'root' }
                Should -Invoke Invoke-Debian13Chage -Times 0 -ParameterFilter { $Arguments -contains 'bob' }
                Should -Invoke Invoke-Debian13Chage -Times 0 -ParameterFilter { $Arguments -contains 'alice' }
            }
            It '5.4.1.1 Set -WhatIf no modifica login.defs ni llama a chage' {
                Set-CIS_Debian13_5_4_1_1 -WhatIf -WarningAction SilentlyContinue
                (Get-Debian13LoginDefs -Key 'PASS_MAX_DAYS') | Should -Be '99999'
                Should -Invoke Invoke-Debian13Chage -Times 0
            }
            It '5.4.1.2 es Manual' { (Test-CIS_Debian13_5_4_1_2).Status | Should -Be 'ManualReviewRequired' }
            It '5.4.1.3 warn >= 7' {
                (Test-CIS_Debian13_5_4_1_3).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:etc 'shadow') @('alice:$6$a$b:19000:1:90:3:30::')
                (Test-CIS_Debian13_5_4_1_3).Status | Should -Be 'Fail'
                Set-CIS_Debian13_5_4_1_3
                Should -Invoke Invoke-Debian13Chage -Times 1 -ParameterFilter { $Arguments -contains '--warndays' -and $Arguments -contains '7' -and $Arguments -contains 'alice' }
            }
            It '5.4.1.4 ENCRYPT_METHOD SHA512/YESCRYPT y Set' {
                (Test-CIS_Debian13_5_4_1_4).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:etc 'login.defs') 'ENCRYPT_METHOD MD5'
                (Test-CIS_Debian13_5_4_1_4).Status | Should -Be 'Fail'
                Set-CIS_Debian13_5_4_1_4
                (Test-CIS_Debian13_5_4_1_4).Status | Should -Be 'Pass'
                @(Get-Content (Join-Path $script:etc 'login.defs') | Where-Object { $_ -match '^ENCRYPT_METHOD' }).Count | Should -Be 1
            }
            It '5.4.1.5 inactive: default y usuarios entre 0 y 45' {
                Mock Get-Debian13UseraddDefaultInactive { 45 }
                Set-Content (Join-Path $script:etc 'shadow') @('alice:$6$a$b:19000:1:90:7:30::')
                (Test-CIS_Debian13_5_4_1_5).Status | Should -Be 'Pass'
                Mock Get-Debian13UseraddDefaultInactive { [int]"-1" }; (Test-CIS_Debian13_5_4_1_5).Status | Should -Be 'Fail'
                Mock Get-Debian13UseraddDefaultInactive { 45 }
                Set-Content (Join-Path $script:etc 'shadow') @('alice:$6$a$b:19000:1:90:7:90::', 'bob:$6$a$b:19000:1:90:7::')
                (Test-CIS_Debian13_5_4_1_5).Status | Should -Be 'Fail'
                Set-CIS_Debian13_5_4_1_5
                Should -Invoke Set-Debian13UseraddDefaultInactive -Times 1 -ParameterFilter { $Days -eq 45 }
                Should -Invoke Invoke-Debian13Chage -Times 2
            }
            It '5.4.1.6 fecha de cambio en el futuro = Fail' {
                Mock Get-Debian13TodayDays { 20000 }
                (Test-CIS_Debian13_5_4_1_6).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:etc 'shadow') @('alice:$6$a$b:20500:1:90:7:30::')
                (Test-CIS_Debian13_5_4_1_6).Status | Should -Be 'Fail'
            }
        }

        Context '5.4.2' {
            It 'UID 0 / GID 0 / grupo GID 0' {
                foreach ($n in 1..3) { (& "Test-CIS_Debian13_5_4_2_$n").Status | Should -Be 'Pass' }   # sync (gid 0) esta excluida
                Add-Content (Join-Path $script:etc 'passwd') @('toor:x:0:0::/root:/bin/bash', 'ops:x:2000:0::/home/ops:/bin/bash')
                Add-Content (Join-Path $script:etc 'group') 'wheel0:x:0:'
                foreach ($n in 1..3) { (& "Test-CIS_Debian13_5_4_2_$n").Status | Should -Be 'Fail' -Because "5.4.2.$n" }
            }
            It '5.4.2.4 root con password o bloqueado' {
                Mock Get-Debian13PasswdStatus { 'P' }; (Test-CIS_Debian13_5_4_2_4).Status | Should -Be 'Pass'
                Mock Get-Debian13PasswdStatus { 'L' }; (Test-CIS_Debian13_5_4_2_4).Status | Should -Be 'Pass'
                Mock Get-Debian13PasswdStatus { 'NP' }; (Test-CIS_Debian13_5_4_2_4).Status | Should -Be 'Fail'
            }
            It '5.4.2.5 PATH de root: detecta ::, ":" final, "." y directorios inexistentes; Pass con directorios reales' {
                $d = Join-Path $script:root 'bin'; New-Item -ItemType Directory $d | Out-Null; & chmod 755 $d
                Mock Get-Debian13RootPath { $d }.GetNewClosure()
                Mock Get-CISFileOwner { 'root:root' }; Mock Get-CISFileMode { '755' }
                (Test-CIS_Debian13_5_4_2_5).Status | Should -Be 'Pass'
                foreach ($bad in ("${d}::${d}"), ("${d}:"), ("${d}:."), (".:${d}"), ("${d}:/no/existe")) {
                    Mock Get-Debian13RootPath { $bad }.GetNewClosure(); (Test-CIS_Debian13_5_4_2_5).Status | Should -Be 'Fail' -Because $bad
                }
                Mock Get-CISFileMode { '775' }; Mock Get-Debian13RootPath { $d }.GetNewClosure(); (Test-CIS_Debian13_5_4_2_5).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '755' }; Mock Get-CISFileOwner { 'alice:alice' }; (Test-CIS_Debian13_5_4_2_5).Status | Should -Be 'Fail'
                Mock Get-Debian13RootPath { $null }; (Test-CIS_Debian13_5_4_2_5).Status | Should -Be 'Error'
            }
            It 'ConvertTo-Debian13UmaskValue y restrictividad (octal y simbolico)' {
                foreach ($ok in '027', '0027', '077', '037', 'u=rwx,g=rx,o=', 'u=rwx,g=,o=') { Test-Debian13UmaskRestrictive $ok | Should -BeTrue -Because $ok }
                foreach ($bad in '022', '002', '0022', '026', '007', 'u=rwx,g=rx,o=rx', 'u=rwx,g=rwx,o=', 'basura') { Test-Debian13UmaskRestrictive $bad | Should -BeFalse -Because $bad }
            }
            It '5.4.2.6 umask de root y Set' {
                (Test-CIS_Debian13_5_4_2_6).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:rh '.bashrc') @('alias ll="ls -l"', 'umask 022')
                Set-Content (Join-Path $script:rh '.profile') 'umask 027'
                (Test-CIS_Debian13_5_4_2_6).Status | Should -Be 'Fail'
                Mock Backup-CISFile { }
                Set-CIS_Debian13_5_4_2_6
                @(Get-Content (Join-Path $script:rh '.bashrc')) | Should -Be @('alias ll="ls -l"', 'umask 027')
                (Test-CIS_Debian13_5_4_2_6).Status | Should -Be 'Pass'
            }
            It '5.4.2.7 cuentas de sistema con shell valido y Set' {
                (Test-CIS_Debian13_5_4_2_7).Status | Should -Be 'Pass'   # daemon: nologin; sync excluida
                Add-Content (Join-Path $script:etc 'passwd') 'svc:x:900:900::/var/svc:/bin/bash'
                (Test-CIS_Debian13_5_4_2_7).Status | Should -Be 'Fail'
                Set-CIS_Debian13_5_4_2_7
                Should -Invoke Invoke-Debian13Usermod -Times 1 -ParameterFilter { $Arguments -contains '-s' -and $Arguments -contains 'svc' }
                Should -Invoke Invoke-Debian13Usermod -Times 0 -ParameterFilter { $Arguments -contains 'alice' -or $Arguments -contains 'root' }
            }
            It '5.4.2.8 cuentas sin shell valido deben estar bloqueadas' {
                Mock Get-Debian13PasswdStatus { 'L' }; (Test-CIS_Debian13_5_4_2_8).Status | Should -Be 'Pass'
                Mock Get-Debian13PasswdStatus { if ($User -eq 'daemon') { 'P' } else { 'L' } }
                (Test-CIS_Debian13_5_4_2_8).Status | Should -Be 'Fail'
                Set-CIS_Debian13_5_4_2_8
                Should -Invoke Invoke-Debian13Usermod -Times 1 -ParameterFilter { $Arguments -contains '-L' -and $Arguments -contains 'daemon' }
            }
        }

        Context '5.4.3' {
            It '5.4.3.1 nologin en /etc/shells y Set' {
                (Test-CIS_Debian13_5_4_3_1).Status | Should -Be 'Fail'
                Mock Backup-CISFile { }
                Set-CIS_Debian13_5_4_3_1
                (Test-CIS_Debian13_5_4_3_1).Status | Should -Be 'Pass'
                @(Get-Content (Join-Path $script:etc 'shells')) | Should -Be @('# shells', '/bin/sh', '/bin/bash')
            }
            It '5.4.3.2 TMOUT: sin configurar Fail; typeset -xr Pass; valores/flags incorrectos Fail' {
                $f = Join-Path $script:etc 'profile.d/50-tmout.sh'
                (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Fail'
                Set-Content $f 'typeset -xr TMOUT=900'; (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Pass'
                Set-Content $f @('TMOUT=600', 'readonly TMOUT', 'export TMOUT'); (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Pass'
                Set-Content $f 'typeset -xr TMOUT=1800'; (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Fail'
                Set-Content $f 'TMOUT=600'; (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Fail'
                Set-Content $f 'typeset -xr TMOUT=0'; (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Fail'
                Set-Content $f @('typeset -xr TMOUT=900'); Set-Content (Join-Path $script:etc 'profile') 'TMOUT=3000'
                (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Fail'
            }
            It '5.4.3.2 Set: comenta otras definiciones y crea 50-tmout.sh' {
                Set-Content (Join-Path $script:etc 'profile') @('export PATH', 'TMOUT=3000', 'readonly TMOUT')
                Mock Backup-CISFile { }
                Set-CIS_Debian13_5_4_3_2
                @(Get-Content (Join-Path $script:etc 'profile')) | Should -Be @('export PATH', '# TMOUT=3000', '# readonly TMOUT')
                (Test-CIS_Debian13_5_4_3_2).Status | Should -Be 'Pass'
            }
            It '5.4.3.3 umask: requiere profile.d y login.defs a 027' {
                (Test-CIS_Debian13_5_4_3_3).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:etc 'profile.d/60-default_umask.sh') 'umask 027'
                (Test-CIS_Debian13_5_4_3_3).Status | Should -Be 'Fail'   # login.defs UMASK 022
                Set-Content (Join-Path $script:etc 'login.defs') 'UMASK 027'
                (Test-CIS_Debian13_5_4_3_3).Status | Should -Be 'Pass'
                Add-Content (Join-Path $script:etc 'profile.d/60-default_umask.sh') 'umask 022'
                (Test-CIS_Debian13_5_4_3_3).Status | Should -Be 'Fail'
            }
            It '5.4.3.3 Set: comenta umask permisivo, agrega 027 y UMASK 027' {
                Set-Content (Join-Path $script:etc 'profile.d/10-x.sh') @('umask 022', 'echo hola')
                Mock Backup-CISFile { }
                Set-CIS_Debian13_5_4_3_3
                @(Get-Content (Join-Path $script:etc 'profile.d/10-x.sh')) | Should -Be @('# umask 022', 'echo hola')
                (Test-CIS_Debian13_5_4_3_3).Status | Should -Be 'Pass'
                (Get-Debian13LoginDefs -Key 'UMASK') | Should -Be '027'
            }
        }
    }
}
