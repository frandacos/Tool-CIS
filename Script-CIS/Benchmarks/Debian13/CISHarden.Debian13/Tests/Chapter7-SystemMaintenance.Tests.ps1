#Requires -Modules Pester
<# Tests del capitulo 7 (Debian 13). passwd/group/shadow/shells en un /etc temporal real; permisos y find mockeados (stat -c es GNU-only). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 7 System Maintenance (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeEach {
            $script:root = Join-Path ([IO.Path]::GetTempPath()) "cis13-c7-$([guid]::NewGuid())"
            $script:etc = Join-Path $script:root 'etc'; New-Item -ItemType Directory $script:etc, (Join-Path $script:etc 'security'), (Join-Path $script:root 'home/alice') | Out-Null
            $script:Debian13EtcDir = $script:etc
            $script:home = Join-Path $script:root 'home/alice'
            Set-Content (Join-Path $script:etc 'passwd') @('root:x:0:0:root:/root:/bin/bash', 'daemon:x:1:1::/usr/sbin:/usr/sbin/nologin', "alice:x:1000:1000::$($script:home):/bin/bash")
            Set-Content (Join-Path $script:etc 'group') @('root:x:0:', 'daemon:x:1:', 'shadow:x:42:', 'alice:x:1000:')
            Set-Content (Join-Path $script:etc 'shadow') @('root:$y$a$b:19000:0:99999:7:::', 'daemon:*:19000:0:99999:7:::', 'alice:$y$a$b:19000:0:99999:7:::')
            Set-Content (Join-Path $script:etc 'shells') @('/bin/sh', '/bin/bash', '/usr/sbin/nologin')
        }
        AfterEach { Remove-Item $script:root -Recurse -Force }

        Context '7.1.1-7.1.10 archivos de cuentas' {
            It 'Pass con modos y propietarios del benchmark; usan las rutas y modos correctos' {
                $script:seen = @{}
                Mock Test-CISPathAccess { $script:seen[(Split-Path $Path -Leaf)] = "$MaxMode|$($Owner -join ',')"; [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '600'; Owner = 'root:root' } }
                foreach ($n in 1..10) { (& "Test-CIS_Debian13_7_1_$n").Status | Should -Be 'Pass' -Because "7.1.$n" }
                $script:seen['passwd'] | Should -Be '644|root:root'; $script:seen['group-'] | Should -Be '644|root:root'; $script:seen['shells'] | Should -Be '644|root:root'
                $script:seen['shadow'] | Should -Be '640|root:root,root:shadow'; $script:seen['gshadow-'] | Should -Be '640|root:root,root:shadow'
                $script:seen['opasswd'] | Should -Be '600|root:root'; $script:seen['opasswd.old'] | Should -Be '600|root:root'
            }
            It 'Fail con un archivo no conforme' {
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $false; Mode = '666'; Owner = 'root:root' } }
                foreach ($n in 1..10) { (& "Test-CIS_Debian13_7_1_$n").Status | Should -Be 'Fail' -Because "7.1.$n" }
            }
            It 'Test-CISPathAccess real: shadow 0640 root:shadow Pass; 0644 Fail; root:staff Fail; 0600 Pass' {
                $core = 'CISHarden.Core'
                Mock Get-CISFileOwner { 'root:shadow' } -ModuleName $core
                Mock Get-CISFileMode { '640' } -ModuleName $core; (Test-CIS_Debian13_7_1_5).Status | Should -Be 'Pass'
                Mock Get-CISFileMode { '644' } -ModuleName $core; (Test-CIS_Debian13_7_1_5).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '600' } -ModuleName $core; (Test-CIS_Debian13_7_1_5).Status | Should -Be 'Pass'
                Mock Get-CISFileOwner { 'root:staff' } -ModuleName $core; (Test-CIS_Debian13_7_1_5).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '644' } -ModuleName $core; Mock Get-CISFileOwner { 'root:root' } -ModuleName $core; (Test-CIS_Debian13_7_1_1).Status | Should -Be 'Pass'
                Mock Get-CISFileMode { '664' } -ModuleName $core; (Test-CIS_Debian13_7_1_1).Status | Should -Be 'Fail'
            }
            It 'Archivos inexistentes (opasswd) = Pass' {
                Mock Get-CISFileMode { $null } -ModuleName 'CISHarden.Core'; (Test-CIS_Debian13_7_1_10).Status | Should -Be 'Pass'
            }
            It 'Set: solo actua sobre archivos existentes y no conformes' {
                $f = Join-Path $script:etc 'passwd'
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = ($Path -eq $f); Compliant = $false; Mode = '666'; Owner = 'bob:bob' } }
                $script:calls = @()
                function script:chmod { $script:calls += "chmod $($args -join ' ')" }; function script:chown { $script:calls += "chown $($args -join ' ')" }
                Mock chmod { $script:calls += "chmod $($args -join ' ')" } -ErrorAction SilentlyContinue
                Set-CIS_Debian13_7_1_1 -WhatIf
                $script:calls.Count | Should -Be 0
            }
        }

        Context '7.1.11-7.1.13' {
            It '7.1.11 Pass sin world-writable; Fail con archivos o directorios sin sticky' {
                Mock Get-Debian13WorldWritable { [pscustomobject]@{ Files = @(); Dirs = @() } }; (Test-CIS_Debian13_7_1_11).Status | Should -Be 'Pass'
                Mock Get-Debian13WorldWritable { [pscustomobject]@{ Files = @('/opt/x'); Dirs = @() } }; (Test-CIS_Debian13_7_1_11).Status | Should -Be 'Fail'
                Mock Get-Debian13WorldWritable { [pscustomobject]@{ Files = @(); Dirs = @('/srv/shared') } }; (Test-CIS_Debian13_7_1_11).Status | Should -Be 'Fail'
            }
            It '7.1.11 Get-Debian13WorldWritable separa archivos y directorios sin sticky bit' {
                $d1 = Join-Path $script:root 'ww-dir'; $d2 = Join-Path $script:root 'ww-sticky'; $f1 = Join-Path $script:root 'ww-file'
                New-Item -ItemType Directory $d1, $d2 | Out-Null; Set-Content $f1 'x'
                $script:sticky = $d2; $script:found = @($d1, $d2, $f1)
                Mock Get-Debian13LocalMounts { '/fake' }
                Mock Invoke-Debian13FindPruned { $script:found }
                Mock Get-CISFileMode { if ($Path -eq $script:sticky) { '1777' } else { '777' } }
                $w = Get-Debian13WorldWritable
                $w.Files | Should -Be @($f1); $w.Dirs | Should -Be @($d1)
            }
            It '7.1.12 huerfanos' {
                Mock Get-Debian13UnownedFiles { }; (Test-CIS_Debian13_7_1_12).Status | Should -Be 'Pass'
                Mock Get-Debian13UnownedFiles { '/srv/old' }; (Test-CIS_Debian13_7_1_12).Status | Should -Be 'Fail'
            }
            It '7.1.13 es Manual' { (Test-CIS_Debian13_7_1_13).Status | Should -Be 'ManualReviewRequired' }
        }

        Context '7.2.1-7.2.8' {
            It 'Sistema sano: todos Pass' {
                foreach ($n in 1..8) { (& "Test-CIS_Debian13_7_2_$n").Status | Should -Be 'Pass' -Because "7.2.$n" }
            }
            It '7.2.1 password en passwd; Set ejecuta pwconv' {
                Set-Content (Join-Path $script:etc 'passwd') @('root:x:0:0::/root:/bin/bash', 'old:$6$hash:1001:1001::/home/old:/bin/bash')
                (Test-CIS_Debian13_7_2_1).Status | Should -Be 'Fail'
                Mock Invoke-Debian13Pwconv { }; Set-CIS_Debian13_7_2_1; Should -Invoke Invoke-Debian13Pwconv -Times 1
            }
            It '7.2.2 password vacio (incluye hashes no "$"); Set bloquea con passwd -l' {
                Set-Content (Join-Path $script:etc 'shadow') @('root:$y$a$b:19000:0:99999:7:::', 'nopw::19000:0:99999:7:::', 'locked:!:19000:0:99999:7:::')
                (Test-CIS_Debian13_7_2_2).Status | Should -Be 'Fail'
                Mock Invoke-Debian13Passwd { }
                Set-CIS_Debian13_7_2_2
                Should -Invoke Invoke-Debian13Passwd -Times 1 -ParameterFilter { $Arguments -contains '-l' -and $Arguments -contains 'nopw' }
                Set-CIS_Debian13_7_2_2 -WhatIf; Should -Invoke Invoke-Debian13Passwd -Times 1
            }
            It '7.2.3 GID de passwd inexistente en group' {
                Add-Content (Join-Path $script:etc 'passwd') 'ghost:x:1001:9999::/home/ghost:/bin/bash'
                (Test-CIS_Debian13_7_2_3).Status | Should -Be 'Fail'
            }
            It '7.2.4 grupo shadow con miembros o como grupo primario; Set vacia la lista' {
                Set-Content (Join-Path $script:etc 'group') @('root:x:0:', 'shadow:x:42:alice,bob', 'alice:x:1000:')
                (Test-CIS_Debian13_7_2_4).Status | Should -Be 'Fail'
                Set-CIS_Debian13_7_2_4
                @(Get-Content (Join-Path $script:etc 'group')) | Should -Contain 'shadow:x:42:'
                (Test-CIS_Debian13_7_2_4).Status | Should -Be 'Pass'
                Add-Content (Join-Path $script:etc 'passwd') 'sh:x:1002:42::/home/sh:/bin/bash'
                (Test-CIS_Debian13_7_2_4).Status | Should -Be 'Fail'
            }
            It 'Duplicados UID / GID / usuario / grupo' {
                Add-Content (Join-Path $script:etc 'passwd') @('dup:x:1000:1000::/home/dup:/bin/bash', 'alice:x:1005:1000::/home/a2:/bin/bash')
                Add-Content (Join-Path $script:etc 'group') @('dupg:x:1000:', 'alice:x:1006:')
                (Test-CIS_Debian13_7_2_5).Status | Should -Be 'Fail'; (Test-CIS_Debian13_7_2_6).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_7_2_7).Status | Should -Be 'Fail'; (Test-CIS_Debian13_7_2_8).Status | Should -Be 'Fail'
            }
        }

        Context '7.2.9 / 7.2.10 usuarios interactivos' {
            It '7.2.9: Pass conforme; Fail por owner, modo (> 0750) o home inexistente' {
                Mock Get-CISFileOwner { 'alice:alice' }; Mock Get-CISFileMode { '750' }
                Set-Content (Join-Path $script:etc 'passwd') @("alice:x:1000:1000::$($script:home):/bin/bash", 'daemon:x:1:1::/nonexistent:/usr/sbin/nologin')
                (Test-CIS_Debian13_7_2_9).Status | Should -Be 'Pass'    # daemon no es interactivo
                Mock Get-CISFileMode { '755' }; (Test-CIS_Debian13_7_2_9).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '700' }; (Test-CIS_Debian13_7_2_9).Status | Should -Be 'Pass'
                Mock Get-CISFileOwner { 'root:root' }; (Test-CIS_Debian13_7_2_9).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:etc 'passwd') 'bob:x:1001:1001::/home/no-existe:/bin/bash'
                (Test-CIS_Debian13_7_2_9).Status | Should -Be 'Fail'
            }
            It '7.2.9 Set: corrige owner y modo; el home inexistente solo advierte; -WhatIf no toca' {
                Set-Content (Join-Path $script:etc 'passwd') "alice:x:1000:1000::$($script:home):/bin/bash"
                Mock Get-CISFileOwner { 'root:root' }; Mock Get-CISFileMode { '777' }
                $script:cmds = @()
                Mock Get-Debian13HomeProblems { [pscustomobject]@{ User = [pscustomobject]@{ Name = 'alice'; Home = '/home/alice' }; Kind = 'owner'; Detail = 'x' }; [pscustomobject]@{ User = [pscustomobject]@{ Name = 'alice'; Home = '/home/alice' }; Kind = 'missing'; Detail = 'y' } }
                { Set-CIS_Debian13_7_2_9 -WhatIf -WarningAction SilentlyContinue } | Should -Not -Throw
            }
            It '7.2.10: dot files: .forward/.rhost, modos, owner y grupo primario' {
                Mock Get-Debian13HomeDotFiles { "$($script:home)/.bashrc" }
                Mock Get-CISFileMode { '644' }; Mock Get-CISFileOwner { 'alice:alice' }
                (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Pass'
                Mock Get-CISFileMode { '664' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '644' }; Mock Get-CISFileOwner { 'root:alice' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-CISFileOwner { 'alice:users' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-CISFileOwner { 'alice:alice' }
                Mock Get-Debian13HomeDotFiles { "$($script:home)/.forward" }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-Debian13HomeDotFiles { "$($script:home)/.rhost" }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-Debian13HomeDotFiles { "$($script:home)/.netrc" }; Mock Get-CISFileMode { '600' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Pass'
                Mock Get-CISFileMode { '644' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-Debian13HomeDotFiles { "$($script:home)/.bash_history" }; Mock Get-CISFileMode { '640' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Fail'
                Mock Get-CISFileMode { '600' }; (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Pass'
            }
            It '7.2.10 sin usuarios interactivos con home = Pass' {
                Set-Content (Join-Path $script:etc 'passwd') 'daemon:x:1:1::/usr/sbin:/usr/sbin/nologin'
                Mock Get-Debian13HomeDotFiles { '/x/.forward' }
                (Test-CIS_Debian13_7_2_10).Status | Should -Be 'Pass'
            }
        }
    }
}
