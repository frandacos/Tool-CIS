#Requires -Modules Pester
<# Tests de 5.3 PAM (Debian 13) con un arbol de archivos temporal real: /etc/pam.d, /etc/security y /usr/share/pam-configs
   se redirigen a un directorio temporal; pam-auth-update se mockea. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 5.3 PAM (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeEach {
            $script:root = Join-Path ([IO.Path]::GetTempPath()) "cis13-pam-$([guid]::NewGuid())"
            $script:pamd = Join-Path $script:root 'pam.d'; $script:sec = Join-Path $script:root 'security'; $script:cfg = Join-Path $script:root 'pam-configs'
            New-Item -ItemType Directory $script:pamd, $script:sec, (Join-Path $script:sec 'pwquality.conf.d'), $script:cfg | Out-Null
            $script:Debian13PamDir = $script:pamd; $script:Debian13SecurityDir = $script:sec; $script:Debian13PamConfigsDir = $script:cfg
            # PAM por defecto de Debian (simplificado)
            Set-Content (Join-Path $script:pamd 'common-auth') @('auth [success=2 default=ignore] pam_unix.so nullok try_first_pass', 'auth requisite pam_deny.so')
            Set-Content (Join-Path $script:pamd 'common-account') @('account [success=1 new_authtok_reqd=done default=ignore] pam_unix.so')
            Set-Content (Join-Path $script:pamd 'common-password') @('# comentario', 'password requisite pam_pwquality.so retry=3', 'password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt')
            Set-Content (Join-Path $script:pamd 'common-session') @('session required pam_unix.so')
            Set-Content (Join-Path $script:pamd 'common-session-noninteractive') @('session required pam_unix.so')
            Mock Invoke-Debian13PamAuthUpdate { }
        }
        AfterEach { Remove-Item $script:root -Recurse -Force }

        It 'Get-Debian13PamArg distingue ausente, flag y valor' {
            Get-Debian13PamArg -Args 'obscure use_authtok remember=5' -Key 'remember' | Should -Be '5'
            Get-Debian13PamArg -Args 'obscure use_authtok remember=5' -Key 'use_authtok' | Should -Be ''
            Get-Debian13PamArg -Args 'obscure' -Key 'nullok' | Should -BeNullOrEmpty
            $null -eq (Get-Debian13PamArg -Args 'obscure' -Key 'nullok') | Should -BeTrue
            $null -ne (Get-Debian13PamArg -Args 'obscure use_authtok' -Key 'use_authtok') | Should -BeTrue
        }

        Context '5.3.2 modulos' {
            It 'pam_unix en los 5 archivos = Pass; falta en uno = Fail' {
                (Test-CIS_Debian13_5_3_2_1).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:pamd 'common-session') @('session required pam_deny.so')
                (Test-CIS_Debian13_5_3_2_1).Status | Should -Be 'Fail'
            }
            It 'pwquality / pwhistory / faillock' {
                (Test-CIS_Debian13_5_3_2_3).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_5_3_2_4).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_5_3_2_2).Status | Should -Be 'Fail'
                Add-Content (Join-Path $script:pamd 'common-password') 'password requisite pam_pwhistory.so'
                (Test-CIS_Debian13_5_3_2_4).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:pamd 'common-auth') @('auth requisite pam_faillock.so preauth', 'auth [default=die] pam_faillock.so authfail', 'auth [success=1] pam_unix.so')
                Set-Content (Join-Path $script:pamd 'common-account') @('account required pam_faillock.so', 'account [success=1] pam_unix.so')
                (Test-CIS_Debian13_5_3_2_2).Status | Should -Be 'Pass'
            }
            It 'Set 5.3.2.2 escribe los perfiles y habilita con la red de seguridad' {
                Set-CIS_Debian13_5_3_2_2
                Test-Path (Join-Path $script:cfg 'faillock') | Should -BeTrue
                Test-Path (Join-Path $script:cfg 'faillock_notify') | Should -BeTrue
                Should -Invoke Invoke-Debian13PamAuthUpdate -Times 1 -ParameterFilter { $Arguments -contains 'faillock' -and $Arguments -contains 'faillock_notify' }
            }
            It 'Invoke-Debian13PamAuthUpdateSafe restaura common-* y lanza error si desaparece pam_unix de common-auth' {
                $orig = Get-Content (Join-Path $script:pamd 'common-auth')
                Mock Invoke-Debian13PamAuthUpdate { Set-Content (Join-Path $script:pamd 'common-auth') 'auth requisite pam_deny.so' }
                { Invoke-Debian13PamAuthUpdateSafe -Arguments '--enable', 'x' } | Should -Throw '*restauraron*'
                @(Get-Content (Join-Path $script:pamd 'common-auth')) | Should -Be @($orig)
            }
            It 'Set -WhatIf no ejecuta pam-auth-update' {
                Set-CIS_Debian13_5_3_2_1 -WhatIf
                Should -Invoke Invoke-Debian13PamAuthUpdate -Times 0
            }
        }

        Context '5.3.1 paquetes al dia' {
            It 'Pass si esta instalado y no aparece en apt list --upgradable; Fail si es actualizable o no instalado' {
                Mock Get-Debian13InstalledPackages { 'libpam-runtime' }
                Mock Get-Debian13UpgradablePackages { 'Listing...', 'curl/stable 8.0 amd64 [upgradable from: 7.9]' }
                (Test-CIS_Debian13_5_3_1_1).Status | Should -Be 'Pass'
                Mock Get-Debian13UpgradablePackages { 'libpam-runtime/stable 1.7 all [upgradable from: 1.6]' }
                (Test-CIS_Debian13_5_3_1_1).Status | Should -Be 'Fail'
                Mock Get-Debian13InstalledPackages { }
                Mock Get-Debian13UpgradablePackages { }
                (Test-CIS_Debian13_5_3_1_2).Status | Should -Be 'Fail'
            }
        }

        Context '5.3.3 reglas conf + argumento PAM' {
            It 'faillock deny: Pass 1..5; Fail con 6, 0, ausente, o argumento PAM fuera de rango' {
                $f = Join-Path $script:sec 'faillock.conf'
                (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Fail'
                Set-Content $f 'deny = 5'; (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Pass'
                Set-Content $f 'deny = 6'; (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Fail'
                Set-Content $f 'deny = 0'; (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Fail'
                Set-Content $f '# deny = 3'; (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Fail'
                Set-Content $f 'deny = 4'; Set-Content (Join-Path $script:pamd 'common-auth') 'auth requisite pam_faillock.so preauth deny=10'
                (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Fail'
            }
            It 'faillock unlock_time: 0 y >= 900 Pass; 600 Fail' {
                $f = Join-Path $script:sec 'faillock.conf'
                foreach ($v in '0', '900', '1800') { Set-Content $f "unlock_time = $v"; (Test-CIS_Debian13_5_3_3_1_2).Status | Should -Be 'Pass' -Because $v }
                foreach ($v in '600', '60', '899') { Set-Content $f "unlock_time = $v"; (Test-CIS_Debian13_5_3_3_1_2).Status | Should -Be 'Fail' -Because $v }
            }
            It 'pwquality: minlen en .d Pass, en archivo principal < 14 Fail' {
                Set-Content (Join-Path $script:sec 'pwquality.conf.d/50-pwlength.conf') 'minlen = 14'
                (Test-CIS_Debian13_5_3_3_2_2).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:sec 'pwquality.conf') 'minlen = 8'
                (Test-CIS_Debian13_5_3_3_2_2).Status | Should -Be 'Fail'
            }
            It 'pwquality: difok/maxrepeat/maxsequence obligatorios; dictcheck y enforcing solo Fail si valen 0' {
                foreach ($n in '2_1', '2_2', '2_4', '2_5', '2_8') { (& "Test-CIS_Debian13_5_3_3_$n").Status | Should -Be 'Fail' -Because $n }
                foreach ($n in '2_6', '2_7') { (& "Test-CIS_Debian13_5_3_3_$n").Status | Should -Be 'Pass' -Because $n }
                Set-Content (Join-Path $script:sec 'pwquality.conf.d/50-x.conf') @('difok = 2', 'maxrepeat = 3', 'maxsequence = 3', 'enforce_for_root', 'dictcheck = 0', 'enforcing = 0')
                foreach ($n in '2_1', '2_4', '2_5', '2_8') { (& "Test-CIS_Debian13_5_3_3_$n").Status | Should -Be 'Pass' -Because $n }
                foreach ($n in '2_6', '2_7') { (& "Test-CIS_Debian13_5_3_3_$n").Status | Should -Be 'Fail' -Because $n }
                Set-Content (Join-Path $script:sec 'pwquality.conf.d/50-x.conf') @('maxrepeat = 0', 'maxsequence = 5', 'difok = 1')
                foreach ($n in '2_1', '2_4', '2_5') { (& "Test-CIS_Debian13_5_3_3_$n").Status | Should -Be 'Fail' -Because $n }
            }
            It 'argumento PAM pam_pwquality fuera de rango = Fail' {
                Set-Content (Join-Path $script:sec 'pwquality.conf.d/50-pwlength.conf') 'minlen = 14'
                Set-Content (Join-Path $script:pamd 'common-password') 'password requisite pam_pwquality.so retry=3 minlen=8'
                (Test-CIS_Debian13_5_3_3_2_2).Status | Should -Be 'Fail'
            }
            It 'pwhistory remember: conf O argumento PAM, nunca ambos' {
                (Test-CIS_Debian13_5_3_3_3_1).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:sec 'pwhistory.conf') 'remember = 24'
                (Test-CIS_Debian13_5_3_3_3_1).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:sec 'pwhistory.conf') 'remember = 5'
                (Test-CIS_Debian13_5_3_3_3_1).Status | Should -Be 'Fail'
                Remove-Item (Join-Path $script:sec 'pwhistory.conf')
                Set-Content (Join-Path $script:pamd 'common-password') 'password requisite pam_pwhistory.so remember=24 enforce_for_root use_authtok'
                (Test-CIS_Debian13_5_3_3_3_1).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_5_3_3_3_2).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_5_3_3_3_3).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:sec 'pwhistory.conf') 'remember = 24'
                (Test-CIS_Debian13_5_3_3_3_1).Status | Should -Be 'Fail'
            }
            It '5.3.3.1.3 root: even_deny_root o root_unlock_time >= 60; < 60 Fail' {
                $f = Join-Path $script:sec 'faillock.conf'
                (Test-CIS_Debian13_5_3_3_1_3).Status | Should -Be 'Fail'
                Set-Content $f 'even_deny_root'; (Test-CIS_Debian13_5_3_3_1_3).Status | Should -Be 'Pass'
                Set-Content $f @('even_deny_root', 'root_unlock_time = 30'); (Test-CIS_Debian13_5_3_3_1_3).Status | Should -Be 'Fail'
                Set-Content $f 'root_unlock_time = 60'; (Test-CIS_Debian13_5_3_3_1_3).Status | Should -Be 'Pass'
            }
            It '5.3.3.2.3 es Manual' { (Test-CIS_Debian13_5_3_3_2_3).Status | Should -Be 'ManualReviewRequired' }

            It 'Set minlen: comenta el valor malo del archivo principal, escribe el .d y quita el argumento del perfil (con pam-auth-update --package)' {
                Set-Content (Join-Path $script:sec 'pwquality.conf') @('# comentario', 'minlen = 8', 'difok = 1')
                Set-Content (Join-Path $script:cfg 'pwquality') @('Name: Pwquality', 'Password-Type: Primary', 'Password:', '        requisite  pam_pwquality.so retry=3 minlen=8')
                Set-CIS_Debian13_5_3_3_2_2
                @(Get-Content (Join-Path $script:sec 'pwquality.conf')) | Should -Be @('# comentario', '# minlen = 8', 'difok = 1')
                (Get-Content (Join-Path $script:sec 'pwquality.conf.d/50-pwlength.conf')) -join '|' | Should -Match 'minlen = 14'
                (Get-Content (Join-Path $script:cfg 'pwquality') -Raw) | Should -Not -Match 'minlen'
                (Get-Content (Join-Path $script:cfg 'pwquality') -Raw) | Should -Match 'retry=3'
                Should -Invoke Invoke-Debian13PamAuthUpdate -Times 1 -ParameterFilter { $Arguments -contains '--package' }
                Set-Content (Join-Path $script:pamd 'common-password') 'password requisite pam_pwquality.so retry=3'   # lo que dejaria pam-auth-update
                (Test-CIS_Debian13_5_3_3_2_2).Status | Should -Be 'Pass'
            }
            It 'Set faillock deny: deja UN solo valor y es idempotente' {
                $f = Join-Path $script:sec 'faillock.conf'
                Set-Content $f @('deny = 10', 'unlock_time = 900')
                Set-CIS_Debian13_5_3_3_1_1; Set-CIS_Debian13_5_3_3_1_1
                (Test-CIS_Debian13_5_3_3_1_1).Status | Should -Be 'Pass'
                (Get-Content $f) | Should -Contain '# deny = 10'
                (Get-Content $f | Where-Object { $_ -match '^deny' }).Count | Should -Be 1
                (Test-CIS_Debian13_5_3_3_1_2).Status | Should -Be 'Pass'
            }
            It 'Set flags: enforce_for_root (pwquality y pwhistory) y 5.3.3.1.3 (even_deny_root)' {
                Set-CIS_Debian13_5_3_3_2_8; (Test-CIS_Debian13_5_3_3_2_8).Status | Should -Be 'Pass'
                Set-CIS_Debian13_5_3_3_3_2; Set-CIS_Debian13_5_3_3_3_3; Set-CIS_Debian13_5_3_3_3_1
                foreach ($n in '3_1', '3_2', '3_3') { (& "Test-CIS_Debian13_5_3_3_$n").Status | Should -Be 'Pass' -Because $n }
                Set-Content (Join-Path $script:sec 'faillock.conf') 'root_unlock_time = 10'
                Set-CIS_Debian13_5_3_3_1_3
                (Test-CIS_Debian13_5_3_3_1_3).Status | Should -Be 'Pass'
                (Get-Content (Join-Path $script:sec 'faillock.conf')) | Should -Contain '# root_unlock_time = 10'
            }
            It 'Set dictcheck/enforcing: comenta el valor 0 sin escribir nada nuevo' {
                $f = Join-Path $script:sec 'pwquality.conf.d/50-x.conf'
                Set-Content $f @('dictcheck = 0', 'enforcing = 0', 'minlen = 14')
                Set-CIS_Debian13_5_3_3_2_6; Set-CIS_Debian13_5_3_3_2_7
                @(Get-Content $f) | Should -Be @('# dictcheck = 0', '# enforcing = 0', 'minlen = 14')
                (Test-CIS_Debian13_5_3_3_2_6).Status | Should -Be 'Pass'
            }
        }

        Context '5.3.3.4 pam_unix' {
            It 'nullok / remember / hashing / use_authtok' {
                (Test-CIS_Debian13_5_3_3_4_1).Status | Should -Be 'Fail'   # common-auth trae nullok
                (Test-CIS_Debian13_5_3_3_4_2).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_5_3_3_4_3).Status | Should -Be 'Pass'
                (Test-CIS_Debian13_5_3_3_4_4).Status | Should -Be 'Pass'
                Set-Content (Join-Path $script:pamd 'common-password') 'password [success=1] pam_unix.so obscure try_first_pass remember=5'
                (Test-CIS_Debian13_5_3_3_4_2).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_5_3_3_4_3).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_5_3_3_4_4).Status | Should -Be 'Fail'
                Set-Content (Join-Path $script:pamd 'common-password') 'password [success=1] pam_unix.so obscure use_authtok sha512'
                (Test-CIS_Debian13_5_3_3_4_3).Status | Should -Be 'Pass'
            }
            It 'sin lineas password de pam_unix: 5.3.3.4.3 y .4 Fail' {
                Set-Content (Join-Path $script:pamd 'common-password') 'password requisite pam_pwquality.so'
                (Test-CIS_Debian13_5_3_3_4_3).Status | Should -Be 'Fail'
                (Test-CIS_Debian13_5_3_3_4_4).Status | Should -Be 'Fail'
            }
            It 'Update-Debian13PamUnixProfiles quita nullok y remember de todas las secciones' {
                $p = Join-Path $script:cfg 'unix'
                Set-Content $p @('Name: Unix authentication', 'Default: yes', 'Priority: 256', 'Auth-Type: Primary', 'Auth:', '        [success=end default=ignore]    pam_unix.so nullok try_first_pass',
                    'Password-Type: Primary', 'Password:', '        [success=end default=ignore]    pam_unix.so obscure use_authtok try_first_pass yescrypt remember=5')
                Set-CIS_Debian13_5_3_3_4_1; Set-CIS_Debian13_5_3_3_4_2
                $t = Get-Content $p -Raw
                $t | Should -Not -Match 'nullok'; $t | Should -Not -Match 'remember'
                $t | Should -Match 'try_first_pass\r?\n'
                Should -Invoke Invoke-Debian13PamAuthUpdate -Times 2 -ParameterFilter { $Arguments -contains '--package' }
            }
            It 'agrega yescrypt/use_authtok SOLO en la seccion Password y solo si faltan' {
                $p = Join-Path $script:cfg 'unix'
                Set-Content $p @('Name: Unix', 'Auth-Type: Primary', 'Auth:', '        [success=end default=ignore]    pam_unix.so try_first_pass',
                    'Password-Type: Primary', 'Password:', '        [success=end default=ignore]    pam_unix.so obscure try_first_pass',
                    'Password-Initial:', '        [success=end default=ignore]    pam_unix.so obscure yescrypt use_authtok')
                Set-CIS_Debian13_5_3_3_4_3; Set-CIS_Debian13_5_3_3_4_4
                $l = @(Get-Content $p)
                $l[3] | Should -Be '        [success=end default=ignore]    pam_unix.so try_first_pass'
                $l[6] | Should -Match 'obscure try_first_pass yescrypt use_authtok$'
                $l[8] | Should -Be '        [success=end default=ignore]    pam_unix.so obscure yescrypt use_authtok'
                Set-CIS_Debian13_5_3_3_4_3; Set-CIS_Debian13_5_3_3_4_4
                @(Get-Content $p)[6] | Should -Match 'yescrypt use_authtok$'
                ((Get-Content $p -Raw) -split 'yescrypt').Count - 1 | Should -Be 2
            }
        }
    }
}
