#Requires -Modules Pester
<# Tests de 5.1 SSH Server (Debian 13). Get-Debian13SshdConfig mockeado con la salida de `sshd -T`. #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 5.1 SSH Server (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        BeforeAll {
            # Configuracion conforme (Debian 13 por defecto + valores del benchmark)
            $script:good = @{
                clientaliveinterval = '15'; clientalivecountmax = '3'; disableforwarding = 'yes'; gssapiauthentication = 'no'
                hostbasedauthentication = 'no'; ignorerhosts = 'yes'; logingracetime = '60'; loglevel = 'INFO'; maxauthtries = '4'
                maxsessions = '10'; maxstartups = '10:30:60'; permitemptypasswords = 'no'; permitrootlogin = 'no'; permituserenvironment = 'no'
                usepam = 'yes'; ciphers = 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr'
                kexalgorithms = 'mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256'
                macs = 'hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com'; allowusers = 'admin'; banner = '/etc/issue.net'
                hostkey = @('/etc/ssh/ssh_host_ed25519_key')
            }
            function script:Cfg { param([hashtable]$Over = @{}) $c = @{}; foreach ($k in $script:good.Keys) { $c[$k] = $script:good[$k] }; foreach ($k in $Over.Keys) { if ($null -eq $Over[$k]) { $c.Remove($k) } else { $c[$k] = $Over[$k] } }; $c }
            $script:ids = 6..23 | Where-Object { $_ -ne 13 }
        }
        It 'Configuracion conforme: 5.1.4 a 5.1.23 dan Pass' {
            Mock Get-Debian13SshdConfig { Cfg }
            Mock Get-Debian13SshdVersion { [version]'10.0' }
            Mock Get-Debian13BannerLeaks { @() }; Mock Test-Path { $true } -ParameterFilter { $Path -eq '/etc/issue.net' }
            Mock Get-Debian13MaxSessionsOverLimit { @() }
            foreach ($n in 4..23) { (& "Test-CIS_Debian13_5_1_$n").Status | Should -Be 'Pass' -Because "5.1.$n" }
        }
        It 'Sin openssh-server: NotApplicable' {
            Mock Get-Debian13SshdConfig { $null }
            foreach ($n in 2..23) { (& "Test-CIS_Debian13_5_1_$n").Status | Should -Be 'NotApplicable' -Because "5.1.$n" }
        }
        It 'Opciones booleanas y numericas fuera de norma dan Fail' {
            $bad = @{
                '5_1_7' = @{ clientaliveinterval = '0' }; '5_1_8' = @{ disableforwarding = 'no' }; '5_1_9' = @{ gssapiauthentication = 'yes' }
                '5_1_10' = @{ hostbasedauthentication = 'yes' }; '5_1_11' = @{ ignorerhosts = 'no' }; '5_1_14' = @{ logingracetime = '120' }
                '5_1_15' = @{ loglevel = 'QUIET' }; '5_1_17' = @{ maxauthtries = '6' }; '5_1_18' = @{ maxsessions = '20' }
                '5_1_19' = @{ maxstartups = '10:30:100' }; '5_1_20' = @{ permitemptypasswords = 'yes' }; '5_1_21' = @{ permitrootlogin = 'prohibit-password' }
                '5_1_22' = @{ permituserenvironment = 'yes' }; '5_1_23' = @{ usepam = 'no' }; '5_1_4' = @{ allowusers = $null }
            }
            Mock Get-Debian13MaxSessionsOverLimit { @() }
            foreach ($id in $bad.Keys) {
                $c = Cfg $bad[$id]; Mock Get-Debian13SshdConfig { $c }.GetNewClosure()
                (& "Test-CIS_Debian13_$id").Status | Should -Be 'Fail' -Because $id
            }
        }
        It '5.1.7 Fail si ClientAliveCountMax es 0' {
            Mock Get-Debian13SshdConfig { Cfg @{ clientalivecountmax = '0' } }
            (Test-CIS_Debian13_5_1_7).Status | Should -Be 'Fail'
        }
        It '5.1.4 acepta cualquiera de Allow/Deny Users/Groups' {
            foreach ($k in 'allowgroups', 'denyusers', 'denygroups') {
                $c = Cfg @{ allowusers = $null; $k = 'x' }; Mock Get-Debian13SshdConfig { $c }.GetNewClosure()
                (Test-CIS_Debian13_5_1_4).Status | Should -Be 'Pass' -Because $k
            }
        }
        It '5.1.6 / 5.1.12 / 5.1.16 detectan algoritmos debiles' {
            Mock Get-Debian13SshdConfig { Cfg @{ ciphers = 'aes256-gcm@openssh.com,aes128-cbc' } }; (Test-CIS_Debian13_5_1_6).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg @{ ciphers = '3des-cbc' } }; (Test-CIS_Debian13_5_1_6).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg @{ kexalgorithms = 'curve25519-sha256,diffie-hellman-group14-sha1' } }; (Test-CIS_Debian13_5_1_12).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg @{ macs = 'hmac-sha2-256,hmac-md5' } }; (Test-CIS_Debian13_5_1_16).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg @{ macs = 'umac-128-etm@openssh.com' } }; (Test-CIS_Debian13_5_1_16).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg @{ macs = 'umac-128@openssh.com,hmac-sha2-256' } }; (Test-CIS_Debian13_5_1_16).Status | Should -Be 'Pass'
        }
        It '5.1.13 PQC: mlkem solo se exige desde OpenSSH 9.9' {
            Mock Get-Debian13SshdConfig { Cfg @{ kexalgorithms = 'sntrup761x25519-sha512,curve25519-sha256' } }
            Mock Get-Debian13SshdVersion { [version]'9.8' }; (Test-CIS_Debian13_5_1_13).Status | Should -Be 'Pass'
            Mock Get-Debian13SshdVersion { [version]'10.0' }; (Test-CIS_Debian13_5_1_13).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg @{ kexalgorithms = 'curve25519-sha256' } }
            Mock Get-Debian13SshdVersion { [version]'9.8' }; (Test-CIS_Debian13_5_1_13).Status | Should -Be 'Fail'
        }
        It '5.1.18 Fail si algun MaxSessions > 10 aparece en los archivos (bloques Match)' {
            Mock Get-Debian13SshdConfig { Cfg }
            Mock Get-Debian13MaxSessionsOverLimit { '/etc/ssh/sshd_config: MaxSessions 50' }
            (Test-CIS_Debian13_5_1_18).Status | Should -Be 'Fail'
        }
        It '5.1.5 Fail si Banner es none, no existe o filtra informacion del SO' {
            Mock Get-Debian13SshdConfig { Cfg @{ banner = 'none' } }; (Test-CIS_Debian13_5_1_5).Status | Should -Be 'Fail'
            Mock Get-Debian13SshdConfig { Cfg }; Mock Test-Path { $false }; (Test-CIS_Debian13_5_1_5).Status | Should -Be 'Fail'
            Mock Test-Path { $true }; Mock Get-Debian13BannerLeaks { '/etc/issue.net' }; (Test-CIS_Debian13_5_1_5).Status | Should -Be 'Fail'
        }
        Context 'permisos 5.1.1-5.1.3' {
            It 'usan los modos del benchmark (600 / 600 / 644)' {
                Mock Get-Debian13SshdConfig { Cfg }
                Mock Get-Debian13SshdConfFiles { '/etc/ssh/sshd_config' }
                $script:seen = @{}
                Mock Test-CISPathAccess { $script:seen[$Path] = $MaxMode; [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $true; Mode = '600'; Owner = 'root:root' } }
                Mock Test-Path { $true }
                Test-CIS_Debian13_5_1_1 | Out-Null; Test-CIS_Debian13_5_1_2 | Out-Null; Test-CIS_Debian13_5_1_3 | Out-Null
                $script:seen['/etc/ssh/sshd_config'] | Should -Be '600'
                $script:seen['/etc/ssh/ssh_host_ed25519_key'] | Should -Be '600'
                $script:seen['/etc/ssh/ssh_host_ed25519_key.pub'] | Should -Be '644'
            }
            It 'Fail si una clave privada es legible por otros' {
                Mock Get-Debian13SshdConfig { Cfg }; Mock Test-Path { $true }
                Mock Test-CISPathAccess { [pscustomobject]@{ Path = $Path; Exists = $true; Compliant = $false; Mode = '644'; Owner = 'root:root' } }
                (Test-CIS_Debian13_5_1_2).Status | Should -Be 'Fail'
            }
        }
        Context 'Set-* usan el motor con la opcion y valor del benchmark' {
            BeforeEach { Mock Get-CISSshdPath { '/usr/sbin/sshd' }; Mock Set-CISSshdOption { }; Mock Get-Debian13SshdVersion { [version]'10.0' } }
            It 'valores' {
                $exp = @{ '5_1_8' = 'DisableForwarding|yes'; '5_1_9' = 'GSSAPIAuthentication|no'; '5_1_10' = 'HostbasedAuthentication|no'; '5_1_11' = 'IgnoreRhosts|yes'
                    '5_1_14' = 'LogingraceTime|60'; '5_1_17' = 'MaxAuthTries|4'; '5_1_18' = 'MaxSessions|10'; '5_1_19' = 'MaxStartups|10:30:60'
                    '5_1_20' = 'PermitEmptyPasswords|no'; '5_1_21' = 'PermitRootLogin|no'; '5_1_22' = 'PermitUserEnvironment|no'; '5_1_23' = 'UsePAM|yes' }
                foreach ($id in $exp.Keys) {
                    $script:seen = $null; Mock Set-CISSshdOption { $script:seen = "$Keyword|$Value" }
                    & "Set-CIS_Debian13_$id"
                    $script:seen | Should -BeLike $exp[$id] -Because $id
                }
            }
            It '5.1.13 agrega mlkem en OpenSSH >= 9.9 y no en versiones anteriores' {
                $script:seen = $null; Mock Set-CISSshdOption { $script:seen = $Value }
                Set-CIS_Debian13_5_1_13; $script:seen | Should -BeLike 'mlkem768x25519-sha256,*'
                Mock Get-Debian13SshdVersion { [version]'9.8' }
                Set-CIS_Debian13_5_1_13; $script:seen | Should -Not -BeLike '*mlkem*'
            }
            It '5.1.12/5.1.16/5.1.6 usan la sintaxis de exclusion (-)' {
                $script:seen = @{}; Mock Set-CISSshdOption { $script:seen[$Keyword] = $Value }
                Set-CIS_Debian13_5_1_12; Set-CIS_Debian13_5_1_16; Set-CIS_Debian13_5_1_6
                foreach ($k in 'KexAlgorithms', 'MACs', 'Ciphers') { $script:seen[$k] | Should -BeLike '-*' -Because $k }
            }
            It '5.1.4 sin listas no inventa nada; con -AllowUsers las aplica' {
                Set-CIS_Debian13_5_1_4 -WarningAction SilentlyContinue
                Should -Invoke Set-CISSshdOption -Times 0
                Set-CIS_Debian13_5_1_4 -AllowUsers 'admin ops'
                Should -Invoke Set-CISSshdOption -Times 1 -ParameterFilter { $Keyword -eq 'AllowUsers' -and $Value -eq 'admin ops' }
            }
            It 'sin openssh-server no llaman al motor' {
                Mock Get-CISSshdPath { $null }
                Set-CIS_Debian13_5_1_21 -WarningAction SilentlyContinue
                Should -Invoke Set-CISSshdOption -Times 0
            }
        }
    }
}
