#Requires -Modules Pester
<# Tests de LinuxSshdEngine: parseo de `sshd -T` y Set-CISSshdOption con un "sshd" falso (script) y un drop-in temporal. #>

BeforeDiscovery {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'CISHarden.Core.psd1') -Force
}

Describe 'ConvertFrom-CISSshdOutput' {
    InModuleScope 'CISHarden.Core' {
        It 'agrupa valores repetidos y normaliza a minusculas' {
            $c = ConvertFrom-CISSshdOutput -Lines 'port 22', 'HostKey /etc/ssh/a', 'hostkey /etc/ssh/b', 'ciphers aes256-ctr,aes128-ctr', 'maxstartups 10:30:100'
            $c['hostkey'] | Should -Be @('/etc/ssh/a', '/etc/ssh/b')
            $c['ciphers'] | Should -Be 'aes256-ctr,aes128-ctr'
            $c['maxstartups'] | Should -Be '10:30:100'
            $c.ContainsKey('nada') | Should -BeFalse
        }
        It 'entrada vacia devuelve hashtable vacio' { (ConvertFrom-CISSshdOutput -Lines @()).Count | Should -Be 0 }
    }
}

Describe 'Set-CISSshdOption' {
    InModuleScope 'CISHarden.Core' {
        BeforeEach {
            $script:dir = Join-Path ([IO.Path]::GetTempPath()) "cis13-sshd-$([guid]::NewGuid())"
            New-Item -ItemType Directory $script:dir | Out-Null
            $script:drop = Join-Path $script:dir '00-cis-hardening.conf'
            $script:okSshd = Join-Path $script:dir 'sshd-ok'; $script:badSshd = Join-Path $script:dir 'sshd-bad'
            Set-Content $script:okSshd "#!/bin/sh`nexit 0"; Set-Content $script:badSshd "#!/bin/sh`necho 'Bad configuration option' >&2`nexit 1"
            & chmod +x $script:okSshd $script:badSshd
            Mock Invoke-CISSshdReload { }
        }
        AfterEach { Remove-Item $script:dir -Recurse -Force }

        It 'crea el drop-in, reemplaza la misma opcion y agrega otras' {
            Mock Get-CISSshdPath { $script:okSshd }
            Set-CISSshdOption -Keyword 'MaxAuthTries' -Value '4' -DropIn $script:drop
            Set-CISSshdOption -Keyword 'LogLevel' -Value 'VERBOSE' -DropIn $script:drop
            Set-CISSshdOption -Keyword 'MaxAuthTries' -Value '3' -DropIn $script:drop
            $l = @(Get-Content $script:drop)
            $l | Should -Be @('MaxAuthTries 3', 'LogLevel VERBOSE')
            Should -Invoke Invoke-CISSshdReload -Times 3
        }
        It 'si sshd -t falla revierte al contenido anterior y lanza error' {
            Mock Get-CISSshdPath { $script:okSshd }
            Set-CISSshdOption -Keyword 'MaxAuthTries' -Value '4' -DropIn $script:drop
            Mock Get-CISSshdPath { $script:badSshd }
            { Set-CISSshdOption -Keyword 'Ciphers' -Value 'nope' -DropIn $script:drop } | Should -Throw '*revertido*'
            @(Get-Content $script:drop) | Should -Be @('MaxAuthTries 4')
        }
        It 'si sshd -t falla y el drop-in no existia, no lo deja creado' {
            Mock Get-CISSshdPath { $script:badSshd }
            { Set-CISSshdOption -Keyword 'Ciphers' -Value 'nope' -DropIn $script:drop } | Should -Throw
            Test-Path $script:drop | Should -BeFalse
        }
        It '-WhatIf no escribe nada' {
            Mock Get-CISSshdPath { $script:okSshd }
            Set-CISSshdOption -Keyword 'MaxAuthTries' -Value '4' -DropIn $script:drop -WhatIf
            Test-Path $script:drop | Should -BeFalse
            Should -Invoke Invoke-CISSshdReload -Times 0
        }
        It 'sin openssh-server lanza error' {
            Mock Get-CISSshdPath { $null }
            { Set-CISSshdOption -Keyword 'X' -Value 'y' -DropIn $script:drop } | Should -Throw '*no esta instalado*'
        }
    }
}
