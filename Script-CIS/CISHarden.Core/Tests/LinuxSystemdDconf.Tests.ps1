#Requires -Modules Pester
<# Tests de LinuxSystemdConfigEngine / LinuxDconfEngine con archivos temporales reales (sin depender de systemd). #>

BeforeDiscovery {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'CISHarden.Core.psd1') -Force
}

Describe 'Get-CISSystemdConfigValue (valor por defecto)' {
    InModuleScope 'CISHarden.Core' {
        It 'devuelve el valor comentado como IsDefault cuando ningun drop-in lo define' {
            # sin systemd-analyze en el host de test: cae al default; se prueba con un archivo real via /etc si existe.
            Mock Test-Path { $false } -ParameterFilter { $Path -like '*systemd-analyze' }
            Mock Test-Path { $Path -eq '/etc/systemd/coredump.conf' } -ParameterFilter { $Path -like '/etc/*' -or $Path -like '/usr/lib/*' }
            Mock Get-Content { '[Coredump]', '#Storage=external', '#ProcessSizeMax=2G' } -ParameterFilter { $Path -eq '/etc/systemd/coredump.conf' }
            $r = Get-CISSystemdConfigValue -ConfName 'systemd/coredump.conf' -Block 'Coredump' -Option 'ProcessSizeMax'
            $r.Value | Should -Be '2G'; $r.IsDefault | Should -BeTrue
        }
    }
}

Describe 'Get-CISDconfValue / Test-CISDconfPathLocked' {
    InModuleScope 'CISHarden.Core' {
        BeforeEach {
            $script:tmp = Join-Path ([IO.Path]::GetTempPath()) "cis13-dconf-$([guid]::NewGuid())"
            New-Item -ItemType Directory "$script:tmp/local.d/locks" -Force | Out-Null
            Set-Content "$script:tmp/local.d/00-screensaver" @('[org/gnome/desktop/session]', 'idle-delay=uint32 900', '[org/gnome/desktop/screensaver]', 'lock-delay=uint32 5')
            Set-Content "$script:tmp/local.d/locks/00-screensaver" @('/org/gnome/desktop/session/idle-delay')
            Mock Get-CISDconfKeyFiles { param([switch]$Locks) Get-ChildItem $script:tmp -Recurse -File | Where-Object { (($_.DirectoryName -match 'locks') -eq [bool]$Locks) } }
        }
        AfterEach { Remove-Item $script:tmp -Recurse -Force }
        It 'lee el valor por seccion' {
            Get-CISDconfValue -Section 'org/gnome/desktop/screensaver' -Key 'lock-delay' | Should -Be 'uint32 5'
            Get-CISDconfValue -Section 'org/gnome/desktop/session' -Key 'lock-delay' | Should -BeNullOrEmpty
        }
        It 'detecta locks' {
            Test-CISDconfPathLocked -DconfPath '/org/gnome/desktop/session/idle-delay' | Should -BeTrue
            Test-CISDconfPathLocked -DconfPath '/org/gnome/desktop/screensaver/lock-delay' | Should -BeFalse
        }
    }
}
