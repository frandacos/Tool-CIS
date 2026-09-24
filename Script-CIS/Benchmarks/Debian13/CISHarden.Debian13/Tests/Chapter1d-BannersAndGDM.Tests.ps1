#Requires -Modules Pester
<# Tests de 1.6 Banners y 1.7 GDM (Debian 13). #>

BeforeDiscovery {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Chapter 1.6 Banners (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        It 'Pass sin informacion del sistema' {
            Mock Get-Debian13BannerFiles { @('/etc/issue') }; Mock Get-Debian13BannerLeaks { @() }
            (Test-CIS_Debian13_1_6_2).Status | Should -Be 'Pass'
        }
        It 'Fail si algun archivo filtra informacion del SO' {
            Mock Get-Debian13BannerFiles { @('/etc/motd', '/etc/motd.d/x') }; Mock Get-Debian13BannerLeaks { @('/etc/motd.d/x') }
            (Test-CIS_Debian13_1_6_1).Status | Should -Be 'Fail'
        }
        It 'Get-Debian13BannerLeaks detecta \v \r \m \s y el ID del SO' {
            $tmp = Join-Path ([IO.Path]::GetTempPath()) "cis13-banner-$([guid]::NewGuid())"
            New-Item -ItemType Directory $tmp | Out-Null
            Set-Content "$tmp/ok" 'Authorized users only.'; Set-Content "$tmp/esc" 'Kernel \r on \m'; Set-Content "$tmp/os" 'Welcome to Debian GNU/Linux'
            Mock Get-Debian13OsId { 'debian' }
            $r = @(Get-Debian13BannerLeaks -Files "$tmp/ok", "$tmp/esc", "$tmp/os")
            $r | Should -Be @("$tmp/esc", "$tmp/os")
            Remove-Item $tmp -Recurse -Force
        }
        It '1.6.4-6 usan 644 y las rutas correctas' {
            $script:seen = @{}
            Mock Test-CISPathAccess { $script:seen[$Path] = $MaxMode; [pscustomobject]@{ Path = $Path; Exists = $false; Compliant = $true; Mode = $null; Owner = $null } }
            Test-CIS_Debian13_1_6_4 | Out-Null; Test-CIS_Debian13_1_6_5 | Out-Null; Test-CIS_Debian13_1_6_6 | Out-Null
            foreach ($p in '/etc/motd', '/etc/issue', '/etc/issue.net') { $script:seen[$p] | Should -Be '644' }
        }
    }
}

Describe 'Chapter 1.7 GDM (Debian 13)' {
    InModuleScope 'CISHarden.Debian13' {
        It '1.7.1 Pass si gdm3 no esta instalado, Fail si esta (Server); NotApplicable en Workstation' {
            Mock Get-CISLinuxProfile { 'Server' }
            Mock Test-CISPackageInstalled { $false }; (Test-CIS_Debian13_1_7_1).Status | Should -Be 'Pass'
            Mock Test-CISPackageInstalled { $true }; (Test-CIS_Debian13_1_7_1).Status | Should -Be 'Fail'
            Mock Get-CISLinuxProfile { 'Workstation' }; (Test-CIS_Debian13_1_7_1).Status | Should -Be 'NotApplicable'
        }
        It '1.7.2-1.7.9 y 1.7.11 son Pass si GDM no esta instalado' {
            Mock Test-Debian13GdmInstalled { $false }
            foreach ($n in 2..9 + 11) { (& "Test-CIS_Debian13_1_7_$n").Status | Should -Be 'Pass' -Because "1.7.$n" }
        }
        Context 'con GDM instalado' {
            BeforeEach { Mock Test-Debian13GdmInstalled { $true } }
            It '1.7.2 requiere enable=true y texto' {
                Mock Get-CISDconfValue { if ($Key -eq 'banner-message-enable') { 'true' } else { "'Authorized'" } }
                (Test-CIS_Debian13_1_7_2).Status | Should -Be 'Pass'
                Mock Get-CISDconfValue { $null }
                (Test-CIS_Debian13_1_7_2).Status | Should -Be 'Fail'
            }
            It '1.7.3 disable-user-list=true' {
                Mock Get-CISDconfValue { 'true' }; (Test-CIS_Debian13_1_7_3).Status | Should -Be 'Pass'
                Mock Get-CISDconfValue { 'false' }; (Test-CIS_Debian13_1_7_3).Status | Should -Be 'Fail'
            }
            It '1.7.4 lock-delay <=5 e idle-delay 1..900' {
                $script:vals = @{ 'lock-delay' = 'uint32 5'; 'idle-delay' = 'uint32 900' }
                Mock Get-CISDconfValue { $script:vals[$Key] }
                (Test-CIS_Debian13_1_7_4).Status | Should -Be 'Pass'
                $script:vals['idle-delay'] = 'uint32 0'; (Test-CIS_Debian13_1_7_4).Status | Should -Be 'Fail'
                $script:vals['idle-delay'] = 'uint32 901'; (Test-CIS_Debian13_1_7_4).Status | Should -Be 'Fail'
                $script:vals['idle-delay'] = 'uint32 600'; $script:vals['lock-delay'] = 'uint32 6'; (Test-CIS_Debian13_1_7_4).Status | Should -Be 'Fail'
                $script:vals.Remove('lock-delay'); (Test-CIS_Debian13_1_7_4).Status | Should -Be 'Fail'
            }
            It 'Locks 1.7.5/1.7.7/1.7.9: Pass solo si todas las rutas estan bloqueadas' {
                Mock Test-CISDconfPathLocked { $true }
                foreach ($n in 5, 7, 9) { (& "Test-CIS_Debian13_1_7_$n").Status | Should -Be 'Pass' }
                Mock Test-CISDconfPathLocked { $DconfPath -like '*/idle-delay' -or $DconfPath -like '*/automount' }
                foreach ($n in 5, 7, 9) { (& "Test-CIS_Debian13_1_7_$n").Status | Should -Be 'Fail' }
            }
            It '1.7.6 y 1.7.8' {
                Mock Get-CISDconfValue { 'false' }; (Test-CIS_Debian13_1_7_6).Status | Should -Be 'Pass'
                Mock Get-CISDconfValue { 'true' }; (Test-CIS_Debian13_1_7_6).Status | Should -Be 'Fail'
                Mock Get-CISDconfValue { 'true' }; (Test-CIS_Debian13_1_7_8).Status | Should -Be 'Pass'
                Mock Get-CISDconfValue { $null }; (Test-CIS_Debian13_1_7_8).Status | Should -Be 'Fail'
            }
            It '1.7.11 exige WaylandEnable=false' {
                Mock Get-Debian13GdmConfFiles { '/etc/gdm3/custom.conf' }
                Mock Get-Debian13IniValue { 'false' }; (Test-CIS_Debian13_1_7_11).Status | Should -Be 'Pass'
                Mock Get-Debian13IniValue { $null }; (Test-CIS_Debian13_1_7_11).Status | Should -Be 'Fail'
            }
        }
        It '1.7.10 Fail si algun archivo tiene Enable=true en [xdmcp]' {
            Mock Get-Debian13GdmConfFiles { '/etc/gdm3/custom.conf' }
            Mock Get-Debian13IniValue { 'true' }; (Test-CIS_Debian13_1_7_10).Status | Should -Be 'Fail'
            Mock Get-Debian13IniValue { $null }; (Test-CIS_Debian13_1_7_10).Status | Should -Be 'Pass'
        }
        It 'Get-Debian13IniValue lee solo el bloque pedido' {
            $f = Join-Path ([IO.Path]::GetTempPath()) "cis13-$([guid]::NewGuid()).conf"
            Set-Content $f @('[daemon]', 'Enable=false', '[xdmcp]', '# Enable=true', 'Enable=true', '[debug]', 'Enable=x')
            Get-Debian13IniValue -File $f -Block 'xdmcp' -Key 'Enable' | Should -Be 'true'
            Get-Debian13IniValue -File $f -Block 'daemon' -Key 'Enable' | Should -Be 'false'
            Remove-Item $f
        }
    }
}
