#Requires -Modules Pester
<# Tests de los helpers Linux agregados para Debian 13: Test-CISPathAccess y sysctl persistido. #>

BeforeDiscovery {
    Import-Module (Join-Path (Split-Path -Parent $PSScriptRoot) 'CISHarden.Core.psd1') -Force
}

Describe 'Test-CISPathAccess' {
    InModuleScope 'CISHarden.Core' {
        It 'Pass con modo igual o mas restrictivo y root:root' {
            Mock Get-CISFileMode { '644' }; Mock Get-CISFileOwner { 'root:root' }
            (Test-CISPathAccess -Path /x -MaxMode 755).Compliant | Should -BeTrue
            (Test-CISPathAccess -Path /x -MaxMode 644).Compliant | Should -BeTrue
        }
        It 'Fail si tiene bits fuera de MaxMode aunque el numero sea menor (ej. 0700 vs 0640 es ok; 0064 no)' {
            Mock Get-CISFileOwner { 'root:root' }
            Mock Get-CISFileMode { '700' }
            (Test-CISPathAccess -Path /x -MaxMode 640).Compliant | Should -BeFalse   # bit x de owner
            Mock Get-CISFileMode { '044' }
            (Test-CISPathAccess -Path /x -MaxMode 600).Compliant | Should -BeFalse
        }
        It 'Fail si el owner no es root:root' {
            Mock Get-CISFileMode { '600' }; Mock Get-CISFileOwner { 'user:user' }
            (Test-CISPathAccess -Path /x -MaxMode 755).Compliant | Should -BeFalse
        }
        It 'Inexistente: Exists=false, Compliant=true' {
            Mock Get-CISFileMode { $null }
            $r = Test-CISPathAccess -Path /x -MaxMode 755
            $r.Exists | Should -BeFalse; $r.Compliant | Should -BeTrue
        }
    }
}

Describe 'Test-CISSysctlSetting' {
    InModuleScope 'CISHarden.Core' {
        It 'Pass cuando ejecucion y primer valor persistido coinciden' {
            Mock Get-CISSysctlValue { '1' }
            Mock Get-CISSysctlPersistedValue { [pscustomobject]@{ File = '/etc/sysctl.d/a.conf'; Value = '1' } }
            (Test-CISSysctlSetting -Key k -Value 1).Compliant | Should -BeTrue
        }
        It 'Fail si no hay valor persistido' {
            Mock Get-CISSysctlValue { '1' }
            Mock Get-CISSysctlPersistedValue { }
            (Test-CISSysctlSetting -Key k -Value 1).Compliant | Should -BeFalse
        }
        It 'Fail si el efectivo persistido (el primero) difiere' {
            Mock Get-CISSysctlValue { '1' }
            Mock Get-CISSysctlPersistedValue { [pscustomobject]@{ File = '/a'; Value = '0' }; [pscustomobject]@{ File = '/b'; Value = '1' } }
            (Test-CISSysctlSetting -Key k -Value 1).Compliant | Should -BeFalse
        }
    }
}
