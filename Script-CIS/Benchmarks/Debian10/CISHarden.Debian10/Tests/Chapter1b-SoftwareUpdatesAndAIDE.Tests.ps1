#Requires -Modules Pester
<# Tests de 1.2.x (AIDE) y 1.3.x (Manual). Ver Chapter1a-*.Tests.ps1 para la nota sobre mockeo de motores de Core. #>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian10.psd1') -Force
}

Describe 'Chapter 1.2 - AIDE / 1.3 - Software Updates' {
    InModuleScope 'CISHarden.Debian10' {

        Context '1.2.1 AIDE installed' {
            It 'Pass cuando aide y aide-common estan instalados' {
                Mock Test-CISPackageInstalled { $true }
                (Test-CIS_Debian10_1_2_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta aide-common' {
                Mock Test-CISPackageInstalled { param($Name) $Name -eq 'aide' }
                (Test-CIS_Debian10_1_2_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.2.2 filesystem integrity regularly checked' {
            It 'Pass cuando aidecheck.service/.timer estan habilitados y el timer activo' {
                Mock Get-ChildItem { @() }
                Mock Test-CISFileContains { $false }
                Mock Test-CISServiceEnabled { $true }
                Mock Test-CISServiceActive { $true }
                (Test-CIS_Debian10_1_2_2).Status | Should -Be 'Pass'
            }
            It 'Fail cuando no hay cron ni timer de aide' {
                Mock Get-ChildItem { @() }
                Mock Test-CISFileContains { $false }
                Mock Test-CISServiceEnabled { $false }
                Mock Test-CISServiceActive { $false }
                (Test-CIS_Debian10_1_2_2).Status | Should -Be 'Fail'
            }
        }

        Context '1.3.x controles Manual' {
            It '1.3.1 es ManualReviewRequired' { (Test-CIS_Debian10_1_3_1).Status | Should -Be 'ManualReviewRequired' }
            It '1.3.2 es ManualReviewRequired' { (Test-CIS_Debian10_1_3_2).Status | Should -Be 'ManualReviewRequired' }
            It '1.3.3 es ManualReviewRequired' { (Test-CIS_Debian10_1_3_3).Status | Should -Be 'ManualReviewRequired' }
            It 'Los Set-* de controles Manual solo advierten, no tiran excepcion' {
                { Set-CIS_Debian10_1_3_1 -WarningAction SilentlyContinue } | Should -Not -Throw
                { Set-CIS_Debian10_1_3_2 -WarningAction SilentlyContinue } | Should -Not -Throw
                { Set-CIS_Debian10_1_3_3 -WarningAction SilentlyContinue } | Should -Not -Throw
            }
        }
    }
}
