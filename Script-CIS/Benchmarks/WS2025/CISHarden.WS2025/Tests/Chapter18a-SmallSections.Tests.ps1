#Requires -Modules Pester
<#
    Tests del primer bloque de la Etapa 5 (18.1 + 18.4 + 18.5 + 18.8 + 18.11
    = 24 controles). Mismo motor de registro que capitulos anteriores, asi
    que alcanza con probar un par de casos representativos (incluyendo el
    valor REG_SZ de 18.5.1 y el Manual de 18.11.2) mas la cobertura de los 24.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.WS2025.psd1') -Force
}

Describe 'Chapter 18a - Control Panel / MS Security Guide / MSS / Start Menu / Custom' {
    InModuleScope 'CISHarden.WS2025' {

        Context 'DWord simple (18.1.1.1 Prevent enabling lock screen camera)' {
            It 'Pass cuando NoLockScreenCamera = 1' {
                Mock Get-ItemProperty { [pscustomobject]@{ NoLockScreenCamera = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_1_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no existe (default)' {
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_1_1_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Valor contraintuitivo (18.4.1 UAC restrictions, MS only)' {
            It 'Pass cuando LocalAccountTokenFilterPolicy = 0 (restriccion activa)' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISServerRole { 'MS' } -ModuleName CISHarden.Core
                Mock Get-ItemProperty { [pscustomobject]@{ LocalAccountTokenFilterPolicy = 0 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_4_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando vale 1 (sin restriccion)' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISServerRole { 'MS' } -ModuleName CISHarden.Core
                Mock Get-ItemProperty { [pscustomobject]@{ LocalAccountTokenFilterPolicy = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_4_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Valor REG_SZ (18.5.1 AutoAdminLogon)' {
            It "Pass cuando AutoAdminLogon = '0'" {
                Mock Get-ItemProperty { [pscustomobject]@{ AutoAdminLogon = '0' } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_5_1).Status | Should -Be 'Pass'
            }
            It "Fail cuando AutoAdminLogon = '1' (logon automatico habilitado)" {
                Mock Get-ItemProperty { [pscustomobject]@{ AutoAdminLogon = '1' } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_5_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Rango con limite superior (18.5.11 WarningLevel)' {
            It 'Pass con 90' {
                Mock Get-ItemProperty { [pscustomobject]@{ WarningLevel = 90 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_5_11).Status | Should -Be 'Pass'
            }
            It 'Fail con 95 (mas del 90% permitido)' {
                Mock Get-ItemProperty { [pscustomobject]@{ WarningLevel = 95 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_5_11).Status | Should -Be 'Fail'
            }
        }

        Context 'Baja confianza declarada (18.11.2)' {
            It 'Es ManualReviewRequired (no se invento la clave de registro)' {
                (Test-CIS_WS2025_18_11_2).Status | Should -Be 'ManualReviewRequired'
            }
        }

        Context 'Cobertura del bloque 18a' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 24 filas del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^18\.(1\.|4\.|5\.|8\.|11\.)' }
                $inventory.Count | Should -Be 24
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_WS2025_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_WS2025_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
