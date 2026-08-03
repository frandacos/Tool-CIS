#Requires -Modules Pester
<#
    Tests del bloque 18.6/18.7 (Network + Printers, 49 controles: 20
    implementados via registro + 29 ManualReviewRequired declarados por
    baja confianza en la clave de registro exacta). Cubre el caso especial
    de Hardened UNC Paths (18.6.14.1, dos entradas en una misma clave) y
    confirma que los 29 Manual efectivamente devuelven ese estado (no un
    Test-* roto o un Fail/Pass inventado).
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.WS2025.psd1') -Force
}

Describe 'Chapter 18b - Network (18.6) y Printers (18.7)' {
    InModuleScope 'CISHarden.WS2025' {

        Context 'DWord simple (18.6.4.4 Turn off multicast name resolution)' {
            It 'Pass cuando EnableMulticast = 0' {
                Mock Get-ItemProperty { [pscustomobject]@{ EnableMulticast = 0 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_6_4_4).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no existe (default)' {
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_6_4_4).Status | Should -Be 'Fail'
            }
        }

        Context 'Alcance MS only (18.6.21.2 Prohibit non-domain networks)' {
            It 'NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_6_21_2).Status | Should -Be 'NotApplicable'
            }
        }

        Context 'Hardened UNC Paths (18.6.14.1, dos entradas en una clave)' {
            It 'Pass cuando NETLOGON y SYSVOL tienen ambos flags' {
                Mock Get-ItemProperty {
                    [pscustomobject]@{
                        '\\*\NETLOGON' = 'RequireMutualAuthentication=1,RequireIntegrity=1'
                        '\\*\SYSVOL'   = 'RequireMutualAuthentication=1,RequireIntegrity=1'
                    }
                }
                (Test-CIS_WS2025_18_6_14_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta SYSVOL' {
                Mock Get-ItemProperty {
                    [pscustomobject]@{
                        '\\*\NETLOGON' = 'RequireMutualAuthentication=1,RequireIntegrity=1'
                    }
                }
                (Test-CIS_WS2025_18_6_14_1).Status | Should -Be 'Fail'
            }
            It 'Fail cuando la clave no existe' {
                Mock Get-ItemProperty { $null }
                (Test-CIS_WS2025_18_6_14_1).Status | Should -Be 'Fail'
            }
        }

        Context 'PrintNightmare (18.7.1 Print Spooler client connections)' {
            It 'Pass cuando RegisterSpoolerRemoteRpcEndPoint = 2' {
                Mock Get-ItemProperty { [pscustomobject]@{ RegisterSpoolerRemoteRpcEndPoint = 2 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_7_1).Status | Should -Be 'Pass'
            }
        }

        Context 'Controles declarados Manual por baja confianza' {
            It 'Los 29 controles nuevos/inciertos devuelven ManualReviewRequired, no Pass/Fail inventado' {
                $manualIds = @(
                    '18_6_4_3',
                    '18_6_7_1', '18_6_7_2', '18_6_7_3', '18_6_7_4', '18_6_7_5', '18_6_7_6', '18_6_7_7',
                    '18_6_8_1', '18_6_8_2', '18_6_8_3', '18_6_8_4', '18_6_8_5', '18_6_8_6', '18_6_8_7',
                    '18_7_2', '18_7_3', '18_7_4', '18_7_5', '18_7_6', '18_7_7', '18_7_8', '18_7_9', '18_7_11', '18_7_14',
                    '18_7_15', '18_7_16', '18_7_17', '18_7_18'
                )
                $manualIds.Count | Should -Be 29
                foreach ($id in $manualIds) {
                    $fn = "Test-CIS_WS2025_$id"
                    (& $fn).Status | Should -Be 'ManualReviewRequired' -Because "$fn deberia ser Manual, no un valor inventado"
                }
            }
        }

        Context 'Cobertura del bloque 18b' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 49 filas 18.6.*/18.7.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^18\.(6\.|7\.)' }
                $inventory.Count | Should -Be 49
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_WS2025_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_WS2025_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
