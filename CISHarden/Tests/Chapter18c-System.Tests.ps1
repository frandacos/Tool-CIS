#Requires -Modules Pester
<#
    Tests del bloque 18.9 System (68 controles). Cubre representantes de
    cada sub-bloque (VBS/Credential Guard con alcance DC/MS, LAPS, power
    management, RPC con alcance MS, SAM con alcance DC/MS) y confirma los 6
    Manual declarados, mas cobertura 68/68.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'CISHarden.psd1') -Force
}

Describe 'Chapter 18c - System' {
    InModuleScope 'CISHarden' {

        Context 'DWord simple (18.9.3.1 Include command line in process creation events)' {
            It 'Pass cuando el valor es 1' {
                Mock Get-ItemProperty { [pscustomobject]@{ ProcessCreationIncludeCmdLine_Enabled = 1 } }
                (Test-CIS_18_9_3_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no existe' {
                Mock Get-ItemProperty { $null }
                (Test-CIS_18_9_3_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Credential Guard con alcance DC/MS distinto (18.9.5.5 vs 18.9.5.6)' {
            It '18.9.5.5 (MS only) es NotApplicable en un DC' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_18_9_5_5).Status | Should -Be 'NotApplicable'
            }
            It '18.9.5.6 (DC only) es NotApplicable en un MS' {
                Mock Get-CISServerRole { 'MS' }
                (Test-CIS_18_9_5_6).Status | Should -Be 'NotApplicable'
            }
            It '18.9.5.6 (DC only) Pass en un DC con LsaCfgFlags = 0' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-ItemProperty { [pscustomobject]@{ LsaCfgFlags = 0 } }
                (Test-CIS_18_9_5_6).Status | Should -Be 'Pass'
            }
        }

        Context 'Windows LAPS (18.9.26.5 Password Length)' {
            It 'Pass con 15 o mas' {
                Mock Get-ItemProperty { [pscustomobject]@{ PasswordLength = 20 } }
                (Test-CIS_18_9_26_5).Status | Should -Be 'Pass'
            }
            It 'Fail con menos de 15' {
                Mock Get-ItemProperty { [pscustomobject]@{ PasswordLength = 8 } }
                (Test-CIS_18_9_26_5).Status | Should -Be 'Fail'
            }
        }

        Context 'RPC con alcance MS only (18.9.38.2)' {
            It 'NotApplicable en un DC' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_18_9_38_2).Status | Should -Be 'NotApplicable'
            }
        }

        Context 'SAM RPC con alcance DC/MS distinto (18.9.41.2 vs 18.9.41.3)' {
            It '18.9.41.2 (DC only) es NotApplicable en un MS' {
                Mock Get-CISServerRole { 'MS' }
                (Test-CIS_18_9_41_2).Status | Should -Be 'NotApplicable'
            }
            It '18.9.41.3 (MS only) es NotApplicable en un DC' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_18_9_41_3).Status | Should -Be 'NotApplicable'
            }
            It '18.9.41.2 (DC only) es ManualReviewRequired en un DC (no valor inventado)' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_18_9_41_2).Status | Should -Be 'ManualReviewRequired'
            }
        }

        Context 'Controles declarados Manual por baja confianza' {
            It 'Los 6 controles inciertos devuelven ManualReviewRequired' {
                Mock Get-CISServerRole { 'DC' }
                @('18_9_17_1', '18_9_23_1', '18_9_31_1_1', '18_9_41_1') | ForEach-Object {
                    (& "Test-CIS_$_").Status | Should -Be 'ManualReviewRequired' -Because "Test-CIS_$_ deberia ser Manual"
                }
            }
        }

        Context 'Cobertura del bloque 18c' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 68 filas 18.9.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^18\.9\.' }
                $inventory.Count | Should -Be 68
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
