#Requires -Modules Pester
<#
    Tests de Etapa 4 (Advanced Audit Policy Configuration, 34 controles via
    auditpol). Cubre los 4 modos del motor (SuccessAndFailure, SuccessOnly,
    IncludeSuccess, IncludeFailure), alcance DC only, y el test de cobertura
    de los 34. Todo dentro de InModuleScope 'CISHarden'.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'CISHarden.psd1') -Force
}

Describe 'Chapter 17 - Advanced Audit Policy Configuration' {
    InModuleScope 'CISHarden' {

        Context 'SuccessAndFailure exacto (17.1.1 Credential Validation)' {
            It "Pass cuando auditpol devuelve 'Success and Failure'" {
                Mock Get-CISAuditSubcategorySetting { 'Success and Failure' }
                (Test-CIS_17_1_1).Status | Should -Be 'Pass'
            }
            It "Fail cuando auditpol devuelve solo 'Success'" {
                Mock Get-CISAuditSubcategorySetting { 'Success' }
                (Test-CIS_17_1_1).Status | Should -Be 'Fail'
            }
            It "Fail cuando auditpol devuelve 'No Auditing' (default de Windows)" {
                Mock Get-CISAuditSubcategorySetting { 'No Auditing' }
                (Test-CIS_17_1_1).Status | Should -Be 'Fail'
            }
        }

        Context 'IncludeSuccess (17.3.2 Process Creation)' {
            It "Pass con 'Success'" {
                Mock Get-CISAuditSubcategorySetting { 'Success' }
                (Test-CIS_17_3_2).Status | Should -Be 'Pass'
            }
            It "Pass con 'Success and Failure' (tambien incluye Success)" {
                Mock Get-CISAuditSubcategorySetting { 'Success and Failure' }
                (Test-CIS_17_3_2).Status | Should -Be 'Pass'
            }
            It "Fail con 'Failure' solo (no incluye Success)" {
                Mock Get-CISAuditSubcategorySetting { 'Failure' }
                (Test-CIS_17_3_2).Status | Should -Be 'Fail'
            }
        }

        Context 'IncludeFailure (17.5.1 Account Lockout)' {
            It "Pass con 'Failure'" {
                Mock Get-CISAuditSubcategorySetting { 'Failure' }
                (Test-CIS_17_5_1).Status | Should -Be 'Pass'
            }
            It "Fail con 'Success' solo (no incluye Failure)" {
                Mock Get-CISAuditSubcategorySetting { 'Success' }
                (Test-CIS_17_5_1).Status | Should -Be 'Fail'
            }
        }

        Context 'SuccessOnly (17.8.1 Sensitive Privilege Use)' {
            It "Pass exacto con 'Success'" {
                Mock Get-CISAuditSubcategorySetting { 'Success' }
                (Test-CIS_17_8_1).Status | Should -Be 'Pass'
            }
            It "Fail con 'Success and Failure' (mas de lo pedido, pero el benchmark pide exactamente Success)" {
                Mock Get-CISAuditSubcategorySetting { 'Success and Failure' }
                (Test-CIS_17_8_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Alcance DC only (17.1.2 Kerberos Authentication Service)' {
            It 'NotApplicable en un Member Server' {
                Mock Get-CISServerRole { 'MS' }
                (Test-CIS_17_1_2).Status | Should -Be 'NotApplicable'
            }
            It 'Evalua normalmente en un DC' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISAuditSubcategorySetting { 'Success and Failure' }
                (Test-CIS_17_1_2).Status | Should -Be 'Pass'
            }
        }

        Context 'Remediacion no reduce auditoria existente (Set-CISAuditPolicyForMode, IncludeSuccess)' {
            It 'Al pedir IncludeSuccess con Failure ya habilitado, no apaga Failure' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISAuditSubcategorySetting { 'Failure' }
                Mock Set-CISAuditSubcategorySetting {}
                Set-CIS_17_3_2
                Should -Invoke Set-CISAuditSubcategorySetting -ParameterFilter { $Success -eq $true -and $Failure -eq $true } -Times 1
            }
        }

        Context 'Cobertura del capitulo 17' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 34 filas 17.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^17\.' }
                $inventory.Count | Should -Be 34
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
