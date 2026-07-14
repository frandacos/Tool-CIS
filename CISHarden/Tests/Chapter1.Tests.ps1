#Requires -Modules Pester
<#
    Tests de Etapa 1 (Account Policies, 11 controles). Corren mockeando
    Get-CISSecurityPolicy / registro / rol de servidor, porque la logica de
    Test-CIS_* debe validarse independientemente de tener un Windows Server
    real a mano. Esto NO reemplaza la validacion en el server de laboratorio
    (ver PLAN.md, "Como se valida cada control"): es la primera pasada, para
    que el patron Test-*/Set-* este probado antes de escalar a los capitulos
    grandes.

    IMPORTANTE: Test-CIS_*/Set-CIS_* son funciones PRIVADAS del modulo (no
    exportadas). Pester no puede mockear ni ver funciones privadas de un
    modulo desde afuera de su scope, asi que todo el bloque corre dentro de
    InModuleScope 'CISHarden' -- sin esto, los mocks no interceptan nada y
    los tests terminarian llamando al secedit/registro REAL de la maquina.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'CISHarden.psd1') -Force
}

Describe 'Chapter 1 - Account Policies' {
    InModuleScope 'CISHarden' {

        Context '1.1.1 Enforce password history' {
            It 'Pass cuando PasswordHistorySize >= 24' {
                Mock Get-CISSecurityPolicy { @{ PasswordHistorySize = '24' } }
                (Test-CIS_1_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando PasswordHistorySize < 24' {
                Mock Get-CISSecurityPolicy { @{ PasswordHistorySize = '10' } }
                (Test-CIS_1_1_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.1.2 Maximum password age' {
            It 'Fail cuando el valor es 0 (nunca expira, no cumple)' {
                Mock Get-CISSecurityPolicy { @{ MaximumPasswordAge = '0' } }
                (Test-CIS_1_1_2).Status | Should -Be 'Fail'
            }
            It 'Pass cuando el valor esta entre 1 y 365' {
                Mock Get-CISSecurityPolicy { @{ MaximumPasswordAge = '365' } }
                (Test-CIS_1_1_2).Status | Should -Be 'Pass'
            }
            It 'Fail cuando el valor supera 365' {
                Mock Get-CISSecurityPolicy { @{ MaximumPasswordAge = '999' } }
                (Test-CIS_1_1_2).Status | Should -Be 'Fail'
            }
        }

        Context '1.1.3 Minimum password age' {
            It 'Fail en el default (0 dias)' {
                Mock Get-CISSecurityPolicy { @{ MinimumPasswordAge = '0' } }
                (Test-CIS_1_1_3).Status | Should -Be 'Fail'
            }
            It 'Pass con 1 o mas dias' {
                Mock Get-CISSecurityPolicy { @{ MinimumPasswordAge = '1' } }
                (Test-CIS_1_1_3).Status | Should -Be 'Pass'
            }
        }

        Context '1.1.4 Minimum password length' {
            It 'Fail con el default de 7 caracteres' {
                Mock Get-CISSecurityPolicy { @{ MinimumPasswordLength = '7' } }
                (Test-CIS_1_1_4).Status | Should -Be 'Fail'
            }
            It 'Pass con 14 o mas caracteres' {
                Mock Get-CISSecurityPolicy { @{ MinimumPasswordLength = '14' } }
                (Test-CIS_1_1_4).Status | Should -Be 'Pass'
            }
        }

        Context '1.1.5 Password complexity' {
            It 'Fail cuando PasswordComplexity = 0' {
                Mock Get-CISSecurityPolicy { @{ PasswordComplexity = '0' } }
                (Test-CIS_1_1_5).Status | Should -Be 'Fail'
            }
            It 'Pass cuando PasswordComplexity = 1' {
                Mock Get-CISSecurityPolicy { @{ PasswordComplexity = '1' } }
                (Test-CIS_1_1_5).Status | Should -Be 'Pass'
            }
        }

        Context '1.1.6 Relax minimum password length limits (MS only)' {
            It 'NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_1_1_6).Status | Should -Be 'NotApplicable'
            }
            It 'Fail en un Member Server sin la clave de registro' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-ItemProperty { $null }
                (Test-CIS_1_1_6).Status | Should -Be 'Fail'
            }
            It 'Pass en un Member Server con RelaxMinimumPasswordLengthLimits = 1' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-ItemProperty { [pscustomobject]@{ RelaxMinimumPasswordLengthLimits = 1 } }
                (Test-CIS_1_1_6).Status | Should -Be 'Pass'
            }
        }

        Context '1.1.7 Store passwords using reversible encryption' {
            It 'Pass cuando ClearTextPassword = 0' {
                Mock Get-CISSecurityPolicy { @{ ClearTextPassword = '0' } }
                (Test-CIS_1_1_7).Status | Should -Be 'Pass'
            }
            It 'Fail cuando ClearTextPassword = 1' {
                Mock Get-CISSecurityPolicy { @{ ClearTextPassword = '1' } }
                (Test-CIS_1_1_7).Status | Should -Be 'Fail'
            }
        }

        Context '1.2.1 Account lockout duration' {
            It 'Pass con 15 o mas minutos' {
                Mock Get-CISSecurityPolicy { @{ LockoutDuration = '15' } }
                (Test-CIS_1_2_1).Status | Should -Be 'Pass'
            }
            It 'Fail con menos de 15 minutos' {
                Mock Get-CISSecurityPolicy { @{ LockoutDuration = '5' } }
                (Test-CIS_1_2_1).Status | Should -Be 'Fail'
            }
        }

        Context '1.2.2 Account lockout threshold' {
            It 'Fail cuando el umbral es 0 (deshabilitado, no cumple)' {
                Mock Get-CISSecurityPolicy { @{ LockoutBadCount = '0' } }
                (Test-CIS_1_2_2).Status | Should -Be 'Fail'
            }
            It 'Pass entre 1 y 5 intentos' {
                Mock Get-CISSecurityPolicy { @{ LockoutBadCount = '5' } }
                (Test-CIS_1_2_2).Status | Should -Be 'Pass'
            }
        }

        Context '1.2.3 Allow Administrator account lockout (MS only, Manual)' {
            It 'NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_1_2_3).Status | Should -Be 'NotApplicable'
            }
            It 'ManualReviewRequired en un Member Server (sin backing automatizable)' {
                Mock Get-CISServerRole { 'MS' }
                (Test-CIS_1_2_3).Status | Should -Be 'ManualReviewRequired'
            }
        }

        Context '1.2.4 Reset account lockout counter after' {
            It 'Pass con 15 o mas minutos' {
                Mock Get-CISSecurityPolicy { @{ ResetLockoutCount = '15' } }
                (Test-CIS_1_2_4).Status | Should -Be 'Pass'
            }
            It 'Fail con menos de 15 minutos' {
                Mock Get-CISSecurityPolicy { @{ ResetLockoutCount = '0' } }
                (Test-CIS_1_2_4).Status | Should -Be 'Fail'
            }
        }

        Context 'Cobertura del capitulo 1' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 11 filas del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.chapter -eq '1' }
                $inventory.Count | Should -Be 11
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
