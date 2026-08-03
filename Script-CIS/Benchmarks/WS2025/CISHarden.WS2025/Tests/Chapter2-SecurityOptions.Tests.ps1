#Requires -Modules Pester
<#
    Tests de Etapa 2b (Security Options, 70 controles). Cubre una muestra
    representativa de cada patron del motor (DWord exacto, rango, bitmask,
    multi-string contains/empty, string exacto, "rename" not-equal, reuse de
    secedit System Access, Manual, alcance DC/MS, Not Configured) mas el test
    de cobertura obligatorio de los 70. No repite un test por cada uno de los
    70 controles porque serian variaciones mecanicas del mismo patron ya
    cubierto -- la responsabilidad de que EXISTAN los 70 la cubre el test de
    cobertura, no la exhaustividad de casos por control.

    Igual que en los capitulos anteriores, todo corre dentro de
    InModuleScope 'CISHarden.WS2025' porque las funciones son privadas del modulo.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.WS2025.psd1') -Force
}

Describe 'Chapter 2.3 - Security Options' {
    InModuleScope 'CISHarden.WS2025' {

        Context 'DWord exacto simple (2.3.1.2 Limit local account use of blank passwords)' {
            It 'Pass cuando LimitBlankPasswordUse = 1' {
                Mock Get-ItemProperty { [pscustomobject]@{ LimitBlankPasswordUse = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_1_2).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no existe (default)' {
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_1_2).Status | Should -Be 'Fail'
            }
        }

        Context 'Rango (2.3.7.3 Machine inactivity limit)' {
            It 'Pass dentro de 1-900' {
                Mock Get-ItemProperty { [pscustomobject]@{ InactivityTimeoutSecs = 900 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_7_3).Status | Should -Be 'Pass'
            }
            It 'Fail con 0 (no cumple "pero no 0")' {
                Mock Get-ItemProperty { [pscustomobject]@{ InactivityTimeoutSecs = 0 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_7_3).Status | Should -Be 'Fail'
            }
            It 'Fail con un valor mayor a 900' {
                Mock Get-ItemProperty { [pscustomobject]@{ InactivityTimeoutSecs = 1200 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_7_3).Status | Should -Be 'Fail'
            }
        }

        Context 'Bitmask (2.3.11.4 Kerberos encryption types)' {
            It 'Pass cuando AES128 y AES256 estan habilitados (con o sin otros bits)' {
                Mock Get-ItemProperty { [pscustomobject]@{ SupportedEncryptionTypes = 2147483672 } } -ModuleName CISHarden.Core # 0x8 + 0x10 + 0x80000000
                (Test-CIS_WS2025_2_3_11_4).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta el bit de AES256' {
                Mock Get-ItemProperty { [pscustomobject]@{ SupportedEncryptionTypes = 0x8 } } -ModuleName CISHarden.Core # solo AES128
                (Test-CIS_WS2025_2_3_11_4).Status | Should -Be 'Fail'
            }
        }

        Context 'Multi-string contains (2.3.10.6 Named Pipes, DC only)' {
            It 'Pass cuando incluye LSARPC, NETLOGON y SAMR (puede tener mas)' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                Mock Get-ItemProperty { [pscustomobject]@{ NullSessionPipes = @('LSARPC', 'NETLOGON', 'SAMR', 'browser') } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_10_6).Status | Should -Be 'Pass'
            }
            It 'Fail cuando falta alguno de los requeridos' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                Mock Get-ItemProperty { [pscustomobject]@{ NullSessionPipes = @('LSARPC') } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_10_6).Status | Should -Be 'Fail'
            }
            It 'NotApplicable en un Member Server' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISServerRole { 'MS' } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_10_6).Status | Should -Be 'NotApplicable'
            }
        }

        Context 'Multi-string vacio (2.3.10.12 Shares that can be accessed anonymously)' {
            It 'Pass cuando la clave no existe (nadie configurado)' {
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_10_12).Status | Should -Be 'Pass'
            }
            It 'Fail cuando hay algun share listado' {
                Mock Get-ItemProperty { [pscustomobject]@{ NullSessionShares = @('PUBLIC') } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_10_12).Status | Should -Be 'Fail'
            }
        }

        Context 'Not Configured (2.3.5.2 Allow vulnerable Netlogon secure channel connections, DC only)' {
            It 'Pass cuando la clave no existe' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_5_2).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave existe con algun valor' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                Mock Get-ItemProperty { [pscustomobject]@{ VulnerableChannelAllowList = 'CONTOSO' } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_5_2).Status | Should -Be 'Fail'
            }
        }

        Context 'Reuse de secedit System Access (2.3.1.1 Guest account status, MS only)' {
            It 'Pass cuando EnableGuestAccount = 0' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-CISServerRole { 'MS' } -ModuleName CISHarden.Core
                Mock Get-CISSecurityPolicy { @{ EnableGuestAccount = '0' } }
                (Test-CIS_WS2025_2_3_1_1).Status | Should -Be 'Pass'
            }
            It 'NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_1_1).Status | Should -Be 'NotApplicable'
            }
        }

        Context 'Rename con valor organization-specific (2.3.1.3 Rename administrator account)' {
            It 'Fail cuando sigue siendo el default (Administrator)' {
                Mock Get-CISSecurityPolicy { @{ NewAdministratorName = 'Administrator' } }
                (Test-CIS_WS2025_2_3_1_3).Status | Should -Be 'Fail'
            }
            It 'Pass cuando fue renombrado' {
                Mock Get-CISSecurityPolicy { @{ NewAdministratorName = 'contoso-adm' } }
                (Test-CIS_WS2025_2_3_1_3).Status | Should -Be 'Pass'
            }
            It 'Fail cuando secedit devuelve el valor entre comillas literales y sigue siendo el default (regresion: bug encontrado auditando un DC real)' {
                # secedit /export envuelve los valores string de [System Access]
                # entre comillas literales: NewAdministratorName = "Administrator".
                # Sin el Trim('"') en Test-CIS_WS2025_2_3_1_3, comparar '"Administrator"'
                # contra 'Administrator' (sin comillas) siempre da "distinto" y
                # el control marcaba Pass aunque la cuenta nunca se hubiera
                # renombrado.
                Mock Get-CISSecurityPolicy { @{ NewAdministratorName = '"Administrator"' } }
                (Test-CIS_WS2025_2_3_1_3).Status | Should -Be 'Fail'
            }
            It 'Pass cuando secedit devuelve el valor entre comillas literales y fue renombrado' {
                Mock Get-CISSecurityPolicy { @{ NewAdministratorName = '"contoso-adm"' } }
                (Test-CIS_WS2025_2_3_1_3).Status | Should -Be 'Pass'
            }
        }

        Context 'Manual (2.3.11.5 Force logoff when logon hours expire)' {
            It 'Devuelve ManualReviewRequired' {
                (Test-CIS_WS2025_2_3_11_5).Status | Should -Be 'ManualReviewRequired'
            }
        }

        Context 'Baja confianza declarada (2.3.5.4 y 2.3.11.7)' {
            It '2.3.5.4 es ManualReviewRequired en DC (no se invento la clave de registro)' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-CISServerRole { 'DC' } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_2_3_5_4).Status | Should -Be 'ManualReviewRequired'
            }
            It '2.3.11.7 es ManualReviewRequired (no se invento la clave de registro)' {
                (Test-CIS_WS2025_2_3_11_7).Status | Should -Be 'ManualReviewRequired'
            }
        }

        Context 'Cobertura de la sub-etapa 2b' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 70 filas 2.3.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^2\.3\.' }
                $inventory.Count | Should -Be 70
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_WS2025_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_WS2025_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
