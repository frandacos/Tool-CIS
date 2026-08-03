#Requires -Modules Pester
<#
    Tests de Etapa 3 (Windows Defender Firewall, 23 controles: Domain,
    Private, Public). Reutiliza el mismo motor de registro que Chapter2, asi
    que estos tests son mas cortos: alcanza con probar el patron una vez por
    tipo de valor (DWord exacto, minimo, string no vacio) mas los 2
    controles unicos del perfil Public, mas el test de cobertura de los 23.

    Todo corre dentro de InModuleScope 'CISHarden.WS2025' (funciones privadas).
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.WS2025.psd1') -Force
}

Describe 'Chapter 9 - Windows Defender Firewall' {
    InModuleScope 'CISHarden.WS2025' {

        Context 'Firewall state (9.1.1 Domain)' {
            It 'Pass cuando EnableFirewall = 1' {
                Mock Get-ItemProperty { [pscustomobject]@{ EnableFirewall = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no existe (firewall no forzado via GPO)' {
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_1_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Logging size limit (9.2.5 Private)' {
            It 'Pass con 16384 o mas' {
                Mock Get-ItemProperty { [pscustomobject]@{ LogFileSize = 32768 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_2_5).Status | Should -Be 'Pass'
            }
            It 'Fail con menos de 16384 (default de Windows es 4096)' {
                Mock Get-ItemProperty { [pscustomobject]@{ LogFileSize = 4096 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_2_5).Status | Should -Be 'Fail'
            }
        }

        Context 'Logging Name configurado (9.3.6 Public)' {
            It 'Fail cuando la clave no existe' {
                Mock Get-ItemProperty { $null } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_3_6).Status | Should -Be 'Fail'
            }
            It 'Pass cuando hay una ruta configurada' {
                Mock Get-ItemProperty { [pscustomobject]@{ LogFilePath = '%SystemRoot%\System32\logfiles\firewall\publicfw.log' } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_3_6).Status | Should -Be 'Pass'
            }
        }

        Context 'Controles unicos de Public (9.3.4/9.3.5 Apply local rules)' {
            It '9.3.4 Pass cuando AllowLocalPolicyMerge = 0' {
                Mock Get-ItemProperty { [pscustomobject]@{ AllowLocalPolicyMerge = 0 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_3_4).Status | Should -Be 'Pass'
            }
            It '9.3.5 Fail cuando AllowLocalIPsecPolicyMerge no esta en 0' {
                Mock Get-ItemProperty { [pscustomobject]@{ AllowLocalIPsecPolicyMerge = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_9_3_5).Status | Should -Be 'Fail'
            }
        }

        Context 'Cobertura del capitulo 9' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 23 filas 9.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^9\.' }
                $inventory.Count | Should -Be 23
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_WS2025_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_WS2025_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
