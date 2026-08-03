#Requires -Modules Pester
<#
    Tests del bloque 18.10 Windows Components (114 controles, el mas grande
    del benchmark). Cubre representantes de cada sub-bloque grande (RDP,
    Event Log con valor SZ, WinRM, Windows Defender, Windows Update) y
    confirma los ~11 Manual, mas cobertura 114/114.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.WS2025.psd1') -Force
}

Describe 'Chapter 18d - Windows Components' {
    InModuleScope 'CISHarden.WS2025' {

        Context 'Event Log con Retention en REG_SZ (18.10.26.2.1 Security)' {
            It "Pass cuando Retention = '0'" {
                Mock Get-ItemProperty { [pscustomobject]@{ Retention = '0' } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_26_2_1).Status | Should -Be 'Pass'
            }
            It "Fail cuando Retention no es '0'" {
                Mock Get-ItemProperty { [pscustomobject]@{ Retention = '30' } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_26_2_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Event Log MaxSize (18.10.26.2.2 Security, 196608 KB minimo)' {
            It 'Pass con 196608' {
                Mock Get-ItemProperty { [pscustomobject]@{ MaxSize = 196608 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_26_2_2).Status | Should -Be 'Pass'
            }
            It 'Fail con el default de Windows (20480 KB aprox)' {
                Mock Get-ItemProperty { [pscustomobject]@{ MaxSize = 20480 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_26_2_2).Status | Should -Be 'Fail'
            }
        }

        Context 'RDP / Terminal Services (18.10.57.3.9.5 Encryption level High)' {
            It 'Pass con MinEncryptionLevel = 3' {
                Mock Get-ItemProperty { [pscustomobject]@{ MinEncryptionLevel = 3 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_57_3_9_5).Status | Should -Be 'Pass'
            }
            It 'Fail con un nivel menor' {
                Mock Get-ItemProperty { [pscustomobject]@{ MinEncryptionLevel = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_57_3_9_5).Status | Should -Be 'Fail'
            }
        }

        Context 'WinRM Client vs Service (mismo nombre de valor, distinta ruta)' {
            It '18.10.90.1.1 (Client) y 18.10.90.2.1 (Service) evaluan independientemente' {
                Mock Get-ItemProperty {
                    param($Path)
                    if ($Path -like '*WinRM\Client*') { return [pscustomobject]@{ AllowBasic = 0 } }
                    if ($Path -like '*WinRM\Service*') { return [pscustomobject]@{ AllowBasic = 1 } }
                    return $null
                } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_90_1_1).Status | Should -Be 'Pass'
                (Test-CIS_WS2025_18_10_90_2_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Windows Defender MAPS (18.10.42.5.2 Join MAPS Advanced)' {
            It 'Pass con SpynetReporting = 2' {
                Mock Get-ItemProperty { [pscustomobject]@{ SpynetReporting = 2 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_42_5_2).Status | Should -Be 'Pass'
            }
        }

        Context 'Windows Update (18.10.94.2.1 Configure Automatic Updates)' {
            It 'Pass con NoAutoUpdate = 0' {
                Mock Get-ItemProperty { [pscustomobject]@{ NoAutoUpdate = 0 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_94_2_1).Status | Should -Be 'Pass'
            }
            It 'Fail con NoAutoUpdate = 1 (auto update deshabilitado)' {
                Mock Get-ItemProperty { [pscustomobject]@{ NoAutoUpdate = 1 } } -ModuleName CISHarden.Core
                (Test-CIS_WS2025_18_10_94_2_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Controles declarados Manual por baja confianza' {
            It 'Los 11 controles inciertos devuelven ManualReviewRequired' {
                $manualIds = @(
                    '18_10_16_4', '18_10_29_2',
                    '18_10_42_4_1', '18_10_42_8_1', '18_10_42_10_1',
                    '18_10_42_11_1_1_1', '18_10_42_11_1_1_2', '18_10_42_11_1_2_1',
                    '18_10_42_13_1', '18_10_42_13_4', '18_10_93_2_1'
                )
                $manualIds.Count | Should -Be 11
                foreach ($id in $manualIds) {
                    (& "Test-CIS_WS2025_$id").Status | Should -Be 'ManualReviewRequired' -Because "Test-CIS_$id deberia ser Manual"
                }
            }
        }

        Context 'Cobertura del bloque 18d' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 114 filas 18.10.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^18\.10\.' }
                $inventory.Count | Should -Be 114
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_WS2025_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_WS2025_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_WS2025_$suffix para $($row.control_id)"
                }
            }
        }
    }
}
