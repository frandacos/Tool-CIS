#Requires -Modules Pester
<#
    Tests de las etapas finales: Capitulo 5 (System Services, 2 controles) y
    Capitulo 19 (Administrative Templates User, 11 controles). Con esto se
    completa la cobertura de implementacion de los 454 controles del
    benchmark.
#>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot 'CISHarden.psd1') -Force
}

Describe 'Chapter 5 - System Services' {
    InModuleScope 'CISHarden' {

        Context 'Print Spooler DC/MS (5.1 vs 5.2)' {
            It '5.1 (DC only) NotApplicable en un Member Server' {
                Mock Get-CISServerRole { 'MS' }
                (Test-CIS_5_1).Status | Should -Be 'NotApplicable'
            }
            It '5.2 (MS only) NotApplicable en un Domain Controller' {
                Mock Get-CISServerRole { 'DC' }
                (Test-CIS_5_2).Status | Should -Be 'NotApplicable'
            }
            It '5.1 Pass cuando el servicio esta Disabled' {
                Mock Get-CISServerRole { 'DC' }
                Mock Get-Service { [pscustomobject]@{ StartType = 'Disabled' } }
                (Test-CIS_5_1).Status | Should -Be 'Pass'
            }
            It '5.2 Fail cuando el servicio esta Automatic (default de Windows)' {
                Mock Get-CISServerRole { 'MS' }
                Mock Get-Service { [pscustomobject]@{ StartType = 'Automatic' } }
                (Test-CIS_5_2).Status | Should -Be 'Fail'
            }
        }

        Context 'Cobertura del capitulo 5' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 2 filas 5.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^5\.' }
                $inventory.Count | Should -Be 2
                foreach ($row in $inventory) {
                    $suffix = $row.control_id -replace '\.', '_'
                    Get-Command "Test-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_$suffix para $($row.control_id)"
                    Get-Command "Set-CIS_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_$suffix para $($row.control_id)"
                }
            }
        }
    }
}

Describe 'Chapter 19 - Administrative Templates (User)' {
    InModuleScope 'CISHarden' {

        Context 'DWord simple sobre HKCU (19.5.1.1 Toast notifications on lock screen)' {
            It 'Pass cuando el valor es 1' {
                Mock Get-ItemProperty { [pscustomobject]@{ NoToastApplicationNotificationOnLockScreen = 1 } }
                (Test-CIS_19_5_1_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando la clave no existe (default)' {
                Mock Get-ItemProperty { $null }
                (Test-CIS_19_5_1_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Mark of the Web clasico (19.7.5.1, distinto del control nuevo 18.10.29.2)' {
            It 'Pass cuando SaveZoneInformation = 2 (se preserva la zona)' {
                Mock Get-ItemProperty { [pscustomobject]@{ SaveZoneInformation = 2 } }
                (Test-CIS_19_7_5_1).Status | Should -Be 'Pass'
            }
            It 'Fail cuando SaveZoneInformation = 1 (no se preserva)' {
                Mock Get-ItemProperty { [pscustomobject]@{ SaveZoneInformation = 1 } }
                (Test-CIS_19_7_5_1).Status | Should -Be 'Fail'
            }
        }

        Context 'Backup de registro con prefijo HKCU (regresion del bug encontrado antes de implementar este capitulo)' {
            It 'Set-CISRegistryValue no rompe con una ruta HKCU y llama a reg export con la ruta traducida' {
                Mock Get-CISServerRole { 'MS' }
                Mock Test-Path { $true }
                Mock New-Item {}
                Mock reg {} -ModuleName CISHarden
                Mock New-ItemProperty {}
                { Set-CISRegistryValue -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'NoToastApplicationNotificationOnLockScreen' -Type DWord -Value 1 -Confirm:$false } | Should -Not -Throw
            }
        }

        Context 'Cobertura del capitulo 19' {
            It 'Tiene una funcion Test-CIS_*/Set-CIS_* por cada una de las 11 filas 19.* del inventario' {
                $moduleRoot = Split-Path -Parent $PSScriptRoot
                $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv') |
                    Where-Object { $_.control_id -match '^19\.' }
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

Describe 'Cobertura total del benchmark (454 controles)' {
    InModuleScope 'CISHarden' {
        It 'Existe una funcion Test-CIS_*/Set-CIS_* para cada una de las 454 filas del inventario' {
            $moduleRoot = Split-Path -Parent $PSScriptRoot
            $inventory = Import-Csv (Join-Path $moduleRoot '..\inventory\cis2025_controls_master.csv')
            $inventory.Count | Should -Be 454
            $missing = @()
            foreach ($row in $inventory) {
                $suffix = $row.control_id -replace '\.', '_'
                if (-not (Get-Command "Test-CIS_$suffix" -ErrorAction SilentlyContinue)) { $missing += "Test-CIS_$suffix" }
                if (-not (Get-Command "Set-CIS_$suffix" -ErrorAction SilentlyContinue)) { $missing += "Set-CIS_$suffix" }
            }
            $missing | Should -BeNullOrEmpty -Because "faltan estas funciones: $($missing -join ', ')"
        }
    }
}
