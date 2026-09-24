#Requires -Modules Pester
<# Verifica que exista Test-CIS_Debian13_*/Set-CIS_Debian13_* por cada fila del inventario dentro de los capitulos/secciones ya implementados. Ampliar $implementedPrefixes al cerrar cada etapa de PLAN_Debian13.md. #>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian13.psd1') -Force
}

Describe 'Cobertura del inventario (etapas implementadas)' {
    It 'Tiene Test/Set por cada fila de las secciones implementadas' {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $implementedPrefixes = @('1.', '2.', '3.', '4.', '5.', '6.', '7.')
        $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis_debian13_controls_master.csv') |
            Where-Object { $id = $_.control_id; $implementedPrefixes | Where-Object { $id.StartsWith($_) } }
        $inventory.Count | Should -Be 343
        InModuleScope 'CISHarden.Debian13' -Parameters @{ Rows = $inventory } {
            foreach ($row in $Rows) {
                $suffix = $row.control_id -replace '\.', '_'
                Get-Command "Test-CIS_Debian13_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test para $($row.control_id)"
                Get-Command "Set-CIS_Debian13_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set para $($row.control_id)"
            }
        }
    }
}
