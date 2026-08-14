#Requires -Modules Pester
<# Verifica que exista una funcion Test-CIS_Debian10_*/Set-CIS_Debian10_* por cada fila del inventario del capitulo 1 -- el mismo chequeo que Invoke-CISAudit -ReportCoverage hace en tiempo de ejecucion. #>

BeforeAll {
    $moduleRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $moduleRoot '..\..\..\CISHarden.Core\CISHarden.Core.psd1') -Force
    Import-Module (Join-Path $moduleRoot 'CISHarden.Debian10.psd1') -Force
}

Describe 'Cobertura del inventario (Capitulo 1)' {
    It 'Tiene una funcion Test-CIS_Debian10_*/Set-CIS_Debian10_* por cada una de las 67 filas del inventario' {
        $moduleRoot = Split-Path -Parent $PSScriptRoot
        $inventory = Import-Csv (Join-Path $moduleRoot 'inventory\cis_debian10_controls_master.csv') |
            Where-Object { $_.chapter -eq '1' }
        $inventory.Count | Should -Be 67
        foreach ($row in $inventory) {
            $suffix = $row.control_id -replace '\.', '_'
            Get-Command "Test-CIS_Debian10_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Test-CIS_Debian10_$suffix para $($row.control_id)"
            Get-Command "Set-CIS_Debian10_$suffix" -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "falta Set-CIS_Debian10_$suffix para $($row.control_id)"
        }
    }
}
