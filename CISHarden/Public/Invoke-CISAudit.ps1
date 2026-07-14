function ConvertTo-CISFunctionSuffix {
    <# '2.2.9' -> '2_2_9', para matchear Test-CIS_2_2_9 #>
    param([Parameter(Mandatory)][string]$ControlId)
    $ControlId -replace '\.', '_'
}

function Get-CISInventory {
    [CmdletBinding()]
    param(
        [string]$InventoryPath = (Join-Path $PSScriptRoot '..\..\inventory\cis2025_controls_master.csv')
    )
    if (-not (Test-Path $InventoryPath)) {
        throw "No se encontro el inventario canonico en $InventoryPath. Sin este CSV no hay checklist contra el cual auditar cobertura."
    }
    Import-Csv -Path $InventoryPath
}

function Invoke-CISAudit {
    <#
    .SYNOPSIS
        Corre las funciones Test-CIS_* disponibles en el modulo contra el
        inventario canonico de 415 controles y devuelve/reporta el resultado.

    .PARAMETER Chapter
        Filtra por capitulo (ej. '1', '2', '18'). Sin este parametro corre
        todo lo que este implementado.

    .PARAMETER ControlId
        Corre un unico control puntual (ej. '1.1.1').

    .PARAMETER OutputPath
        Si se especifica, exporta el resultado a CSV ademas de mostrarlo.

    .PARAMETER ReportCoverage
        Ademas de auditar, imprime cuantas filas del inventario de ese
        capitulo todavia no tienen una funcion Test-CIS_* implementada -
        para que ninguna etapa se de por cerrada con controles pendientes.
    #>
    [CmdletBinding()]
    param(
        [string]$Chapter,
        [string]$ControlId,
        [string]$OutputPath,
        [switch]$ReportCoverage
    )

    $inventory = Get-CISInventory
    if ($Chapter) { $inventory = $inventory | Where-Object { $_.chapter -eq $Chapter } }
    if ($ControlId) { $inventory = $inventory | Where-Object { $_.control_id -eq $ControlId } }

    $results = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($row in $inventory) {
        $suffix = ConvertTo-CISFunctionSuffix -ControlId $row.control_id
        $fn = "Test-CIS_$suffix"
        if (Get-Command $fn -ErrorAction SilentlyContinue) {
            try {
                $results.Add((& $fn))
            }
            catch {
                $results.Add((New-CISResult -ControlId $row.control_id -Title $row.title -Status 'Error' -Notes $_.Exception.Message))
            }
        }
        else {
            $missing.Add($row.control_id)
        }
    }

    if ($ReportCoverage) {
        $total = $inventory.Count
        $implemented = $total - $missing.Count
        Write-Host "Cobertura: $implemented/$total controles implementados en este alcance." -ForegroundColor Cyan
        if ($missing.Count -gt 0) {
            Write-Warning "Controles del inventario SIN funcion Test-CIS_* todavia: $($missing -join ', ')"
        }
    }

    if ($OutputPath) {
        $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host "Reporte exportado a $OutputPath" -ForegroundColor Green
    }

    return $results
}
