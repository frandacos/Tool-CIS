function ConvertTo-CISFunctionSuffix {
    <# '2.2.9' -> '2_2_9', para matchear Test-CIS_<Tag>_2_2_9 #>
    param([Parameter(Mandatory)][string]$ControlId)
    $ControlId -replace '\.', '_'
}

function Get-CISInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Benchmark)
    $info = Get-CISBenchmarkInfo -Benchmark $Benchmark
    if (-not (Test-Path $info.InventoryPath)) {
        throw "No se encontro el inventario canonico del benchmark '$Benchmark' en $($info.InventoryPath). Sin este CSV no hay checklist contra el cual auditar cobertura."
    }
    [pscustomobject]@{
        Rows           = Import-Csv -Path $info.InventoryPath
        FunctionPrefix = $info.FunctionPrefix
    }
}

function Invoke-CISAudit {
    <#
    .SYNOPSIS
        Corre las funciones Test-CIS_<Tag>_* disponibles en el modulo de un
        benchmark (CISHarden.<Benchmark>) contra su inventario canonico y
        devuelve/reporta el resultado. Generico: no sabe nada de ningun
        benchmark en particular, solo orquesta.

    .PARAMETER Benchmark
        Tag del benchmark a auditar (ej. 'WS2025' para CIS Microsoft Windows
        Server 2025). Usa Get-CISBenchmarks para ver los instalados.

    .PARAMETER Chapter
        Filtra por capitulo (ej. '1', '2', '18'). Sin este parametro corre
        todo lo que este implementado.

    .PARAMETER ControlId
        Corre un unico control puntual (ej. '1.1.1').

    .PARAMETER ControlIds
        Corre una lista puntual de controles (ej. una tanda curada de "quick
        wins" de bajo riesgo, sin importar de que capitulo sean).

    .PARAMETER Section
        Corre una subseccion por prefijo de ID (ej. '2.2' trae 2.2.1..2.2.48,
        '18.9' trae todo 18.9.*). Los filtros se pueden combinar entre si.

    .PARAMETER Level
        Filtra por perfil de riesgo del benchmark: 'Level 1', 'Level 2' o
        'Next Generation Windows Security'. Se puede combinar con
        -Chapter/-Section.

    .PARAMETER OutputPath
        Si se especifica, exporta el resultado a CSV ademas de mostrarlo.

    .PARAMETER ReportCoverage
        Ademas de auditar, imprime cuantas filas del inventario de ese
        capitulo todavia no tienen una funcion Test-CIS_<Tag>_* implementada.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Benchmark,
        [string]$Chapter,
        [string]$ControlId,
        [string[]]$ControlIds,
        [string]$Section,
        [ValidateSet('Level 1', 'Level 2', 'Next Generation Windows Security')][string]$Level,
        [string]$OutputPath,
        [switch]$ReportCoverage
    )

    $inv = Get-CISInventory -Benchmark $Benchmark
    $inventory = $inv.Rows
    if ($Chapter) { $inventory = $inventory | Where-Object { $_.chapter -eq $Chapter } }
    if ($Section) { $inventory = $inventory | Where-Object { $_.control_id -eq $Section -or $_.control_id.StartsWith("$Section.") } }
    if ($ControlId) { $inventory = $inventory | Where-Object { $_.control_id -eq $ControlId } }
    if ($ControlIds) { $inventory = $inventory | Where-Object { $_.control_id -in $ControlIds } }
    if ($Level) { $inventory = $inventory | Where-Object { $_.level -eq $Level } }

    $results = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[string]

    foreach ($row in $inventory) {
        $suffix = ConvertTo-CISFunctionSuffix -ControlId $row.control_id
        $fn = "Test-CIS_$($inv.FunctionPrefix)_$suffix"
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
        Write-Host "Cobertura ($Benchmark): $implemented/$total controles implementados en este alcance." -ForegroundColor Cyan
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
