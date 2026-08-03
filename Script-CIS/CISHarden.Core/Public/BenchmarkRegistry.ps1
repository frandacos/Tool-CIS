<#
    Mecanismo generico para descubrir/cargar modulos de benchmark
    (CISHarden.<Tag>, uno por cada CIS Benchmark soportado, en
    Benchmarks/<Tag>/CISHarden.<Tag>/). CISHarden.Core no conoce el
    contenido de ningun benchmark en particular -- solo sabe que cada
    modulo de benchmark debe exportar una funcion Get-CISBenchmarkInfo_<Tag>
    que devuelva Tag/DisplayName/InventoryPath/FunctionPrefix. Asi se agrega
    un benchmark nuevo (ej. CIS Windows Server 2022) sin tocar Core.
#>

function Get-CISBenchmarks {
    <#
    .SYNOPSIS
        Lista los benchmarks disponibles (instalados en Benchmarks/) sin
        necesidad de importarlos.
    #>
    [CmdletBinding()]
    param()
    $benchmarksRoot = Join-Path $PSScriptRoot '..\..\Benchmarks'
    if (-not (Test-Path $benchmarksRoot)) { return @() }
    Get-ChildItem -Path $benchmarksRoot -Directory | ForEach-Object {
        $tag = $_.Name
        $manifestPath = Join-Path $_.FullName "CISHarden.$tag\CISHarden.$tag.psd1"
        if (Test-Path $manifestPath) {
            $data = Import-PowerShellDataFile -Path $manifestPath
            [pscustomobject]@{
                Tag          = $tag
                Version      = $data.ModuleVersion
                Description  = $data.Description
                ManifestPath = $manifestPath
            }
        }
    }
}

function Resolve-CISBenchmarkModule {
    <# Importa CISHarden.<Benchmark> si todavia no esta cargado. #>
    param([Parameter(Mandatory)][string]$Benchmark)
    $moduleName = "CISHarden.$Benchmark"
    $existing = Get-Module -Name $moduleName
    if ($existing) { return $existing }

    $benchmarksRoot = Join-Path $PSScriptRoot '..\..\Benchmarks'
    $manifestPath = Join-Path $benchmarksRoot "$Benchmark\$moduleName\$moduleName.psd1"
    if (-not (Test-Path $manifestPath)) {
        $available = (Get-CISBenchmarks | Select-Object -ExpandProperty Tag) -join ', '
        throw "No se encontro el benchmark '$Benchmark' (se esperaba el modulo $moduleName en $manifestPath). Benchmarks disponibles: $available"
    }
    Import-Module $manifestPath -Force -Global
}

function Get-CISBenchmarkInfo {
    <# Metadata del benchmark (InventoryPath, FunctionPrefix, etc.), delegando en Get-CISBenchmarkInfo_<Tag> que expone el propio modulo del benchmark. #>
    param([Parameter(Mandatory)][string]$Benchmark)
    Resolve-CISBenchmarkModule -Benchmark $Benchmark | Out-Null
    $infoFn = "Get-CISBenchmarkInfo_$Benchmark"
    if (-not (Get-Command $infoFn -ErrorAction SilentlyContinue)) {
        throw "El modulo CISHarden.$Benchmark no expone $infoFn -- todo modulo de benchmark debe exportar esa funcion de metadata (Tag/DisplayName/InventoryPath/FunctionPrefix)."
    }
    & $infoFn
}
