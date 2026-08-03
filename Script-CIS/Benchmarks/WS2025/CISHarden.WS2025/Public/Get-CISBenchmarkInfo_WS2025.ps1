function Get-CISBenchmarkInfo_WS2025 {
    <#
    .SYNOPSIS
        Metadata que CISHarden.Core necesita para orquestar este benchmark:
        donde esta el inventario canonico y con que prefijo se nombran sus
        funciones Test-CIS_<prefijo>_*/Set-CIS_<prefijo>_*. Todo modulo
        CISHarden.<Tag> debe exportar una funcion Get-CISBenchmarkInfo_<Tag>
        con esta misma forma para que Core lo pueda usar.
    #>
    [pscustomobject]@{
        Tag            = 'WS2025'
        DisplayName    = 'CIS Microsoft Windows Server 2025 Benchmark v2.0.0'
        InventoryPath  = Join-Path $PSScriptRoot '..\inventory\cis2025_controls_master.csv'
        FunctionPrefix = 'WS2025'
    }
}
