function Get-CISBenchmarkInfo_Debian13 {
    <#
    .SYNOPSIS
        Metadata que CISHarden.Core necesita para orquestar este benchmark:
        donde esta el inventario canonico y con que prefijo se nombran sus
        funciones Test-CIS_<prefijo>_*/Set-CIS_<prefijo>_*.
    #>
    [pscustomobject]@{
        Tag            = 'Debian13'
        DisplayName    = 'CIS Debian Linux 13 Benchmark v1.0.0'
        InventoryPath  = Join-Path $PSScriptRoot '..\inventory\cis_debian13_controls_master.csv'
        FunctionPrefix = 'Debian13'
    }
}
