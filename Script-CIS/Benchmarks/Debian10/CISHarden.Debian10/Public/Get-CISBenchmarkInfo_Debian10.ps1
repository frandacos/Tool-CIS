function Get-CISBenchmarkInfo_Debian10 {
    <#
    .SYNOPSIS
        Metadata que CISHarden.Core necesita para orquestar este benchmark:
        donde esta el inventario canonico y con que prefijo se nombran sus
        funciones Test-CIS_<prefijo>_*/Set-CIS_<prefijo>_*.
    #>
    [pscustomobject]@{
        Tag            = 'Debian10'
        DisplayName    = 'CIS Debian Linux 10 Benchmark v2.0.0'
        InventoryPath  = Join-Path $PSScriptRoot '..\inventory\cis_debian10_controls_master.csv'
        FunctionPrefix = 'Debian10'
    }
}
