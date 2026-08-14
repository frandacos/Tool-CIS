@{
    RootModule        = 'CISHarden.Debian10.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'c4d9e1a3-2f6b-4e8a-9d1c-7b5a3e2f9c1d'
    Author            = 'VULPS'
    Description       = 'Contenido del CIS Debian Linux 10 Benchmark v2.0.0, Capitulo 1 (Initial Setup): 67 controles Test-CIS_Debian10_*/Set-CIS_Debian10_*, mapeados 1 a 1 contra inventory/cis_debian10_controls_master.csv. Capitulos 2-6 pendientes. Requiere CISHarden.Core (motores de modulos de kernel, fstab, archivos, paquetes, servicios y sysctl para Linux).'
    PowerShellVersion = '7.0'
    RequiredModules   = @('CISHarden.Core')
    FunctionsToExport = @('Test-CIS_Debian10_*', 'Set-CIS_Debian10_*', 'Get-CISBenchmarkInfo_Debian10')
    PrivateData       = @{
        PSData = @{
            Tags = @('CIS', 'Hardening', 'Debian10', 'Linux', 'Unix', 'Compliance')
        }
    }
}
