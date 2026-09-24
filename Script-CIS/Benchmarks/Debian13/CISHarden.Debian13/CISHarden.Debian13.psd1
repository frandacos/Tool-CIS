@{
    RootModule        = 'CISHarden.Debian13.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'a7e3b5c2-9d14-4f60-8b2e-3c1d5f7a9e42'
    Author            = 'VULPS'
    Description       = 'Contenido del CIS Debian Linux 13 Benchmark v1.0.0 (343 controles, capitulos 1-7). Estado: esqueleto + inventario; Test-CIS_Debian13_*/Set-CIS_Debian13_* se implementan por etapas segun PLAN_Debian13.md. Requiere CISHarden.Core (motores Linux).'
    PowerShellVersion = '7.0'
    RequiredModules   = @('CISHarden.Core')
    FunctionsToExport = @('Test-CIS_Debian13_*', 'Set-CIS_Debian13_*', 'Get-CISBenchmarkInfo_Debian13')
    PrivateData       = @{
        PSData = @{
            Tags = @('CIS', 'Hardening', 'Debian13', 'Linux', 'Unix', 'Compliance')
        }
    }
}
