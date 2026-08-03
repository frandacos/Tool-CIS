@{
    RootModule        = 'CISHarden.WS2025.psm1'
    ModuleVersion     = '2.0.0'
    GUID              = 'b3f2a7b0-6c8e-4a9d-9a1a-3f5e6c7d8e9f'
    Author            = 'VULPS'
    Description       = 'Contenido del CIS Microsoft Windows Server 2025 Benchmark v2.0.0: 454 controles Test-CIS_WS2025_*/Set-CIS_WS2025_*, mapeados 1 a 1 contra inventory/cis2025_controls_master.csv. Requiere CISHarden.Core (motores de registro/secedit/auditpol/user rights).'
    PowerShellVersion = '5.1'
    RequiredModules   = @('CISHarden.Core')
    FunctionsToExport = @('Test-CIS_WS2025_*', 'Set-CIS_WS2025_*', 'Get-CISBenchmarkInfo_WS2025')
    PrivateData       = @{
        PSData = @{
            Tags = @('CIS', 'Hardening', 'WindowsServer2025', 'Compliance')
        }
    }
}
