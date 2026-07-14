@{
    RootModule        = 'CISHarden.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = 'b3f2a7b0-6c8e-4a9d-9a1a-3f5e6c7d8e9f'
    Author            = 'VULPS'
    Description       = 'Audit y remediacion del CIS Microsoft Windows Server 2025 Benchmark v2.0.0, control por control, mapeado 1 a 1 contra inventory/cis2025_controls_master.csv.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-CISAudit', 'Invoke-CISRemediate')
    PrivateData       = @{
        PSData = @{
            Tags = @('CIS', 'Hardening', 'WindowsServer2025', 'Compliance')
        }
    }
}
