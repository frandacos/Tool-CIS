@{
    RootModule        = 'CISHarden.Core.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'a1e4f6c2-8b3d-4f2a-9c7e-1d2b3a4c5d6e'
    Author            = 'VULPS'
    Description       = 'Motor generico de auditoria/remediacion CIS (Windows: registro, secedit, auditpol, user rights; Linux/Unix: modulos de kernel, fstab, archivos/permisos, paquetes dpkg, servicios systemd, sysctl) + orquestador Invoke-CISAudit/Invoke-CISRemediate. No contiene contenido de ningun benchmark especifico -- eso vive en modulos separados CISHarden.<Tag> (ver carpeta Benchmarks/).'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-CISAudit', 'Invoke-CISRemediate', 'Get-CISBenchmarks',
        'Get-CISServerRole', 'New-CISResult', 'Get-CISSecurityPolicy',
        'Backup-CISSecurityPolicy', 'Set-CISSecurityPolicyValue',
        'Get-CISAuditSubcategorySetting', 'Set-CISAuditSubcategorySetting',
        'Test-CISAuditPolicy', 'Set-CISAuditPolicyForMode',
        'Get-CISPrivilegeRights', 'Resolve-CISPrincipalToSid',
        'Test-CISUserRight', 'Set-CISUserRight',
        'Test-CISRegistryValue', 'Set-CISRegistryValue', 'Remove-CISRegistryValue',
        'New-CISValidatorMinValue', 'New-CISValidatorMaxValueNotZero',
        'New-CISValidatorRange', 'New-CISValidatorExact', 'New-CISValidatorOneOf',
        'New-CISValidatorNonEmptyString', 'New-CISValidatorNotEqualCaseInsensitive',
        'New-CISValidatorNotConfigured', 'New-CISValidatorBitmaskAll',
        'New-CISValidatorMultiStringContainsAll', 'New-CISValidatorMultiStringEmpty',
        'Get-CISLinuxProfile', 'Invoke-CISLinuxCommand',
        'Test-CISKernelModuleDisabled', 'Disable-CISKernelModule',
        'Test-CISPartitionExists', 'Get-CISMountOptions', 'Test-CISMountOption', 'Set-CISFstabMountOption',
        'Backup-CISFile', 'Test-CISFileContains', 'Set-CISFileLine',
        'Get-CISFileMode', 'Set-CISFileMode', 'Get-CISFileOwner', 'Set-CISFileOwner',
        'Test-CISPackageInstalled', 'Install-CISPackage', 'Remove-CISPackage',
        'Test-CISServiceEnabled', 'Test-CISServiceActive', 'Enable-CISService', 'Disable-CISService', 'Set-CISServiceMasked',
        'Get-CISSysctlValue', 'Set-CISSysctlValue'
    )
    PrivateData       = @{
        PSData = @{
            Tags = @('CIS', 'Hardening', 'Compliance', 'Core')
        }
    }
}
