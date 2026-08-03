$here = $PSScriptRoot

Get-ChildItem -Path (Join-Path $here 'Public') -Filter '*.ps1' -Recurse | ForEach-Object {
    . $_.FullName
}

Export-ModuleMember -Function @(
    # Orquestacion (uso normal desde la consola)
    'Invoke-CISAudit',
    'Invoke-CISRemediate',
    'Get-CISBenchmarks',
    # Motores genericos de Windows -- API publica para que los modulos de
    # benchmark (CISHarden.<Tag>) los consuman. No estan pensados para uso
    # interactivo directo, pero deben exportarse porque viven en un modulo
    # distinto al de las funciones Test-CIS_*/Set-CIS_* que los invocan.
    'Get-CISServerRole',
    'New-CISResult',
    'Get-CISSecurityPolicy',
    'Backup-CISSecurityPolicy',
    'Set-CISSecurityPolicyValue',
    'Get-CISAuditSubcategorySetting',
    'Set-CISAuditSubcategorySetting',
    'Test-CISAuditPolicy',
    'Set-CISAuditPolicyForMode',
    'Get-CISPrivilegeRights',
    'Resolve-CISPrincipalToSid',
    'Test-CISUserRight',
    'Set-CISUserRight',
    'Test-CISRegistryValue',
    'Set-CISRegistryValue',
    'Remove-CISRegistryValue',
    'New-CISValidatorMinValue',
    'New-CISValidatorMaxValueNotZero',
    'New-CISValidatorRange',
    'New-CISValidatorExact',
    'New-CISValidatorOneOf',
    'New-CISValidatorNonEmptyString',
    'New-CISValidatorNotEqualCaseInsensitive',
    'New-CISValidatorNotConfigured',
    'New-CISValidatorBitmaskAll',
    'New-CISValidatorMultiStringContainsAll',
    'New-CISValidatorMultiStringEmpty'
)
