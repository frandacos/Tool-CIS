# Motor compartido para los 34 controles del Capitulo 17 (Advanced Audit
# Policy Configuration). Todos via auditpol.exe, que es el mecanismo oficial
# (y el unico soportado) para leer/escribir subcategorias de auditoria
# avanzada -- el propio benchmark remite a "Advanced Audit Policy
# Configuration" en vez de a secedit para estas 9 categorias.

function Get-CISAuditSubcategorySetting {
    <#
        Devuelve el string tal cual lo informa auditpol ("Success and
        Failure", "Success", "Failure", "No Auditing") para una subcategoria,
        parseando la salida /r (CSV) en vez de la salida de texto libre.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Subcategory)

    $raw = auditpol /get /subcategory:"$Subcategory" /r 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "auditpol /get /subcategory:`"$Subcategory`" fallo (exit $LASTEXITCODE): $raw"
    }

    $rows = $raw | ConvertFrom-Csv
    if (-not $rows -or -not $rows[0].'Inclusion Setting') {
        throw "No se pudo parsear la salida de auditpol para la subcategoria '$Subcategory'."
    }

    return $rows[0].'Inclusion Setting'
}

function Set-CISAuditSubcategorySetting {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Subcategory,
        [bool]$Success,
        [bool]$Failure
    )

    $successFlag = if ($Success) { 'enable' } else { 'disable' }
    $failureFlag = if ($Failure) { 'enable' } else { 'disable' }

    if ($PSCmdlet.ShouldProcess($Subcategory, "success:$successFlag failure:$failureFlag")) {
        $backupDir = Join-Path $PSScriptRoot '..\Reports\backups'
        if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $backupFile = Join-Path $backupDir "auditpol_backup_$stamp.csv"
        auditpol /backup /file:$backupFile 2>&1 | Out-Null

        $null = auditpol /set /subcategory:"$Subcategory" /success:$successFlag /failure:$failureFlag 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "auditpol /set /subcategory:`"$Subcategory`" fallo (exit $LASTEXITCODE)."
        }
    }
}

function Test-CISAuditPolicy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Subcategory,
        [Parameter(Mandatory)][ValidateSet('SuccessAndFailure', 'IncludeSuccess', 'IncludeFailure', 'SuccessOnly')][string]$Mode,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )

    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'NotApplicable' `
            -Notes "Control marcado ($Scope only) en el benchmark; este equipo no es $Scope."
    }

    $actual = Get-CISAuditSubcategorySetting -Subcategory $Subcategory

    $ok = switch ($Mode) {
        'SuccessAndFailure' { $actual -eq 'Success and Failure' }
        'SuccessOnly' { $actual -eq 'Success' }
        'IncludeSuccess' { $actual -in @('Success', 'Success and Failure') }
        'IncludeFailure' { $actual -in @('Failure', 'Success and Failure') }
    }

    $expectedDisplay = switch ($Mode) {
        'SuccessAndFailure' { 'Success and Failure' }
        'SuccessOnly' { 'Success' }
        'IncludeSuccess' { 'Incluye Success (Success o Success and Failure)' }
        'IncludeFailure' { 'Incluye Failure (Failure o Success and Failure)' }
    }

    $status = if ($ok) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status -ExpectedValue $expectedDisplay -ActualValue $actual
}

function Set-CISAuditPolicyForMode {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Subcategory,
        [Parameter(Mandatory)][ValidateSet('SuccessAndFailure', 'IncludeSuccess', 'IncludeFailure', 'SuccessOnly')][string]$Mode,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )

    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        Write-Warning "$Subcategory es ($Scope only): no se aplica en este equipo."
        return
    }

    # Para los modos "Include*" alcanza con habilitar el flag pedido; no se
    # apaga el otro flag si ya estaba prendido (no se reduce auditoria
    # existente por accidente al remediar un requisito minimo).
    $current = Get-CISAuditSubcategorySetting -Subcategory $Subcategory
    $currentSuccess = $current -in @('Success', 'Success and Failure')
    $currentFailure = $current -in @('Failure', 'Success and Failure')

    switch ($Mode) {
        'SuccessAndFailure' { Set-CISAuditSubcategorySetting -Subcategory $Subcategory -Success $true -Failure $true }
        'SuccessOnly' { Set-CISAuditSubcategorySetting -Subcategory $Subcategory -Success $true -Failure $false }
        'IncludeSuccess' { Set-CISAuditSubcategorySetting -Subcategory $Subcategory -Success $true -Failure $currentFailure }
        'IncludeFailure' { Set-CISAuditSubcategorySetting -Subcategory $Subcategory -Success $currentSuccess -Failure $true }
    }
}
