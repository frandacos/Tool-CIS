function Invoke-CISRemediate {
    <#
    .SYNOPSIS
        Corre Set-CIS_* solo para los controles que Invoke-CISAudit marco
        como 'Fail'. Nunca toca controles en 'ManualReviewRequired',
        'NotApplicable' o ya en 'Pass'.

    .PARAMETER ControlId
        Remediar un unico control.

    .PARAMETER Chapter
        Remediar todos los 'Fail' de un capitulo.

    .PARAMETER WhatIf
        Heredado de SupportsShouldProcess: cada Set-CIS_* individual respeta
        -WhatIf/-Confirm, no se aplica nada realmente.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Chapter,
        [string]$ControlId
    )

    $auditParams = @{}
    if ($Chapter) { $auditParams.Chapter = $Chapter }
    if ($ControlId) { $auditParams.ControlId = $ControlId }

    $current = Invoke-CISAudit @auditParams
    $toFix = $current | Where-Object { $_.Status -eq 'Fail' }

    if (-not $toFix) {
        Write-Host 'Nada para remediar: no hay controles en estado Fail en este alcance.' -ForegroundColor Green
        return
    }

    foreach ($item in $toFix) {
        $suffix = ConvertTo-CISFunctionSuffix -ControlId $item.ControlId
        $fn = "Set-CIS_$suffix"
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Write-Warning "No existe $fn todavia para remediar $($item.ControlId); saltea (implementalo antes de cerrar la etapa)."
            continue
        }
        if ($PSCmdlet.ShouldProcess($item.ControlId, "Remediar via $fn")) {
            & $fn
        }
    }

    Write-Host 'Re-auditando controles remediados...' -ForegroundColor Cyan
    Invoke-CISAudit @auditParams
}
