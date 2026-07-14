function Invoke-CISRemediate {
    <#
    .SYNOPSIS
        Corre Set-CIS_* solo para los controles que la auditoria marco
        'Fail', con 4 niveles de alcance: un control puntual, una lista de
        controles ("grupo"), una subseccion, un capitulo completo, o los 454
        del benchmark entero. Nunca toca controles en 'Pass', 'NotApplicable'
        ni 'ManualReviewRequired'.

    .PARAMETER ControlId
        Remediar un unico control (ej. '1.1.4').

    .PARAMETER ControlIds
        Remediar una lista puntual de controles, sin importar el capitulo
        (ej. una tanda curada de "quick wins" de bajo riesgo elegida a mano).

    .PARAMETER Section
        Remediar una subseccion por prefijo de ID (ej. '2.2', '18.9').

    .PARAMETER Chapter
        Remediar todos los 'Fail' de un capitulo completo (ej. '18').

    .PARAMETER Level
        Filtra por perfil de riesgo: 'Level 1', 'Level 2' o
        'Next Generation Windows Security'. Sirve como alcance propio (ej.
        "remediar todo lo Level 1 en Fail de todo el benchmark") o
        combinado con -Chapter/-Section (ej. Chapter 18 + Level 1 = "lo de
        bajo riesgo de Administrative Templates"). Level 2 es justo el que
        conviene revisar a mano antes de remediar en masa: el benchmark
        mismo advierte que puede afectar funcionalidad.

    .PARAMETER All
        Remediar los 454 controles del benchmark de una. Hay que pasar este
        switch explicitamente -- es la unica forma de disparar una
        remediacion masiva; sin alcance (ni ControlId, ni ControlIds, ni
        Section, ni Chapter, ni All) la funcion tira error en vez de asumir
        "todo", justamente para que una corrida sin parametros no remedie
        454 controles por accidente.

    .PARAMETER Force
        Salta la confirmacion de lote ("vas a remediar N controles,
        seguro?"). Pensado para correrlo desatendido/programado. -WhatIf
        sigue funcionando igual con o sin -Force.

    .PARAMETER LogPath
        Exporta el detalle de la remediacion (que se remedio y confirmo en
        Pass, que sigue en Fail, que fallo con error, que no tiene Set-CIS_*
        todavia) a un CSV, ademas de mostrarlo en pantalla.

    .EXAMPLE
        Invoke-CISRemediate -ControlId '1.1.4' -WhatIf

    .EXAMPLE
        Invoke-CISRemediate -ControlIds '1.1.4','2.3.17.6','9.1.1' -WhatIf

    .EXAMPLE
        Invoke-CISRemediate -Section '18.9' -LogPath .\remediacion_18_9.csv

    .EXAMPLE
        Invoke-CISRemediate -Chapter 2

    .EXAMPLE
        Invoke-CISRemediate -All -Force -LogPath .\remediacion_full.csv
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [string]$ControlId,
        [string[]]$ControlIds,
        [string]$Section,
        [string]$Chapter,
        [ValidateSet('Level 1', 'Level 2', 'Next Generation Windows Security')][string]$Level,
        [switch]$All,
        [switch]$Force,
        [string]$LogPath
    )

    if (-not $ControlId -and -not $ControlIds -and -not $Section -and -not $Chapter -and -not $Level -and -not $All) {
        throw "Especifica un alcance: -ControlId, -ControlIds, -Section, -Chapter, -Level, o -All (para remediar los 454). " +
              "Sin alcance no se ejecuta nada -- es a proposito, para que nunca se dispare una remediacion masiva sin querer."
    }

    $auditParams = @{}
    if ($Chapter) { $auditParams.Chapter = $Chapter }
    if ($Section) { $auditParams.Section = $Section }
    if ($ControlId) { $auditParams.ControlId = $ControlId }
    if ($ControlIds) { $auditParams.ControlIds = $ControlIds }
    if ($Level) { $auditParams.Level = $Level }

    $scopeDescription =
        if ($All) { 'los 454 controles del benchmark' }
        elseif ($Chapter) { "el capitulo $Chapter" }
        elseif ($Section) { "la seccion $Section" }
        elseif ($ControlIds) { "$($ControlIds.Count) controles puntuales ($($ControlIds -join ', '))" }
        elseif ($ControlId) { "el control $ControlId" }
        else { "los controles $Level" }
    if ($Level -and ($Chapter -or $Section)) { $scopeDescription += " (perfil $Level)" }

    Write-Host "Auditando $scopeDescription para ver que esta en Fail..." -ForegroundColor Cyan
    $current = Invoke-CISAudit @auditParams
    $toFix = @($current | Where-Object { $_.Status -eq 'Fail' })

    if (-not $toFix.Count) {
        Write-Host "Nada para remediar en $scopeDescription: no hay controles en Fail." -ForegroundColor Green
        return
    }

    Write-Host "$($toFix.Count) controles en Fail dentro de $scopeDescription." -ForegroundColor Yellow

    # Compuerta de confirmacion a nivel de lote (una sola vez, no por
    # control). En modo -WhatIf no hace falta: cada Set-CIS_* va a mostrar
    # su propio "What if" especifico via ShouldProcess heredado del motor
    # (RegistryEngine/UserRightsEngine/AuditPolicyEngine), que es mas
    # informativo que un mensaje generico de lote.
    if (-not $Force -and -not $WhatIfPreference) {
        if (-not $PSCmdlet.ShouldProcess($scopeDescription, "Remediar $($toFix.Count) controles en Fail")) {
            Write-Host 'Cancelado.' -ForegroundColor Yellow
            return
        }
    }

    $summary = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($item in $toFix) {
        $i++
        Write-Progress -Activity 'Remediando controles CIS' -Status "$($item.ControlId) ($i/$($toFix.Count))" `
            -PercentComplete (($i / $toFix.Count) * 100)

        $suffix = ConvertTo-CISFunctionSuffix -ControlId $item.ControlId
        $fn = "Set-CIS_$suffix"

        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            Write-Warning "No existe $fn todavia para remediar $($item.ControlId); saltea."
            $summary.Add([pscustomobject]@{
                ControlId = $item.ControlId; Title = $item.Title
                Action    = 'SkippedNoFunction'; Detail = ''; PostStatus = ''
            })
            continue
        }

        try {
            # Sin pasar -WhatIf/-Confirm explicito: muchos Set-CIS_* son
            # wrappers simples sin [CmdletBinding(SupportsShouldProcess)]
            # propio (delegan en el motor), asi que no todos aceptan esos
            # parametros directamente. $WhatIfPreference/$ConfirmPreference
            # ya estan seteados en el scope de esta funcion (por
            # SupportsShouldProcess de Invoke-CISRemediate) y PowerShell los
            # propaga automaticamente hacia abajo en la cadena de llamadas
            # -- es el mecanismo estandar, no hace falta reenviarlos a mano.
            & $fn
            $action = if ($WhatIfPreference) { 'WhatIf' } else { 'Remediated' }
            $summary.Add([pscustomobject]@{
                ControlId = $item.ControlId; Title = $item.Title
                Action    = $action; Detail = ''; PostStatus = ''
            })
        }
        catch {
            Write-Warning "Fallo remediando $($item.ControlId): $($_.Exception.Message)"
            $summary.Add([pscustomobject]@{
                ControlId = $item.ControlId; Title = $item.Title
                Action    = 'Failed'; Detail = $_.Exception.Message; PostStatus = ''
            })
        }
    }
    Write-Progress -Activity 'Remediando controles CIS' -Completed

    if (-not $WhatIfPreference) {
        Write-Host 'Re-auditando los controles remediados...' -ForegroundColor Cyan
        $reaudit = Invoke-CISAudit @auditParams
        $reauditMap = @{}
        foreach ($r in $reaudit) { $reauditMap[$r.ControlId] = $r.Status }
        foreach ($s in $summary) {
            if ($s.Action -eq 'Remediated') {
                $s.PostStatus = $reauditMap[$s.ControlId]
            }
        }
    }

    $confirmedPass = @($summary | Where-Object { $_.Action -eq 'Remediated' -and $_.PostStatus -eq 'Pass' }).Count
    $stillNotPass = @($summary | Where-Object { $_.Action -eq 'Remediated' -and $_.PostStatus -ne 'Pass' }).Count
    $failedCount = @($summary | Where-Object { $_.Action -eq 'Failed' }).Count
    $skippedCount = @($summary | Where-Object { $_.Action -eq 'SkippedNoFunction' }).Count

    if (-not $WhatIfPreference) {
        Write-Host ("Resumen: {0} remediados y confirmados en Pass, {1} remediados pero sin confirmar Pass, " +
            "{2} con error, {3} sin Set-CIS_* todavia." -f $confirmedPass, $stillNotPass, $failedCount, $skippedCount) `
            -ForegroundColor Cyan
        if ($stillNotPass -gt 0) {
            Write-Warning "Revisar a mano: $stillNotPass controles se remediaron pero la re-auditoria no los confirmo en Pass."
        }
    }

    if ($LogPath) {
        $summary | Export-Csv -Path $LogPath -NoTypeInformation -Encoding UTF8
        Write-Host "Log de remediacion exportado a $LogPath" -ForegroundColor Green
    }

    return $summary
}
