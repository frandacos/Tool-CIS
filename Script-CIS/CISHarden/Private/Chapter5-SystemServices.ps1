# CIS Microsoft Windows Server 2025 Benchmark v2.0.0 - Capitulo 5
# System Services (2 controles). Fuente: cis2025.md paginas 325-328.
# Via Get-Service/Set-Service (StartupType), no registro directo -- es el
# mecanismo nativo y soportado para servicios de Windows.

function Test-CIS_5_1 {
    if ((Get-CISServerRole) -ne 'DC') {
        return New-CISResult -ControlId '5.1' -Title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)" -Status 'NotApplicable' -Notes 'Control (DC only); este equipo no es DC.'
    }
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $actual = if ($svc) { $svc.StartType } else { $null }
    $status = if ($actual -eq 'Disabled') { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '5.1' -Title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (DC only)" -Status $status -ExpectedValue 'Disabled' -ActualValue $actual
}
function Set-CIS_5_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ((Get-CISServerRole) -ne 'DC') { Write-Warning '5.1 es (DC only).'; return }
    if ($PSCmdlet.ShouldProcess('Spooler', 'Stop y deshabilitar servicio')) {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    }
}

function Test-CIS_5_2 {
    if ((Get-CISServerRole) -ne 'MS') {
        return New-CISResult -ControlId '5.2' -Title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)" -Status 'NotApplicable' -Notes 'Control (MS only); este equipo no es MS.'
    }
    $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
    $actual = if ($svc) { $svc.StartType } else { $null }
    $status = if ($actual -eq 'Disabled') { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '5.2' -Title "Ensure 'Print Spooler (Spooler)' is set to 'Disabled' (MS only)" -Status $status -ExpectedValue 'Disabled' -ActualValue $actual `
        -Notes 'Excepcion legitima: si este servidor es un servidor de impresion, no aplicar (revisar con el equipo antes de remediar).'
}
function Set-CIS_5_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ((Get-CISServerRole) -ne 'MS') { Write-Warning '5.2 es (MS only).'; return }
    if ($PSCmdlet.ShouldProcess('Spooler', 'Stop y deshabilitar servicio')) {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled
    }
}
