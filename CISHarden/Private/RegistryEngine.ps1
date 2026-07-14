# Motor compartido para los controles de 2.3 Security Options que se
# resuelven via un valor de registro puntual (la gran mayoria). Los que en
# realidad viven en [System Access] de secedit (Guest account status, Rename
# administrator/guest account, Allow server operators to schedule tasks,
# Refuse machine account password changes, Allow anonymous SID/Name
# translation) reutilizan Get-CISSecurityPolicy/Set-CISSecurityPolicyValue de
# Helpers.ps1 (ya probado contra un DC real en el Capitulo 1), no este motor.

function Test-CISRegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Validator,
        [Parameter(Mandatory)][string]$ExpectedValue,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )

    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'NotApplicable' `
            -Notes "Control marcado ($Scope only) en el benchmark; este equipo no es $Scope."
    }

    $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    $actual = if ($null -ne $prop) { $prop.$Name } else { $null }

    $ok = & $Validator $actual
    $status = if ($ok) { 'Pass' } else { 'Fail' }
    $actualDisplay = if ($null -eq $actual) { '' } elseif ($actual -is [array]) { $actual -join ', ' } else { $actual }

    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue $ExpectedValue -ActualValue $actualDisplay
}

function Set-CISRegistryValue {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('DWord', 'String', 'MultiString')][string]$Type,
        [Parameter(Mandatory)]$Value,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )

    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        Write-Warning "$Path\$Name es ($Scope only): no se aplica en este equipo."
        return
    }

    if ($PSCmdlet.ShouldProcess("$Path\$Name", "Set to $Value")) {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }

        # Backup de la clave completa antes de tocar nada (no solo del valor).
        $backupDir = Join-Path $PSScriptRoot '..\Reports\backups'
        if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
        $regPath = $Path -replace '^(HKLM|HKCU|HKCR|HKU|HKCC):\\', '$1\'
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $safeName = ($regPath -replace '[\\:]', '_')
        $backupFile = Join-Path $backupDir "reg_${safeName}_$stamp.reg"
        reg export $regPath $backupFile /y 2>$null | Out-Null

        New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
    }
}

function Remove-CISRegistryValue {
    <# Para controles cuyo estado deseado es 'Not Configured' (la clave no debe existir). #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [ValidateSet('DC', 'MS', 'All')][string]$Scope = 'All'
    )

    if ($Scope -ne 'All' -and (Get-CISServerRole) -ne $Scope) {
        Write-Warning "$Path\$Name es ($Scope only): no se aplica en este equipo."
        return
    }

    if ($PSCmdlet.ShouldProcess("$Path\$Name", 'Remove value')) {
        $backupDir = Join-Path $PSScriptRoot '..\Reports\backups'
        if (-not (Test-Path $backupDir)) { New-Item -Path $backupDir -ItemType Directory -Force | Out-Null }
        $regPath = $Path -replace '^(HKLM|HKCU|HKCR|HKU|HKCC):\\', '$1\'
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $safeName = ($regPath -replace '[\\:]', '_')
        $backupFile = Join-Path $backupDir "reg_${safeName}_$stamp.reg"
        reg export $regPath $backupFile /y 2>$null | Out-Null

        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    }
}

# --- Validadores reutilizables --------------------------------------------

function New-CISValidatorMinValue([int]$Min) { { param($v) $null -ne $v -and [int]$v -ge $Min }.GetNewClosure() }
function New-CISValidatorMaxValueNotZero([int]$Max) { { param($v) $null -ne $v -and [int]$v -gt 0 -and [int]$v -le $Max }.GetNewClosure() }
function New-CISValidatorRange([int]$Min, [int]$Max) { { param($v) $null -ne $v -and [int]$v -ge $Min -and [int]$v -le $Max }.GetNewClosure() }
function New-CISValidatorExact($Expected) { { param($v) $null -ne $v -and "$v" -eq "$Expected" }.GetNewClosure() }
function New-CISValidatorOneOf([array]$Allowed) { { param($v) $null -ne $v -and ("$v" -in ($Allowed | ForEach-Object { "$_" })) }.GetNewClosure() }
function New-CISValidatorNonEmptyString { { param($v) -not [string]::IsNullOrWhiteSpace($v) } }
function New-CISValidatorNotEqualCaseInsensitive([string]$Forbidden) { { param($v) $null -ne $v -and $v.ToString().ToLowerInvariant() -ne $Forbidden.ToLowerInvariant() }.GetNewClosure() }
function New-CISValidatorNotConfigured { { param($v) $null -eq $v } }
function New-CISValidatorBitmaskAll([long]$Mask) { { param($v) $null -ne $v -and ([long]$v -band $Mask) -eq $Mask }.GetNewClosure() }
function New-CISValidatorMultiStringContainsAll([string[]]$Required) {
    {
        param($v)
        if ($null -eq $v) { return $Required.Count -eq 0 }
        $set = @($v)
        foreach ($r in $Required) { if ($r -notin $set) { return $false } }
        return $true
    }.GetNewClosure()
}
function New-CISValidatorMultiStringEmpty { { param($v) $null -eq $v -or @($v).Count -eq 0 } }
