# CIS Debian Linux 13 Benchmark v1.0.0 - 5.3.3.1.3 (faillock y root), 5.3.3.2.3
# (complejidad, Manual) y 5.3.3.4 Configure pam_unix module. 6 controles.
# Fuente: cis_debian_13.md, paginas 608-660. RIESGO: ver Chapter5c-Pam.ps1.

$script:Debian13PamCommonFiles = 'common-password', 'common-auth', 'common-account', 'common-session', 'common-session-noninteractive'

# --- 5.3.3.1.3 faillock incluye a root (Level 2) ------------------------------------------------------------

function Get-Debian13FaillockRootState {
    $flagConf = @(Get-Debian13PamConfSettings -Conf faillock -Key 'even_deny_root')
    $rutConf = @(Get-Debian13PamConfSettings -Conf faillock -Key 'root_unlock_time')
    $pam = @(Get-Debian13PamEntries -Files 'common-auth' | Where-Object { $_.Module -eq 'pam_faillock.so' })
    $flagPam = @($pam | Where-Object { $null -ne (Get-Debian13PamArg -Args $_.Args -Key 'even_deny_root') })
    $rutPam = @($pam | ForEach-Object { Get-Debian13PamArg -Args $_.Args -Key 'root_unlock_time' } | Where-Object { $null -ne $_ } | ForEach-Object { [pscustomobject]@{ File = 'common-auth'; Value = $_ } })
    $ruts = @($rutConf) + @($rutPam)
    [pscustomobject]@{
        Flag = ($flagConf.Count + $flagPam.Count) -gt 0
        Good = @($ruts | Where-Object { $_.Value -match '^([6-9]\d|[1-9]\d{2,})$' }); Bad = @($ruts | Where-Object { $_.Value -notmatch '^([6-9]\d|[1-9]\d{2,})$' })
    }
}
function Test-CIS_Debian13_5_3_3_1_3 {
    $s = Get-Debian13FaillockRootState
    $ok = ($s.Flag -or $s.Good.Count) -and -not $s.Bad.Count
    New-CISResult -ControlId '5.3.3.1.3' -Title 'Ensure password failed attempts lockout includes root account' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'even_deny_root y/o root_unlock_time >= 60 (sin root_unlock_time menor a 60)' `
        -ActualValue "even_deny_root=$($s.Flag); root_unlock_time bueno=$($s.Good.Count); fuera de rango=$($s.Bad.Count)"
}
function Set-CIS_Debian13_5_3_3_1_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    # 1) comentar/quitar root_unlock_time < 60 (conf y perfiles); 2) even_deny_root en faillock.conf
    Set-Debian13PamRule -Rule @{ Id = '5.3.3.1.3'; Conf = 'faillock'; Key = 'root_unlock_time'; Ok = { param($v) $v -match '^([6-9]\d|[1-9]\d{2,})$' }; PamModule = 'pam_faillock.so'; PamFile = 'common-auth'; WriteFile = 'faillock.conf'; SetLine = $null }
    if (-not (Get-Debian13FaillockRootState).Flag) {
        Set-Debian13PamRule -Rule @{ Id = '5.3.3.1.3'; Conf = 'faillock'; Key = 'even_deny_root'; Ok = { param($v) $true }; PamModule = 'pam_faillock.so'; PamFile = 'common-auth'; WriteFile = 'faillock.conf'; SetLine = 'even_deny_root' }
    }
}

# --- 5.3.3.2.3 complejidad (Manual: politica del sitio) --------------------------------------------------------

function Test-CIS_Debian13_5_3_3_2_3 {
    New-CISResult -ControlId '5.3.3.2.3' -Title 'Ensure password complexity is configured' -Status 'ManualReviewRequired' `
        -Notes 'Revisar minclass/dcredit/ucredit/lcredit/ocredit en pwquality.conf[.d] (deben ser 0 o negativos, segun politica del sitio) y que no esten como argumentos de pam_pwquality.'
}
function Set-CIS_Debian13_5_3_3_2_3 { Write-Warning '5.3.3.2.3: sin remediacion automatizada -- definir minclass o los credits segun la politica del sitio (ver ejemplos del benchmark).' }

# --- 5.3.3.4 pam_unix ----------------------------------------------------------------------------------------------

function Get-Debian13PamUnixEntries {
    param([string[]]$Files = $script:Debian13PamCommonFiles)
    @(Get-Debian13PamEntries -Files $Files | Where-Object { $_.Module -eq 'pam_unix.so' })
}

function Test-CIS_Debian13_5_3_3_4_1 {
    $bad = @(Get-Debian13PamUnixEntries | Where-Object { $null -ne (Get-Debian13PamArg -Args $_.Args -Key 'nullok') })
    New-CISResult -ControlId '5.3.3.4.1' -Title 'Ensure pam_unix does not include nullok' -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'pam_unix sin nullok' `
        -ActualValue $(if ($bad.Count) { "nullok en: $((($bad | ForEach-Object File) | Select-Object -Unique) -join ', ')" } else { 'sin nullok' })
}
function Test-CIS_Debian13_5_3_3_4_2 {
    $bad = @(Get-Debian13PamUnixEntries | Where-Object { $_.Args -match '(^|\s)remember=\d+\b' })
    New-CISResult -ControlId '5.3.3.4.2' -Title 'Ensure pam_unix does not include remember' -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'pam_unix sin remember=N' `
        -ActualValue $(if ($bad.Count) { "remember en: $((($bad | ForEach-Object File) | Select-Object -Unique) -join ', ')" } else { 'sin remember' })
}
function Test-CIS_Debian13_5_3_3_4_3 {
    $pw = @(Get-Debian13PamUnixEntries -Files 'common-password' | Where-Object { $_.Type -eq 'password' })
    $weak = @($pw | Where-Object { $_.Args -notmatch '(^|\s)(sha512|yescrypt)(\s|$)' })
    New-CISResult -ControlId '5.3.3.4.3' -Title 'Ensure pam_unix includes a strong password hashing algorithm' -Status $(if ($pw.Count -and -not $weak.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'sha512 o yescrypt en todas las lineas password de pam_unix' -ActualValue "lineas=$($pw.Count); sin algoritmo fuerte=$($weak.Count)"
}
function Test-CIS_Debian13_5_3_3_4_4 {
    $pw = @(Get-Debian13PamUnixEntries -Files 'common-password' | Where-Object { $_.Type -eq 'password' })
    $bad = @($pw | Where-Object { $null -eq (Get-Debian13PamArg -Args $_.Args -Key 'use_authtok') })
    New-CISResult -ControlId '5.3.3.4.4' -Title 'Ensure pam_unix includes use_authtok' -Status $(if ($pw.Count -and -not $bad.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'use_authtok en todas las lineas password de pam_unix' -ActualValue "lineas=$($pw.Count); sin use_authtok=$($bad.Count)"
}

function Update-Debian13PamUnixProfiles {
    <#
        Edita los perfiles de /usr/share/pam-configs que llevan pam_unix.so. -RemoveRegex quita ese patron (con su espacio previo) de
        toda linea pam_unix; -AddPasswordArg agrega el argumento a las lineas pam_unix de las subsecciones Password/Password-Initial
        que no tengan ninguno de -Unless (regex). Devuelve la cantidad de archivos modificados.
    #>
    param([string]$RemoveRegex, [string]$AddPasswordArg, [string]$Unless)
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'; $n = 0
    foreach ($p in @(Get-ChildItem $script:Debian13PamConfigsDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.bak_' })) {
        $lines = @(Get-Content $p.FullName); if (-not ($lines -match 'pam_unix\.so')) { continue }
        $sub = ''; $changed = $false
        $new = foreach ($l in $lines) {
            if ($l -match '^(Auth|Account|Session|Password)(-Initial)?:\s*$') { $sub = $Matches[0].Trim(); $l; continue }
            if ($l -match '^\S' ) { if ($l -match '^\w+-Type:') { $sub = '' }; $l; continue }
            if ($l -match 'pam_unix\.so') {
                $x = $l
                if ($RemoveRegex) { $x = $x -replace "\s+($RemoveRegex)(?=\s|$)", '' }
                if ($AddPasswordArg -and $sub -like 'Password*' -and $x -notmatch $Unless) { $x = ($x.TrimEnd() + " $AddPasswordArg") }
                if ($x -ne $l) { $changed = $true }
                $x
            } else { $l }
        }
        if ($changed) { Copy-Item $p.FullName "$($p.FullName).bak_$stamp"; Set-Content -Path $p.FullName -Value $new; $n++ }
    }
    $n
}
function Set-Debian13PamUnix {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$What, [string]$RemoveRegex, [string]$AddPasswordArg, [string]$Unless)
    if (-not $PSCmdlet.ShouldProcess($script:Debian13PamConfigsDir, "$What (perfiles pam_unix + pam-auth-update --package)")) { return }
    if ((Update-Debian13PamUnixProfiles -RemoveRegex $RemoveRegex -AddPasswordArg $AddPasswordArg -Unless $Unless) -gt 0) { Invoke-Debian13PamAuthUpdateSafe -Arguments '--package' }
}
function Set-CIS_Debian13_5_3_3_4_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PamUnix -What '5.3.3.4.1 quitar nullok' -RemoveRegex 'nullok' }
function Set-CIS_Debian13_5_3_3_4_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PamUnix -What '5.3.3.4.2 quitar remember=N' -RemoveRegex 'remember=\d+' }
function Set-CIS_Debian13_5_3_3_4_3 { [CmdletBinding(SupportsShouldProcess)] param([ValidateSet('yescrypt', 'sha512')][string]$Algorithm = 'yescrypt') Set-Debian13PamUnix -What "5.3.3.4.3 agregar $Algorithm" -AddPasswordArg $Algorithm -Unless '(^|\s)(sha512|yescrypt)(\s|$)' }
function Set-CIS_Debian13_5_3_3_4_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PamUnix -What '5.3.3.4.4 agregar use_authtok' -AddPasswordArg 'use_authtok' -Unless '(^|\s)use_authtok(\s|$)' }
