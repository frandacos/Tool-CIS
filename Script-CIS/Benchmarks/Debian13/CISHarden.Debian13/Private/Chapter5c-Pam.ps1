# CIS Debian Linux 13 Benchmark v1.0.0 - 5.3 Pluggable Authentication Modules
# (paquetes, modulos, argumentos). 25 controles. Fuente: cis_debian_13.md,
# paginas 590-660.
#
# RIESGO ALTO: una configuracion PAM incorrecta puede impedir TODOS los logins.
# Antes de cualquier `pam-auth-update` se respaldan /etc/pam.d/common-*; si el
# resultado no conserva pam_unix en common-auth se restauran y se lanza error.
# Aun asi: simular con -WhatIf y probar desde una SEGUNDA sesion (no cerrar la
# actual) antes de dar por bueno un cambio. Los ajustes de conf se centralizan en
# faillock.conf / pwquality.conf.d / pwhistory.conf (metodo preferido del
# benchmark) y se quitan los argumentos duplicados de los perfiles de
# /usr/share/pam-configs. Si se usan archivos PAM propios en /etc/pam.d hay que
# editarlos a mano (el benchmark lo advierte).

$script:Debian13PamDir = '/etc/pam.d'
$script:Debian13SecurityDir = '/etc/security'
$script:Debian13PamConfigsDir = '/usr/share/pam-configs'

# --- lectura ------------------------------------------------------------------------------------

function Get-Debian13PamEntries {
    # Entradas no comentadas de los archivos PAM dados (nombres bajo /etc/pam.d): @{File; Type; Control; Module; Args}
    param([Parameter(Mandatory)][string[]]$Files)
    foreach ($name in $Files) {
        $path = Join-Path $script:Debian13PamDir $name
        foreach ($l in @(Get-Content $path -ErrorAction SilentlyContinue)) {
            if ($l -match '^\s*-?(auth|account|password|session)\s+(\[[^\]]*\]|\S+)\s+(\S+)\s*(.*?)\s*(#.*)?$') {
                [pscustomobject]@{ File = $name; Type = $Matches[1]; Control = $Matches[2]; Module = $Matches[3]; Args = $Matches[4] }
            }
        }
    }
}
function Get-Debian13PamArg {
    # $null si <Key> no esta en Args; '' si es un flag sin valor; el valor si es key=value.
    param([string]$Args, [Parameter(Mandatory)][string]$Key)
    if ($Args -match "(^|\s)$([regex]::Escape($Key))(=(\S*))?(\s|$)") { if ($Matches[3]) { $Matches[3] } else { '' } }
}
function Get-Debian13PamConfFiles {
    param([Parameter(Mandatory)][ValidateSet('faillock', 'pwquality', 'pwhistory')][string]$Conf)
    $d = $script:Debian13SecurityDir
    $files = switch ($Conf) {
        'faillock' { , (Join-Path $d 'faillock.conf') }
        'pwhistory' { , (Join-Path $d 'pwhistory.conf') }
        'pwquality' { @(Join-Path $d 'pwquality.conf') + @(Get-ChildItem (Join-Path $d 'pwquality.conf.d') -Filter '*.conf' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object FullName) }
    }
    @($files | Where-Object { Test-Path $_ })
}
function Get-Debian13PamConfSettings {
    # Definiciones de <Key> (con valor "k = v" o flag) en los archivos de <Conf>: @{File; Value}
    param([Parameter(Mandatory)][string]$Conf, [Parameter(Mandatory)][string]$Key)
    foreach ($f in @(Get-Debian13PamConfFiles -Conf $Conf)) {
        foreach ($l in @(Get-Content $f -ErrorAction SilentlyContinue)) {
            if ($l -match "^\s*$([regex]::Escape($Key))\s*(=\s*(\S+))?\s*(#.*)?$") { [pscustomobject]@{ File = $f; Value = "$($Matches[2])" } }
        }
    }
}

# --- 5.3.1 paquetes -----------------------------------------------------------------------------

function Get-Debian13UpgradablePackages { @(& apt list --upgradable 2>&1) }
function Test-Debian13LatestPackage {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Package)
    $installed = @(Get-Debian13InstalledPackages -Patterns $Package).Count -gt 0
    $upgradable = @(Get-Debian13UpgradablePackages | Where-Object { $_ -match "^$([regex]::Escape($Package))\b" })
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($installed -and -not $upgradable.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "$Package instalado y en su ultima version" -ActualValue "instalado=$installed; actualizable=$($upgradable.Count -gt 0)" `
        -Notes 'Depende de la cache de apt: ejecutar "apt update" antes de auditar para un resultado confiable.'
}
function Set-Debian13LatestPackage {
    [CmdletBinding(SupportsShouldProcess)] param([Parameter(Mandatory)][string]$Package)
    if ($PSCmdlet.ShouldProcess($Package, 'apt-get install -y (ultima version)')) { & apt-get install -y $Package }
}
# El titulo de 5.3.1.1 dice "pam" pero el Audit/Remediation del benchmark verifican el paquete libpam-runtime.
function Test-CIS_Debian13_5_3_1_1 { Test-Debian13LatestPackage -ControlId '5.3.1.1' -Title 'Ensure latest version of pam is installed' -Package 'libpam-runtime' }
function Set-CIS_Debian13_5_3_1_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13LatestPackage -Package 'libpam-runtime' }
function Test-CIS_Debian13_5_3_1_2 { Test-Debian13LatestPackage -ControlId '5.3.1.2' -Title 'Ensure latest version of libpam-modules is installed' -Package 'libpam-modules' }
function Set-CIS_Debian13_5_3_1_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13LatestPackage -Package 'libpam-modules' }
function Test-CIS_Debian13_5_3_1_3 { Test-Debian13LatestPackage -ControlId '5.3.1.3' -Title 'Ensure latest version of libpam-pwquality is installed' -Package 'libpam-pwquality' }
function Set-CIS_Debian13_5_3_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13LatestPackage -Package 'libpam-pwquality' }

# --- pam-auth-update con red de seguridad ------------------------------------------------------------

function Invoke-Debian13PamAuthUpdate { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) & pam-auth-update @Arguments 2>&1 | Out-Null }

function Invoke-Debian13PamAuthUpdateSafe {
    <# Respalda /etc/pam.d/common-*, ejecuta pam-auth-update y verifica que common-auth conserve pam_unix; si no, restaura y lanza error. #>
    param([Parameter(Mandatory)][string[]]$Arguments)
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $files = @(Get-ChildItem $script:Debian13PamDir -Filter 'common-*' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '\.bak_' })
    foreach ($f in $files) { Copy-Item $f.FullName "$($f.FullName).bak_$stamp" }
    Invoke-Debian13PamAuthUpdate @Arguments
    if (-not (@(Get-Debian13PamEntries -Files 'common-auth' | Where-Object { $_.Module -eq 'pam_unix.so' }).Count)) {
        foreach ($f in $files) { Copy-Item "$($f.FullName).bak_$stamp" $f.FullName -Force }
        throw 'pam-auth-update dejo common-auth sin pam_unix.so: se restauraron los archivos /etc/pam.d/common-* originales.'
    }
}

# --- 5.3.2 modulos habilitados ----------------------------------------------------------------------------

function Test-CIS_Debian13_5_3_2_1 {
    $missing = @('common-account', 'common-auth', 'common-password', 'common-session', 'common-session-noninteractive' | Where-Object { -not @(Get-Debian13PamEntries -Files $_ | Where-Object { $_.Module -eq 'pam_unix.so' }).Count })
    New-CISResult -ControlId '5.3.2.1' -Title 'Ensure pam_unix module is enabled' -Status $(if ($missing.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'pam_unix.so en common-account/auth/password/session/session-noninteractive' -ActualValue $(if ($missing.Count) { "falta en: $($missing -join ', ')" } else { 'presente en los 5 archivos' })
}
function Set-CIS_Debian13_5_3_2_1 { [CmdletBinding(SupportsShouldProcess)] param() if ($PSCmdlet.ShouldProcess('pam-auth-update', '5.3.2.1 - --enable unix')) { Invoke-Debian13PamAuthUpdateSafe -Arguments '--enable', 'unix' } }

function Test-CIS_Debian13_5_3_2_2 {
    $auth = @(Get-Debian13PamEntries -Files 'common-auth' | Where-Object { $_.Module -eq 'pam_faillock.so' })
    $acct = @(Get-Debian13PamEntries -Files 'common-account' | Where-Object { $_.Module -eq 'pam_faillock.so' })
    $pre = [bool]($auth | Where-Object { $_.Args -match '\bpreauth\b' }); $fail = [bool]($auth | Where-Object { $_.Args -match '\bauthfail\b' })
    New-CISResult -ControlId '5.3.2.2' -Title 'Ensure pam_faillock module is enabled' -Status $(if ($pre -and $fail -and $acct.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'pam_faillock preauth y authfail en common-auth, y en common-account' -ActualValue "preauth=$pre; authfail=$fail; account=$($acct.Count -gt 0)"
}
function Write-Debian13PamProfile {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Lines)
    New-Item -ItemType Directory -Path $script:Debian13PamConfigsDir -Force | Out-Null
    Set-Content -Path (Join-Path $script:Debian13PamConfigsDir $Name) -Value $Lines
}
function Set-CIS_Debian13_5_3_2_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('pam-auth-update', '5.3.2.2 - perfiles faillock y faillock_notify')) { return }
    Write-Debian13PamProfile -Name 'faillock' -Lines 'Name: Enable pam_faillock to deny access', 'Default: yes', 'Priority: 0', 'Auth-Type: Primary', 'Auth:', '        [default=die]                   pam_faillock.so authfail'
    Write-Debian13PamProfile -Name 'faillock_notify' -Lines 'Name: Notify of failed login attempts and reset count upon success', 'Default: yes', 'Priority: 1024', 'Auth-Type: Primary', 'Auth:', '        requisite                       pam_faillock.so preauth', 'Account-Type: Primary', 'Account:', '        required                        pam_faillock.so'
    Invoke-Debian13PamAuthUpdateSafe -Arguments '--enable', 'faillock', 'faillock_notify'
}

function Test-CIS_Debian13_5_3_2_3 {
    $hit = @(Get-Debian13PamEntries -Files 'common-password' | Where-Object { $_.Module -eq 'pam_pwquality.so' })
    New-CISResult -ControlId '5.3.2.3' -Title 'Ensure pam_pwquality module is enabled' -Status $(if ($hit.Count) { 'Pass' } else { 'Fail' }) -ExpectedValue 'pam_pwquality.so en common-password' -ActualValue "$($hit.Count) linea(s)"
}
function Set-CIS_Debian13_5_3_2_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('pam-auth-update', '5.3.2.3 - perfil pwquality')) { return }
    if (-not (Test-Path (Join-Path $script:Debian13PamConfigsDir 'pwquality'))) {
        Write-Debian13PamProfile -Name 'pwquality' -Lines 'Name: Pwquality password strength checking', 'Default: yes', 'Priority: 1024', 'Conflicts: cracklib', 'Password-Type: Primary', 'Password:', '        requisite                       pam_pwquality.so retry=3'
    }
    Invoke-Debian13PamAuthUpdateSafe -Arguments '--enable', 'pwquality'
}

function Test-CIS_Debian13_5_3_2_4 {
    $hit = @(Get-Debian13PamEntries -Files 'common-password' | Where-Object { $_.Module -eq 'pam_pwhistory.so' })
    New-CISResult -ControlId '5.3.2.4' -Title 'Ensure pam_pwhistory module is enabled' -Status $(if ($hit.Count) { 'Pass' } else { 'Fail' }) -ExpectedValue 'pam_pwhistory.so en common-password' -ActualValue "$($hit.Count) linea(s)"
}
# Los parametros (remember/enforce_for_root/use_authtok) se dejan a pwhistory.conf (5.3.3.3.x), metodo preferido del benchmark.
function Set-CIS_Debian13_5_3_2_4 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('pam-auth-update', '5.3.2.4 - perfil pwhistory')) { return }
    if (-not (Test-Path (Join-Path $script:Debian13PamConfigsDir 'pwhistory'))) {
        Write-Debian13PamProfile -Name 'pwhistory' -Lines 'Name: pwhistory password history checking', 'Default: yes', 'Priority: 1024', 'Password-Type: Primary', 'Password:', '        requisite                       pam_pwhistory.so'
    }
    Invoke-Debian13PamAuthUpdateSafe -Arguments '--enable', 'pwhistory'
}
