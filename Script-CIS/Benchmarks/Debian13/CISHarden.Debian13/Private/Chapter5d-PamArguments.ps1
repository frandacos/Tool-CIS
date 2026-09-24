# CIS Debian Linux 13 Benchmark v1.0.0 - 5.3.3 Configure PAM Arguments
# (pam_faillock, pam_pwquality, pam_pwhistory, pam_unix). 18 controles.
# Fuente: cis_debian_13.md, paginas 608-660. Ver advertencias de RIESGO en
# Chapter5c-Pam.ps1 (helpers y pam-auth-update con restauracion automatica).
#
# Regla de auditoria (comun a 5.3.3.1-5.3.3.3): el valor se evalua en el archivo de
# configuracion (faillock.conf / pwquality.conf[.d] / pwhistory.conf) Y como
# argumento del modulo en /etc/pam.d/common-*. Cumple si ninguna definicion
# esta fuera de rango y, si la opcion es obligatoria, hay al menos una valida.

function Get-Debian13PamRuleState {
    param([Parameter(Mandatory)][hashtable]$Rule)
    $ok = $Rule.Ok
    $conf = @(Get-Debian13PamConfSettings -Conf $Rule.Conf -Key $Rule.Key)
    $pam = @(Get-Debian13PamEntries -Files $Rule.PamFile | Where-Object { $_.Module -eq $Rule.PamModule } |
            ForEach-Object { $v = Get-Debian13PamArg -Args $_.Args -Key $Rule.Key; if ($null -ne $v) { [pscustomobject]@{ File = $_.File; Value = $v } } })
    [pscustomobject]@{
        Conf = $conf; Pam = $pam
        BadConf = @($conf | Where-Object { -not (& $ok $_.Value) }); GoodConf = @($conf | Where-Object { & $ok $_.Value })
        BadPam = @($pam | Where-Object { -not (& $ok $_.Value) }); GoodPam = @($pam | Where-Object { & $ok $_.Value })
    }
}

function Test-Debian13PamRule {
    param([Parameter(Mandatory)][hashtable]$Rule)
    $s = Get-Debian13PamRuleState -Rule $Rule
    $problems = @()
    foreach ($b in $s.BadConf) { $problems += "$($b.File): $($Rule.Key)=$($b.Value)" }
    foreach ($b in $s.BadPam) { $problems += "/etc/pam.d/$($b.File): argumento $($Rule.Key)=$($b.Value)" }
    if ($Rule.Required -and -not ($s.GoodConf.Count -or $s.GoodPam.Count)) { $problems += "$($Rule.Key) no esta configurado" }
    if ($Rule.Exclusive -and $s.GoodConf.Count -and $s.GoodPam.Count) { $problems += "$($Rule.Key) configurado en el archivo conf Y como argumento PAM (usar un solo metodo)" }
    New-CISResult -ControlId $Rule.Id -Title $Rule.Title -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue $Rule.Expected `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { $(if ($s.GoodConf.Count) { "$($Rule.Key) = $($s.GoodConf[-1].Value) ($($s.GoodConf[-1].File))" } elseif ($s.GoodPam.Count) { "$($Rule.Key) = $($s.GoodPam[-1].Value) (argumento PAM)" } else { "$($Rule.Key) no definido (valor por defecto)" }) })
}

function Get-Debian13PamProfilesWithArg {
    # Perfiles de /usr/share/pam-configs cuya linea del modulo lleva el argumento <Key>.
    param([string]$Module, [string]$Key)
    @(Get-ChildItem $script:Debian13PamConfigsDir -File -ErrorAction SilentlyContinue | Where-Object {
            Select-String -Path $_.FullName -Pattern "\b$([regex]::Escape($Module))\s+([^#\r\n]+\s+)?$([regex]::Escape($Key))\b" -Quiet } | ForEach-Object FullName)
}

function Set-Debian13PamRule {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][hashtable]$Rule)
    if (-not $PSCmdlet.ShouldProcess("$($Rule.Conf) / $($Rule.PamModule)", "$($Rule.Id) - $($Rule.Key)")) { return }
    $key = [regex]::Escape($Rule.Key)
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $writeFile = Join-Path $script:Debian13SecurityDir $Rule.WriteFile
    $ok = $Rule.Ok

    # 1) archivos conf: comentar definiciones fuera de rango; para pwquality, tambien las del archivo principal
    #    (segun el benchmark precede a los .d) para dejar UN solo lugar.
    foreach ($f in @(Get-Debian13PamConfFiles -Conf $Rule.Conf)) {
        $isMain = ($Rule.Conf -eq 'pwquality') -and ((Split-Path $f -Leaf) -eq 'pwquality.conf')
        $changed = $false
        $new = foreach ($l in @(Get-Content $f)) {
            if ($l -match "^\s*$key\s*(=\s*(\S+))?\s*(#.*)?$" -and ((-not (& $ok "$($Matches[2])")) -or ($isMain -and $Rule.SetLine))) { $changed = $true; "# $l" } else { $l }
        }
        if ($changed) { Copy-Item $f "$f.bak_$stamp"; Set-Content -Path $f -Value $new }
    }
    # 2) escribir el valor del benchmark si la regla lo define
    if ($Rule.SetLine) {
        New-Item -ItemType Directory -Path (Split-Path $writeFile) -Force | Out-Null
        if ($Rule.WriteFile -like 'pwquality.conf.d/*') {
            # archivo dedicado del benchmark (50-pw<x>.conf): se reemplaza su contenido
            if (Test-Path $writeFile) { Copy-Item $writeFile "$writeFile.bak_$stamp" }
            Set-Content -Path $writeFile -Value @('', $Rule.SetLine)
        }
        elseif (-not @(Get-Debian13PamConfSettings -Conf $Rule.Conf -Key $Rule.Key | Where-Object { & $ok $_.Value }).Count) {
            # archivo compartido (faillock.conf / pwhistory.conf): solo se agrega la linea si no hay ya una valida
            if (Test-Path $writeFile) { Copy-Item $writeFile "$writeFile.bak_$stamp" }
            Add-Content -Path $writeFile -Value @('', $Rule.SetLine)
        }
    }
    # 3) quitar el argumento duplicado de los perfiles de pam-auth-update
    $profiles = @(Get-Debian13PamProfilesWithArg -Module $Rule.PamModule -Key $Rule.Key)
    foreach ($p in $profiles) {
        Copy-Item $p "$p.bak_$stamp"
        (Get-Content $p) | ForEach-Object { if ($_ -match "\b$([regex]::Escape($Rule.PamModule))\b") { $_ -replace "\s+$key(=\S+)?", '' } else { $_ } } | Set-Content $p
    }
    if ($profiles.Count) { Invoke-Debian13PamAuthUpdateSafe -Arguments '--package' }
}

# --- reglas -----------------------------------------------------------------------------------------------------

$script:Debian13PamRules = [ordered]@{
    '5.3.3.1.1' = @{ Title = 'Ensure password failed attempts lockout is configured'; Conf = 'faillock'; Key = 'deny'; Required = $true; Ok = { param($v) $v -match '^[1-5]$' }
        PamFile = 'common-auth'; PamModule = 'pam_faillock.so'; WriteFile = 'faillock.conf'; SetLine = 'deny = 5'; Expected = 'deny entre 1 y 5 en faillock.conf (y sin deny fuera de rango como argumento PAM)' }
    '5.3.3.1.2' = @{ Title = 'Ensure password unlock time is configured'; Conf = 'faillock'; Key = 'unlock_time'; Required = $true; Ok = { param($v) $v -match '^(0|9\d\d|[1-9]\d{3,})$' }
        PamFile = 'common-auth'; PamModule = 'pam_faillock.so'; WriteFile = 'faillock.conf'; SetLine = 'unlock_time = 900'; Expected = 'unlock_time 0 (nunca) o >= 900 segundos' }
    '5.3.3.2.1' = @{ Title = 'Ensure password number of changed characters is configured'; Conf = 'pwquality'; Key = 'difok'; Required = $true; Ok = { param($v) $v -match '^([2-9]|[1-9]\d+)$' }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwdifok.conf'; SetLine = 'difok = 2'; Expected = 'difok >= 2' }
    '5.3.3.2.2' = @{ Title = 'Ensure password length is configured'; Conf = 'pwquality'; Key = 'minlen'; Required = $true; Ok = { param($v) $v -match '^(1[4-9]|[2-9]\d|[1-9]\d{2,})$' }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwlength.conf'; SetLine = 'minlen = 14'; Expected = 'minlen >= 14' }
    '5.3.3.2.4' = @{ Title = 'Ensure password same consecutive characters is configured'; Conf = 'pwquality'; Key = 'maxrepeat'; Required = $true; Ok = { param($v) $v -match '^[1-3]$' }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwrepeat.conf'; SetLine = 'maxrepeat = 3'; Expected = 'maxrepeat entre 1 y 3 (no 0)' }
    '5.3.3.2.5' = @{ Title = 'Ensure password maximum sequential characters is configured'; Conf = 'pwquality'; Key = 'maxsequence'; Required = $true; Ok = { param($v) $v -match '^[1-3]$' }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwmaxsequence.conf'; SetLine = 'maxsequence = 3'; Expected = 'maxsequence entre 1 y 3 (no 0)' }
    '5.3.3.2.6' = @{ Title = 'Ensure password dictionary check is enabled'; Conf = 'pwquality'; Key = 'dictcheck'; Required = $false; Ok = { param($v) $v -ne '0' }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwdictcheck.conf'; SetLine = $null; Expected = 'dictcheck distinto de 0 (por defecto habilitado)' }
    '5.3.3.2.7' = @{ Title = 'Ensure password quality checking is enforced'; Conf = 'pwquality'; Key = 'enforcing'; Required = $false; Ok = { param($v) $v -ne '0' }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwenforcing.conf'; SetLine = $null; Expected = 'enforcing distinto de 0 (por defecto habilitado)' }
    '5.3.3.2.8' = @{ Title = 'Ensure password quality is enforced for the root user'; Conf = 'pwquality'; Key = 'enforce_for_root'; Required = $true; Ok = { param($v) $true }
        PamFile = 'common-password'; PamModule = 'pam_pwquality.so'; WriteFile = 'pwquality.conf.d/50-pwroot.conf'; SetLine = 'enforce_for_root'; Expected = 'enforce_for_root habilitado' }
    '5.3.3.3.1' = @{ Title = 'Ensure password history remember is configured'; Conf = 'pwhistory'; Key = 'remember'; Required = $true; Exclusive = $true; Ok = { param($v) $v -match '^(2[4-9]|[3-9]\d|\d{3,})$' }
        PamFile = 'common-password'; PamModule = 'pam_pwhistory.so'; WriteFile = 'pwhistory.conf'; SetLine = 'remember = 24'; Expected = 'remember >= 24 en pwhistory.conf O como argumento PAM (no ambos)' }
    '5.3.3.3.2' = @{ Title = 'Ensure password history is enforced for the root user'; Conf = 'pwhistory'; Key = 'enforce_for_root'; Required = $true; Ok = { param($v) $true }
        PamFile = 'common-password'; PamModule = 'pam_pwhistory.so'; WriteFile = 'pwhistory.conf'; SetLine = 'enforce_for_root'; Expected = 'enforce_for_root en pwhistory.conf o como argumento PAM' }
    '5.3.3.3.3' = @{ Title = 'Ensure pam_pwhistory includes use_authtok'; Conf = 'pwhistory'; Key = 'use_authtok'; Required = $true; Ok = { param($v) $true }
        PamFile = 'common-password'; PamModule = 'pam_pwhistory.so'; WriteFile = 'pwhistory.conf'; SetLine = 'use_authtok'; Expected = 'use_authtok en pwhistory.conf o como argumento PAM' }
}

foreach ($id in $script:Debian13PamRules.Keys) {
    $rule = $script:Debian13PamRules[$id]; $rule.Id = $id
    $suffix = $id -replace '\.', '_'
    Set-Item -Path "function:script:Test-CIS_Debian13_$suffix" -Value ([scriptblock]::Create("Test-Debian13PamRule -Rule `$script:Debian13PamRules['$id']"))
    Set-Item -Path "function:script:Set-CIS_Debian13_$suffix" -Value ([scriptblock]::Create("[CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PamRule -Rule `$script:Debian13PamRules['$id']"))
}
