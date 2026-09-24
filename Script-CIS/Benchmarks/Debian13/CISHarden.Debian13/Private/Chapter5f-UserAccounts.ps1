# CIS Debian Linux 13 Benchmark v1.0.0 - 5.4 User Accounts and Environment
# (shadow suite, root y cuentas de sistema, entorno de usuario). 17 controles.
# Fuente: cis_debian_13.md, paginas 661-702.
#
# Los Set-* que tocan cuentas reales son conservadores: no se bloquea, expira ni
# cambia el UID/GID de cuentas de forma automatica salvo donde el benchmark da un
# comando inequivoco (chage/usermod -s/usermod -L). Se listan las cuentas afectadas
# en -WhatIf. Los casos que requieren juicio (UID 0 duplicado, password de root,
# PATH de root, fechas futuras) quedan como advertencia.

$script:Debian13EtcDir = '/etc'
$script:Debian13RootHome = '/root'

# --- lectura de cuentas ----------------------------------------------------------------------

function Get-Debian13PasswdEntries {
    foreach ($l in @(Get-Content (Join-Path $script:Debian13EtcDir 'passwd') -ErrorAction SilentlyContinue)) {
        $f = $l -split ':'
        if ($f.Count -ge 7) { [pscustomobject]@{ Name = $f[0]; Uid = [int]$f[2]; Gid = [int]$f[3]; Home = $f[5]; Shell = $f[6] } }
    }
}
function Get-Debian13GroupEntries {
    foreach ($l in @(Get-Content (Join-Path $script:Debian13EtcDir 'group') -ErrorAction SilentlyContinue)) {
        $f = $l -split ':'; if ($f.Count -ge 3) { [pscustomobject]@{ Name = $f[0]; Gid = [int]$f[2] } }
    }
}
function Get-Debian13ShadowEntries {
    # Solo cuentas con password (hash "$id$..."), como el filtro $2~/^\$.+\$/ del benchmark.
    foreach ($l in @(Get-Content (Join-Path $script:Debian13EtcDir 'shadow') -ErrorAction SilentlyContinue)) {
        $f = $l -split ':'
        if ($f.Count -ge 7 -and $f[1] -match '^\$.+\$') {
            $n = { param($x) if ($x -match '^-?\d+$') { [int]$x } else { $null } }
            [pscustomobject]@{ Name = $f[0]; LastChange = (& $n $f[2]); Min = (& $n $f[3]); Max = (& $n $f[4]); Warn = (& $n $f[5]); Inactive = (& $n $f[6]) }
        }
    }
}
function Get-Debian13LoginDefs {
    param([Parameter(Mandatory)][string]$Key)
    $l = @(Get-Content (Join-Path $script:Debian13EtcDir 'login.defs') -ErrorAction SilentlyContinue | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s+\S+" }) | Select-Object -Last 1
    if ($l -match "^\s*$([regex]::Escape($Key))\s+(\S+)") { $Matches[1] }
}
function Set-Debian13LoginDefs {
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Value)
    $f = Join-Path $script:Debian13EtcDir 'login.defs'
    if (Test-Path $f) { Copy-Item $f "$f.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    $done = $false
    $new = foreach ($l in @(Get-Content $f -ErrorAction SilentlyContinue)) {
        if ($l -match "^\s*$([regex]::Escape($Key))\s+") { if (-not $done) { "$Key`t$Value"; $done = $true } else { "# $l" } } else { $l }
    }
    if (-not $done) { $new = @($new) + "$Key`t$Value" }
    Set-Content -Path $f -Value $new
}
function Invoke-Debian13Chage { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) & chage @Arguments 2>&1 | Out-Null }
function Invoke-Debian13Usermod { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) & usermod @Arguments 2>&1 | Out-Null }
function Set-Debian13UseraddDefaultInactive { param([Parameter(Mandatory)][int]$Days) & useradd -D -f $Days 2>&1 | Out-Null }
function Get-Debian13TodayDays { [int][math]::Floor(([datetime]::UtcNow - [datetime]'1970-01-01').TotalDays) }

# --- 5.4.1 shadow password suite -------------------------------------------------------------------

function Test-Debian13AgingControl {
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$DefsKey,
        [Parameter(Mandatory)][scriptblock]$DefsOk, [Parameter(Mandatory)][string]$ShadowField, [Parameter(Mandatory)][scriptblock]$UserOk, [Parameter(Mandatory)][string]$Expected
    )
    $d = Get-Debian13LoginDefs -Key $DefsKey
    $bad = @(Get-Debian13ShadowEntries | Where-Object { -not (& $UserOk $_.$ShadowField) })
    $problems = @()
    if (-not $d) { $problems += "$DefsKey no definido en login.defs" } elseif (-not (& $DefsOk ([int]$d))) { $problems += "login.defs $DefsKey $d" }
    if ($bad.Count) { $problems += "usuarios fuera de norma ($ShadowField): $((($bad | ForEach-Object { "$($_.Name)=$($_.$ShadowField)" }) -join ', '))" }
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue $Expected `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { "$DefsKey $d; todos los usuarios con password conformes" })
}
function Set-Debian13AgingControl {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$DefsKey, [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][string]$ShadowField, [Parameter(Mandatory)][scriptblock]$UserOk, [Parameter(Mandatory)][string]$ChageOption)
    if ($PSCmdlet.ShouldProcess((Join-Path $script:Debian13EtcDir 'login.defs'), "$ControlId - $DefsKey $Value")) { Set-Debian13LoginDefs -Key $DefsKey -Value $Value }
    foreach ($u in @(Get-Debian13ShadowEntries | Where-Object { -not (& $UserOk $_.$ShadowField) })) {
        if ($ControlId -eq '5.4.1.1' -and $null -eq $u.LastChange) {
            Write-Warning "$ControlId : $($u.Name) no tiene fecha de ultimo cambio de password; aplicar maxdays la expiraria de inmediato. Poblarla antes (chage -d <fecha> $($u.Name)) y reintentar."; continue
        }
        if ($PSCmdlet.ShouldProcess($u.Name, "$ControlId - chage --$ChageOption $Value")) { Invoke-Debian13Chage "--$ChageOption" $Value $u.Name }
    }
}

function Test-CIS_Debian13_5_4_1_1 {
    Test-Debian13AgingControl -ControlId '5.4.1.1' -Title 'Ensure password expiration is configured' -DefsKey 'PASS_MAX_DAYS' -DefsOk { param($v) $v -ge 1 -and $v -le 365 } `
        -ShadowField 'Max' -UserOk { param($v) $null -ne $v -and $v -ge 1 -and $v -le 365 } -Expected 'PASS_MAX_DAYS entre 1 y 365 en login.defs y para cada usuario con password'
}
function Set-CIS_Debian13_5_4_1_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13AgingControl -ControlId '5.4.1.1' -DefsKey 'PASS_MAX_DAYS' -Value '365' -ShadowField 'Max' -UserOk { param($v) $null -ne $v -and $v -ge 1 -and $v -le 365 } -ChageOption 'maxdays' }

# Manual en el benchmark (politica del sitio); se informan los valores encontrados.
function Test-CIS_Debian13_5_4_1_2 {
    $d = Get-Debian13LoginDefs -Key 'PASS_MIN_DAYS'
    $bad = @(Get-Debian13ShadowEntries | Where-Object { $null -eq $_.Min -or $_.Min -lt 1 })
    New-CISResult -ControlId '5.4.1.2' -Title 'Ensure minimum password days is configured' -Status 'ManualReviewRequired' -ActualValue "PASS_MIN_DAYS $d; usuarios con mindays < 1: $($bad.Count)" `
        -Notes 'Verificar que PASS_MIN_DAYS (> 0) y el minimo por usuario sigan la politica del sitio (ejemplo del benchmark: 1).'
}
function Set-CIS_Debian13_5_4_1_2 { Write-Warning '5.4.1.2: sin remediacion automatizada -- fijar PASS_MIN_DAYS en login.defs y "chage --mindays <N> <usuario>" segun politica del sitio.' }

function Test-CIS_Debian13_5_4_1_3 {
    Test-Debian13AgingControl -ControlId '5.4.1.3' -Title 'Ensure password expiration warning days is configured' -DefsKey 'PASS_WARN_AGE' -DefsOk { param($v) $v -ge 7 } `
        -ShadowField 'Warn' -UserOk { param($v) $null -ne $v -and $v -ge 7 } -Expected 'PASS_WARN_AGE >= 7 en login.defs y para cada usuario con password'
}
function Set-CIS_Debian13_5_4_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13AgingControl -ControlId '5.4.1.3' -DefsKey 'PASS_WARN_AGE' -Value '7' -ShadowField 'Warn' -UserOk { param($v) $null -ne $v -and $v -ge 7 } -ChageOption 'warndays' }

function Test-CIS_Debian13_5_4_1_4 {
    $m = Get-Debian13LoginDefs -Key 'ENCRYPT_METHOD'
    New-CISResult -ControlId '5.4.1.4' -Title 'Ensure strong password hashing algorithm is configured' -Status $(if ($m -in 'SHA512', 'YESCRYPT') { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'ENCRYPT_METHOD SHA512 o YESCRYPT' -ActualValue $(if ($m) { $m } else { 'no definido' })
}
function Set-CIS_Debian13_5_4_1_4 { [CmdletBinding(SupportsShouldProcess)] param([ValidateSet('YESCRYPT', 'SHA512')][string]$Method = 'YESCRYPT') if ($PSCmdlet.ShouldProcess('login.defs', "5.4.1.4 - ENCRYPT_METHOD $Method")) { Set-Debian13LoginDefs -Key 'ENCRYPT_METHOD' -Value $Method } }

function Get-Debian13UseraddDefaultInactive { $l = (& useradd -D 2>$null) | Where-Object { $_ -match '^INACTIVE=' } | Select-Object -First 1; if ($l -match '=(-?\d+)') { [int]$Matches[1] } }
function Test-CIS_Debian13_5_4_1_5 {
    $def = Get-Debian13UseraddDefaultInactive
    $bad = @(Get-Debian13ShadowEntries | Where-Object { $null -eq $_.Inactive -or $_.Inactive -gt 45 -or $_.Inactive -lt 0 })
    $problems = @()
    if ($null -eq $def -or $def -lt 0 -or $def -gt 45) { $problems += "INACTIVE por defecto (useradd -D) = $def" }
    if ($bad.Count) { $problems += "usuarios fuera de norma: $((($bad | ForEach-Object { "$($_.Name)=$($_.Inactive)" }) -join ', '))" }
    New-CISResult -ControlId '5.4.1.5' -Title 'Ensure inactive password lock is configured' -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'INACTIVE entre 0 y 45 dias (por defecto y por usuario)' -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { "INACTIVE=$def; usuarios conformes" })
}
function Set-CIS_Debian13_5_4_1_5 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('useradd -D', '5.4.1.5 - INACTIVE=45')) { Set-Debian13UseraddDefaultInactive -Days 45 }
    foreach ($u in @(Get-Debian13ShadowEntries | Where-Object { $null -eq $_.Inactive -or $_.Inactive -gt 45 -or $_.Inactive -lt 0 })) {
        if ($PSCmdlet.ShouldProcess($u.Name, '5.4.1.5 - chage --inactive 45')) { Invoke-Debian13Chage '--inactive' '45' $u.Name }
    }
}

function Test-CIS_Debian13_5_4_1_6 {
    $today = Get-Debian13TodayDays
    $bad = @(Get-Debian13ShadowEntries | Where-Object { $null -ne $_.LastChange -and $_.LastChange -gt $today })
    New-CISResult -ControlId '5.4.1.6' -Title 'Ensure all users last password change date is in the past' -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Ninguna fecha de ultimo cambio de password en el futuro' -ActualValue $(if ($bad.Count) { "en el futuro: $((($bad | ForEach-Object Name) -join ', '))" } else { 'todas en el pasado' })
}
function Set-CIS_Debian13_5_4_1_6 { Write-Warning '5.4.1.6: sin remediacion automatizada -- investigar las cuentas (bloquear, expirar o resetear el password segun corresponda).' }

# --- 5.4.2 root y cuentas de sistema -----------------------------------------------------------------------

function Test-CIS_Debian13_5_4_2_1 {
    $x = @(Get-Debian13PasswdEntries | Where-Object { $_.Uid -eq 0 } | ForEach-Object Name)
    New-CISResult -ControlId '5.4.2.1' -Title 'Ensure root is the only UID 0 account' -Status $(if ($x.Count -eq 1 -and $x[0] -eq 'root') { 'Pass' } else { 'Fail' }) -ExpectedValue 'root es la unica cuenta con UID 0' -ActualValue "UID 0: $($x -join ', ')"
}
function Set-CIS_Debian13_5_4_2_1 { Write-Warning '5.4.2.1: sin remediacion automatizada -- asignar un nuevo UID a las cuentas distintas de root con UID 0 (usermod -u).' }

function Test-CIS_Debian13_5_4_2_2 {
    $x = @(Get-Debian13PasswdEntries | Where-Object { $_.Name -notmatch '^(sync|shutdown|halt|operator)' -and $_.Gid -eq 0 } | ForEach-Object Name)
    New-CISResult -ControlId '5.4.2.2' -Title 'Ensure root is the only GID 0 account' -Status $(if ($x.Count -eq 1 -and $x[0] -eq 'root') { 'Pass' } else { 'Fail' }) -ExpectedValue 'root es la unica cuenta con GID primario 0 (excepto sync/shutdown/halt/operator)' -ActualValue "GID 0: $($x -join ', ')"
}
function Set-CIS_Debian13_5_4_2_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ((@(Get-Debian13PasswdEntries | Where-Object Name -EQ 'root' | Where-Object Gid -NE 0)).Count -and $PSCmdlet.ShouldProcess('root', '5.4.2.2 - usermod -g 0 root')) { Invoke-Debian13Usermod '-g' '0' 'root' }
    Write-Warning '5.4.2.2: otras cuentas con GID 0 requieren decidir un nuevo GID (usermod -g) -- no se automatiza.'
}

function Test-CIS_Debian13_5_4_2_3 {
    $x = @(Get-Debian13GroupEntries | Where-Object { $_.Gid -eq 0 } | ForEach-Object Name)
    New-CISResult -ControlId '5.4.2.3' -Title 'Ensure group root is the only GID 0 group' -Status $(if ($x.Count -eq 1 -and $x[0] -eq 'root') { 'Pass' } else { 'Fail' }) -ExpectedValue 'root es el unico grupo con GID 0' -ActualValue "GID 0: $($x -join ', ')"
}
function Set-CIS_Debian13_5_4_2_3 { Write-Warning '5.4.2.3: sin remediacion automatizada -- reasignar el GID de los grupos distintos de root (groupmod -g).' }

function Get-Debian13PasswdStatus { param([Parameter(Mandatory)][string]$User) $o = (& passwd -S $User 2>$null) -join ' '; if ($o -match '^\S+\s+(\S+)') { $Matches[1] } }
function Test-CIS_Debian13_5_4_2_4 {
    $s = Get-Debian13PasswdStatus -User root
    New-CISResult -ControlId '5.4.2.4' -Title 'Ensure root account access is controlled' -Status $(if ($s -match '^(P|L)') { 'Pass' } else { 'Fail' }) -ExpectedValue 'root con password (P) o bloqueado (L)' -ActualValue "passwd -S root: $s"
}
function Set-CIS_Debian13_5_4_2_4 { Write-Warning '5.4.2.4: sin remediacion automatizada -- "passwd root" o "usermod -L root" (bloquear root solo si hay otra via de administracion, ej. sudo).' }

function Get-Debian13RootPath {
    # Como root `su - root` no pide password; sin root podria quedar esperando en el tty, asi que no se intenta.
    if ((& id -u 2>$null) -ne '0') { return $null }
    $o = (& su - root -c env 2>$null) | Where-Object { $_ -match '^PATH=' } | Select-Object -First 1; if ($o) { $o.Substring(5) }
}
function Test-CIS_Debian13_5_4_2_5 {
    $p = Get-Debian13RootPath
    if ($null -eq $p) { return New-CISResult -ControlId '5.4.2.5' -Title 'Ensure root path integrity' -Status 'Error' -Notes 'No se pudo obtener el PATH de root.' }
    $problems = @()
    if ($p -match '::') { $problems += 'contiene un directorio vacio (::)' }
    if ($p -match ':\s*$') { $problems += 'termina en ":"' }
    if ($p -match '(^\s*|:)\.(:|\s*$)') { $problems += 'contiene el directorio actual (.)' }
    foreach ($d in ($p -split ':' | Where-Object { $_ })) {
        if (-not (Test-Path $d -PathType Container)) { $problems += "$d no es un directorio"; continue }
        $mode = Get-CISFileMode -Path $d; $own = (Get-CISFileOwner -Path $d)
        if ($own -and ($own -split ':')[0] -ne 'root') { $problems += "$d pertenece a $($own -split ':' | Select-Object -First 1)" }
        if ($mode -and ([Convert]::ToInt32($mode, 8) -band 18) -gt 0) { $problems += "$d modo $mode (debe ser 0755 o mas restrictivo)" }
    }
    New-CISResult -ControlId '5.4.2.5' -Title 'Ensure root path integrity' -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'PATH de root sin ::, ":" final, ".", ni directorios inexistentes/ajenos/con escritura de grupo u otros' `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { $p })
}
function Set-CIS_Debian13_5_4_2_5 { Write-Warning '5.4.2.5: sin remediacion automatizada -- corregir o justificar cada entrada del PATH de root (ver Remediation del benchmark).' }

# umask: octal (027, 0027) o simbolico (u=rwx,g=rx,o=) -> mascara entera; $null si no se puede interpretar.
function ConvertTo-Debian13UmaskValue {
    param([string]$Text)
    $t = $Text.Trim()
    if ($t -match '^[0-7]{1,4}$') { return [Convert]::ToInt32($t, 8) -band 511 }
    if ($t -match '^([ugoa]=[rwx]*)(,[ugoa]=[rwx]*)*$') {
        $allowed = @{ u = 0; g = 0; o = 0 }
        foreach ($part in $t -split ',') {
            $who, $perm = $part -split '='
            $bits = 0; if ($perm -match 'r') { $bits += 4 }; if ($perm -match 'w') { $bits += 2 }; if ($perm -match 'x') { $bits += 1 }
            foreach ($w in $(if ($who -eq 'a') { 'u', 'g', 'o' } else { , $who })) { $allowed[$w] = $bits }
        }
        return (511 -bxor ((($allowed.u -shl 6) -bor ($allowed.g -shl 3) -bor $allowed.o)))
    }
    $null
}
function Test-Debian13UmaskRestrictive { param([string]$Text) $m = ConvertTo-Debian13UmaskValue -Text $Text; ($null -ne $m) -and (($m -band 23) -eq 23) }   # 023 = g-w y o-rwx (>= 027)

function Get-Debian13UmaskLines {
    # Lineas "umask <valor>" no comentadas de los archivos: @{File; Value; Line}
    param([string[]]$Files)
    foreach ($f in $Files) { foreach ($l in @(Get-Content $f -ErrorAction SilentlyContinue)) { if ($l -match '^\s*umask\s+(\S+)') { [pscustomobject]@{ File = $f; Value = $Matches[1]; Line = $l } } } }
}
function Test-CIS_Debian13_5_4_2_6 {
    $files = @('.profile', '.bashrc' | ForEach-Object { Join-Path $script:Debian13RootHome $_ })
    $bad = @(Get-Debian13UmaskLines -Files $files | Where-Object { -not (Test-Debian13UmaskRestrictive $_.Value) })
    New-CISResult -ControlId '5.4.2.6' -Title 'Ensure root user umask is configured' -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Sin umask menos restrictivo que 027 en /root/.profile y /root/.bashrc' `
        -ActualValue $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.File): umask $($_.Value)" }) -join '; ' } else { 'conforme' })
}
function Set-CIS_Debian13_5_4_2_6 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($f in @('.profile', '.bashrc' | ForEach-Object { Join-Path $script:Debian13RootHome $_ })) {
        if (-not (@(Get-Debian13UmaskLines -Files $f | Where-Object { -not (Test-Debian13UmaskRestrictive $_.Value) }).Count)) { continue }
        if (-not $PSCmdlet.ShouldProcess($f, '5.4.2.6 - umask 027')) { continue }
        Backup-CISFile -Path $f | Out-Null
        (Get-Content $f) | ForEach-Object { if ($_ -match '^\s*umask\s+(\S+)' -and -not (Test-Debian13UmaskRestrictive $Matches[1])) { 'umask 027' } else { $_ } } | Set-Content $f
    }
}

function Get-Debian13ValidShells { @(Get-Content (Join-Path $script:Debian13EtcDir 'shells') -ErrorAction SilentlyContinue | Where-Object { $_ -match '^/' -and ($_ -split '/')[-1] -ne 'nologin' } | ForEach-Object { $_.Trim() }) }
function Get-Debian13SystemAccountsWithShell {
    $uidMin = [int]$(if ($v = Get-Debian13LoginDefs -Key 'UID_MIN') { $v } else { 1000 })
    $valid = Get-Debian13ValidShells
    @(Get-Debian13PasswdEntries | Where-Object { $_.Name -notmatch '^(root|halt|sync|shutdown|nfsnobody)$' -and ($_.Uid -lt $uidMin -or $_.Uid -eq 65534) -and ($valid -contains $_.Shell) })
}
function Test-CIS_Debian13_5_4_2_7 {
    $x = @(Get-Debian13SystemAccountsWithShell)
    New-CISResult -ControlId '5.4.2.7' -Title 'Ensure system accounts do not have a valid login shell' -Status $(if ($x.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Cuentas de sistema (excepto root/halt/sync/shutdown/nfsnobody) sin shell valido' `
        -ActualValue $(if ($x.Count) { ($x | ForEach-Object { "$($_.Name): $($_.Shell)" }) -join '; ' } else { 'conforme' })
}
function Set-CIS_Debian13_5_4_2_7 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $nologin = (Get-Command nologin -ErrorAction SilentlyContinue).Source; if (-not $nologin) { $nologin = '/usr/sbin/nologin' }
    foreach ($u in @(Get-Debian13SystemAccountsWithShell)) { if ($PSCmdlet.ShouldProcess($u.Name, "5.4.2.7 - usermod -s $nologin")) { Invoke-Debian13Usermod '-s' $nologin $u.Name } }
}

function Get-Debian13NoShellAccounts { $valid = Get-Debian13ValidShells; @(Get-Debian13PasswdEntries | Where-Object { $_.Name -ne 'root' -and ($valid -notcontains $_.Shell) }) }
function Test-CIS_Debian13_5_4_2_8 {
    $unlocked = @(Get-Debian13NoShellAccounts | Where-Object { (Get-Debian13PasswdStatus -User $_.Name) -notmatch '^L' })
    New-CISResult -ControlId '5.4.2.8' -Title 'Ensure accounts without a valid login shell are locked' -Status $(if ($unlocked.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Cuentas no-root sin shell valido, bloqueadas (passwd -S = L)' `
        -ActualValue $(if ($unlocked.Count) { "sin bloquear: $((($unlocked | ForEach-Object Name) -join ', '))" } else { 'conforme' })
}
function Set-CIS_Debian13_5_4_2_8 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($u in @(Get-Debian13NoShellAccounts | Where-Object { (Get-Debian13PasswdStatus -User $_.Name) -notmatch '^L' })) { if ($PSCmdlet.ShouldProcess($u.Name, '5.4.2.8 - usermod -L')) { Invoke-Debian13Usermod '-L' $u.Name } }
}

# --- 5.4.3 entorno de usuario -----------------------------------------------------------------------------------------------

function Test-CIS_Debian13_5_4_3_1 {
    $hit = @(Get-Content (Join-Path $script:Debian13EtcDir 'shells') -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '/nologin\b' })
    New-CISResult -ControlId '5.4.3.1' -Title 'Ensure nologin is not listed in /etc/shells' -Status $(if ($hit.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue '/etc/shells sin lineas con nologin' -ActualValue $(if ($hit.Count) { $hit -join '; ' } else { 'sin nologin' })
}
function Set-CIS_Debian13_5_4_3_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $f = Join-Path $script:Debian13EtcDir 'shells'
    if ((Test-Path $f) -and $PSCmdlet.ShouldProcess($f, '5.4.3.1 - quitar lineas con nologin')) {
        Backup-CISFile -Path $f | Out-Null
        (Get-Content $f) | Where-Object { $_ -match '^\s*#' -or $_ -notmatch '/nologin\b' } | Set-Content $f
    }
}

function Get-Debian13TmoutFiles {
    @(Get-ChildItem $script:Debian13EtcDir -Filter '*bashrc' -File -ErrorAction SilentlyContinue | ForEach-Object FullName) + @(Join-Path $script:Debian13EtcDir 'profile') +
    @(Get-ChildItem (Join-Path $script:Debian13EtcDir 'profile.d') -Filter '*.sh' -File -ErrorAction SilentlyContinue | ForEach-Object FullName) |
        Where-Object { (Test-Path $_) -and (Select-String -Path $_ -Pattern '^([^#\r\n]+)?\bTMOUT\b' -Quiet) }
}
function Test-CIS_Debian13_5_4_3_2 {
    $good = @(); $problems = @()
    foreach ($f in @(Get-Debian13TmoutFiles)) {
        $c = @(Get-Content $f)
        $val = ($c | ForEach-Object { if ($_ -match '^([^#\r\n]+)?\bTMOUT=(\d+)\b') { [int]$Matches[2] } } | Select-Object -Last 1)
        $ro = [bool]($c | Where-Object { $_ -match '^\s*(typeset\s+-xr\s+TMOUT=\d+|([^#\r\n]+)?\breadonly\s+TMOUT\b)' })
        $ex = [bool]($c | Where-Object { $_ -match '^\s*(typeset\s+-xr\s+TMOUT=\d+|([^#\r\n]+)?\bexport\b([^#\r\n]+\b)?TMOUT\b)' })
        if ($null -eq $val) { $problems += "$f : TMOUT no asignado" }
        elseif ($val -le 0 -or $val -gt 900) { $problems += "$f : TMOUT=$val" }
        elseif (-not $ro -or -not $ex) { $problems += "$f : TMOUT=$val sin readonly/export" }
        else { $good += "$f : TMOUT=$val" }
    }
    if (-not $good.Count -and -not $problems.Count) { $problems += 'TMOUT no esta configurado' }
    New-CISResult -ControlId '5.4.3.2' -Title 'Ensure default user shell timeout is configured' -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'TMOUT entre 1 y 900, readonly y exportado, sin valores contradictorios' `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { $good -join '; ' })
}
function Set-CIS_Debian13_5_4_3_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $ours = Join-Path $script:Debian13EtcDir 'profile.d/50-tmout.sh'
    if (-not $PSCmdlet.ShouldProcess($ours, '5.4.3.2 - typeset -xr TMOUT=900 (y comentar otras definiciones de TMOUT)')) { return }
    foreach ($f in @(Get-Debian13TmoutFiles | Where-Object { $_ -ne $ours })) {
        Backup-CISFile -Path $f | Out-Null
        (Get-Content $f) | ForEach-Object { if ($_ -notmatch '^\s*#' -and $_ -match '\bTMOUT\b') { "# $_" } else { $_ } } | Set-Content $f
    }
    New-Item -ItemType Directory -Path (Split-Path $ours) -Force | Out-Null
    Set-Content -Path $ours -Value @('# Set TMOUT to 900 seconds', 'typeset -xr TMOUT=900')
}

function Test-CIS_Debian13_5_4_3_3 {
    $profFiles = @(Get-ChildItem (Join-Path $script:Debian13EtcDir 'profile.d') -Filter '*.sh' -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
    $lines = @(Get-Debian13UmaskLines -Files $profFiles)
    $badLines = @($lines | Where-Object { -not (Test-Debian13UmaskRestrictive $_.Value) })
    $defs = Get-Debian13LoginDefs -Key 'UMASK'
    $problems = @()
    if (-not $lines.Count) { $problems += 'sin umask en /etc/profile.d/*.sh' }
    foreach ($b in $badLines) { $problems += "$($b.File): umask $($b.Value)" }
    if (-not $defs) { $problems += 'UMASK no definido en login.defs' } elseif (-not (Test-Debian13UmaskRestrictive $defs)) { $problems += "login.defs UMASK $defs" }
    New-CISResult -ControlId '5.4.3.3' -Title 'Ensure default user umask is configured' -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'umask 027 o mas restrictivo en /etc/profile.d/*.sh y UMASK 027 o mas restrictivo en login.defs' `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { "profile.d: $(($lines | ForEach-Object Value) -join ','); login.defs UMASK $defs" })
}
function Set-CIS_Debian13_5_4_3_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $dir = Join-Path $script:Debian13EtcDir 'profile.d'
    if (-not $PSCmdlet.ShouldProcess($dir, '5.4.3.3 - umask 027 en profile.d y UMASK 027 en login.defs')) { return }
    foreach ($f in @(Get-ChildItem $dir -Filter '*.sh' -File -ErrorAction SilentlyContinue | ForEach-Object FullName)) {
        if (-not (@(Get-Debian13UmaskLines -Files $f | Where-Object { -not (Test-Debian13UmaskRestrictive $_.Value) }).Count)) { continue }
        Backup-CISFile -Path $f | Out-Null
        (Get-Content $f) | ForEach-Object { if ($_ -match '^\s*umask\s+(\S+)' -and -not (Test-Debian13UmaskRestrictive $Matches[1])) { "# $_" } else { $_ } } | Set-Content $f
    }
    $profFiles = @(Get-ChildItem $dir -Filter '*.sh' -File -ErrorAction SilentlyContinue | ForEach-Object FullName)
    if (-not @(Get-Debian13UmaskLines -Files $profFiles | Where-Object { Test-Debian13UmaskRestrictive $_.Value }).Count) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Add-Content -Path (Join-Path $dir '60-default_umask.sh') -Value @('', 'umask 027')
    }
    Set-Debian13LoginDefs -Key 'UMASK' -Value '027'
}
