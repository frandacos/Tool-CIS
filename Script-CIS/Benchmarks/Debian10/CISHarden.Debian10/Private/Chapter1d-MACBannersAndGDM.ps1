# CIS Debian Linux 10 Benchmark v2.0.0 - Capitulo 1.6 Mandatory Access
# Control (AppArmor), 1.7 Command Line Warning Banners y 1.8 GNOME Display
# Manager. 20 controles. Fuente: cis_debian_10.md, paginas 168-231.

# ===================== 1.6.1 AppArmor =====================

function Test-CIS_Debian10_1_6_1_1 {
    [CmdletBinding()]
    param()
    $apparmor = Test-CISPackageInstalled -Name 'apparmor'
    $utils = Test-CISPackageInstalled -Name 'apparmor-utils'
    $status = if ($apparmor -and $utils) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.6.1.1' -Title 'Ensure AppArmor is installed' -Status $status `
        -ExpectedValue 'apparmor y apparmor-utils instalados' -ActualValue "apparmor=$apparmor; apparmor-utils=$utils"
}
function Set-CIS_Debian10_1_6_1_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('apparmor, apparmor-utils', 'apt-get install -y')) {
        Install-CISPackage -Name 'apparmor'
        Install-CISPackage -Name 'apparmor-utils'
    }
}

function Test-CIS_Debian10_1_6_1_2 {
    [CmdletBinding()]
    param()
    $grubCfg = '/boot/grub/grub.cfg'
    $linuxLines = if (Test-Path $grubCfg) { Select-String -Path $grubCfg -Pattern '^\s*linux' } else { @() }
    $missing = $linuxLines | Where-Object { $_.Line -notmatch 'apparmor=1' -or $_.Line -notmatch 'security=apparmor' }
    $status = if ($linuxLines.Count -gt 0 -and $missing.Count -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.6.1.2' -Title 'Ensure AppArmor is enabled in the bootloader configuration' -Status $status `
        -ExpectedValue "todas las lineas 'linux' de $grubCfg tienen apparmor=1 y security=apparmor" `
        -ActualValue "lineas linux=$($linuxLines.Count); sin ambos parametros=$($missing.Count)"
}
function Set-CIS_Debian10_1_6_1_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('/etc/default/grub', "Agregar apparmor=1 security=apparmor a GRUB_CMDLINE_LINUX y correr update-grub")) {
        Set-CISFileLine -Path '/etc/default/grub' -Line 'GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"' -MatchPattern '^GRUB_CMDLINE_LINUX='
        & update-grub 2>$null
    }
}

function Get-Debian10RegexIntOrZero {
    param([string]$Text, [string]$Pattern)
    $m = [regex]::Match($Text, $Pattern)
    if ($m.Success) { return [int]$m.Groups[1].Value }
    return 0
}

function Get-Debian10AppArmorStatus {
    <# Parsea la salida de apparmor_status en un objeto con los contadores relevantes. #>
    $r = Invoke-CISLinuxCommand -Command 'apparmor_status'
    $text = ($r.Output -join "`n")
    [pscustomobject]@{
        Success          = $r.Success
        ProfilesLoaded   = Get-Debian10RegexIntOrZero -Text $text -Pattern '(\d+)\s+profiles are loaded'
        ProfilesEnforce  = Get-Debian10RegexIntOrZero -Text $text -Pattern '(\d+)\s+profiles are in enforce mode'
        ProfilesComplain = Get-Debian10RegexIntOrZero -Text $text -Pattern '(\d+)\s+profiles are in complain mode'
        ProcessesUnconf  = Get-Debian10RegexIntOrZero -Text $text -Pattern '(\d+)\s+processes are unconfined'
    }
}

function Test-CIS_Debian10_1_6_1_3 {
    [CmdletBinding()]
    param()
    $s = Get-Debian10AppArmorStatus
    $allAccounted = $s.ProfilesLoaded -gt 0 -and ($s.ProfilesEnforce + $s.ProfilesComplain) -ge $s.ProfilesLoaded
    $status = if ($s.Success -and $allAccounted -and $s.ProcessesUnconf -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.6.1.3' -Title 'Ensure all AppArmor Profiles are in enforce or complain mode' -Status $status `
        -ExpectedValue 'todos los perfiles cargados en enforce o complain; 0 procesos unconfined' `
        -ActualValue "Loaded=$($s.ProfilesLoaded); Enforce=$($s.ProfilesEnforce); Complain=$($s.ProfilesComplain); Unconfined=$($s.ProcessesUnconf)"
}
function Set-CIS_Debian10_1_6_1_3 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('/etc/apparmor.d/*', 'aa-enforce')) {
        Invoke-CISLinuxCommand -Command 'aa-enforce /etc/apparmor.d/*' | Out-Null
    }
}

function Test-CIS_Debian10_1_6_1_4 {
    [CmdletBinding()]
    param()
    $s = Get-Debian10AppArmorStatus
    $allEnforce = $s.ProfilesLoaded -gt 0 -and $s.ProfilesComplain -eq 0 -and $s.ProfilesEnforce -ge $s.ProfilesLoaded
    $status = if ($s.Success -and $allEnforce -and $s.ProcessesUnconf -eq 0) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.6.1.4' -Title 'Ensure all AppArmor Profiles are enforcing' -Status $status `
        -ExpectedValue 'todos los perfiles cargados en enforce (0 en complain); 0 procesos unconfined' `
        -ActualValue "Loaded=$($s.ProfilesLoaded); Enforce=$($s.ProfilesEnforce); Complain=$($s.ProfilesComplain); Unconfined=$($s.ProcessesUnconf)"
}
function Set-CIS_Debian10_1_6_1_4 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('/etc/apparmor.d/*', 'aa-enforce')) {
        Invoke-CISLinuxCommand -Command 'aa-enforce /etc/apparmor.d/*' | Out-Null
    }
}

# ===================== 1.7 Command Line Warning Banners =====================
# 1.7.1 tiene un criterio objetivo explicito en el benchmark (el banner no
# debe filtrar info de SO). 1.7.2/1.7.3 el benchmark solo pide "verificar
# que el contenido cumple la politica del sitio" sin dar un criterio
# objetivo -- se marcan ManualReviewRequired (regla: no inventar heuristica
# para lo que el propio benchmark deja como revision de politica).

function Test-Debian10BannerNoOsInfo {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Path)
    $leaks = Test-CISFileContains -Path $Path -Pattern '\\v|\\r|\\m|\\s'
    $status = if (-not $leaks) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue "$Path sin \v \r \m \s (no revela version/release/arquitectura de SO)" `
        -ActualValue $(if ($leaks) { 'contiene escapes de info de SO' } else { 'sin escapes de info de SO' })
}

function Test-CIS_Debian10_1_7_1 { Test-Debian10BannerNoOsInfo -ControlId '1.7.1' -Title 'Ensure message of the day is configured properly' -Path '/etc/motd' }
function Set-CIS_Debian10_1_7_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('/etc/motd', 'Quitar escapes de info de SO (\v \r \m \s)')) {
        if (Test-Path '/etc/motd') {
            Backup-CISFile -Path '/etc/motd' | Out-Null
            (Get-Content -Path '/etc/motd') -replace '\\[vrms]', '' | Set-Content -Path '/etc/motd'
        }
    }
}

function Test-CIS_Debian10_1_7_2 {
    New-CISResult -ControlId '1.7.2' -Title 'Ensure local login warning banner is configured properly' -Status 'ManualReviewRequired' `
        -Notes 'El benchmark pide verificar que /etc/issue cumple la politica de avisos legales del sitio; no da un criterio objetivo automatizable.'
}
function Set-CIS_Debian10_1_7_2 { Write-Warning "1.7.2: sin remediacion automatizada -- editar /etc/issue segun la politica de avisos legales del sitio." }

function Test-CIS_Debian10_1_7_3 {
    New-CISResult -ControlId '1.7.3' -Title 'Ensure remote login warning banner is configured properly' -Status 'ManualReviewRequired' `
        -Notes 'El benchmark pide verificar que /etc/issue.net cumple la politica de avisos legales del sitio; no da un criterio objetivo automatizable.'
}
function Set-CIS_Debian10_1_7_3 { Write-Warning "1.7.3: sin remediacion automatizada -- editar /etc/issue.net segun la politica de avisos legales del sitio." }

function Test-Debian10BannerFilePermissions {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue "$Path no existe, o root:root 0644 o mas restrictivo" -ActualValue "$Path no existe"
    }
    $mode = Get-CISFileMode -Path $Path
    $owner = Get-CISFileOwner -Path $Path
    $modeOk = ($null -ne $mode) -and ([Convert]::ToInt32($mode, 8) -le [Convert]::ToInt32('644', 8))
    $ownerOk = ($owner -eq 'root:root')
    $status = if ($modeOk -and $ownerOk) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue 'root:root, 0644 o mas restrictivo' -ActualValue "owner=$owner; mode=$mode"
}
function Set-Debian10BannerFilePermissions {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return }
    if ($PSCmdlet.ShouldProcess($Path, "$ControlId - chown root:root; chmod 644")) {
        Set-CISFileOwner -Path $Path -Owner 'root:root'
        Set-CISFileMode -Path $Path -Mode '644'
    }
}

function Test-CIS_Debian10_1_7_4 { Test-Debian10BannerFilePermissions -ControlId '1.7.4' -Title 'Ensure permissions on /etc/motd are configured' -Path '/etc/motd' }
function Set-CIS_Debian10_1_7_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10BannerFilePermissions -ControlId '1.7.4' -Path '/etc/motd' }

function Test-CIS_Debian10_1_7_5 { Test-Debian10BannerFilePermissions -ControlId '1.7.5' -Title 'Ensure permissions on /etc/issue are configured' -Path '/etc/issue' }
function Set-CIS_Debian10_1_7_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10BannerFilePermissions -ControlId '1.7.5' -Path '/etc/issue' }

function Test-CIS_Debian10_1_7_6 { Test-Debian10BannerFilePermissions -ControlId '1.7.6' -Title 'Ensure permissions on /etc/issue.net are configured' -Path '/etc/issue.net' }
function Set-CIS_Debian10_1_7_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10BannerFilePermissions -ControlId '1.7.6' -Path '/etc/issue.net' }

# ===================== 1.8 GNOME Display Manager =====================
# Los controles de dconf (1.8.2-1.8.9) siguen el patron del benchmark: si
# gdm/gdm3 no esta instalado, el control es Pass (Not Applicable en la
# practica). Cuando esta instalado, se verifica la clave/valor esperado en
# /etc/dconf/db/*.d (o el candado correspondiente en .../locks para los
# controles "is not overridden"). Notes deja constancia de que no se
# revalida la existencia del profile de dconf paso a paso como hace el
# script bash original del benchmark -- solo la clave/candado final.

function Test-Debian10GdmInstalled {
    (Test-CISPackageInstalled -Name 'gdm') -or (Test-CISPackageInstalled -Name 'gdm3')
}

function Get-Debian10DconfDbFiles {
    Get-ChildItem -Path '/etc/dconf/db' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match '\.d(\\|/|$)' -and $_.DirectoryName -notmatch 'locks' }
}

function Get-Debian10DconfLockFiles {
    Get-ChildItem -Path '/etc/dconf/db' -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -match 'locks' }
}

function Test-Debian10DconfKeySet {
    param([Parameter(Mandatory)][string]$Pattern)
    foreach ($f in (Get-Debian10DconfDbFiles)) {
        if (Test-CISFileContains -Path $f.FullName -Pattern $Pattern) { return $true }
    }
    return $false
}

function Test-Debian10DconfPathLocked {
    param([Parameter(Mandatory)][string]$DconfPath)
    foreach ($f in (Get-Debian10DconfLockFiles)) {
        if (Test-CISFileContains -Path $f.FullName -Pattern ([regex]::Escape($DconfPath))) { return $true }
    }
    return $false
}

function Set-Debian10DconfKeyFile {
    <#
        Crea (si hace falta) el profile 'gdm', su directorio db y un
        keyfile con la seccion+linea pedidas, siguiendo el mismo patron que
        la Remediation del benchmark para 1.8.2 (profile 'gdm',
        /etc/dconf/db/gdm.d/<FileName>). Reutilizable para todos los
        settings de org/gnome/desktop/* y org/gnome/login-screen.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Profile = 'gdm',
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string[]]$KeyValueLines
    )

    $profilePath = "/etc/dconf/profile/$Profile"
    $dbDir = "/etc/dconf/db/$Profile.d"
    $keyFile = "$dbDir/$FileName"

    if (-not $PSCmdlet.ShouldProcess($keyFile, 'Crear/actualizar keyfile de dconf')) { return }

    if (-not (Test-Path $profilePath)) {
        New-Item -Path '/etc/dconf/profile' -ItemType Directory -Force | Out-Null
        Set-Content -Path $profilePath -Value @("user-db:user", "system-db:$Profile", "file-db:/usr/share/$Profile/greeter-dconf-defaults")
    }
    if (-not (Test-Path $dbDir)) {
        New-Item -Path $dbDir -ItemType Directory -Force | Out-Null
    }

    $lines = @()
    if (Test-Path $keyFile) { $lines = Get-Content -Path $keyFile }
    if ($lines -notcontains "[$Section]") {
        $lines += ''
        $lines += "[$Section]"
    }
    foreach ($kv in $KeyValueLines) {
        $key = ($kv -split '=')[0]
        if ($lines -match "^\s*$([regex]::Escape($key))\s*=") {
            $lines = $lines -replace "^\s*$([regex]::Escape($key))\s*=.*$", $kv
        }
        else {
            $lines += $kv
        }
    }
    Set-Content -Path $keyFile -Value $lines
    & dconf update
}

function Set-Debian10DconfLock {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Profile = 'gdm',
        [Parameter(Mandatory)][string]$FileName,
        [Parameter(Mandatory)][string[]]$DconfPaths
    )
    $locksDir = "/etc/dconf/db/$Profile.d/locks"
    $lockFile = "$locksDir/$FileName"
    if (-not $PSCmdlet.ShouldProcess($lockFile, 'Crear/actualizar lock de dconf')) { return }
    if (-not (Test-Path $locksDir)) { New-Item -Path $locksDir -ItemType Directory -Force | Out-Null }
    $lines = @()
    if (Test-Path $lockFile) { $lines = Get-Content -Path $lockFile }
    foreach ($p in $DconfPaths) {
        if ($lines -notcontains $p) { $lines += $p }
    }
    Set-Content -Path $lockFile -Value $lines
    & dconf update
}

# --- 1.8.1 Ensure GNOME Display Manager is removed (Level 2, Server only) ---

function Test-CIS_Debian10_1_8_1 {
    [CmdletBinding()]
    param()
    if ((Get-CISLinuxProfile) -eq 'Workstation') {
        return New-CISResult -ControlId '1.8.1' -Title 'Ensure GNOME Display Manager is removed' -Status 'NotApplicable' `
            -Notes 'Control (Level 2 - Server) unicamente; este equipo se detecto como Workstation y necesita GDM.'
    }
    $installed = Test-CISPackageInstalled -Name 'gdm3'
    $status = if (-not $installed) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.1' -Title 'Ensure GNOME Display Manager is removed' -Status $status `
        -ExpectedValue 'gdm3 no instalado' -ActualValue $(if ($installed) { 'instalado' } else { 'no instalado' })
}
function Set-CIS_Debian10_1_8_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ((Get-CISLinuxProfile) -eq 'Workstation') { Write-Warning '1.8.1 es (Level 2 - Server only): no se aplica en una Workstation.'; return }
    if (-not (Test-CISPackageInstalled -Name 'gdm3')) { return }
    if ($PSCmdlet.ShouldProcess('gdm3', 'apt-get purge -y')) {
        Remove-CISPackage -Name 'gdm3' -Purge
    }
}

# --- 1.8.2 GDM login banner ---------------------------------------------------

function Test-CIS_Debian10_1_8_2 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.2' -Title 'Ensure GDM login banner is configured' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o banner configurado' -ActualValue 'gdm/gdm3 no instalado'
    }
    $enabled = Test-Debian10DconfKeySet -Pattern '^\s*banner-message-enable\s*=\s*true\b'
    $textSet = Test-Debian10DconfKeySet -Pattern "^\s*banner-message-text\s*="
    $status = if ($enabled -and $textSet) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.2' -Title 'Ensure GDM login banner is configured' -Status $status `
        -ExpectedValue 'banner-message-enable=true y banner-message-text definido en org/gnome/login-screen' `
        -ActualValue "enable=$enabled; text=$textSet"
}
function Set-CIS_Debian10_1_8_2 {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$BannerText = 'Authorized uses only. All activity may be monitored and reported')
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('org/gnome/login-screen', 'Habilitar banner y setear texto')) {
        Set-Debian10DconfKeyFile -FileName '01-banner-message' -Section 'org/gnome/login-screen' `
            -KeyValueLines @('banner-message-enable=true', "banner-message-text='$BannerText'")
    }
}

# --- 1.8.3 GDM disable-user-list ---------------------------------------------

function Test-CIS_Debian10_1_8_3 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.3' -Title 'Ensure GDM disable-user-list option is enabled' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o disable-user-list=true' -ActualValue 'gdm/gdm3 no instalado'
    }
    $set = Test-Debian10DconfKeySet -Pattern '^\s*disable-user-list\s*=\s*true\b'
    $status = if ($set) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.3' -Title 'Ensure GDM disable-user-list option is enabled' -Status $status `
        -ExpectedValue 'disable-user-list=true en org/gnome/login-screen' -ActualValue "disable-user-list=true encontrado=$set"
}
function Set-CIS_Debian10_1_8_3 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('org/gnome/login-screen', 'Set disable-user-list=true')) {
        Set-Debian10DconfKeyFile -FileName '00-login-screen' -Section 'org/gnome/login-screen' -KeyValueLines @('disable-user-list=true')
    }
}

# --- 1.8.4 GDM screen locks when idle ----------------------------------------

function Test-CIS_Debian10_1_8_4 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.4' -Title 'Ensure GDM screen locks when the user is idle' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o idle-delay/lock-delay configurados' -ActualValue 'gdm/gdm3 no instalado'
    }
    $idleOk = $false
    foreach ($f in (Get-Debian10DconfDbFiles)) {
        $m = Select-String -Path $f.FullName -Pattern 'idle-delay\s*=\s*uint32\s+(\d+)' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($m) { $v = [int]$m.Matches[0].Groups[1].Value; if ($v -gt 0 -and $v -le 900) { $idleOk = $true } }
    }
    $lockOk = $false
    foreach ($f in (Get-Debian10DconfDbFiles)) {
        $m = Select-String -Path $f.FullName -Pattern 'lock-delay\s*=\s*uint32\s+(\d+)' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($m) { $v = [int]$m.Matches[0].Groups[1].Value; if ($v -ge 0 -and $v -le 5) { $lockOk = $true } }
    }
    $status = if ($idleOk -and $lockOk) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.4' -Title 'Ensure GDM screen locks when the user is idle' -Status $status `
        -ExpectedValue 'idle-delay entre 1 y 900; lock-delay entre 0 y 5' -ActualValue "idle-delay ok=$idleOk; lock-delay ok=$lockOk"
}
function Set-CIS_Debian10_1_8_4 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('org/gnome/desktop/session,screensaver', 'Set idle-delay=900 lock-delay=5')) {
        Set-Debian10DconfKeyFile -FileName '00-screensaver' -Section 'org/gnome/desktop/session' -KeyValueLines @('idle-delay=uint32 900')
        Set-Debian10DconfKeyFile -FileName '00-screensaver' -Section 'org/gnome/desktop/screensaver' -KeyValueLines @('lock-delay=uint32 5')
    }
}

# --- 1.8.5 GDM screen locks cannot be overridden -----------------------------

function Test-CIS_Debian10_1_8_5 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.5' -Title 'Ensure GDM screen locks cannot be overridden' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o idle-delay/lock-delay bloqueados' -ActualValue 'gdm/gdm3 no instalado'
    }
    $idleLocked = Test-Debian10DconfPathLocked -DconfPath '/org/gnome/desktop/session/idle-delay'
    $lockLocked = Test-Debian10DconfPathLocked -DconfPath '/org/gnome/desktop/screensaver/lock-delay'
    $status = if ($idleLocked -and $lockLocked) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.5' -Title 'Ensure GDM screen locks cannot be overridden' -Status $status `
        -ExpectedValue 'idle-delay y lock-delay bloqueados en .../locks' -ActualValue "idle-delay locked=$idleLocked; lock-delay locked=$lockLocked"
}
function Set-CIS_Debian10_1_8_5 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('locks', 'Bloquear idle-delay y lock-delay')) {
        Set-Debian10DconfLock -FileName '00-screensaver' -DconfPaths @('/org/gnome/desktop/session/idle-delay', '/org/gnome/desktop/screensaver/lock-delay')
    }
}

# --- 1.8.6 GDM automatic mounting of removable media disabled ---------------

function Test-CIS_Debian10_1_8_6 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.6' -Title 'Ensure GDM automatic mounting of removable media is disabled' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o automount(-open)=false' -ActualValue 'gdm/gdm3 no instalado'
    }
    $automountOff = Test-Debian10DconfKeySet -Pattern '^\s*automount\s*=\s*false\b'
    $automountOpenOff = Test-Debian10DconfKeySet -Pattern '^\s*automount-open\s*=\s*false\b'
    $status = if ($automountOff -and $automountOpenOff) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.6' -Title 'Ensure GDM automatic mounting of removable media is disabled' -Status $status `
        -ExpectedValue 'automount=false y automount-open=false en org/gnome/desktop/media-handling' -ActualValue "automount=false: $automountOff; automount-open=false: $automountOpenOff"
}
function Set-CIS_Debian10_1_8_6 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('org/gnome/desktop/media-handling', 'Set automount=false automount-open=false')) {
        Set-Debian10DconfKeyFile -FileName '00-media-automount' -Section 'org/gnome/desktop/media-handling' -KeyValueLines @('automount=false', 'automount-open=false')
    }
}

# --- 1.8.7 GDM automount disabling cannot be overridden ----------------------

function Test-CIS_Debian10_1_8_7 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.7' -Title 'Ensure GDM disabling automatic mounting of removable media is not overridden' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o automount(-open) bloqueados' -ActualValue 'gdm/gdm3 no instalado'
    }
    $automountLocked = Test-Debian10DconfPathLocked -DconfPath '/org/gnome/desktop/media-handling/automount'
    $automountOpenLocked = Test-Debian10DconfPathLocked -DconfPath '/org/gnome/desktop/media-handling/automount-open'
    $status = if ($automountLocked -and $automountOpenLocked) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.7' -Title 'Ensure GDM disabling automatic mounting of removable media is not overridden' -Status $status `
        -ExpectedValue 'automount y automount-open bloqueados en .../locks' -ActualValue "automount locked=$automountLocked; automount-open locked=$automountOpenLocked"
}
function Set-CIS_Debian10_1_8_7 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('locks', 'Bloquear automount y automount-open')) {
        Set-Debian10DconfLock -FileName '00-media-automount' -DconfPaths @('/org/gnome/desktop/media-handling/automount', '/org/gnome/desktop/media-handling/automount-open')
    }
}

# --- 1.8.8 GDM autorun-never enabled ------------------------------------------

function Test-CIS_Debian10_1_8_8 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.8' -Title 'Ensure GDM autorun-never is enabled' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o autorun-never=true' -ActualValue 'gdm/gdm3 no instalado'
    }
    $set = Test-Debian10DconfKeySet -Pattern '^\s*autorun-never\s*=\s*true\b'
    $status = if ($set) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.8' -Title 'Ensure GDM autorun-never is enabled' -Status $status `
        -ExpectedValue 'autorun-never=true en org/gnome/desktop/media-handling' -ActualValue "autorun-never=true encontrado=$set"
}
function Set-CIS_Debian10_1_8_8 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('org/gnome/desktop/media-handling', 'Set autorun-never=true')) {
        Set-Debian10DconfKeyFile -FileName '00-media-automount' -Section 'org/gnome/desktop/media-handling' -KeyValueLines @('autorun-never=true')
    }
}

# --- 1.8.9 GDM autorun-never cannot be overridden -----------------------------

function Test-CIS_Debian10_1_8_9 {
    [CmdletBinding()]
    param()
    if (-not (Test-Debian10GdmInstalled)) {
        return New-CISResult -ControlId '1.8.9' -Title 'Ensure GDM autorun-never is not overridden' -Status 'Pass' -ExpectedValue 'gdm/gdm3 no instalado, o autorun-never bloqueado' -ActualValue 'gdm/gdm3 no instalado'
    }
    $locked = Test-Debian10DconfPathLocked -DconfPath '/org/gnome/desktop/media-handling/autorun-never'
    $status = if ($locked) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.9' -Title 'Ensure GDM autorun-never is not overridden' -Status $status `
        -ExpectedValue 'autorun-never bloqueado en .../locks' -ActualValue "autorun-never locked=$locked"
}
function Set-CIS_Debian10_1_8_9 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Debian10GdmInstalled)) { return }
    if ($PSCmdlet.ShouldProcess('locks', 'Bloquear autorun-never')) {
        Set-Debian10DconfLock -FileName '00-media-automount' -DconfPaths @('/org/gnome/desktop/media-handling/autorun-never')
    }
}

# --- 1.8.10 XDMCP not enabled -------------------------------------------------

function Test-CIS_Debian10_1_8_10 {
    [CmdletBinding()]
    param()
    $enabled = Test-CISFileContains -Path '/etc/gdm3/custom.conf' -Pattern '^\s*Enable\s*=\s*true'
    $status = if (-not $enabled) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.8.10' -Title 'Ensure XDCMP is not enabled' -Status $status `
        -ExpectedValue "sin 'Enable=true' en la seccion [xdmcp] de /etc/gdm3/custom.conf" -ActualValue $(if ($enabled) { 'Enable=true presente' } else { 'sin Enable=true' })
}
function Set-CIS_Debian10_1_8_10 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-Path '/etc/gdm3/custom.conf')) { return }
    if ($PSCmdlet.ShouldProcess('/etc/gdm3/custom.conf', 'Quitar Enable=true de [xdmcp]')) {
        Backup-CISFile -Path '/etc/gdm3/custom.conf' | Out-Null
        (Get-Content -Path '/etc/gdm3/custom.conf') | Where-Object { $_ -notmatch '^\s*Enable\s*=\s*true' } | Set-Content -Path '/etc/gdm3/custom.conf'
    }
}
