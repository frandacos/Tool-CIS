# CIS Debian Linux 13 Benchmark v1.0.0 - 1.6 Command Line Warning Banners y
# 1.7 GNOME Display Manager. 17 controles. Fuente: cis_debian_13.md, paginas 207-252.

# --- 1.6 Banners -----------------------------------------------------------------

function Get-Debian13OsId {
    $l = Get-Content -Path '/etc/os-release' -ErrorAction SilentlyContinue | Where-Object { $_ -match '^ID=' } | Select-Object -First 1
    if ($l) { ($l -split '=', 2)[1].Trim('"') } else { 'debian' }
}
function Get-Debian13BannerFiles {
    param([Parameter(Mandatory)][string]$Path, [switch]$IncludeDropIns)
    $files = @(); if (Test-Path $Path) { $files += $Path }
    if ($IncludeDropIns) { $files += @(Get-ChildItem "$Path.d" -File -ErrorAction SilentlyContinue | ForEach-Object FullName) }
    $files
}
function Get-Debian13BannerLeaks {
    # Archivos con \v \r \m \s o el ID del SO (criterio del Audit del benchmark).
    param([string[]]$Files)
    $re = "(\\[vrms]|\b$([regex]::Escape((Get-Debian13OsId)))\b)"
    @($Files | Where-Object { Select-String -Path $_ -Pattern $re -Quiet })
}

function Test-Debian13BannerControl {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Path, [switch]$IncludeDropIns)
    $files = @(Get-Debian13BannerFiles -Path $Path -IncludeDropIns:$IncludeDropIns)
    $leaks = @(Get-Debian13BannerLeaks -Files $files)
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($leaks.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Sin \v \r \m \s ni referencias al SO; contenido conforme a la politica del sitio' `
        -ActualValue $(if ($leaks.Count) { "Con informacion del sistema: $($leaks -join ', ')" } else { 'sin informacion del sistema' }) `
        -Notes 'Verificar manualmente que el contenido cumple la politica de avisos legales del sitio.'
}
function Set-Debian13BannerControl {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Path, [switch]$IncludeDropIns)
    $osId = [regex]::Escape((Get-Debian13OsId))
    foreach ($f in (Get-Debian13BannerLeaks -Files (Get-Debian13BannerFiles -Path $Path -IncludeDropIns:$IncludeDropIns))) {
        if ($PSCmdlet.ShouldProcess($f, "$ControlId - quitar \v \r \m \s y referencias al SO")) {
            Backup-CISFile -Path $f | Out-Null
            (Get-Content $f) -replace '\\[vrms]', '' -replace "(?i)\b$osId\b", '' | Set-Content $f
        }
    }
}

function Test-CIS_Debian13_1_6_1 { Test-Debian13BannerControl -ControlId '1.6.1' -Title 'Ensure /etc/motd is configured' -Path '/etc/motd' -IncludeDropIns }
function Set-CIS_Debian13_1_6_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13BannerControl -ControlId '1.6.1' -Path '/etc/motd' -IncludeDropIns }
function Test-CIS_Debian13_1_6_2 { Test-Debian13BannerControl -ControlId '1.6.2' -Title 'Ensure /etc/issue is configured' -Path '/etc/issue' }
function Set-CIS_Debian13_1_6_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13BannerControl -ControlId '1.6.2' -Path '/etc/issue' }
function Test-CIS_Debian13_1_6_3 { Test-Debian13BannerControl -ControlId '1.6.3' -Title 'Ensure /etc/issue.net is configured' -Path '/etc/issue.net' }
function Set-CIS_Debian13_1_6_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13BannerControl -ControlId '1.6.3' -Path '/etc/issue.net' }

# Permisos: root:root, 0644 o mas restrictivo; si el archivo no existe, Pass (helpers de Chapter1b).
function Test-CIS_Debian13_1_6_4 { Test-Debian13PathControl -ControlId '1.6.4' -Title 'Ensure access to /etc/motd is configured' -Path '/etc/motd' -MaxMode '644' }
function Set-CIS_Debian13_1_6_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.6.4' -Path '/etc/motd' -SymbolicMode 'u-x,go-wx' }
function Test-CIS_Debian13_1_6_5 { Test-Debian13PathControl -ControlId '1.6.5' -Title 'Ensure access to /etc/issue is configured' -Path '/etc/issue' -MaxMode '644' }
function Set-CIS_Debian13_1_6_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.6.5' -Path '/etc/issue' -SymbolicMode 'u-x,go-wx' }
function Test-CIS_Debian13_1_6_6 { Test-Debian13PathControl -ControlId '1.6.6' -Title 'Ensure access to /etc/issue.net is configured' -Path '/etc/issue.net' -MaxMode '644' }
function Set-CIS_Debian13_1_6_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.6.6' -Path '/etc/issue.net' -SymbolicMode 'u-x,go-wx' }

# --- 1.7 GNOME Display Manager ---------------------------------------------------
# Si GDM no esta instalado, los controles 1.7.2-1.7.11 son Pass (nada que
# configurar). Se verifican las claves/locks de dconf en /etc/dconf/db/*.d.

function Test-Debian13GdmInstalled { (Test-CISPackageInstalled -Name 'gdm3') -or (Test-CISPackageInstalled -Name 'gdm') }

function New-Debian13GdmNotInstalledResult {
    param([string]$ControlId, [string]$Title)
    New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue 'GDM no instalado, o configurado' -ActualValue 'GDM no instalado'
}

function Get-Debian13DconfUint {
    param([string]$Section, [string]$Key)
    $v = Get-CISDconfValue -Section $Section -Key $Key
    if ($v -match '(\d+)\s*$') { [int]$Matches[1] } else { $null }
}

function Test-CIS_Debian13_1_7_1 {
    if ((Get-CISLinuxProfile) -eq 'Workstation') {
        return New-CISResult -ControlId '1.7.1' -Title 'Ensure GDM is removed' -Status 'NotApplicable' -Notes 'Control Level 2 - Server unicamente; este equipo se detecto como Workstation.'
    }
    $installed = Test-CISPackageInstalled -Name 'gdm3'
    New-CISResult -ControlId '1.7.1' -Title 'Ensure GDM is removed' -Status $(if ($installed) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'gdm3 no instalado' -ActualValue $(if ($installed) { 'instalado' } else { 'no instalado' })
}
function Set-CIS_Debian13_1_7_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ((Get-CISLinuxProfile) -eq 'Workstation') { Write-Warning '1.7.1 es Level 2 - Server: no se aplica en una Workstation.'; return }
    if ((Test-CISPackageInstalled -Name 'gdm3') -and $PSCmdlet.ShouldProcess('gdm3', 'apt purge gdm3 y autoremove')) {
        Remove-CISPackage -Name 'gdm3' -Purge
        & apt-get autoremove -y 2>&1 | Out-Null
    }
}

function Test-CIS_Debian13_1_7_2 {
    $t = 'Ensure GDM login banner is configured'
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult '1.7.2' $t }
    $en = Get-CISDconfValue -Section 'org/gnome/login-screen' -Key 'banner-message-enable'
    $tx = Get-CISDconfValue -Section 'org/gnome/login-screen' -Key 'banner-message-text'
    New-CISResult -ControlId '1.7.2' -Title $t -Status $(if ($en -eq 'true' -and $tx) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'banner-message-enable=true y banner-message-text definido' -ActualValue "enable=$en; text=$tx"
}
function Set-CIS_Debian13_1_7_2 {
    [CmdletBinding(SupportsShouldProcess)] param([string]$BannerText = 'Authorized uses only. All activity may be monitored and reported')
    if (Test-Debian13GdmInstalled) {
        Set-CISDconfKeyFile -Database gdm -FileName '01-banner-message' -Section 'org/gnome/login-screen' -KeyValueLines 'banner-message-enable=true', "banner-message-text='$BannerText'"
    }
}

function Test-CIS_Debian13_1_7_3 {
    $t = 'Ensure GDM disable-user-list option is enabled'
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult '1.7.3' $t }
    $v = Get-CISDconfValue -Section 'org/gnome/login-screen' -Key 'disable-user-list'
    New-CISResult -ControlId '1.7.3' -Title $t -Status $(if ($v -eq 'true') { 'Pass' } else { 'Fail' }) -ExpectedValue 'disable-user-list=true' -ActualValue "$v"
}
function Set-CIS_Debian13_1_7_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (Test-Debian13GdmInstalled) { Set-CISDconfKeyFile -Database gdm -FileName '00-login-screen' -Section 'org/gnome/login-screen' -KeyValueLines 'disable-user-list=true' }
}

function Test-CIS_Debian13_1_7_4 {
    $t = 'Ensure GDM screen locks when the user is idle'
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult '1.7.4' $t }
    $lock = Get-Debian13DconfUint -Section 'org/gnome/desktop/screensaver' -Key 'lock-delay'
    $idle = Get-Debian13DconfUint -Section 'org/gnome/desktop/session' -Key 'idle-delay'
    $ok = ($null -ne $lock -and $lock -le 5) -and ($null -ne $idle -and $idle -gt 0 -and $idle -le 900)
    New-CISResult -ControlId '1.7.4' -Title $t -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'lock-delay <= 5 e idle-delay entre 1 y 900 segundos' -ActualValue "lock-delay=$lock; idle-delay=$idle"
}
function Set-CIS_Debian13_1_7_4 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not (Test-Debian13GdmInstalled)) { return }
    Set-CISDconfKeyFile -Database local -FileName '00-screensaver' -Section 'org/gnome/desktop/session' -KeyValueLines 'idle-delay=uint32 900'
    Set-CISDconfKeyFile -Database local -FileName '00-screensaver' -Section 'org/gnome/desktop/screensaver' -KeyValueLines 'lock-delay=uint32 5'
}

function Test-Debian13DconfLocksControl {
    param([string]$ControlId, [string]$Title, [string[]]$Paths)
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult $ControlId $Title }
    $missing = @($Paths | Where-Object { -not (Test-CISDconfPathLocked -DconfPath $_) })
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($missing.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue "Bloqueadas en dconf locks: $($Paths -join ', ')" -ActualValue $(if ($missing.Count) { "sin bloquear: $($missing -join ', ')" } else { 'bloqueadas' })
}

$script:Debian13ScreenLockPaths = '/org/gnome/desktop/session/idle-delay', '/org/gnome/desktop/screensaver/lock-delay'
function Test-CIS_Debian13_1_7_5 { Test-Debian13DconfLocksControl '1.7.5' 'Ensure GDM screen locks cannot be overridden' $script:Debian13ScreenLockPaths }
function Set-CIS_Debian13_1_7_5 { [CmdletBinding(SupportsShouldProcess)] param() if (Test-Debian13GdmInstalled) { Set-CISDconfLock -Database local -FileName '00-screensaver' -DconfPaths $script:Debian13ScreenLockPaths } }

function Test-CIS_Debian13_1_7_6 {
    $t = 'Ensure GDM automatic mounting of removable media is disabled'
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult '1.7.6' $t }
    $a = Get-CISDconfValue -Section 'org/gnome/desktop/media-handling' -Key 'automount'
    $o = Get-CISDconfValue -Section 'org/gnome/desktop/media-handling' -Key 'automount-open'
    New-CISResult -ControlId '1.7.6' -Title $t -Status $(if ($a -eq 'false' -and $o -eq 'false') { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'automount=false y automount-open=false' -ActualValue "automount=$a; automount-open=$o"
}
function Set-CIS_Debian13_1_7_6 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (Test-Debian13GdmInstalled) { Set-CISDconfKeyFile -Database local -FileName '00-media-automount' -Section 'org/gnome/desktop/media-handling' -KeyValueLines 'automount=false', 'automount-open=false' }
}

$script:Debian13AutomountPaths = '/org/gnome/desktop/media-handling/automount', '/org/gnome/desktop/media-handling/automount-open'
function Test-CIS_Debian13_1_7_7 { Test-Debian13DconfLocksControl '1.7.7' 'Ensure GDM disabling automatic mounting of removable media is not overridden' $script:Debian13AutomountPaths }
function Set-CIS_Debian13_1_7_7 { [CmdletBinding(SupportsShouldProcess)] param() if (Test-Debian13GdmInstalled) { Set-CISDconfLock -Database local -FileName '00-media-automount' -DconfPaths $script:Debian13AutomountPaths } }

function Test-CIS_Debian13_1_7_8 {
    $t = 'Ensure GDM autorun-never is enabled'
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult '1.7.8' $t }
    $v = Get-CISDconfValue -Section 'org/gnome/desktop/media-handling' -Key 'autorun-never'
    New-CISResult -ControlId '1.7.8' -Title $t -Status $(if ($v -eq 'true') { 'Pass' } else { 'Fail' }) -ExpectedValue 'autorun-never=true' -ActualValue "$v"
}
function Set-CIS_Debian13_1_7_8 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (Test-Debian13GdmInstalled) { Set-CISDconfKeyFile -Database local -FileName '00-media-autorun' -Section 'org/gnome/desktop/media-handling' -KeyValueLines 'autorun-never=true' }
}

$script:Debian13AutorunPaths = , '/org/gnome/desktop/media-handling/autorun-never'
function Test-CIS_Debian13_1_7_9 { Test-Debian13DconfLocksControl '1.7.9' 'Ensure GDM autorun-never is not overridden' $script:Debian13AutorunPaths }
function Set-CIS_Debian13_1_7_9 { [CmdletBinding(SupportsShouldProcess)] param() if (Test-Debian13GdmInstalled) { Set-CISDconfLock -Database local -FileName '00-media-autorun' -DconfPaths $script:Debian13AutorunPaths } }

# --- 1.7.10 XDMCP / 1.7.11 Xwayland (archivos INI de gdm) -------------------------

function Get-Debian13GdmConfFiles {
    param([string[]]$Names = @('custom.conf', 'daemon.conf'))
    foreach ($d in '/etc/gdm3', '/etc/gdm') { foreach ($n in $Names) { if (Test-Path "$d/$n") { "$d/$n" } } }
}
function Get-Debian13IniValue {
    param([string]$File, [string]$Block, [string]$Key)
    $in = $false; $v = $null
    foreach ($l in (Get-Content -Path $File -ErrorAction SilentlyContinue)) {
        if ($l -match '^\s*\[(.+)\]') { $in = ($Matches[1] -eq $Block); continue }
        if ($in -and $l -match "^\s*$([regex]::Escape($Key))\s*=\s*(\S+)") { $v = $Matches[1] }
    }
    $v
}

function Test-CIS_Debian13_1_7_10 {
    $t = 'Ensure XDMCP is not enabled'
    $bad = @(Get-Debian13GdmConfFiles | Where-Object { (Get-Debian13IniValue -File $_ -Block 'xdmcp' -Key 'Enable') -eq 'true' })
    New-CISResult -ControlId '1.7.10' -Title $t -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Sin Enable=true en el bloque [xdmcp]' `
        -ActualValue $(if ($bad.Count) { "Enable=true en: $($bad -join ', ')" } else { 'sin Enable=true' })
}
function Set-CIS_Debian13_1_7_10 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($f in @(Get-Debian13GdmConfFiles | Where-Object { (Get-Debian13IniValue -File $_ -Block 'xdmcp' -Key 'Enable') -eq 'true' })) {
        if (-not $PSCmdlet.ShouldProcess($f, '1.7.10 - comentar Enable=true en [xdmcp]')) { continue }
        Backup-CISFile -Path $f | Out-Null
        $in = $false
        (Get-Content $f) | ForEach-Object {
            if ($_ -match '^\s*\[(.+)\]') { $in = ($Matches[1] -eq 'xdmcp') }
            if ($in -and $_ -match '^\s*Enable\s*=\s*true') { "# $_" } else { $_ }
        } | Set-Content $f
    }
}

function Test-CIS_Debian13_1_7_11 {
    $t = 'Ensure Xwayland is configured'
    if (-not (Test-Debian13GdmInstalled)) { return New-Debian13GdmNotInstalledResult '1.7.11' $t }
    $vals = @(Get-Debian13GdmConfFiles -Names 'custom.conf' | ForEach-Object { Get-Debian13IniValue -File $_ -Block 'daemon' -Key 'WaylandEnable' })
    New-CISResult -ControlId '1.7.11' -Title $t -Status $(if ($vals -contains 'false') { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'WaylandEnable=false en el bloque [daemon] de custom.conf' -ActualValue $(if ($vals.Count) { "WaylandEnable=$($vals -join ',')" } else { 'no definido' })
}
function Set-CIS_Debian13_1_7_11 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not (Test-Debian13GdmInstalled)) { return }
    $f = @(Get-Debian13GdmConfFiles -Names 'custom.conf')[0]; if (-not $f) { $f = '/etc/gdm3/custom.conf' }
    if (-not $PSCmdlet.ShouldProcess($f, '1.7.11 - WaylandEnable=false en [daemon]')) { return }
    if (Test-Path $f) { Backup-CISFile -Path $f | Out-Null }
    $lines = @(if (Test-Path $f) { Get-Content $f })
    $out = [System.Collections.Generic.List[string]]::new(); $in = $false; $done = $false; $seen = $false
    foreach ($l in $lines) {
        if ($l -match '^\s*\[(.+)\]') {
            if ($in -and -not $done) { $out.Add('WaylandEnable=false'); $done = $true }
            $in = ($Matches[1] -eq 'daemon'); if ($in) { $seen = $true }
        }
        elseif ($in -and $l -match '^\s*#?\s*WaylandEnable\s*=') { if (-not $done) { $out.Add('WaylandEnable=false'); $done = $true }; continue }
        $out.Add($l)
    }
    if (-not $done) { if (-not $seen) { $out.Add('[daemon]') }; $out.Add('WaylandEnable=false') }
    New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
    Set-Content -Path $f -Value $out
}
