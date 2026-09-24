# CIS Debian Linux 13 Benchmark v1.0.0 - 2.3 Configure Time Synchronization y
# 2.4 Job Schedulers (cron/at). 16 controles. Fuente: cis_debian_13.md,
# paginas 322-368.

function Get-Debian13TimeSyncState {
    # "En uso" = enabled o active (mismo criterio que el script del Audit 2.3.1.1).
    $u = @(Get-Debian13UnitStates -Units 'systemd-timesyncd.service', 'chrony.service')
    $f = { param($n) $x = $u | Where-Object Unit -EQ $n; [pscustomobject]@{ Enabled = ($x.UnitFileState -eq 'enabled'); Active = ($x.ActiveState -eq 'active') } }
    $t = & $f 'systemd-timesyncd.service'; $c = & $f 'chrony.service'
    [pscustomobject]@{
        TimesyncdEnabled = $t.Enabled; TimesyncdActive = $t.Active; TimesyncdInUse = ($t.Enabled -or $t.Active)
        ChronyEnabled    = $c.Enabled; ChronyActive = $c.Active; ChronyInUse = ($c.Enabled -or $c.Active)
    }
}

# --- 2.3.1.1 un unico daemon de sincronizacion --------------------------------------

function Test-CIS_Debian13_2_3_1_1 {
    $s = Get-Debian13TimeSyncState
    $n = @($s.TimesyncdInUse, $s.ChronyInUse | Where-Object { $_ }).Count
    New-CISResult -ControlId '2.3.1.1' -Title 'Ensure a single time synchronization daemon is in use' -Status $(if ($n -eq 1) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'Exactamente uno de systemd-timesyncd / chrony en uso (enabled o active)' `
        -ActualValue "timesyncd=$($s.TimesyncdInUse); chrony=$($s.ChronyInUse)"
}
function Set-CIS_Debian13_2_3_1_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $s = Get-Debian13TimeSyncState
    if ($s.TimesyncdInUse -and $s.ChronyInUse) {
        # Opcion 1 del benchmark: quedarse con chrony y detener/enmascarar timesyncd.
        if ($PSCmdlet.ShouldProcess('systemd-timesyncd.service', '2.3.1.1 - stop + mask (se conserva chrony)')) {
            Invoke-Debian13Systemctl stop systemd-timesyncd.service; Invoke-Debian13Systemctl mask systemd-timesyncd.service
        }
    }
    elseif (-not $s.TimesyncdInUse -and -not $s.ChronyInUse) {
        Write-Warning '2.3.1.1: ningun daemon en uso -- elegir uno (apt install chrony, o habilitar systemd-timesyncd) segun politica del sitio.'
    }
}

# --- 2.3.2 systemd-timesyncd ---------------------------------------------------------

function Test-CIS_Debian13_2_3_2_1 {
    $t = 'Ensure systemd-timesyncd configured with authorized timeserver'
    $s = Get-Debian13TimeSyncState
    if ($s.ChronyInUse -and -not $s.TimesyncdInUse) {
        return New-CISResult -ControlId '2.3.2.1' -Title $t -Status 'Pass' -ExpectedValue 'NTP/FallbackNTP definidos si timesyncd esta en uso' -ActualValue 'timesyncd no esta en uso (se usa chrony)'
    }
    $ntp = Get-CISSystemdConfigValue -ConfName 'systemd/timesyncd.conf' -Block 'Time' -Option 'NTP'
    $fb = Get-CISSystemdConfigValue -ConfName 'systemd/timesyncd.conf' -Block 'Time' -Option 'FallbackNTP'
    $set = @($ntp, $fb | Where-Object { $_ -and -not $_.IsDefault })
    New-CISResult -ControlId '2.3.2.1' -Title $t -Status $(if ($set.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'NTP y/o FallbackNTP definidos en [Time] (servidores autorizados por la politica del sitio)' `
        -ActualValue "NTP=$($ntp.Value); FallbackNTP=$($fb.Value)" -Notes 'Verificar que los servidores sean los aprobados por el sitio.'
}
function Set-CIS_Debian13_2_3_2_1 {
    [CmdletBinding(SupportsShouldProcess)] param([string]$Ntp, [string]$FallbackNtp)
    if (-not $Ntp -and -not $FallbackNtp) {
        Write-Warning "2.3.2.1: los servidores autorizados dependen de la politica del sitio -- volver a ejecutar con -Ntp '<servidor>' [-FallbackNtp '<s1> <s2>']."; return
    }
    if ($Ntp) { Set-CISSystemdConfigValue -ConfName 'systemd/timesyncd.conf' -Block 'Time' -Option 'NTP' -Value $Ntp }
    if ($FallbackNtp) { Set-CISSystemdConfigValue -ConfName 'systemd/timesyncd.conf' -Block 'Time' -Option 'FallbackNTP' -Value $FallbackNtp }
    if ($PSCmdlet.ShouldProcess('systemd-timesyncd', 'reload-or-restart')) { Invoke-Debian13Systemctl reload-or-restart systemd-timesyncd }
}

function Test-CIS_Debian13_2_3_2_2 {
    $t = 'Ensure systemd-timesyncd is enabled and running'
    $s = Get-Debian13TimeSyncState
    if ($s.ChronyInUse) {
        return New-CISResult -ControlId '2.3.2.2' -Title $t -Status 'Pass' -ExpectedValue 'enabled y active si timesyncd es el daemon en uso' -ActualValue 'otro daemon (chrony) esta en uso'
    }
    New-CISResult -ControlId '2.3.2.2' -Title $t -Status $(if ($s.TimesyncdEnabled -and $s.TimesyncdActive) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'systemd-timesyncd enabled y active' -ActualValue "enabled=$($s.TimesyncdEnabled); active=$($s.TimesyncdActive)"
}
function Set-CIS_Debian13_2_3_2_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('systemd-timesyncd.service', '2.3.2.2 - unmask + enable --now')) {
        Invoke-Debian13Systemctl unmask systemd-timesyncd.service; Invoke-Debian13Systemctl enable --now systemd-timesyncd.service
    }
}

# --- 2.3.3 chrony ----------------------------------------------------------------------

function Get-Debian13ChronySourceLines {
    # Lineas server/pool de chrony.conf y de los archivos incluidos por confdir/sourcedir.
    $files = [System.Collections.Generic.List[string]]::new()
    if (Test-Path '/etc/chrony/chrony.conf') { $files.Add('/etc/chrony/chrony.conf') }
    foreach ($inc in @(Get-Content '/etc/chrony/chrony.conf' -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(confdir|sourcedir)\s+\S+' } | ForEach-Object { ($_ -split '\s+')[1] })) {
        if (Test-Path $inc -PathType Container) { Get-ChildItem $inc -File -ErrorAction SilentlyContinue | ForEach-Object { $files.Add($_.FullName) } }
        elseif ($inc -match '\*') { Get-ChildItem (Split-Path $inc) -File -Filter (Split-Path $inc -Leaf) -ErrorAction SilentlyContinue | ForEach-Object { $files.Add($_.FullName) } }
        elseif (Test-Path $inc) { $files.Add($inc) }
    }
    foreach ($f in $files) { Get-Content $f -ErrorAction SilentlyContinue | Where-Object { $_ -match '^\s*(server|pool)(\s+|\s*:\s*).+' } | ForEach-Object { "${f}: $_" } }
}
function Get-Debian13ChronydUsers { @(& ps -eo user,comm 2>$null | Where-Object { $_ -match '\bchronyd\s*$' } | ForEach-Object { ($_.Trim() -split '\s+')[0] }) }

function Test-CIS_Debian13_2_3_3_1 {
    $t = 'Ensure chrony is configured with authorized timeserver'
    $s = Get-Debian13TimeSyncState
    if ($s.TimesyncdInUse -and -not $s.ChronyInUse) {
        return New-CISResult -ControlId '2.3.3.1' -Title $t -Status 'Pass' -ExpectedValue 'server/pool definidos si chrony esta en uso' -ActualValue 'chrony no esta en uso (se usa systemd-timesyncd)'
    }
    $lines = @(Get-Debian13ChronySourceLines)
    New-CISResult -ControlId '2.3.3.1' -Title $t -Status $(if ($lines.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'Al menos una linea server/pool (servidores autorizados por la politica del sitio)' `
        -ActualValue $(if ($lines.Count) { $lines -join ' | ' } else { 'sin server/pool' }) -Notes 'Verificar que los servidores sean los aprobados por el sitio.'
}
function Set-CIS_Debian13_2_3_3_1 {
    [CmdletBinding(SupportsShouldProcess)] param([string]$Pool, [string[]]$Server)
    if (-not $Pool -and -not $Server) {
        Write-Warning "2.3.3.1: los servidores autorizados dependen de la politica del sitio -- volver a ejecutar con -Pool '<pool>' y/o -Server '<s1>','<s2>'."; return
    }
    $f = '/etc/chrony/sources.d/60-sources.sources'
    if (-not $PSCmdlet.ShouldProcess($f, '2.3.3.1 - agregar server/pool y recargar chrony')) { return }
    New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
    if (Test-Path $f) { Backup-CISFile -Path $f | Out-Null }
    $add = @(''); if ($Pool) { $add += "pool $Pool iburst maxsources 4" }; foreach ($s in $Server) { $add += "server $s iburst" }
    Add-Content -Path $f -Value $add
    Invoke-Debian13Systemctl reload-or-restart chronyd
}

function Test-CIS_Debian13_2_3_3_2 {
    $t = 'Ensure chrony is running as user _chrony'
    $bad = @(Get-Debian13ChronydUsers | Where-Object { $_ -ne '_chrony' })
    New-CISResult -ControlId '2.3.3.2' -Title $t -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'chronyd corre como _chrony (o no esta corriendo)' `
        -ActualValue $(if ($bad.Count) { "chronyd corre como: $($bad -join ', ')" } else { 'ok' })
}
function Set-CIS_Debian13_2_3_3_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $f = '/etc/chrony/conf.d/60-user.conf'
    if ($PSCmdlet.ShouldProcess($f, '2.3.3.2 - user _chrony y reiniciar chrony')) {
        New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
        Set-Content -Path $f -Value 'user _chrony'
        Invoke-Debian13Systemctl reload-or-restart chronyd
    }
}

function Test-CIS_Debian13_2_3_3_3 {
    $t = 'Ensure chrony is enabled and running'
    $s = Get-Debian13TimeSyncState
    if (-not $s.ChronyInUse) {
        return New-CISResult -ControlId '2.3.3.3' -Title $t -Status 'Pass' -ExpectedValue 'enabled y active si chrony es el daemon en uso' -ActualValue 'chrony no esta en uso'
    }
    New-CISResult -ControlId '2.3.3.3' -Title $t -Status $(if ($s.ChronyEnabled -and $s.ChronyActive) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'chrony enabled y active' -ActualValue "enabled=$($s.ChronyEnabled); active=$($s.ChronyActive)"
}
function Set-CIS_Debian13_2_3_3_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('chrony.service', '2.3.3.3 - unmask + enable --now')) {
        Invoke-Debian13Systemctl unmask chrony.service; Invoke-Debian13Systemctl enable --now chrony.service
    }
}

# --- 2.4.1 cron ------------------------------------------------------------------------------

function Test-Debian13CronControl {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$MaxMode)
    if (-not (Test-CISPackageInstalled -Name 'cron')) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue 'cron no instalado, o acceso configurado' -ActualValue 'cron no instalado'
    }
    Test-Debian13PathControl -ControlId $ControlId -Title $Title -Path $Path -MaxMode $MaxMode
}
function Set-Debian13CronControl {
    [CmdletBinding(SupportsShouldProcess)] param([string]$ControlId, [string]$Path)
    if (Test-CISPackageInstalled -Name 'cron') { Set-Debian13PathControl -ControlId $ControlId -Path $Path -SymbolicMode 'og-rwx' }
}

function Test-CIS_Debian13_2_4_1_1 {
    $t = 'Ensure cron daemon is enabled and active'
    if (-not (Test-CISPackageInstalled -Name 'cron')) {
        return New-CISResult -ControlId '2.4.1.1' -Title $t -Status 'Pass' -ExpectedValue 'cron no instalado, o enabled y active' -ActualValue 'cron no instalado'
    }
    $u = @(Get-Debian13UnitStates -Units 'cron.service')[0]
    $ok = ($u.UnitFileState -eq 'enabled') -and ($u.ActiveState -eq 'active')
    New-CISResult -ControlId '2.4.1.1' -Title $t -Status $(if ($ok) { 'Pass' } else { 'Fail' }) -ExpectedValue 'cron.service enabled y active' -ActualValue "$($u.UnitFileState)/$($u.ActiveState)"
}
function Set-CIS_Debian13_2_4_1_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ((Test-CISPackageInstalled -Name 'cron') -and $PSCmdlet.ShouldProcess('cron.service', '2.4.1.1 - unmask + enable --now')) {
        Invoke-Debian13Systemctl unmask cron.service; Invoke-Debian13Systemctl enable --now cron.service
    }
}

function Test-CIS_Debian13_2_4_1_2 { Test-Debian13CronControl -ControlId '2.4.1.2' -Title 'Ensure access to /etc/crontab is configured' -Path '/etc/crontab' -MaxMode '600' }
function Set-CIS_Debian13_2_4_1_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.2' -Path '/etc/crontab' }
function Test-CIS_Debian13_2_4_1_3 { Test-Debian13CronControl -ControlId '2.4.1.3' -Title 'Ensure access to /etc/cron.hourly is configured' -Path '/etc/cron.hourly' -MaxMode '700' }
function Set-CIS_Debian13_2_4_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.3' -Path '/etc/cron.hourly' }
function Test-CIS_Debian13_2_4_1_4 { Test-Debian13CronControl -ControlId '2.4.1.4' -Title 'Ensure access to /etc/cron.daily is configured' -Path '/etc/cron.daily' -MaxMode '700' }
function Set-CIS_Debian13_2_4_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.4' -Path '/etc/cron.daily' }
function Test-CIS_Debian13_2_4_1_5 { Test-Debian13CronControl -ControlId '2.4.1.5' -Title 'Ensure access to /etc/cron.weekly is configured' -Path '/etc/cron.weekly' -MaxMode '700' }
function Set-CIS_Debian13_2_4_1_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.5' -Path '/etc/cron.weekly' }
function Test-CIS_Debian13_2_4_1_6 { Test-Debian13CronControl -ControlId '2.4.1.6' -Title 'Ensure access to /etc/cron.monthly is configured' -Path '/etc/cron.monthly' -MaxMode '700' }
function Set-CIS_Debian13_2_4_1_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.6' -Path '/etc/cron.monthly' }
function Test-CIS_Debian13_2_4_1_7 { Test-Debian13CronControl -ControlId '2.4.1.7' -Title 'Ensure access to /etc/cron.yearly is configured' -Path '/etc/cron.yearly' -MaxMode '700' }
function Set-CIS_Debian13_2_4_1_7 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.7' -Path '/etc/cron.yearly' }
function Test-CIS_Debian13_2_4_1_8 { Test-Debian13CronControl -ControlId '2.4.1.8' -Title 'Ensure access to /etc/cron.d is configured' -Path '/etc/cron.d' -MaxMode '700' }
function Set-CIS_Debian13_2_4_1_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13CronControl -ControlId '2.4.1.8' -Path '/etc/cron.d' }

# --- 2.4.1.9 crontab / 2.4.2.1 at: archivos allow/deny -------------------------------------

function Test-Debian13GroupExists { param([string]$Name) [bool](Select-String -Path /etc/group -Pattern "^$([regex]::Escape($Name)):" -Quiet -ErrorAction SilentlyContinue) }

function Test-Debian13AllowDenyControl {
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Package,
        [Parameter(Mandatory)][string]$Allow, [Parameter(Mandatory)][string]$Deny, [Parameter(Mandatory)][string[]]$Groups
    )
    if (-not (Test-CISPackageInstalled -Name $Package)) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue "$Package no instalado, o acceso configurado" -ActualValue "$Package no instalado"
    }
    $owners = @($Groups | ForEach-Object { "root:$_" })
    $a = Test-CISPathAccess -Path $Allow -MaxMode '640' -Owner $owners
    $d = Test-CISPathAccess -Path $Deny -MaxMode '640' -Owner $owners
    $problems = @()
    if (-not $a.Exists) { $problems += "$Allow no existe" } elseif (-not $a.Compliant) { $problems += "$Allow ($($a.Owner) $($a.Mode))" }
    if ($d.Exists -and -not $d.Compliant) { $problems += "$Deny ($($d.Owner) $($d.Mode))" }
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue "$Allow existe (0640 o mas restrictivo, root:$($Groups -join ' o root:')); $Deny inexistente o igual" `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { 'conforme' })
}
function Set-Debian13AllowDenyControl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Package, [Parameter(Mandatory)][string]$Allow,
        [Parameter(Mandatory)][string]$Deny, [Parameter(Mandatory)][string]$Group
    )
    if (-not (Test-CISPackageInstalled -Name $Package)) { return }
    foreach ($f in $Allow, $Deny) {
        if ($f -eq $Deny -and -not (Test-Path $f)) { continue }
        if (-not $PSCmdlet.ShouldProcess($f, "$ControlId - crear si falta, chown root:$Group, chmod u-x,g-wx,o-rwx")) { continue }
        if (-not (Test-Path $f)) { New-Item -ItemType File -Path $f | Out-Null }
        & chmod 'u-x,g-wx,o-rwx' $f
        & chown "root:$Group" $f
    }
}

function Test-CIS_Debian13_2_4_1_9 { Test-Debian13AllowDenyControl -ControlId '2.4.1.9' -Title 'Ensure access to crontab is configured' -Package 'cron' -Allow '/etc/cron.allow' -Deny '/etc/cron.deny' -Groups 'root', 'crontab' }
function Set-CIS_Debian13_2_4_1_9 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $g = if (Test-Debian13GroupExists 'crontab') { 'crontab' } else { 'root' }
    Set-Debian13AllowDenyControl -ControlId '2.4.1.9' -Package 'cron' -Allow '/etc/cron.allow' -Deny '/etc/cron.deny' -Group $g
}
function Test-CIS_Debian13_2_4_2_1 { Test-Debian13AllowDenyControl -ControlId '2.4.2.1' -Title 'Ensure access to at is configured' -Package 'at' -Allow '/etc/at.allow' -Deny '/etc/at.deny' -Groups 'daemon', 'root' }
function Set-CIS_Debian13_2_4_2_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $g = if (Test-Debian13GroupExists 'daemon') { 'daemon' } else { 'root' }
    Set-Debian13AllowDenyControl -ControlId '2.4.2.1' -Package 'at' -Allow '/etc/at.allow' -Deny '/etc/at.deny' -Group $g
}
