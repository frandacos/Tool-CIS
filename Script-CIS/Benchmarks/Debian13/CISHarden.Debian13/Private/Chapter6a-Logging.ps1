# CIS Debian Linux 13 Benchmark v1.0.0 - 6.1 System Logging (journald, rsyslog y
# archivos de log). 22 controles. Fuente: cis_debian_13.md, paginas 704-764.
#
# Metodo de registro: el benchmark ofrece journald O rsyslog ("IF rsyslog is being
# used..." / "IF journald is the method..."). Aqui se infiere que rsyslog esta en
# uso si el paquete esta instalado; si no, se asume journald. Los controles del
# metodo no elegido dan Pass con nota (no aplican). Para elegir rsyslog hay que
# instalarlo (Set-CIS_Debian13_6_1_2_1 lo hace), tras lo cual los controles 6.1.2.x
# pasan a evaluarse. 7 controles son Manual (politica del sitio).

function Test-Debian13RsyslogInUse { @(Get-Debian13InstalledPackages -Patterns 'rsyslog').Count -gt 0 }
function Get-Debian13RsyslogConfFiles {
    $c = Join-Path $script:Debian13EtcDir 'rsyslog.conf'
    @($c) + @(Get-ChildItem (Join-Path $script:Debian13EtcDir 'rsyslog.d') -Filter '*.conf' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object FullName) | Where-Object { Test-Path $_ }
}
function New-Debian13NotApplicableLogResult {
    param([string]$ControlId, [string]$Title, [string]$Why)
    New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue 'Aplica solo al otro metodo de registro' -ActualValue $Why -Notes 'No aplica segun el metodo de registro inferido (ver cabecera del archivo).'
}
function Restart-Debian13Service { param([string]$Name) Invoke-Debian13Systemctl restart $Name }

# --- 6.1.1.1 systemd-journald ----------------------------------------------------------------------

function Test-CIS_Debian13_6_1_1_1_1 {
    $u = @(Get-Debian13UnitStates -Units 'systemd-journald.service')[0]
    New-CISResult -ControlId '6.1.1.1.1' -Title 'Ensure journald service is active' -Status $(if ($u.ActiveState -eq 'active') { 'Pass' } else { 'Fail' }) -ExpectedValue 'systemd-journald.service active' -ActualValue $u.ActiveState
}
function Set-CIS_Debian13_6_1_1_1_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('systemd-journald.service', '6.1.1.1.1 - unmask + enable --now')) { Invoke-Debian13Systemctl unmask systemd-journald.service; Invoke-Debian13Systemctl enable --now systemd-journald.service }
}

function Test-CIS_Debian13_6_1_1_1_2 {
    New-CISResult -ControlId '6.1.1.1.2' -Title 'Ensure journald log file access is configured' -Status 'ManualReviewRequired' `
        -Notes 'Revisar los permisos de /var/log/journal (0640 o la politica del sitio si es menos restrictiva; /usr/lib/tmpfiles.d/systemd.conf o /etc/tmpfiles.d/systemd.conf).'
}
function Set-CIS_Debian13_6_1_1_1_2 { Write-Warning '6.1.1.1.2: sin remediacion automatizada -- ajustar /etc/tmpfiles.d/systemd.conf segun politica del sitio.' }
function Test-CIS_Debian13_6_1_1_1_3 {
    New-CISResult -ControlId '6.1.1.1.3' -Title 'Ensure journald log file rotation is configured' -Status 'ManualReviewRequired' `
        -Notes 'Revisar SystemMaxUse/SystemKeepFree/RuntimeMaxUse/RuntimeKeepFree/MaxFileSec en journald.conf[.d] segun politica del sitio (ejemplo del benchmark: 1G/500M/200M/50M/1month).'
}
function Set-CIS_Debian13_6_1_1_1_3 { Write-Warning '6.1.1.1.3: sin remediacion automatizada -- definir la rotacion de journald segun politica del sitio.' }

function Test-Debian13JournaldOption {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Option, [Parameter(Mandatory)][scriptblock]$Ok, [Parameter(Mandatory)][string]$Expected)
    $r = Get-CISSystemdConfigValue -ConfName 'systemd/journald.conf' -Block 'Journal' -Option $Option
    $v = if ($r) { $r.Value } else { $null }
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if (& $Ok $v) { 'Pass' } else { 'Fail' }) -ExpectedValue $Expected `
        -ActualValue $(if ($r) { "$Option=$v ($($r.File)$(if ($r.IsDefault) { ', por defecto' }))" } else { "$Option no definido" })
}
function Set-Debian13JournaldOption {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Option, [Parameter(Mandatory)][string]$Value)
    if (-not $PSCmdlet.ShouldProcess('journald.conf', "$Option=$Value y reiniciar systemd-journald")) { return }
    Set-CISSystemdConfigValue -ConfName 'systemd/journald.conf' -Block 'Journal' -Option $Option -Value $Value
    Restart-Debian13Service -Name 'systemd-journald'
}

function Test-CIS_Debian13_6_1_1_1_4 {
    if (Test-Debian13RsyslogInUse) { return New-Debian13NotApplicableLogResult '6.1.1.1.4' 'Ensure journald ForwardToSyslog is disabled' 'rsyslog esta en uso (ForwardToSyslog=yes lo exige 6.1.2.3)' }
    Test-Debian13JournaldOption -ControlId '6.1.1.1.4' -Title 'Ensure journald ForwardToSyslog is disabled' -Option 'ForwardToSyslog' -Ok { param($v) $v -ne 'yes' } -Expected 'ForwardToSyslog distinto de yes'
}
function Set-CIS_Debian13_6_1_1_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13JournaldOption -Option 'ForwardToSyslog' -Value 'no' }
function Test-CIS_Debian13_6_1_1_1_5 { Test-Debian13JournaldOption -ControlId '6.1.1.1.5' -Title 'Ensure journald Storage is configured' -Option 'Storage' -Ok { param($v) $v -eq 'persistent' } -Expected 'Storage=persistent' }
function Set-CIS_Debian13_6_1_1_1_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13JournaldOption -Option 'Storage' -Value 'persistent' }
function Test-CIS_Debian13_6_1_1_1_6 { Test-Debian13JournaldOption -ControlId '6.1.1.1.6' -Title 'Ensure journald Compress is configured' -Option 'Compress' -Ok { param($v) $v -eq 'yes' } -Expected 'Compress=yes' }
function Set-CIS_Debian13_6_1_1_1_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13JournaldOption -Option 'Compress' -Value 'yes' }

# --- 6.1.1.2 systemd-journal-remote / upload -----------------------------------------------------------

function Test-CIS_Debian13_6_1_1_2_1 {
    $t = 'Ensure systemd-journal-remote is installed'
    if (Test-Debian13RsyslogInUse) { return New-Debian13NotApplicableLogResult '6.1.1.2.1' $t 'rsyslog esta en uso (aplica cuando journald es el metodo)' }
    $i = @(Get-Debian13InstalledPackages -Patterns 'systemd-journal-remote').Count -gt 0
    New-CISResult -ControlId '6.1.1.2.1' -Title $t -Status $(if ($i) { 'Pass' } else { 'Fail' }) -ExpectedValue 'systemd-journal-remote instalado' -ActualValue $(if ($i) { 'instalado' } else { 'no instalado' })
}
function Set-CIS_Debian13_6_1_1_2_1 { [CmdletBinding(SupportsShouldProcess)] param() if (-not @(Get-Debian13InstalledPackages -Patterns 'systemd-journal-remote').Count) { Install-CISPackage -Name 'systemd-journal-remote' } }

function Test-CIS_Debian13_6_1_1_2_2 {
    New-CISResult -ControlId '6.1.1.2.2' -Title 'Ensure systemd-journal-upload authentication is configured' -Status 'ManualReviewRequired' `
        -Notes 'Revisar /etc/systemd/journal-upload.conf[.d]: URL y ServerKeyFile/ServerCertificateFile/TrustedCertificateFile segun la politica del sitio.'
}
function Set-CIS_Debian13_6_1_1_2_2 { Write-Warning '6.1.1.2.2: sin remediacion automatizada -- configurar URL y certificados de journal-upload segun politica del sitio.' }

function Test-CIS_Debian13_6_1_1_2_3 {
    $t = 'Ensure systemd-journal-upload is enabled and active'
    if (Test-Debian13RsyslogInUse) { return New-Debian13NotApplicableLogResult '6.1.1.2.3' $t 'rsyslog esta en uso (aplica cuando journald es el metodo)' }
    $u = @(Get-Debian13UnitStates -Units 'systemd-journal-upload.service')[0]
    New-CISResult -ControlId '6.1.1.2.3' -Title $t -Status $(if ($u.UnitFileState -eq 'enabled' -and $u.ActiveState -eq 'active') { 'Pass' } else { 'Fail' }) -ExpectedValue 'enabled y active' -ActualValue "$($u.UnitFileState)/$($u.ActiveState)"
}
function Set-CIS_Debian13_6_1_1_2_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('systemd-journal-upload.service', '6.1.1.2.3 - unmask + enable --now (requiere URL de destino configurada)')) {
        Invoke-Debian13Systemctl unmask systemd-journal-upload.service; Invoke-Debian13Systemctl enable --now systemd-journal-upload.service
    }
}

function Test-CIS_Debian13_6_1_1_2_4 {
    $bad = @(Get-Debian13UnitStates -Units 'systemd-journal-remote.socket', 'systemd-journal-remote.service' | Where-Object { $_.UnitFileState -eq 'enabled' -or $_.ActiveState -eq 'active' })
    New-CISResult -ControlId '6.1.1.2.4' -Title 'Ensure systemd-journal-remote service is not in use' -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'systemd-journal-remote.socket y .service ni enabled ni active' `
        -ActualValue $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.Unit) [$($_.UnitFileState)/$($_.ActiveState)]" }) -join ', ' } else { 'sin uso' })
}
function Set-CIS_Debian13_6_1_1_2_4 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $u = 'systemd-journal-remote.socket', 'systemd-journal-remote.service'
    if ($PSCmdlet.ShouldProcess(($u -join ', '), '6.1.1.2.4 - stop + mask')) { Invoke-Debian13Systemctl stop @u; Invoke-Debian13Systemctl mask @u }
}

# --- 6.1.2 rsyslog --------------------------------------------------------------------------------------------------

function Test-CIS_Debian13_6_1_2_1 {
    $t = 'Ensure rsyslog is installed'
    if (Test-Debian13RsyslogInUse) { return New-CISResult -ControlId '6.1.2.1' -Title $t -Status 'Pass' -ExpectedValue 'rsyslog instalado (si es el metodo elegido)' -ActualValue 'instalado' }
    New-Debian13NotApplicableLogResult '6.1.2.1' $t 'rsyslog no esta instalado: se asume journald como metodo de registro'
}
function Set-CIS_Debian13_6_1_2_1 { [CmdletBinding(SupportsShouldProcess)] param() if (-not (Test-Debian13RsyslogInUse)) { Install-CISPackage -Name 'rsyslog' } }

function Test-CIS_Debian13_6_1_2_2 {
    $t = 'Ensure rsyslog service is enabled and active'
    if (-not (Test-Debian13RsyslogInUse)) { return New-Debian13NotApplicableLogResult '6.1.2.2' $t 'rsyslog no esta en uso' }
    $u = @(Get-Debian13UnitStates -Units 'rsyslog.service')[0]
    New-CISResult -ControlId '6.1.2.2' -Title $t -Status $(if ($u.UnitFileState -eq 'enabled' -and $u.ActiveState -eq 'active') { 'Pass' } else { 'Fail' }) -ExpectedValue 'rsyslog.service enabled y active' -ActualValue "$($u.UnitFileState)/$($u.ActiveState)"
}
function Set-CIS_Debian13_6_1_2_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ((Test-Debian13RsyslogInUse) -and $PSCmdlet.ShouldProcess('rsyslog.service', '6.1.2.2 - unmask + enable --now')) { Invoke-Debian13Systemctl unmask rsyslog.service; Invoke-Debian13Systemctl enable --now rsyslog.service }
}

function Test-CIS_Debian13_6_1_2_3 {
    if (-not (Test-Debian13RsyslogInUse)) { return New-Debian13NotApplicableLogResult '6.1.2.3' 'Ensure journald is configured to send logs to rsyslog' 'rsyslog no esta en uso' }
    Test-Debian13JournaldOption -ControlId '6.1.2.3' -Title 'Ensure journald is configured to send logs to rsyslog' -Option 'ForwardToSyslog' -Ok { param($v) $v -eq 'yes' } -Expected 'ForwardToSyslog=yes'
}
function Set-CIS_Debian13_6_1_2_3 { [CmdletBinding(SupportsShouldProcess)] param() if (Test-Debian13RsyslogInUse) { Set-Debian13JournaldOption -Option 'ForwardToSyslog' -Value 'yes' } }

function Test-CIS_Debian13_6_1_2_4 {
    $t = 'Ensure rsyslog log file creation mode is configured'
    if (-not (Test-Debian13RsyslogInUse)) { return New-Debian13NotApplicableLogResult '6.1.2.4' $t 'rsyslog no esta en uso' }
    $hit = @(Get-Debian13RsyslogConfFiles | ForEach-Object { Select-String -Path $_ -Pattern '^\s*\$FileCreateMode\s+0[0246][024]0\b' } | ForEach-Object { $_.Line.Trim() })
    New-CISResult -ControlId '6.1.2.4' -Title $t -Status $(if ($hit.Count) { 'Pass' } else { 'Fail' }) -ExpectedValue '$FileCreateMode 0640 o mas restrictivo' -ActualValue $(if ($hit.Count) { $hit -join '; ' } else { '$FileCreateMode no configurado' })
}
function Set-CIS_Debian13_6_1_2_4 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $f = Join-Path $script:Debian13EtcDir 'rsyslog.d/50-cis-filecreatemode.conf'
    if ((Test-Debian13RsyslogInUse) -and $PSCmdlet.ShouldProcess($f, '6.1.2.4 - $FileCreateMode 0640 y reiniciar rsyslog')) {
        New-Item -ItemType Directory -Path (Split-Path $f) -Force | Out-Null
        Set-Content -Path $f -Value '$FileCreateMode 0640'
        Restart-Debian13Service -Name 'rsyslog'
    }
}

foreach ($n in '5', '6', '8', '11') {
    $id = "6.1.2.$n"
    $title = @{ '5' = 'Ensure rsyslog logging is configured'; '6' = 'Ensure rsyslog is configured to send logs to a remote log host'; '8' = 'Ensure logrotate is configured'; '11' = 'Ensure rsyslog CA certificates are configured' }[$n]
    $note = @{ '5' = 'Revisar /etc/rsyslog.conf y rsyslog.d/*.conf: que los archivos y facilities/prioridades cumplan la politica de logging del sitio.'
        '6' = 'Verificar que rsyslog envie los logs a un host remoto autorizado (action omfwd / target).'
        '8' = 'Revisar /etc/logrotate.conf y /etc/logrotate.d/* segun la politica de retencion del sitio.'
        '11' = 'Verificar DefaultNetstreamDriverCAFile (global) apuntando a la CA autorizada por el sitio.' }[$n]
    Set-Item -Path "function:script:Test-CIS_Debian13_$($id -replace '\.', '_')" -Value ([scriptblock]::Create("New-CISResult -ControlId '$id' -Title '$title' -Status 'ManualReviewRequired' -Notes '$note'"))
    Set-Item -Path "function:script:Set-CIS_Debian13_$($id -replace '\.', '_')" -Value ([scriptblock]::Create("Write-Warning '$id : sin remediacion automatizada -- configurar segun politica del sitio.'"))
}

function Test-CIS_Debian13_6_1_2_7 {
    $t = 'Ensure rsyslog is not configured to receive logs from a remote client'
    if (-not (Test-Debian13RsyslogInUse)) { return New-Debian13NotApplicableLogResult '6.1.2.7' $t 'rsyslog no esta en uso' }
    $pat = '^\s*module\(load="?imtcp"?\)', '^\s*input\(type="?imtcp"?\b', '^\s*\$ModLoad\s+imtcp\b', '^\s*\$InputTCPServerRun\b'
    $hit = @(Get-Debian13RsyslogConfFiles | ForEach-Object { $f = $_; foreach ($p in $pat) { Select-String -Path $f -Pattern $p } } | ForEach-Object { "$($_.Path): $($_.Line.Trim())" })
    New-CISResult -ControlId '6.1.2.7' -Title $t -Status $(if ($hit.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Sin imtcp / InputTCPServerRun' -ActualValue $(if ($hit.Count) { $hit -join ' | ' } else { 'sin recepcion remota' })
}
function Set-CIS_Debian13_6_1_2_7 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not (Test-Debian13RsyslogInUse)) { return }
    $re = '^\s*(module\(load="?imtcp"?\)|input\(type="?imtcp"?\b|\$ModLoad\s+imtcp\b|\$InputTCPServerRun\b)'
    $changed = $false
    foreach ($f in @(Get-Debian13RsyslogConfFiles | Where-Object { Select-String -Path $_ -Pattern $re -Quiet })) {
        if (-not $PSCmdlet.ShouldProcess($f, '6.1.2.7 - comentar la recepcion remota (imtcp)')) { continue }
        Backup-CISFile -Path $f | Out-Null
        (Get-Content $f) | ForEach-Object { if ($_ -match $re) { "# $_" } else { $_ } } | Set-Content $f; $changed = $true
    }
    if ($changed) { Restart-Debian13Service -Name 'rsyslog' }
}

function Test-CIS_Debian13_6_1_2_9 {
    $i = @(Get-Debian13InstalledPackages -Patterns 'rsyslog-gnutls').Count -gt 0
    New-CISResult -ControlId '6.1.2.9' -Title 'Ensure rsyslog-gnutls is installed' -Status $(if ($i) { 'Pass' } else { 'Fail' }) -ExpectedValue 'rsyslog-gnutls instalado' -ActualValue $(if ($i) { 'instalado' } else { 'no instalado' })
}
function Set-CIS_Debian13_6_1_2_9 { [CmdletBinding(SupportsShouldProcess)] param() if (-not @(Get-Debian13InstalledPackages -Patterns 'rsyslog-gnutls').Count) { Install-CISPackage -Name 'rsyslog-gnutls' } }

function Test-CIS_Debian13_6_1_2_10 {
    $t = 'Ensure rsyslog forwarding uses gtls'
    if (-not (Test-Debian13RsyslogInUse)) { return New-Debian13NotApplicableLogResult '6.1.2.10' $t 'rsyslog no esta en uso' }
    $hit = @(Get-Debian13RsyslogConfFiles | ForEach-Object { Select-String -Path $_ -Pattern 'StreamDriver="gtls"' } | ForEach-Object { "$($_.Path)" })
    New-CISResult -ControlId '6.1.2.10' -Title $t -Status $(if ($hit.Count) { 'Pass' } else { 'Fail' }) -ExpectedValue 'StreamDriver="gtls" en la configuracion de reenvio de rsyslog' -ActualValue $(if ($hit.Count) { "en: $($hit -join ', ')" } else { 'sin StreamDriver="gtls"' })
}
function Set-CIS_Debian13_6_1_2_10 { Write-Warning '6.1.2.10: sin remediacion automatizada -- el reenvio (target, CA, StreamDriverAuthMode) es politica del sitio; ver el ejemplo /etc/rsyslog.d/40-forward.conf del benchmark.' }

# --- 6.1.3 acceso a archivos de log -----------------------------------------------------------------------------------

function Get-Debian13LogFileCandidates {
    # Archivos de /var/log con algun bit de 0137, o no root:root: @{Path; Mode(int); User; Group}
    foreach ($l in @(& find -L /var/log -type f '(' -perm /0137 -o '!' -user root -o '!' -group root ')' -exec stat -Lc '%n:%#a:%U:%G' '{}' + 2>$null)) {
        $p = $l -split ':'
        if ($p.Count -ge 4) { [pscustomobject]@{ Path = ($p[0..($p.Count - 4)] -join ':'); Mode = [Convert]::ToInt32($p[-3], 8); User = $p[-2]; Group = $p[-1] } }
    }
}
function Get-Debian13LogFileRule {
    # Regla del benchmark para un archivo: mascara de permisos prohibidos, usuarios y grupos aceptados (regex) y chmod de reparacion.
    param([Parameter(Mandatory)]$File, [string[]]$ValidShells = @())
    $name = Split-Path $File.Path -Leaf; $dir = Split-Path $File.Path -Parent
    if ($dir -match '/apt$') { return @{ Mask = 0x5B; User = '^root$'; Group = '^(root|adm)$'; Chmod = 'u-x,go-wx' } }
    switch -Regex ($name) {
        '^(lastlog|wtmp|btmp)(\.|-|$)|^README$' { return @{ Mask = 0x4B; User = '^root$'; Group = '^(root|utmp)$'; Chmod = 'ug-x,o-wx' } }
        '^(cloud-init\.log|localmessages|waagent\.log)' { return @{ Mask = 0x5B; User = '^(root|syslog)$'; Group = '^(root|adm)$'; Chmod = 'u-x,go-wx' } }
        '^(secure(\..*|-.*)?|auth\.log|syslog|messages)$' { return @{ Mask = 0x5F; User = '^(root|syslog)$'; Group = '^(root|adm)$'; Chmod = 'u-x,g-wx,o-rwx' } }
        '\.journal~?$' { return @{ Mask = 0x5F; User = '^root$'; Group = '^(root|systemd-journal)$'; Chmod = 'u-x,g-wx,o-rwx' } }
    }
    $u = '^(root|syslog)$'; $g = '^(root|adm)$'
    # Cuentas de servicio (root, o cuyo shell no es valido) pueden ser duenas de sus propios logs.
    $shell = if ($File.User -ne 'root' -and $script:Debian13LogShellLookup) { & $script:Debian13LogShellLookup $File.User }
    if ($File.User -eq 'root' -or ($ValidShells -notcontains $shell)) {
        if ($File.User -notmatch $u) { $u = "^(root|syslog|$([regex]::Escape($File.User)))$" }
        if ($File.Group -notmatch $g) { $g = "^(root|adm|$([regex]::Escape($File.Group)))$" }
    }
    @{ Mask = 0x5F; User = $u; Group = $g; Chmod = 'u-x,g-wx,o-rwx' }
}
function Get-Debian13LogFileViolations {
    $valid = @(Get-Debian13ValidShells)
    foreach ($f in @(Get-Debian13LogFileCandidates)) {
        $r = Get-Debian13LogFileRule -File $f -ValidShells $valid
        $p = @()
        if (($f.Mode -band $r.Mask) -gt 0) { $p += "modo 0$([Convert]::ToString($f.Mode, 8))" }
        if ($f.User -notmatch $r.User) { $p += "owner $($f.User)" }
        if ($f.Group -notmatch $r.Group) { $p += "grupo $($f.Group)" }
        if ($p.Count) { [pscustomobject]@{ Path = $f.Path; Problems = $p; Rule = $r; File = $f } }
    }
}
$script:Debian13LogShellLookup = { param($user) $l = Get-Content (Join-Path $script:Debian13EtcDir 'passwd') -ErrorAction SilentlyContinue | Where-Object { $_ -match "^$([regex]::Escape($user)):" } | Select-Object -First 1; if ($l) { ($l -split ':')[6] } }

function Test-CIS_Debian13_6_1_3_1 {
    $v = @(Get-Debian13LogFileViolations)
    New-CISResult -ControlId '6.1.3.1' -Title 'Ensure access to all logfiles has been configured' -Status $(if ($v.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Archivos de /var/log con permisos y propietarios segun el benchmark' `
        -ActualValue $(if ($v.Count) { (($v | Select-Object -First 15 | ForEach-Object { "$($_.Path): $($_.Problems -join ', ')" }) -join ' | ') + $(if ($v.Count -gt 15) { " ... (+$($v.Count - 15) mas)" }) } else { 'todos conformes' })
}
function Set-CIS_Debian13_6_1_3_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($v in @(Get-Debian13LogFileViolations)) {
        if (-not $PSCmdlet.ShouldProcess($v.Path, "6.1.3.1 - $($v.Problems -join ', ')")) { continue }
        if (($v.File.Mode -band $v.Rule.Mask) -gt 0) { & chmod $v.Rule.Chmod $v.Path }
        if ($v.File.User -notmatch $v.Rule.User) { & chown root $v.Path }
        if ($v.File.Group -notmatch $v.Rule.Group) { & chgrp root $v.Path }
    }
}
