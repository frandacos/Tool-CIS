# CIS Debian Linux 13 Benchmark v1.0.0 - 6.2.1 auditd, 6.2.2 retencion de datos,
# 6.2.4 acceso a archivos de auditd y 6.3 Integrity Checking (AIDE). 21 controles
# (las reglas de auditoria 6.2.3.x van en la Etapa 14). Fuente: cis_debian_13.md,
# paginas 765-937. Todos Level 2 salvo AIDE 6.3.1/6.3.2 (Level 1).
#
# RIESGO: 6.2.2.3 (disk_full_action=halt/single) detiene o degrada el host al llenarse
# el disco de auditoria; 6.2.2.4 con email requiere un MTA. Los cambios de GRUB
# (6.2.1.3/.4) requieren reinicio.

$script:Debian13AuditDir = '/etc/audit'
$script:Debian13SbinDir = '/sbin'
$script:Debian13GrubDropInDir = '/etc/default/grub.d'
$script:Debian13AuditTools = 'auditctl', 'aureport', 'ausearch', 'auditd', 'augenrules'

function Get-Debian13AuditdConfValue {
    param([Parameter(Mandatory)][string]$Key)
    $f = Join-Path $script:Debian13AuditDir 'auditd.conf'
    $l = @(Get-Content $f -ErrorAction SilentlyContinue | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))\s*=\s*\S+" }) | Select-Object -Last 1
    if ($l -match '=\s*(\S+)') { $Matches[1] }
}
function Set-Debian13AuditdConfValue {
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Value)
    $f = Join-Path $script:Debian13AuditDir 'auditd.conf'
    if (Test-Path $f) { Copy-Item $f "$f.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    $done = $false
    $new = foreach ($l in @(Get-Content $f -ErrorAction SilentlyContinue)) {
        if ($l -match "^\s*#?\s*$([regex]::Escape($Key))\s*=") { if (-not $done) { "$Key = $Value"; $done = $true } else { $l } } else { $l }
    }
    if (-not $done) { $new = @($new) + "$Key = $Value" }
    Set-Content -Path $f -Value $new
}
function Get-Debian13AuditLogDir {
    $lf = Get-Debian13AuditdConfValue -Key 'log_file'
    if (-not (Test-Path (Join-Path $script:Debian13AuditDir 'auditd.conf'))) { return $null }
    if ($lf) { Split-Path $lf -Parent } else { '/var/log/audit' }
}
function Invoke-Debian13UpdateGrub { & update-grub 2>&1 | Out-Null }
function Set-Debian13FileAttr {
    # chmod / chown / chgrp (mockeable)
    param([Parameter(Mandatory)][string]$Path, [string]$Chmod, [string]$Chown, [string]$Chgrp)
    if ($Chmod) { & chmod $Chmod $Path }; if ($Chown) { & chown $Chown $Path }; if ($Chgrp) { & chgrp $Chgrp $Path }
}

# --- 6.2.1 auditd ------------------------------------------------------------------------------------

function Test-CIS_Debian13_6_2_1_1 {
    $a = @(Get-Debian13InstalledPackages -Patterns 'auditd').Count -gt 0; $p = @(Get-Debian13InstalledPackages -Patterns 'audispd-plugins').Count -gt 0
    New-CISResult -ControlId '6.2.1.1' -Title 'Ensure auditd packages are installed' -Status $(if ($a -and $p) { 'Pass' } else { 'Fail' }) -ExpectedValue 'auditd y audispd-plugins instalados' -ActualValue "auditd=$a; audispd-plugins=$p"
}
function Set-CIS_Debian13_6_2_1_1 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($p in 'auditd', 'audispd-plugins') { if (-not @(Get-Debian13InstalledPackages -Patterns $p).Count) { Install-CISPackage -Name $p } } }

function Test-CIS_Debian13_6_2_1_2 {
    $u = @(Get-Debian13UnitStates -Units 'auditd.service')[0]
    New-CISResult -ControlId '6.2.1.2' -Title 'Ensure auditd service is enabled and active' -Status $(if ($u.UnitFileState -eq 'enabled' -and $u.ActiveState -eq 'active') { 'Pass' } else { 'Fail' }) -ExpectedValue 'auditd enabled y active' -ActualValue "$($u.UnitFileState)/$($u.ActiveState)"
}
function Set-CIS_Debian13_6_2_1_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('auditd.service', '6.2.1.2 - unmask + enable + start')) { Invoke-Debian13Systemctl unmask auditd.service; Invoke-Debian13Systemctl enable auditd.service; Invoke-Debian13Systemctl start auditd.service }
}

# Ojo: Get-ChildItem <ruta inexistente> -Recurse -Filter se cuelga en PowerShell 7.6; siempre se guarda con Test-Path.
function Get-Debian13GrubLinuxLines { if (-not (Test-Path /boot)) { return @() }; @(Get-ChildItem /boot -Recurse -Filter 'grub.cfg' -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Content $_.FullName | Where-Object { $_ -match '^\s*linux' } }) }
function Test-Debian13GrubParam {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Regex, [Parameter(Mandatory)][string]$Expected)
    $lines = @(Get-Debian13GrubLinuxLines)
    if (-not $lines.Count) { return New-CISResult -ControlId $ControlId -Title $Title -Status 'Error' -Notes 'No se encontraron lineas linux en grub.cfg (bootloader no GRUB?): aplicar el equivalente manualmente.' }
    $bad = @($lines | Where-Object { $_ -notmatch $Regex })
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue $Expected -ActualValue "$($bad.Count) de $($lines.Count) lineas linux sin el parametro"
}
# Deviacion segura: el benchmark propone `GRUB_CMDLINE_LINUX="audit=1"` en un drop-in, lo que REEMPLAZA los parametros de /etc/default/grub (quiet, etc.);
# aqui se ANEXA al valor existente. Requiere update-grub y reinicio.
function Set-Debian13GrubParam {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$FileName, [Parameter(Mandatory)][string]$Param)
    $f = Join-Path $script:Debian13GrubDropInDir $FileName
    if (-not $PSCmdlet.ShouldProcess($f, "$ControlId - agregar $Param a GRUB_CMDLINE_LINUX y update-grub (requiere reinicio)")) { return }
    New-Item -ItemType Directory -Path $script:Debian13GrubDropInDir -Force | Out-Null
    Set-Content -Path $f -Value @('', "GRUB_CMDLINE_LINUX=`"`$GRUB_CMDLINE_LINUX $Param`"")
    Invoke-Debian13UpdateGrub
    Write-Warning "$ControlId : reiniciar el sistema para aplicar $Param."
}
function Test-CIS_Debian13_6_2_1_3 { Test-Debian13GrubParam -ControlId '6.2.1.3' -Title 'Ensure auditing for processes that start prior to auditd is enabled' -Regex '\baudit=1\b' -Expected 'audit=1 en todas las lineas linux de grub.cfg' }
function Set-CIS_Debian13_6_2_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13GrubParam -ControlId '6.2.1.3' -FileName '40-cis-audit.cfg' -Param 'audit=1' }
function Test-CIS_Debian13_6_2_1_4 { Test-Debian13GrubParam -ControlId '6.2.1.4' -Title 'Ensure audit_backlog_limit is configured' -Regex '\baudit_backlog_limit=\d+\b' -Expected 'audit_backlog_limit=N en todas las lineas linux (recomendado >= 8192)' }
function Set-CIS_Debian13_6_2_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13GrubParam -ControlId '6.2.1.4' -FileName '41-cis-audit-backlog.cfg' -Param 'audit_backlog_limit=8192' }

# --- 6.2.2 retencion (auditd.conf) ---------------------------------------------------------------------

function Test-Debian13AuditdConfControl {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][hashtable]$Rules, [Parameter(Mandatory)][string]$Expected)
    $bad = @(); $act = @()
    foreach ($k in $Rules.Keys) { $v = Get-Debian13AuditdConfValue -Key $k; $act += "$k=$v"; if ($null -eq $v -or $v -notmatch $Rules[$k]) { $bad += "$k=$v" } }
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue $Expected -ActualValue $(if ($bad.Count) { "fuera de norma: $($bad -join ', ')" } else { $act -join '; ' })
}
function Set-Debian13AuditdConf {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][hashtable]$Values)
    if (-not $PSCmdlet.ShouldProcess((Join-Path $script:Debian13AuditDir 'auditd.conf'), "$ControlId - $(($Values.Keys | ForEach-Object { "$_=$($Values[$_])" }) -join ', ')")) { return }
    foreach ($k in $Values.Keys) { Set-Debian13AuditdConfValue -Key $k -Value $Values[$k] }
    Invoke-Debian13Systemctl restart auditd
}

# El tamano maximo es politica del sitio: Pass si esta definido explicitamente (numerico); Set exige -SizeMB.
function Test-CIS_Debian13_6_2_2_1 {
    $v = Get-Debian13AuditdConfValue -Key 'max_log_file'
    New-CISResult -ControlId '6.2.2.1' -Title 'Ensure audit log storage size is configured' -Status $(if ($v -match '^\d+$') { 'Pass' } else { 'Fail' }) -ExpectedValue 'max_log_file = <MB> segun politica del sitio' -ActualValue "max_log_file=$v" -Notes 'Verificar que el tamano cumpla la politica del sitio (por defecto 8 MB).'
}
function Set-CIS_Debian13_6_2_2_1 {
    [CmdletBinding(SupportsShouldProcess)] param([int]$SizeMB)
    if (-not $SizeMB) { Write-Warning '6.2.2.1: el tamano es politica del sitio -- reintentar con -SizeMB <N>.'; return }
    Set-Debian13AuditdConf -ControlId '6.2.2.1' -Values @{ max_log_file = "$SizeMB" }
}
function Test-CIS_Debian13_6_2_2_2 { Test-Debian13AuditdConfControl -ControlId '6.2.2.2' -Title 'Ensure audit logs are not automatically deleted' -Rules @{ max_log_file_action = '^keep_logs$' } -Expected 'max_log_file_action = keep_logs' }
function Set-CIS_Debian13_6_2_2_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13AuditdConf -ControlId '6.2.2.2' -Values @{ max_log_file_action = 'keep_logs' } }
function Test-CIS_Debian13_6_2_2_3 { Test-Debian13AuditdConfControl -ControlId '6.2.2.3' -Title 'Ensure system is disabled when audit logs are full' -Rules @{ disk_full_action = '^(halt|single)$'; disk_error_action = '^(syslog|single|halt)$' } -Expected 'disk_full_action halt|single y disk_error_action syslog|single|halt' }
function Set-CIS_Debian13_6_2_2_3 { [CmdletBinding(SupportsShouldProcess)] param([ValidateSet('halt', 'single')][string]$Action = 'halt') Set-Debian13AuditdConf -ControlId '6.2.2.3' -Values @{ disk_full_action = $Action; disk_error_action = $Action } }
function Test-CIS_Debian13_6_2_2_4 { Test-Debian13AuditdConfControl -ControlId '6.2.2.4' -Title 'Ensure system warns when audit logs are low on space' -Rules @{ space_left_action = '^(email|exec|single|halt)$'; admin_space_left_action = '^(single|halt)$' } -Expected 'space_left_action email|exec|single|halt y admin_space_left_action single|halt' }
function Set-CIS_Debian13_6_2_2_4 {
    [CmdletBinding(SupportsShouldProcess)] param([ValidateSet('email', 'exec', 'single', 'halt')][string]$SpaceLeftAction = 'email', [ValidateSet('single', 'halt')][string]$AdminSpaceLeftAction = 'single')
    if ($SpaceLeftAction -eq 'email' -and -not (Get-Command sendmail -ErrorAction SilentlyContinue)) { Write-Warning '6.2.2.4: space_left_action=email requiere un MTA instalado y configurado (no se detecto sendmail).' }
    Set-Debian13AuditdConf -ControlId '6.2.2.4' -Values @{ space_left_action = $SpaceLeftAction; admin_space_left_action = $AdminSpaceLeftAction }
}

# --- 6.2.4 acceso a logs, configuracion y herramientas de auditd -----------------------------------------------

function Test-Debian13AuditAttr {
    <# Kind: mode (MaxMode), owner (root), group (Groups). Paths vacios = Pass. #>
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [string[]]$Paths, [Parameter(Mandatory)][ValidateSet('mode', 'owner', 'group')][string]$Kind, [string]$MaxMode, [string[]]$Groups = @('root'), [string]$Expected)
    $bad = @()
    foreach ($p in @($Paths)) {
        switch ($Kind) {
            'mode' { $m = Get-CISFileMode -Path $p; if ($null -ne $m -and ([Convert]::ToInt32($m, 8) -band (-bnot [Convert]::ToInt32($MaxMode, 8)) -band 511) -gt 0) { $bad += "$p modo $m" } }
            'owner' { $o = Get-CISFileOwner -Path $p; if ($o -and ($o -split ':')[0] -ne 'root') { $bad += "$p owner $(($o -split ':')[0])" } }
            'group' { $o = Get-CISFileOwner -Path $p; if ($o -and $Groups -notcontains ($o -split ':')[1]) { $bad += "$p grupo $(($o -split ':')[1])" } }
        }
    }
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue $Expected -ActualValue $(if ($bad.Count) { $bad -join '; ' } else { 'conforme' })
}
function Get-Debian13AuditLogFiles { $d = Get-Debian13AuditLogDir; if ($d -and (Test-Path $d)) { @(Get-ChildItem $d -File -ErrorAction SilentlyContinue | ForEach-Object FullName) } }
function Get-Debian13AuditConfFiles { if (-not (Test-Path $script:Debian13AuditDir)) { return @() }; @(Get-ChildItem $script:Debian13AuditDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*.conf' -or $_.Name -like '*.rules' } | ForEach-Object FullName) }
function Get-Debian13AuditToolPaths { @($script:Debian13AuditTools | ForEach-Object { Join-Path $script:Debian13SbinDir $_ } | Where-Object { Test-Path $_ }) }
function Test-Debian13AuditLogDirKnown {
    param([string]$ControlId, [string]$Title)
    if ($null -eq (Get-Debian13AuditLogDir)) { New-CISResult -ControlId $ControlId -Title $Title -Status 'Fail' -Notes '/etc/audit/auditd.conf no existe: verificar que auditd este instalado.' }
}

function Test-CIS_Debian13_6_2_4_1 {
    $t = 'Ensure audit log files mode is configured'; $x = Test-Debian13AuditLogDirKnown '6.2.4.1' $t; if ($x) { return $x }
    Test-Debian13AuditAttr -ControlId '6.2.4.1' -Title $t -Paths (Get-Debian13AuditLogFiles) -Kind mode -MaxMode '640' -Expected 'Archivos de log de auditd 0640 o mas restrictivo'
}
function Set-CIS_Debian13_6_2_4_1 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditLogFiles)) { $m = Get-CISFileMode -Path $f; if ($m -and ([Convert]::ToInt32($m, 8) -band 95) -gt 0 -and $PSCmdlet.ShouldProcess($f, '6.2.4.1 - chmod u-x,g-wx,o-rwx')) { Set-Debian13FileAttr -Path $f -Chmod 'u-x,g-wx,o-rwx' } } }
function Test-CIS_Debian13_6_2_4_2 {
    $t = 'Ensure audit log files owner is configured'; $x = Test-Debian13AuditLogDirKnown '6.2.4.2' $t; if ($x) { return $x }
    Test-Debian13AuditAttr -ControlId '6.2.4.2' -Title $t -Paths (Get-Debian13AuditLogFiles) -Kind owner -Expected 'Archivos de log de auditd propiedad de root'
}
function Set-CIS_Debian13_6_2_4_2 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditLogFiles)) { $o = Get-CISFileOwner -Path $f; if ($o -and ($o -split ':')[0] -ne 'root' -and $PSCmdlet.ShouldProcess($f, '6.2.4.2 - chown root')) { Set-Debian13FileAttr -Path $f -Chown 'root' } } }
function Test-CIS_Debian13_6_2_4_3 {
    $t = 'Ensure audit log files group owner is configured'; $x = Test-Debian13AuditLogDirKnown '6.2.4.3' $t; if ($x) { return $x }
    $r = Test-Debian13AuditAttr -ControlId '6.2.4.3' -Title $t -Paths (Get-Debian13AuditLogFiles) -Kind group -Groups 'root', 'adm' -Expected 'log_group = adm (o root) y archivos con grupo root o adm'
    $lg = Get-Debian13AuditdConfValue -Key 'log_group'
    if ($lg -and $lg -notin 'adm', 'root') { $r.Status = 'Fail'; $r.ActualValue = "log_group=$lg; $($r.ActualValue)" }
    $r
}
function Set-CIS_Debian13_6_2_4_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($f in @(Get-Debian13AuditLogFiles)) { $o = Get-CISFileOwner -Path $f; if ($o -and ($o -split ':')[1] -notin 'root', 'adm' -and $PSCmdlet.ShouldProcess($f, '6.2.4.3 - chgrp adm')) { Set-Debian13FileAttr -Path $f -Chgrp 'adm' } }
    $lg = Get-Debian13AuditdConfValue -Key 'log_group'
    if ($lg -notin 'adm', 'root') { Set-Debian13AuditdConf -ControlId '6.2.4.3' -Values @{ log_group = 'adm' } }
}
function Test-CIS_Debian13_6_2_4_4 {
    $t = 'Ensure the audit log file directory mode is configured'; $x = Test-Debian13AuditLogDirKnown '6.2.4.4' $t; if ($x) { return $x }
    Test-Debian13AuditAttr -ControlId '6.2.4.4' -Title $t -Paths (Get-Debian13AuditLogDir) -Kind mode -MaxMode '750' -Expected 'Directorio de logs de auditd 0750 o mas restrictivo'
}
function Set-CIS_Debian13_6_2_4_4 { [CmdletBinding(SupportsShouldProcess)] param() $d = Get-Debian13AuditLogDir; if ($d -and $PSCmdlet.ShouldProcess($d, '6.2.4.4 - chmod g-w,o-rwx')) { Set-Debian13FileAttr -Path $d -Chmod 'g-w,o-rwx' } }

function Test-CIS_Debian13_6_2_4_5 { Test-Debian13AuditAttr -ControlId '6.2.4.5' -Title 'Ensure audit configuration files mode is configured' -Paths (Get-Debian13AuditConfFiles) -Kind mode -MaxMode '640' -Expected 'Archivos .conf/.rules de /etc/audit 0640 o mas restrictivo' }
function Set-CIS_Debian13_6_2_4_5 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditConfFiles)) { $m = Get-CISFileMode -Path $f; if ($m -and ([Convert]::ToInt32($m, 8) -band 95) -gt 0 -and $PSCmdlet.ShouldProcess($f, '6.2.4.5 - chmod u-x,g-wx,o-rwx')) { Set-Debian13FileAttr -Path $f -Chmod 'u-x,g-wx,o-rwx' } } }
function Test-CIS_Debian13_6_2_4_6 { Test-Debian13AuditAttr -ControlId '6.2.4.6' -Title 'Ensure audit configuration files owner is configured' -Paths (Get-Debian13AuditConfFiles) -Kind owner -Expected 'Archivos de configuracion de auditd propiedad de root' }
function Set-CIS_Debian13_6_2_4_6 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditConfFiles)) { $o = Get-CISFileOwner -Path $f; if ($o -and ($o -split ':')[0] -ne 'root' -and $PSCmdlet.ShouldProcess($f, '6.2.4.6 - chown root')) { Set-Debian13FileAttr -Path $f -Chown 'root' } } }
function Test-CIS_Debian13_6_2_4_7 { Test-Debian13AuditAttr -ControlId '6.2.4.7' -Title 'Ensure audit configuration files group owner is configured' -Paths (Get-Debian13AuditConfFiles) -Kind group -Groups 'root' -Expected 'Archivos de configuracion de auditd con grupo root' }
function Set-CIS_Debian13_6_2_4_7 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditConfFiles)) { $o = Get-CISFileOwner -Path $f; if ($o -and ($o -split ':')[1] -ne 'root' -and $PSCmdlet.ShouldProcess($f, '6.2.4.7 - chgrp root')) { Set-Debian13FileAttr -Path $f -Chgrp 'root' } } }
function Test-CIS_Debian13_6_2_4_8 { Test-Debian13AuditAttr -ControlId '6.2.4.8' -Title 'Ensure audit tools mode is configured' -Paths (Get-Debian13AuditToolPaths) -Kind mode -MaxMode '755' -Expected 'Herramientas de auditd 0755 o mas restrictivo' }
function Set-CIS_Debian13_6_2_4_8 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditToolPaths)) { $m = Get-CISFileMode -Path $f; if ($m -and ([Convert]::ToInt32($m, 8) -band 18) -gt 0 -and $PSCmdlet.ShouldProcess($f, '6.2.4.8 - chmod go-w')) { Set-Debian13FileAttr -Path $f -Chmod 'go-w' } } }
function Test-CIS_Debian13_6_2_4_9 { Test-Debian13AuditAttr -ControlId '6.2.4.9' -Title 'Ensure audit tools owner is configured' -Paths (Get-Debian13AuditToolPaths) -Kind owner -Expected 'Herramientas de auditd propiedad de root' }
function Set-CIS_Debian13_6_2_4_9 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditToolPaths)) { $o = Get-CISFileOwner -Path $f; if ($o -and ($o -split ':')[0] -ne 'root' -and $PSCmdlet.ShouldProcess($f, '6.2.4.9 - chown root')) { Set-Debian13FileAttr -Path $f -Chown 'root' } } }
function Test-CIS_Debian13_6_2_4_10 { Test-Debian13AuditAttr -ControlId '6.2.4.10' -Title 'Ensure audit tools group owner is configured' -Paths (Get-Debian13AuditToolPaths) -Kind group -Groups 'root' -Expected 'Herramientas de auditd con grupo root' }
function Set-CIS_Debian13_6_2_4_10 { [CmdletBinding(SupportsShouldProcess)] param() foreach ($f in @(Get-Debian13AuditToolPaths)) { $o = Get-CISFileOwner -Path $f; if ($o -and ($o -split ':')[1] -ne 'root' -and $PSCmdlet.ShouldProcess($f, '6.2.4.10 - chgrp root')) { Set-Debian13FileAttr -Path $f -Chgrp 'root' } } }

# --- 6.3 AIDE -----------------------------------------------------------------------------------------------------------

function Test-CIS_Debian13_6_3_1 {
    $a = @(Get-Debian13InstalledPackages -Patterns 'aide').Count -gt 0; $c = @(Get-Debian13InstalledPackages -Patterns 'aide-common').Count -gt 0
    New-CISResult -ControlId '6.3.1' -Title 'Ensure AIDE is installed' -Status $(if ($a -and $c) { 'Pass' } else { 'Fail' }) -ExpectedValue 'aide y aide-common instalados' -ActualValue "aide=$a; aide-common=$c"
}
function Set-CIS_Debian13_6_3_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('aide, aide-common', '6.3.1 - apt install y aideinit (si no hay base de datos)')) { return }
    foreach ($p in 'aide', 'aide-common') { if (-not @(Get-Debian13InstalledPackages -Patterns $p).Count) { Install-CISPackage -Name $p } }
    if (-not (Test-Path '/var/lib/aide/aide.db')) { & aideinit 2>&1 | Out-Null; if (Test-Path '/var/lib/aide/aide.db.new') { Move-Item '/var/lib/aide/aide.db.new' '/var/lib/aide/aide.db' } }
}
function Test-CIS_Debian13_6_3_2 {
    $u = @(Get-Debian13UnitStates -Units 'dailyaidecheck.timer', 'dailyaidecheck.service')
    $t = $u | Where-Object Unit -EQ 'dailyaidecheck.timer'; $s = $u | Where-Object Unit -EQ 'dailyaidecheck.service'
    $ok = ($t.UnitFileState -eq 'enabled') -and ($t.ActiveState -eq 'active') -and ($s.UnitFileState -in 'static', 'enabled')
    New-CISResult -ControlId '6.3.2' -Title 'Ensure filesystem integrity is regularly checked' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) -ExpectedValue 'dailyaidecheck.timer enabled y active; .service static o enabled' `
        -ActualValue "timer=$($t.UnitFileState)/$($t.ActiveState); service=$($s.UnitFileState)"
}
function Set-CIS_Debian13_6_3_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('dailyaidecheck.timer', '6.3.2 - unmask + enable --now')) { Invoke-Debian13Systemctl unmask dailyaidecheck.timer dailyaidecheck.service; Invoke-Debian13Systemctl enable --now dailyaidecheck.timer }
}

function Get-Debian13AideConfFiles { @('/etc/aide/aide.conf') + @(Get-ChildItem '/etc/aide/aide.conf.d' -File -ErrorAction SilentlyContinue | ForEach-Object FullName) | Where-Object { Test-Path $_ } }
function Resolve-Debian13AuditToolRealPath { param([string]$Tool) $r = (& readlink -f (Join-Path $script:Debian13SbinDir $Tool) 2>$null); if ($r) { "$r".Trim() } else { Join-Path $script:Debian13SbinDir $Tool } }
$script:Debian13AideItems = 'p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'
function Test-CIS_Debian13_6_3_3 {
    $t = 'Ensure cryptographic mechanisms are used to protect the integrity of audit tools'
    if (-not @(Get-Debian13InstalledPackages -Patterns 'aide').Count) { return New-CISResult -ControlId '6.3.3' -Title $t -Status 'Fail' -Notes 'AIDE no esta instalado (ver 6.3.1).' }
    $lines = @(Get-Debian13AideConfFiles | ForEach-Object { Get-Content $_ -ErrorAction SilentlyContinue } | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '^\s*\S+\s+\S+' })
    $problems = @()
    foreach ($tool in $script:Debian13AuditTools) {
        $path = Resolve-Debian13AuditToolRealPath -Tool $tool
        $l = $lines | Where-Object { ($_ -split '\s+' | Where-Object { $_ } | Select-Object -First 1) -eq $path } | Select-Object -Last 1
        if (-not $l) { $problems += "$path sin regla en aide.conf"; continue }
        $opts = @(($l.Trim() -split '\s+')[1] -split '\+')
        $missing = @($script:Debian13AideItems | Where-Object { $opts -notcontains $_ })
        if ($missing.Count) { $problems += "${path}: faltan $($missing -join ',')" }
    }
    New-CISResult -ControlId '6.3.3' -Title $t -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Cada herramienta de auditd en aide.conf con p+i+n+u+g+s+b+acl+xattrs+sha512' -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { 'las 5 herramientas conformes' })
}
function Set-CIS_Debian13_6_3_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $f = '/etc/aide/aide.conf'
    if (-not $PSCmdlet.ShouldProcess($f, '6.3.3 - agregar reglas de las herramientas de auditd')) { return }
    Backup-CISFile -Path $f | Out-Null
    $add = @('', '# Audit Tools') + @($script:Debian13AuditTools | ForEach-Object { "$(Resolve-Debian13AuditToolRealPath -Tool $_) $($script:Debian13AideItems -join '+')" })
    Add-Content -Path $f -Value $add
}
