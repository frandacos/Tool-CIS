# CIS Debian Linux 13 Benchmark v1.0.0 - 5.2 Configure privilege escalation
# (sudo / su). 7 controles. Fuente: cis_debian_13.md, paginas 575-589.
#
# Los cambios a sudoers se hacen en /etc/sudoers.d/60-cis (sin punto en el nombre:
# sudo ignora archivos con '.'), con modo 0440 y validados con `visudo -cf`;
# si la validacion falla se restaura el archivo original (un sudoers roto deja
# al host sin sudo). Riesgo: 5.2.4/5.2.5 pueden dejar sin sudo a cuentas sin
# password (cloud-init); por eso 5.2.4 exige -RemoveNoPasswd.

$script:Debian13SudoersCisFile = '/etc/sudoers.d/60-cis'

function Get-Debian13SudoersFiles {
    @('/etc/sudoers') + $(if (Test-Path '/etc/sudoers.d') { @(Get-ChildItem '/etc/sudoers.d' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object FullName) }) | Where-Object { Test-Path $_ }
}
function Get-Debian13SudoersLines {
    # Lineas (no comentario) de sudoers*, que cumplen <Pattern>: @{File; Line}
    param([Parameter(Mandatory)][string]$Pattern)
    foreach ($f in @(Get-Debian13SudoersFiles)) {
        foreach ($l in @(Get-Content -Path $f -ErrorAction SilentlyContinue)) {
            if ($l -notmatch '^\s*#' -and $l -match $Pattern) { [pscustomobject]@{ File = $f; Line = $l.Trim() } }
        }
    }
}
function Test-Debian13SudoersSyntax {
    param([Parameter(Mandatory)][string]$File)
    & visudo -cf $File 2>&1 | Out-Null
    $LASTEXITCODE -eq 0
}

function Update-Debian13SudoersFile {
    <# Aplica -Transform (string[] -> string[]) a <File>; valida con visudo y revierte si falla. Devuelve $true si cambio algo. #>
    param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][scriptblock]$Transform)
    $exists = Test-Path $File
    $old = if ($exists) { @(Get-Content $File) } else { @() }
    $new = @(& $Transform $old)
    if (($new -join "`n") -eq ($old -join "`n")) { return $false }
    $backup = "$File.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    if ($exists) { Copy-Item $File $backup; & chmod u+w $File }   # sudoers queda 0440 tras cada cambio
    Set-Content -Path $File -Value $new
    if (-not (Test-Debian13SudoersSyntax -File $File)) {
        if ($exists) { Copy-Item $backup $File -Force } else { Remove-Item $File -Force }
        throw "visudo rechazo el cambio en $File (revertido)."
    }
    & chmod 440 $File; & chown root:root $File
    $true
}
function Set-Debian13SudoersDefault {
    # Agrega/reemplaza una linea "Defaults ..." en el archivo propio de CIS.
    param([Parameter(Mandatory)][string]$Line, [Parameter(Mandatory)][string]$KeyPattern)
    Update-Debian13SudoersFile -File $script:Debian13SudoersCisFile -Transform {
        param($lines)
        $out = @($lines | Where-Object { $_ -notmatch $KeyPattern }) + $Line
        $out
    } | Out-Null
}

function Test-CIS_Debian13_5_2_1 {
    $sudo = @(Get-Debian13InstalledPackages -Patterns 'sudo', 'sudo-ldap').Count -gt 0
    $sss = (@(Get-Debian13InstalledPackages -Patterns 'libsss-sudo').Count -gt 0) -and (@(Get-Debian13InstalledPackages -Patterns 'sssd').Count -gt 0)
    New-CISResult -ControlId '5.2.1' -Title 'Ensure sudo is installed' -Status $(if ($sudo -or $sss) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'sudo o sudo-ldap instalado, o libsss-sudo + sssd' -ActualValue "sudo/sudo-ldap=$sudo; libsss-sudo+sssd=$sss"
}
function Set-CIS_Debian13_5_2_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (@(Get-Debian13InstalledPackages -Patterns 'sudo', 'sudo-ldap', 'libsss-sudo').Count -eq 0) { Install-CISPackage -Name 'sudo' }
}

function Test-CIS_Debian13_5_2_2 {
    $on = @(Get-Debian13SudoersLines -Pattern '(?i)^\s*Defaults\s+([^#\r\n]+,\s*)?use_pty\b')
    $off = @(Get-Debian13SudoersLines -Pattern '(?i)^\s*Defaults\s+([^#\r\n]+,\s*)?!use_pty\b')
    New-CISResult -ControlId '5.2.2' -Title 'Ensure sudo commands use pty' -Status $(if ($on.Count -and -not $off.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'Defaults use_pty presente y sin !use_pty' -ActualValue "use_pty: $($on.Count) linea(s); !use_pty: $($off.Count) linea(s)"
}
function Set-CIS_Debian13_5_2_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('sudoers', '5.2.2 - Defaults use_pty y quitar !use_pty')) { return }
    foreach ($f in @(Get-Debian13SudoersLines -Pattern '(?i)^\s*Defaults\s+([^#\r\n]+,\s*)?!use_pty\b' | ForEach-Object File | Select-Object -Unique)) {
        Update-Debian13SudoersFile -File $f -Transform { param($l) $l | ForEach-Object { if ($_ -notmatch '^\s*#' -and $_ -match '(?i)!use_pty\b') { "# $_" } else { $_ } } } | Out-Null
    }
    Set-Debian13SudoersDefault -Line 'Defaults use_pty' -KeyPattern '(?i)^\s*Defaults\s+use_pty\s*$'
}

function Test-CIS_Debian13_5_2_3 {
    $m = @(Get-Debian13SudoersLines -Pattern '(?i)^\s*Defaults\s+([^#]+,\s*)?logfile\s*=\s*["'']?\S+')
    New-CISResult -ControlId '5.2.3' -Title 'Ensure sudo log file exists' -Status $(if ($m.Count) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'Defaults logfile="<ruta>"' -ActualValue $(if ($m.Count) { ($m | ForEach-Object Line) -join ' | ' } else { 'sin logfile' })
}
function Set-CIS_Debian13_5_2_3 {
    [CmdletBinding(SupportsShouldProcess)] param([string]$LogFile = '/var/log/sudo.log')
    if ($PSCmdlet.ShouldProcess($script:Debian13SudoersCisFile, "5.2.3 - Defaults logfile=`"$LogFile`"")) {
        Set-Debian13SudoersDefault -Line "Defaults logfile=`"$LogFile`"" -KeyPattern '(?i)^\s*Defaults\s+logfile\s*='
    }
}

function Test-CIS_Debian13_5_2_4 {
    $m = @(Get-Debian13SudoersLines -Pattern 'NOPASSWD')
    New-CISResult -ControlId '5.2.4' -Title 'Ensure users must provide password for escalation' -Status $(if ($m.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Sin NOPASSWD en sudoers' -ActualValue $(if ($m.Count) { ($m | ForEach-Object { "$($_.File): $($_.Line)" }) -join ' | ' } else { 'sin NOPASSWD' }) `
        -Notes 'No aplica si no se usan passwords para autenticar (ej. cuentas cloud sin password).'
}
# Desviacion: el benchmark dice "remover toda linea con NOPASSWD"; eso eliminaria el permiso de sudo entero.
# Aqui solo se quita la etiqueta NOPASSWD: (la regla queda y pide password). Puede dejar sin sudo a cuentas sin password: exige -RemoveNoPasswd.
function Set-CIS_Debian13_5_2_4 {
    [CmdletBinding(SupportsShouldProcess)] param([switch]$RemoveNoPasswd)
    if (-not $RemoveNoPasswd) {
        Write-Warning '5.2.4: quitar NOPASSWD exige que esas cuentas tengan password; si no, pierden sudo. Verificarlo y reintentar con -RemoveNoPasswd.'; return
    }
    foreach ($f in @(Get-Debian13SudoersLines -Pattern 'NOPASSWD' | ForEach-Object File | Select-Object -Unique)) {
        if ($PSCmdlet.ShouldProcess($f, '5.2.4 - quitar la etiqueta NOPASSWD:')) {
            Update-Debian13SudoersFile -File $f -Transform { param($l) $l | ForEach-Object { if ($_ -notmatch '^\s*#') { $_ -replace 'NOPASSWD\s*:\s*', '' } else { $_ } } } | Out-Null
        }
    }
}

function Test-CIS_Debian13_5_2_5 {
    $m = @(Get-Debian13SudoersLines -Pattern '!authenticate')
    New-CISResult -ControlId '5.2.5' -Title 'Ensure re-authentication for privilege escalation is not disabled globally' -Status $(if ($m.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Sin !authenticate en sudoers' -ActualValue $(if ($m.Count) { ($m | ForEach-Object { "$($_.File): $($_.Line)" }) -join ' | ' } else { 'sin !authenticate' })
}
function Set-CIS_Debian13_5_2_5 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($f in @(Get-Debian13SudoersLines -Pattern '!authenticate' | ForEach-Object File | Select-Object -Unique)) {
        if (-not $PSCmdlet.ShouldProcess($f, '5.2.5 - quitar !authenticate')) { continue }
        Update-Debian13SudoersFile -File $f -Transform {
            param($l)
            $l | ForEach-Object {
                if ($_ -match '^\s*#' -or $_ -notmatch '!authenticate') { $_ }
                else { $n = ($_ -replace '\s*!authenticate\s*,?', ' ') -replace '\s+$', ''; if ($n -match '^\s*Defaults\s*$') { "# $_" } else { $n } }
            }
        } | Out-Null
    }
}

function Get-Debian13SudoDefaultTimeout {
    # Minutos del timestamp_timeout por defecto segun `sudo -V`; $null si no se puede leer.
    $l = (& sudo -V 2>$null) | Where-Object { $_ -match 'timestamp\s+timeout' } | Select-Object -First 1
    if ($l -match '(-?\d+(\.\d+)?)') { [double]$Matches[1] }
}
function Test-CIS_Debian13_5_2_6 {
    $vals = @(Get-Debian13SudoersLines -Pattern 'timestamp_timeout\s*=\s*-?\d+' | ForEach-Object { [regex]::Matches($_.Line, 'timestamp_timeout\s*=\s*(-?\d+)') | ForEach-Object { [int]$_.Groups[1].Value } })
    $usedDefault = $false
    if (-not $vals.Count) { $d = Get-Debian13SudoDefaultTimeout; if ($null -ne $d) { $vals = @($d); $usedDefault = $true } }
    $ok = ($vals.Count -gt 0) -and -not ($vals | Where-Object { $_ -lt 0 -or $_ -gt 15 })
    New-CISResult -ControlId '5.2.6' -Title 'Ensure sudo timestamp_timeout is configured' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'timestamp_timeout entre 0 y 15 minutos (no negativo)' `
        -ActualValue $(if ($vals.Count) { "$($vals -join ', ')$(if ($usedDefault) { ' (por defecto, sudo -V)' })" } else { 'no determinable' })
}
function Set-CIS_Debian13_5_2_6 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess('sudoers', '5.2.6 - timestamp_timeout=15')) { return }
    foreach ($f in @(Get-Debian13SudoersLines -Pattern 'timestamp_timeout\s*=\s*(-\d+|1[6-9]|[2-9]\d|\d{3,})\b' | ForEach-Object File | Select-Object -Unique)) {
        Update-Debian13SudoersFile -File $f -Transform { param($l) $l | ForEach-Object { if ($_ -notmatch '^\s*#') { $_ -replace 'timestamp_timeout\s*=\s*(-\d+|1[6-9]|[2-9]\d|\d{3,})\b', 'timestamp_timeout=15' } else { $_ } } } | Out-Null
    }
    Set-Debian13SudoersDefault -Line 'Defaults timestamp_timeout=15' -KeyPattern '(?i)^\s*Defaults\s+timestamp_timeout\s*='
}

# --- 5.2.7 su restringido con pam_wheel + grupo vacio ------------------------------------------

function Get-Debian13PamSuLines { @(Get-Content '/etc/pam.d/su' -ErrorAction SilentlyContinue) }
function Get-Debian13GroupMembers {
    # Miembros (por nombre) de un grupo de /etc/group; vacio si no tiene o no existe (usar Test-Debian13GroupExists para distinguir).
    param([string]$Name)
    $l = Get-Content /etc/group -ErrorAction SilentlyContinue | Where-Object { $_ -match "^$([regex]::Escape($Name)):" } | Select-Object -First 1
    if ($l) { @(($l -split ':')[3] -split ',' | Where-Object { $_ }) }
}

function Test-CIS_Debian13_5_2_7 {
    $t = 'Ensure access to the su command is restricted'
    $line = Get-Debian13PamSuLines | Where-Object { $_ -match '^\s*auth\s+(required|requisite)\s+pam_wheel\.so\b' -and $_ -match '\buse_uid\b' -and $_ -match '\bgroup=\S+' } | Select-Object -First 1
    if (-not $line) {
        return New-CISResult -ControlId '5.2.7' -Title $t -Status 'Fail' -ExpectedValue 'auth required pam_wheel.so use_uid group=<grupo vacio> en /etc/pam.d/su' -ActualValue 'linea pam_wheel no encontrada'
    }
    $g = if ($line -match '\bgroup=(\S+)') { $Matches[1] }
    $exists = Test-Debian13GroupExists -Name $g
    $members = @(Get-Debian13GroupMembers -Name $g)
    $ok = $exists -and ($members.Count -eq 0)
    New-CISResult -ControlId '5.2.7' -Title $t -Status $(if ($ok) { 'Pass' } else { 'Fail' }) -ExpectedValue 'Grupo de pam_wheel existente y sin miembros' `
        -ActualValue $(if (-not $exists) { "el grupo '$g' no existe" } else { "grupo '$g': $($members.Count) miembro(s)" })
}
function Set-CIS_Debian13_5_2_7 {
    [CmdletBinding(SupportsShouldProcess)] param([string]$Group = 'sugroup')
    if (-not $PSCmdlet.ShouldProcess('/etc/pam.d/su', "5.2.7 - grupo vacio '$Group' y pam_wheel use_uid group=$Group")) { return }
    if (-not (Test-Debian13GroupExists -Name $Group)) { & groupadd $Group }
    Backup-CISFile -Path '/etc/pam.d/su' | Out-Null
    $line = "auth required pam_wheel.so use_uid group=$Group"
    $lines = @(Get-Debian13PamSuLines | Where-Object { $_ -notmatch '^\s*auth\s+(required|requisite)\s+pam_wheel\.so\b' -or $_ -match '^\s*#' })
    $i = [array]::FindIndex([string[]]$lines, [Predicate[string]] { param($x) $x -match '^\s*auth\b' -and $x -notmatch '^\s*#' })
    if ($i -lt 0) { $lines += $line } elseif ($i -eq 0) { $lines = @($line) + $lines } else { $lines = @($lines[0..($i - 1)]) + $line + @($lines[$i..($lines.Count - 1)]) }
    Set-Content -Path '/etc/pam.d/su' -Value $lines
}
