# CIS Debian Linux 13 Benchmark v1.0.0 - 7 System Maintenance: 7.1 archivos de
# sistema y de directorio, 7.2 usuarios y grupos locales. 23 controles.
# Fuente: cis_debian_13.md, paginas 938-1000 (aprox.).
#
# Set-*: solo se corrige lo inequivoco (permisos/propietarios, pwconv, bloqueo de
# cuentas sin password, home/dot files de usuarios interactivos, world-writable).
# Duplicados, GIDs inexistentes, archivos sin dueno y demas casos que requieren
# decidir quedan como advertencia. 7.1.13 es Manual.

$script:Debian13WorldWritableExcludeFs = 'nfs|proc|cifs|smb|vfat|iso9660|efivarfs|selinuxfs|ncpfs'

# --- 7.1.1-7.1.10 permisos de archivos de cuentas ---------------------------------------------

function Test-Debian13SecFile {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string[]]$Paths, [Parameter(Mandatory)][string]$MaxMode, [string[]]$Owners = @('root:root'))
    $bad = @($Paths | ForEach-Object { Test-CISPathAccess -Path $_ -MaxMode $MaxMode -Owner $Owners } | Where-Object { -not $_.Compliant })
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue "$($Owners -join ' o '), modo $MaxMode o mas restrictivo (si existe)" `
        -ActualValue $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.Path) ($($_.Owner) $($_.Mode))" }) -join '; ' } else { 'conforme' })
}
function Set-Debian13SecFile {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string[]]$Paths, [Parameter(Mandatory)][string]$MaxMode, [Parameter(Mandatory)][string]$Chmod, [Parameter(Mandatory)][string[]]$Owners, [Parameter(Mandatory)][string]$DefaultOwner)
    foreach ($p in $Paths) {
        $r = Test-CISPathAccess -Path $p -MaxMode $MaxMode -Owner $Owners
        if ($r.Exists -and -not $r.Compliant -and $PSCmdlet.ShouldProcess($p, "$ControlId - chmod $Chmod; chown $DefaultOwner")) {
            & chmod $Chmod $p
            if ($Owners -notcontains $r.Owner) { & chown $DefaultOwner $p }
        }
    }
}
function Get-Debian13EtcPath { param([string]$Name) Join-Path $script:Debian13EtcDir $Name }

$script:Debian13SecFiles = [ordered]@{
    '7.1.1'  = @{ Files = 'passwd'; Mode = '644'; Chmod = 'u-x,go-wx'; Owners = 'root:root'; Def = 'root:root' }
    '7.1.2'  = @{ Files = 'passwd-'; Mode = '644'; Chmod = 'u-x,go-wx'; Owners = 'root:root'; Def = 'root:root' }
    '7.1.3'  = @{ Files = 'group'; Mode = '644'; Chmod = 'u-x,go-wx'; Owners = 'root:root'; Def = 'root:root' }
    '7.1.4'  = @{ Files = 'group-'; Mode = '644'; Chmod = 'u-x,go-wx'; Owners = 'root:root'; Def = 'root:root' }
    '7.1.5'  = @{ Files = 'shadow'; Mode = '640'; Chmod = 'u-x,g-wx,o-rwx'; Owners = 'root:root', 'root:shadow'; Def = 'root:shadow' }
    '7.1.6'  = @{ Files = 'shadow-'; Mode = '640'; Chmod = 'u-x,g-wx,o-rwx'; Owners = 'root:root', 'root:shadow'; Def = 'root:shadow' }
    '7.1.7'  = @{ Files = 'gshadow'; Mode = '640'; Chmod = 'u-x,g-wx,o-rwx'; Owners = 'root:root', 'root:shadow'; Def = 'root:shadow' }
    '7.1.8'  = @{ Files = 'gshadow-'; Mode = '640'; Chmod = 'u-x,g-wx,o-rwx'; Owners = 'root:root', 'root:shadow'; Def = 'root:shadow' }
    '7.1.9'  = @{ Files = 'shells'; Mode = '644'; Chmod = 'u-x,go-wx'; Owners = 'root:root'; Def = 'root:root' }
    '7.1.10' = @{ Files = 'security/opasswd', 'security/opasswd.old'; Mode = '600'; Chmod = 'u-x,go-rwx'; Owners = 'root:root'; Def = 'root:root' }
}
$script:Debian13SecFileTitles = @{
    '7.1.1' = 'Ensure access to /etc/passwd is configured'; '7.1.2' = 'Ensure access to /etc/passwd- is configured'; '7.1.3' = 'Ensure access to /etc/group is configured'
    '7.1.4' = 'Ensure access to /etc/group- is configured'; '7.1.5' = 'Ensure access to /etc/shadow is configured'; '7.1.6' = 'Ensure access to /etc/shadow- is configured'
    '7.1.7' = 'Ensure access to /etc/gshadow is configured'; '7.1.8' = 'Ensure access to /etc/gshadow- is configured'; '7.1.9' = 'Ensure access to /etc/shells is configured'
    '7.1.10' = 'Ensure access to /etc/security/opasswd is configured'
}
foreach ($id in $script:Debian13SecFiles.Keys) {
    $suffix = $id -replace '\.', '_'
    Set-Item -Path "function:script:Test-CIS_Debian13_$suffix" -Value ([scriptblock]::Create("`$d = `$script:Debian13SecFiles['$id']; Test-Debian13SecFile -ControlId '$id' -Title `$script:Debian13SecFileTitles['$id'] -Paths @(`$d.Files | ForEach-Object { Get-Debian13EtcPath `$_ }) -MaxMode `$d.Mode -Owners `$d.Owners"))
    Set-Item -Path "function:script:Set-CIS_Debian13_$suffix" -Value ([scriptblock]::Create("[CmdletBinding(SupportsShouldProcess)] param() `$d = `$script:Debian13SecFiles['$id']; Set-Debian13SecFile -ControlId '$id' -Paths @(`$d.Files | ForEach-Object { Get-Debian13EtcPath `$_ }) -MaxMode `$d.Mode -Chmod `$d.Chmod -Owners `$d.Owners -DefaultOwner `$d.Def"))
}

# --- 7.1.11 world writable / 7.1.12 sin dueno / 7.1.13 SUID-SGID -------------------------------------

function Get-Debian13LocalMounts {
    @(& findmnt -Dkerno fstype,target 2>$null | ForEach-Object { $f = $_ -split '\s+', 2; if ($f[0] -notmatch "^($script:Debian13WorldWritableExcludeFs)" -and $f[1] -notmatch '^(/run|/tmp|/var/tmp)(/|$)') { $f[1] } })
}
function Invoke-Debian13FindPruned {
    # find en <Mount> excluyendo rutas de contenedores/sistema; -Expr son los argumentos de seleccion.
    param([string]$Mount, [string[]]$Expr)
    & find $Mount -mount -xdev '(' -path '*/containers/storage/*' -o -path '*/containerd/*' -o -path '*/kubelet/*' -o -path '/sys/*' -o -path '/snap/*' -o -path '/boot/efi/*' ')' -prune -o @Expr -print 2>$null
}
function Get-Debian13WorldWritable {
    $files = @(); $dirs = @()
    foreach ($m in @(Get-Debian13LocalMounts)) {
        foreach ($p in @(Invoke-Debian13FindPruned -Mount $m -Expr '(', '-type', 'f', '-o', '-type', 'd', ')', '-perm', '-0002')) {
            if (Test-Path -LiteralPath $p -PathType Leaf) { $files += $p }
            elseif (Test-Path -LiteralPath $p -PathType Container) { $mode = Get-CISFileMode -Path $p; if ($mode -and ([Convert]::ToInt32($mode, 8) -band 512) -eq 0) { $dirs += $p } }
        }
    }
    [pscustomobject]@{ Files = $files; Dirs = $dirs }
}
function Test-CIS_Debian13_7_1_11 {
    $w = Get-Debian13WorldWritable
    $p = @(); if ($w.Files.Count) { $p += "$($w.Files.Count) archivo(s) world-writable: $(($w.Files | Select-Object -First 5) -join ', ')" }; if ($w.Dirs.Count) { $p += "$($w.Dirs.Count) directorio(s) world-writable sin sticky bit: $(($w.Dirs | Select-Object -First 5) -join ', ')" }
    New-CISResult -ControlId '7.1.11' -Title 'Ensure world writable files and directories are secured' -Status $(if ($p.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Sin archivos world-writable ni directorios world-writable sin sticky bit' -ActualValue $(if ($p.Count) { $p -join '; ' } else { 'conforme' }) -Notes 'La busqueda recorre todos los filesystems locales y puede tardar.'
}
function Set-CIS_Debian13_7_1_11 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $w = Get-Debian13WorldWritable
    foreach ($f in $w.Files) { if ($PSCmdlet.ShouldProcess($f, '7.1.11 - chmod o-w')) { & chmod 'o-w' $f } }
    foreach ($d in $w.Dirs) { if ($PSCmdlet.ShouldProcess($d, '7.1.11 - chmod a+t (sticky bit)')) { & chmod 'a+t' $d } }
}

function Get-Debian13UnownedFiles {
    foreach ($m in @(Get-Debian13LocalMounts)) { Invoke-Debian13FindPruned -Mount $m -Expr '(', '-type', 'f', '-o', '-type', 'd', ')', '(', '-nouser', '-o', '-nogroup', ')' }
}
function Test-CIS_Debian13_7_1_12 {
    $u = @(Get-Debian13UnownedFiles)
    New-CISResult -ControlId '7.1.12' -Title 'Ensure no files or directories without an owner and a group exist' -Status $(if ($u.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Sin archivos ni directorios huerfanos (nouser/nogroup)' `
        -ActualValue $(if ($u.Count) { "$($u.Count): $(($u | Select-Object -First 8) -join ', ')" } else { 'conforme' }) -Notes 'La busqueda recorre todos los filesystems locales y puede tardar.'
}
function Set-CIS_Debian13_7_1_12 { Write-Warning '7.1.12: sin remediacion automatizada -- eliminar los archivos o asignarles un usuario/grupo activo segun corresponda.' }
function Test-CIS_Debian13_7_1_13 {
    New-CISResult -ControlId '7.1.13' -Title 'Ensure SUID and SGID files are reviewed' -Status 'ManualReviewRequired' -Notes 'Revisar la lista de binarios SUID/SGID (find <particion> -xdev -perm /6000 -type f) y confirmar que cada uno es necesario segun la politica del sitio.'
}
function Set-CIS_Debian13_7_1_13 { Write-Warning '7.1.13: sin remediacion automatizada -- revisar los archivos SUID/SGID.' }

# --- 7.2.1-7.2.8 consistencia de cuentas y grupos -------------------------------------------------------

function Get-Debian13ShadowRaw { foreach ($l in @(Get-Content (Get-Debian13EtcPath 'shadow') -ErrorAction SilentlyContinue)) { $f = $l -split ':'; if ($f.Count -ge 2) { [pscustomobject]@{ Name = $f[0]; Hash = $f[1] } } } }
function Get-Debian13GroupRaw { foreach ($l in @(Get-Content (Get-Debian13EtcPath 'group') -ErrorAction SilentlyContinue)) { $f = $l -split ':'; if ($f.Count -ge 3) { [pscustomobject]@{ Name = $f[0]; Gid = [int]$f[2]; Members = $(if ($f.Count -ge 4) { @($f[3] -split ',' | Where-Object { $_ }) } else { @() }) } } } }
function Get-Debian13PasswdRaw { foreach ($l in @(Get-Content (Get-Debian13EtcPath 'passwd') -ErrorAction SilentlyContinue)) { $f = $l -split ':'; if ($f.Count -ge 7) { [pscustomobject]@{ Name = $f[0]; Pw = $f[1]; Uid = [int]$f[2]; Gid = [int]$f[3]; Home = $f[5]; Shell = $f[6] } } } }
function Invoke-Debian13Passwd { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) & passwd @Arguments 2>&1 | Out-Null }
function Invoke-Debian13Pwconv { & pwconv 2>&1 | Out-Null }

function Test-CIS_Debian13_7_2_1 {
    $x = @(Get-Debian13PasswdRaw | Where-Object { $_.Pw -ne 'x' })
    New-CISResult -ControlId '7.2.1' -Title 'Ensure accounts in /etc/passwd use shadowed passwords' -Status $(if ($x.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Todas las cuentas con "x" en el campo de password' -ActualValue $(if ($x.Count) { "sin shadow: $((($x | ForEach-Object Name) -join ', '))" } else { 'conforme' })
}
function Set-CIS_Debian13_7_2_1 { [CmdletBinding(SupportsShouldProcess)] param() if ($PSCmdlet.ShouldProcess('/etc/passwd', '7.2.1 - pwconv')) { Invoke-Debian13Pwconv } }

function Test-CIS_Debian13_7_2_2 {
    $x = @(Get-Debian13ShadowRaw | Where-Object { $_.Hash -eq '' })
    New-CISResult -ControlId '7.2.2' -Title 'Ensure /etc/shadow password fields are not empty' -Status $(if ($x.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Ninguna cuenta con password vacio' -ActualValue $(if ($x.Count) { "sin password: $((($x | ForEach-Object Name) -join ', '))" } else { 'conforme' })
}
function Set-CIS_Debian13_7_2_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($u in @(Get-Debian13ShadowRaw | Where-Object { $_.Hash -eq '' })) { if ($PSCmdlet.ShouldProcess($u.Name, '7.2.2 - passwd -l (bloquear hasta investigar)')) { Invoke-Debian13Passwd '-l' $u.Name } }
}

function Test-CIS_Debian13_7_2_3 {
    $gids = @(Get-Debian13GroupRaw | ForEach-Object Gid)
    $x = @(Get-Debian13PasswdRaw | Where-Object { $gids -notcontains $_.Gid })
    New-CISResult -ControlId '7.2.3' -Title 'Ensure all groups in /etc/passwd exist in /etc/group' -Status $(if ($x.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Todo GID primario existe en /etc/group' -ActualValue $(if ($x.Count) { ($x | ForEach-Object { "$($_.Name) (GID $($_.Gid))" }) -join ', ' } else { 'conforme' })
}
function Set-CIS_Debian13_7_2_3 { Write-Warning '7.2.3: sin remediacion automatizada -- crear el grupo o corregir el GID de cada cuenta segun corresponda.' }

function Test-CIS_Debian13_7_2_4 {
    $sh = Get-Debian13GroupRaw | Where-Object Name -EQ 'shadow' | Select-Object -First 1
    $members = if ($sh) { @($sh.Members) } else { @() }
    $prim = if ($sh) { @(Get-Debian13PasswdRaw | Where-Object { $_.Gid -eq $sh.Gid }) } else { @() }
    $p = @(); if ($members.Count) { $p += "miembros: $($members -join ', ')" }; if ($prim.Count) { $p += "grupo primario de: $((($prim | ForEach-Object Name) -join ', '))" }
    New-CISResult -ControlId '7.2.4' -Title 'Ensure shadow group is empty' -Status $(if ($p.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Grupo shadow sin miembros ni usuarios con shadow como grupo primario' -ActualValue $(if ($p.Count) { $p -join '; ' } else { 'conforme' })
}
function Set-CIS_Debian13_7_2_4 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $f = Get-Debian13EtcPath 'group'
    if (@(Get-Debian13GroupRaw | Where-Object { $_.Name -eq 'shadow' -and $_.Members.Count }).Count -and $PSCmdlet.ShouldProcess($f, '7.2.4 - vaciar la lista de miembros de shadow')) {
        Copy-Item $f "$f.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        (Get-Content $f) | ForEach-Object { if ($_ -match '^shadow:') { ($_ -replace '^(shadow:[^:]*:[^:]*:).*$', '$1') } else { $_ } } | Set-Content $f
    }
    if (@(Get-Debian13PasswdRaw | Where-Object { $_.Gid -eq ((Get-Debian13GroupRaw | Where-Object Name -EQ 'shadow' | Select-Object -First 1).Gid) }).Count) { Write-Warning '7.2.4: hay usuarios con shadow como grupo primario -- cambiarlo con "usermod -g <grupo> <usuario>".' }
}

function Test-Debian13Duplicates {
    param([string]$ControlId, [string]$Title, [object[]]$Items, [string]$Prop, [string]$Label)
    $dup = @($Items | Group-Object $Prop | Where-Object Count -GT 1)
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($dup.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue "Sin $Label duplicados" -ActualValue $(if ($dup.Count) { ($dup | ForEach-Object { "$($_.Name): $(($_.Group | ForEach-Object Name) -join ', ')" }) -join ' | ' } else { 'conforme' })
}
function Test-CIS_Debian13_7_2_5 { Test-Debian13Duplicates -ControlId '7.2.5' -Title 'Ensure no duplicate UIDs exist' -Items @(Get-Debian13PasswdRaw) -Prop 'Uid' -Label 'UID' }
function Test-CIS_Debian13_7_2_6 { Test-Debian13Duplicates -ControlId '7.2.6' -Title 'Ensure no duplicate GIDs exist' -Items @(Get-Debian13GroupRaw) -Prop 'Gid' -Label 'GID' }
function Test-CIS_Debian13_7_2_7 { Test-Debian13Duplicates -ControlId '7.2.7' -Title 'Ensure no duplicate user names exist' -Items @(Get-Debian13PasswdRaw) -Prop 'Name' -Label 'nombres de usuario' }
function Test-CIS_Debian13_7_2_8 { Test-Debian13Duplicates -ControlId '7.2.8' -Title 'Ensure no duplicate group names exist' -Items @(Get-Debian13GroupRaw) -Prop 'Name' -Label 'nombres de grupo' }
function Set-CIS_Debian13_7_2_5 { Write-Warning '7.2.5: sin remediacion automatizada -- asignar UIDs unicos y revisar los archivos de cada cuenta.' }
function Set-CIS_Debian13_7_2_6 { Write-Warning '7.2.6: sin remediacion automatizada -- asignar GIDs unicos y revisar los archivos de cada grupo.' }
function Set-CIS_Debian13_7_2_7 { Write-Warning '7.2.7: sin remediacion automatizada -- renombrar las cuentas duplicadas.' }
function Set-CIS_Debian13_7_2_8 { Write-Warning '7.2.8: sin remediacion automatizada -- renombrar los grupos duplicados.' }

# --- 7.2.9 / 7.2.10 usuarios interactivos ---------------------------------------------------------------------------

function Get-Debian13InteractiveUsers { $valid = Get-Debian13ValidShells; @(Get-Debian13PasswdRaw | Where-Object { $valid -contains $_.Shell }) }
function Test-Debian13ModeRestrictive { param($Mode, [int]$Mask) $null -ne $Mode -and (([Convert]::ToInt32($Mode, 8) -band $Mask) -eq 0) }

function Get-Debian13HomeProblems {
    foreach ($u in @(Get-Debian13InteractiveUsers)) {
        if (-not (Test-Path -LiteralPath $u.Home -PathType Container)) { [pscustomobject]@{ User = $u; Kind = 'missing'; Detail = "$($u.Name): home $($u.Home) no existe" }; continue }
        $own = (Get-CISFileOwner -Path $u.Home); $mode = Get-CISFileMode -Path $u.Home
        if ($own -and ($own -split ':')[0] -ne $u.Name) { [pscustomobject]@{ User = $u; Kind = 'owner'; Detail = "$($u.Name): $($u.Home) pertenece a $(($own -split ':')[0])" } }
        if ($mode -and -not (Test-Debian13ModeRestrictive $mode 23)) { [pscustomobject]@{ User = $u; Kind = 'mode'; Detail = "$($u.Name): $($u.Home) modo $mode (max 0750)" } }
    }
}
function Test-CIS_Debian13_7_2_9 {
    $p = @(Get-Debian13HomeProblems)
    New-CISResult -ControlId '7.2.9' -Title 'Ensure local interactive user home directories are configured' -Status $(if ($p.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Home existente, propiedad del usuario y modo 0750 o mas restrictivo' -ActualValue $(if ($p.Count) { ($p | ForEach-Object Detail) -join '; ' } else { 'conforme' })
}
function Set-CIS_Debian13_7_2_9 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($p in @(Get-Debian13HomeProblems)) {
        switch ($p.Kind) {
            'owner' { if ($PSCmdlet.ShouldProcess($p.User.Home, "7.2.9 - chown $($p.User.Name)")) { & chown $p.User.Name $p.User.Home } }
            'mode' { if ($PSCmdlet.ShouldProcess($p.User.Home, '7.2.9 - chmod g-w,o-rwx')) { & chmod 'g-w,o-rwx' $p.User.Home } }
            'missing' { Write-Warning "7.2.9: $($p.Detail) -- bloquear la cuenta, eliminarla o crear el directorio segun politica del sitio." }
        }
    }
}

function Get-Debian13HomeDotFiles { param([string]$HomeDir) @(& find $HomeDir -xdev -type f -name '.*' 2>$null) }
function Get-Debian13DotFileProblems {
    $groups = @{}; foreach ($g in @(Get-Debian13GroupRaw)) { $groups[$g.Gid] = $g.Name }
    foreach ($u in @(Get-Debian13InteractiveUsers)) {
        if (-not (Test-Path -LiteralPath $u.Home -PathType Container)) { continue }
        $grp = $groups[$u.Gid]
        foreach ($f in @(Get-Debian13HomeDotFiles -HomeDir $u.Home)) {
            $name = Split-Path $f -Leaf
            if ($name -in '.forward', '.rhost') { [pscustomobject]@{ User = $u; File = $f; Fix = 'none'; Detail = "$f existe" }; continue }
            $mask = if ($name -in '.netrc', '.bash_history') { 127 } else { 91 }   # 0177 / 0133
            $mode = Get-CISFileMode -Path $f; $own = Get-CISFileOwner -Path $f
            $p = @()
            if ($mode -and -not (Test-Debian13ModeRestrictive $mode $mask)) { $p += "modo $mode" }
            if ($own -and ($own -split ':')[0] -ne $u.Name) { $p += "owner $(($own -split ':')[0])" }
            if ($own -and $grp -and ($own -split ':')[1] -ne $grp) { $p += "grupo $(($own -split ':')[1])" }
            if ($p.Count) { [pscustomobject]@{ User = $u; File = $f; Fix = 'attr'; Mask = $mask; Group = $grp; Detail = "$f ($($p -join ', '))" } }
        }
    }
}
function Test-CIS_Debian13_7_2_10 {
    $p = @(Get-Debian13DotFileProblems)
    New-CISResult -ControlId '7.2.10' -Title 'Ensure local interactive user dot files access is configured' -Status $(if ($p.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Sin .forward/.rhost; dot files 0644 (.netrc y .bash_history 0600) del usuario y su grupo primario' `
        -ActualValue $(if ($p.Count) { (($p | Select-Object -First 10 | ForEach-Object Detail) -join '; ') + $(if ($p.Count -gt 10) { " ... (+$($p.Count - 10))" }) } else { 'conforme' })
}
function Set-CIS_Debian13_7_2_10 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($p in @(Get-Debian13DotFileProblems)) {
        if ($p.Fix -eq 'none') { Write-Warning "7.2.10: $($p.Detail) -- investigar y eliminar manualmente."; continue }
        if (-not $PSCmdlet.ShouldProcess($p.File, "7.2.10 - corregir permisos/propietario ($($p.Detail))")) { continue }
        & chmod $(if ($p.Mask -eq 127) { 'u-x,go-rwx' } else { 'u-x,go-wx' }) $p.File
        & chown "$($p.User.Name):$($p.Group)" $p.File
    }
}
