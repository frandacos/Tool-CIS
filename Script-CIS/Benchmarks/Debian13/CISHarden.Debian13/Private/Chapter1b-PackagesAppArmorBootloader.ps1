# CIS Debian Linux 13 Benchmark v1.0.0 - 1.2 Package Management, 1.3 Mandatory
# Access Control (AppArmor) y 1.4 Configure Bootloader. 16 controles.
# Fuente: cis_debian_13.md, paginas 123-158.

# --- Helpers privados (mockeables en Pester) ---------------------------------

function Get-Debian13AptConfigDump { @(& apt-config dump 2>$null) }
function Get-Debian13AppArmorStatus { @(& apparmor_status 2>$null) }
function Get-Debian13FilesIn {
    param([Parameter(Mandatory)][string]$Directory, [string[]]$Filter = @('*'))
    if (-not (Test-Path $Directory)) { return @() }
    @(Get-ChildItem -Path $Directory -File -Force -Recurse:$false -ErrorAction SilentlyContinue |
            Where-Object { $n = $_.Name; $Filter | Where-Object { $n -like $_ } } | ForEach-Object FullName)
}

function Test-Debian13PathControl {
    <# Un path (archivo o directorio) con owner y modo maximo. Inexistente = Pass (nada que proteger). #>
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$MaxMode
    )
    $r = Test-CISPathAccess -Path $Path -MaxMode $MaxMode
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($r.Compliant) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "root:root, $MaxMode o mas restrictivo" -ActualValue "owner=$($r.Owner); mode=$($r.Mode)" `
        -Notes $(if (-not $r.Exists) { "$Path no existe; nada que proteger." })
}

function Set-Debian13PathControl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$SymbolicMode
    )
    if ((Test-Path $Path) -and $PSCmdlet.ShouldProcess($Path, "$ControlId - chown root:root; chmod $SymbolicMode")) {
        Set-CISFileOwner -Path $Path -Owner 'root:root'
        & chmod $SymbolicMode $Path
    }
}

function Test-Debian13FilesControl {
    <# Todos los archivos de <Paths> con owner root:root y modo maximo. #>
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths, [Parameter(Mandatory)][string]$MaxMode
    )
    $bad = @($Paths | ForEach-Object { Test-CISPathAccess -Path $_ -MaxMode $MaxMode } | Where-Object { -not $_.Compliant })
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($bad.Count -eq 0) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "root:root, $MaxMode o mas restrictivo" `
        -ActualValue $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.Path) ($($_.Owner) $($_.Mode))" }) -join '; ' } else { 'todos conformes' })
}

function Set-Debian13FilesControl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths,
        [Parameter(Mandatory)][string]$MaxMode, [Parameter(Mandatory)][string]$SymbolicMode
    )
    foreach ($p in $Paths) {
        if (-not (Test-CISPathAccess -Path $p -MaxMode $MaxMode).Compliant -and
            $PSCmdlet.ShouldProcess($p, "$ControlId - chown root:root; chmod $SymbolicMode")) {
            Set-CISFileOwner -Path $p -Owner 'root:root'
            & chmod $SymbolicMode $p
        }
    }
}

function Get-Debian13SignedByFiles {
    # Archivos *.list/*.sources de sources.list.d que usan Signed-By (1.2.1.3, paso 2).
    Get-Debian13FilesIn -Directory '/etc/apt/sources.list.d' -Filter '*.list', '*.sources' |
        Where-Object { Select-String -Path $_ -Pattern '^([^#\r\n]+)?\bSigned-By\b' -Quiet }
}
function Get-Debian13GpgKeyFiles {
    @('/usr/share/keyrings', '/etc/apt/trusted.gpg.d') | ForEach-Object { Get-Debian13FilesIn -Directory $_ -Filter '*gpg' }
}

# --- 1.2.1 Configure Package Repositories ------------------------------------

# Manual: el benchmark pide revisar que cada repositorio use Signed-By segun politica del sitio.
function Test-CIS_Debian13_1_2_1_1 {
    New-CISResult -ControlId '1.2.1.1' -Title 'Ensure the source.list and .source files use the Signed-By option' -Status 'ManualReviewRequired' `
        -Notes 'Revisar /etc/apt/sources.list y sources.list.d/*: cada repositorio debe usar Signed-By con el keyring correcto (ver Audit del benchmark).'
}
function Set-CIS_Debian13_1_2_1_1 { Write-Warning '1.2.1.1: sin remediacion automatizada -- agregar Signed-By a cada repositorio segun politica del sitio.' }

function Test-CIS_Debian13_1_2_1_2 {
    $dump = Get-Debian13AptConfigDump
    $rec = [bool]($dump -match '^APT::Install-Recommends\s+"0";')
    $sug = [bool]($dump -match '^APT::Install-Suggests\s+"0";')
    New-CISResult -ControlId '1.2.1.2' -Title 'Ensure weak dependencies are configured' -Status $(if ($rec -and $sug) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'APT::Install-Recommends "0"; APT::Install-Suggests "0"' `
        -ActualValue "Recommends0=$rec; Suggests0=$sug"
}
function Set-CIS_Debian13_1_2_1_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $f = '/etc/apt/apt.conf.d/60-no-weak-dependencies'
    if ($PSCmdlet.ShouldProcess($f, '1.2.1.2 - Deshabilitar Recommends/Suggests')) {
        if (Test-Path $f) { Copy-Item $f "$f.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
        Set-Content -Path $f -Value @('', 'APT::Install-Recommends "0";', 'APT::Install-Suggests "0";')
    }
}

function Test-CIS_Debian13_1_2_1_3 {
    Test-Debian13FilesControl -ControlId '1.2.1.3' -Title 'Ensure access to gpg key files are configured' `
        -Paths @(@(Get-Debian13GpgKeyFiles) + @(Get-Debian13SignedByFiles)) -MaxMode '644'
}
function Set-CIS_Debian13_1_2_1_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13FilesControl -ControlId '1.2.1.3' -Paths @(@(Get-Debian13GpgKeyFiles) + @(Get-Debian13SignedByFiles)) -MaxMode '644' -SymbolicMode 'u-x,go-wx'
}

function Test-CIS_Debian13_1_2_1_4 { Test-Debian13PathControl -ControlId '1.2.1.4' -Title 'Ensure access to /etc/apt/trusted.gpg.d directory is configured' -Path '/etc/apt/trusted.gpg.d' -MaxMode '755' }
function Set-CIS_Debian13_1_2_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.2.1.4' -Path '/etc/apt/trusted.gpg.d' -SymbolicMode 'u=rwx,g=rx,o=rx' }

function Test-CIS_Debian13_1_2_1_5 { Test-Debian13PathControl -ControlId '1.2.1.5' -Title 'Ensure access to /etc/apt/auth.conf.d directory is configured' -Path '/etc/apt/auth.conf.d' -MaxMode '755' }
function Set-CIS_Debian13_1_2_1_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.2.1.5' -Path '/etc/apt/auth.conf.d' -SymbolicMode 'u=rwx,g=rx,o=rx' }

function Test-CIS_Debian13_1_2_1_6 {
    Test-Debian13FilesControl -ControlId '1.2.1.6' -Title 'Ensure access to files in the /etc/apt/auth.conf.d/ directory is configured' `
        -Paths @(Get-Debian13FilesIn -Directory '/etc/apt/auth.conf.d') -MaxMode '640'
}
function Set-CIS_Debian13_1_2_1_6 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13FilesControl -ControlId '1.2.1.6' -Paths @(Get-Debian13FilesIn -Directory '/etc/apt/auth.conf.d') -MaxMode '640' -SymbolicMode 'u-x,g-wx,o-rwx'
}

function Test-CIS_Debian13_1_2_1_7 { Test-Debian13PathControl -ControlId '1.2.1.7' -Title 'Ensure access to /usr/share/keyrings directory is configured' -Path '/usr/share/keyrings' -MaxMode '755' }
function Set-CIS_Debian13_1_2_1_7 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.2.1.7' -Path '/usr/share/keyrings' -SymbolicMode 'u=rwx,g=rx,o=rx' }

function Test-CIS_Debian13_1_2_1_8 { Test-Debian13PathControl -ControlId '1.2.1.8' -Title 'Ensure access to /etc/apt/sources.list.d directory is configured' -Path '/etc/apt/sources.list.d' -MaxMode '755' }
function Set-CIS_Debian13_1_2_1_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.2.1.8' -Path '/etc/apt/sources.list.d' -SymbolicMode 'u=rwx,g=rx,o=rx' }

function Test-CIS_Debian13_1_2_1_9 {
    Test-Debian13FilesControl -ControlId '1.2.1.9' -Title 'Ensure access to files in /etc/apt/sources.list.d are configured' `
        -Paths @(Get-Debian13FilesIn -Directory '/etc/apt/sources.list.d') -MaxMode '644'
}
function Set-CIS_Debian13_1_2_1_9 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13FilesControl -ControlId '1.2.1.9' -Paths @(Get-Debian13FilesIn -Directory '/etc/apt/sources.list.d') -MaxMode '644' -SymbolicMode 'u-x,go-wx'
}

# --- 1.2.2 Configure Package Updates -----------------------------------------

# Manual: aplicar parches segun la politica del sitio; no hay valor objetivo unico.
function Test-CIS_Debian13_1_2_2_1 {
    New-CISResult -ControlId '1.2.2.1' -Title 'Ensure updates, patches, and additional security software are installed' -Status 'ManualReviewRequired' `
        -Notes "Verificar 'apt update && apt -s upgrade' sin pendientes y que no exista /var/run/reboot-required."
}
function Set-CIS_Debian13_1_2_2_1 { Write-Warning '1.2.2.1: sin remediacion automatizada -- aplicar apt upgrade/dist-upgrade segun politica del sitio.' }

# --- 1.3.1 Configure AppArmor -------------------------------------------------

function Test-CIS_Debian13_1_3_1_1 {
    $a = Test-CISPackageInstalled -Name 'apparmor'
    $u = Test-CISPackageInstalled -Name 'apparmor-utils'
    New-CISResult -ControlId '1.3.1.1' -Title 'Ensure apparmor packages are installed' -Status $(if ($a -and $u) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'apparmor y apparmor-utils instalados' -ActualValue "apparmor=$a; apparmor-utils=$u"
}
function Set-CIS_Debian13_1_3_1_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    foreach ($p in 'apparmor', 'apparmor-utils') { if (-not (Test-CISPackageInstalled -Name $p)) { Install-CISPackage -Name $p } }
}

function Test-Debian13GrubCfgExists { Test-Path '/boot/grub/grub.cfg' }
function Get-Debian13GrubApparmorOff {
    # Lineas "linux" de grub.cfg con apparmor=0 (vacio si no hay ninguna).
    @(Select-String -Path '/boot/grub/grub.cfg' -Pattern '^\s*linux' | Where-Object { $_.Line -match 'apparmor=0' })
}
function Test-CIS_Debian13_1_3_1_2 {
    if (-not (Test-Debian13GrubCfgExists)) {
        return New-CISResult -ControlId '1.3.1.2' -Title 'Ensure AppArmor is enabled' -Status 'Error' -Notes '/boot/grub/grub.cfg no existe (bootloader no GRUB?): aplicar el equivalente manualmente.'
    }
    $off = @(Get-Debian13GrubApparmorOff)
    New-CISResult -ControlId '1.3.1.2' -Title 'Ensure AppArmor is enabled' -Status $(if ($off.Count -eq 0) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "Ninguna linea 'linux' de grub.cfg con apparmor=0" -ActualValue "$($off.Count) linea(s) con apparmor=0"
}
function Set-CIS_Debian13_1_3_1_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $files = @('/etc/default/grub') + @(Get-Debian13FilesIn -Directory '/etc/default/grub.d')
    if (-not $PSCmdlet.ShouldProcess(($files -join ', '), '1.3.1.2 - Quitar apparmor=0 y ejecutar update-grub (requiere reinicio)')) { return }
    foreach ($f in $files) {
        if ((Test-Path $f) -and (Select-String -Path $f -Pattern 'apparmor=0' -Quiet)) {
            Copy-Item $f "$f.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            (Get-Content $f) -replace '\s*apparmor=0', '' | Set-Content $f
        }
    }
    & update-grub 2>&1 | Out-Null
    Write-Warning '1.3.1.2: reiniciar el sistema para aplicar el cambio.'
}

function Get-Debian13AppArmorCounts {
    $out = (Get-Debian13AppArmorStatus) -join "`n"
    $n = { param($re) if ($out -match $re) { [int]$Matches[1] } else { 0 } }
    [pscustomobject]@{
        Loaded     = & $n '(?m)^(\d+) profiles are loaded'
        Enforce    = & $n '(?m)^(\d+) profiles are in enforce mode'
        Complain   = & $n '(?m)^(\d+) profiles are in complain mode'
        Unconfined = & $n '(?m)^(\d+) processes are unconfined but have a profile defined'
    }
}
function Test-CIS_Debian13_1_3_1_3 {
    $c = Get-Debian13AppArmorCounts
    $ok = ($c.Loaded -gt 0) -and ($c.Complain -eq 0) -and ($c.Unconfined -eq 0) -and ($c.Enforce -eq $c.Loaded)
    New-CISResult -ControlId '1.3.1.3' -Title 'Ensure all AppArmor Profiles are enforcing' -Status $(if ($ok) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue 'Perfiles cargados, todos en enforce, 0 en complain, 0 procesos sin confinar con perfil' `
        -ActualValue "loaded=$($c.Loaded); enforce=$($c.Enforce); complain=$($c.Complain); unconfined=$($c.Unconfined)"
}
function Set-CIS_Debian13_1_3_1_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('/etc/apparmor.d/*', '1.3.1.3 - aa-enforce en todos los perfiles')) {
        & bash -c 'aa-enforce /etc/apparmor.d/*' 2>&1 | Out-Null
        Write-Warning '1.3.1.3: los procesos sin confinar pueden requerir crear/activar un perfil y reiniciar el proceso.'
    }
}

function Test-CIS_Debian13_1_3_1_4 {
    $key = 'kernel.apparmor_restrict_unprivileged_unconfined'
    $r = Test-CISSysctlSetting -Key $key -Value '1'
    New-CISResult -ControlId '1.3.1.4' -Title 'Ensure apparmor_restrict_unprivileged_unconfined is enabled' -Status $(if ($r.Compliant) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue '1 (en ejecucion y persistido)' -ActualValue "running=$($r.Running); persisted=$($r.Persisted) ($($r.File))"
}
function Set-CIS_Debian13_1_3_1_4 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-CISSysctlEnforced -Key 'kernel.apparmor_restrict_unprivileged_unconfined' -Value '1'
}

# --- 1.4 Configure Bootloader ---------------------------------------------------

function Test-CIS_Debian13_1_4_1 {
    $cfg = '/boot/grub/grub.cfg'
    $su = Test-CISFileContains -Path $cfg -Pattern '^set superusers'
    $pw = Test-CISFileContains -Path $cfg -Pattern '^\s*password_pbkdf2'
    New-CISResult -ControlId '1.4.1' -Title 'Ensure bootloader password is set' -Status $(if ($su -and $pw) { 'Pass' } else { 'Fail' }) `
        -ExpectedValue "$cfg define 'set superusers' y 'password_pbkdf2'" -ActualValue "set superusers=$su; password_pbkdf2=$pw"
}
function Set-CIS_Debian13_1_4_1 {
    Write-Warning "1.4.1: sin remediacion automatizada -- generar el hash con 'grub-mkpasswd-pbkdf2 --iteration-count=600000 --salt=64', agregar 'set superusers'/'password_pbkdf2' a un archivo propio en /etc/grub.d (no 00_header) y ejecutar update-grub."
}

function Test-CIS_Debian13_1_4_2 { Test-Debian13PathControl -ControlId '1.4.2' -Title 'Ensure access to bootloader config is configured' -Path '/boot/grub/grub.cfg' -MaxMode '600' }
function Set-CIS_Debian13_1_4_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13PathControl -ControlId '1.4.2' -Path '/boot/grub/grub.cfg' -SymbolicMode 'u-x,go-rwx' }
