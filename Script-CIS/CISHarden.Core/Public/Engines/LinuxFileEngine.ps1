<#
    Motor generico de archivos de configuracion: contenido de linea (estilo
    grep/append idempotente), permisos y ownership via stat/chmod/chown.
    Usado por bootloader (1.4.x), banners (1.7.x) y, a futuro, SSH/PAM.
#>

function Backup-CISFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$BackupDir = (Join-Path $PSScriptRoot '..\..\Reports\backups')
    )
    if (-not (Test-Path $Path)) { return $null }
    if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFile = Join-Path $BackupDir "$([IO.Path]::GetFileName($Path))_backup_$stamp"
    Copy-Item -Path $Path -Destination $backupFile -Force
    return $backupFile
}

function Test-CISFileContains {
    <# Analogo a grep -P: $true si alguna linea de <Path> matchea <Pattern> (regex). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern
    )
    if (-not (Test-Path $Path)) { return $false }
    return [bool](Select-String -Path $Path -Pattern $Pattern -Quiet)
}

function Set-CISFileLine {
    <#
        Agrega <Line> a <Path> si ninguna linea existente matchea
        <MatchPattern>; si <MatchPattern> matchea una linea, la reemplaza por
        <Line> en vez de duplicarla. Crea el archivo si no existe.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][string]$MatchPattern
    )

    if (-not $PSCmdlet.ShouldProcess($Path, "Asegurar linea que matchea '$MatchPattern'")) {
        return
    }

    if (Test-Path $Path) {
        Backup-CISFile -Path $Path | Out-Null
        $content = Get-Content -Path $Path
    }
    else {
        $content = @()
    }

    if ($content -and ($content -match $MatchPattern)) {
        $content = $content -replace $MatchPattern, $Line
    }
    else {
        $content += $Line
    }
    Set-Content -Path $Path -Value $content
}

function Get-CISFileMode {
    <# Permisos octales de <Path> (ej. '644'), o $null si no existe. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = (& stat -c '%a' $Path 2>$null)
    if ($LASTEXITCODE -ne 0) { return $null }
    return $raw.Trim()
}

function Set-CISFileMode {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Mode
    )
    if ($PSCmdlet.ShouldProcess($Path, "chmod $Mode")) {
        & chmod $Mode $Path
    }
}

function Get-CISFileOwner {
    <# 'usuario:grupo' de <Path>, o $null si no existe. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = (& stat -c '%U:%G' $Path 2>$null)
    if ($LASTEXITCODE -ne 0) { return $null }
    return $raw.Trim()
}

function Set-CISFileOwner {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Owner
    )
    if ($PSCmdlet.ShouldProcess($Path, "chown $Owner")) {
        & chown $Owner $Path
    }
}

function Test-CISPathAccess {
    <#
        Verifica que <Path> tenga el owner esperado y un modo IGUAL O MAS
        RESTRICTIVO que <MaxMode> ("0755 or more restrictive" del benchmark):
        cumple si no tiene ningun bit fuera de MaxMode. Path inexistente ->
        Exists=$false, Compliant=$true (nada que proteger).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$MaxMode,
        [string[]]$Owner = 'root:root'   # uno o varios owner:group aceptados
    )
    $mode = Get-CISFileMode -Path $Path
    if ($null -eq $mode) {
        return [pscustomobject]@{ Path = $Path; Exists = $false; Compliant = $true; Mode = $null; Owner = $null }
    }
    $own = Get-CISFileOwner -Path $Path
    $extraBits = [Convert]::ToInt32($mode, 8) -band (-bnot [Convert]::ToInt32($MaxMode, 8))
    [pscustomobject]@{
        Path      = $Path
        Exists    = $true
        Compliant = ($extraBits -eq 0) -and ($Owner -contains $own)
        Mode      = $mode
        Owner     = $own
    }
}
