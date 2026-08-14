<#
    Motor para los controles de particiones/opciones de montaje (1.1.2-
    1.1.24): existencia de particiones separadas (/tmp, /dev/shm, /home,
    /var, etc.) y presencia de opciones nodev/nosuid/noexec en cada una.
    Usa findmnt (parte de util-linux, presente en cualquier Debian) en vez
    de parsear /etc/fstab a mano, para reflejar el estado real montado.
#>

function Test-CISPartitionExists {
    <# Devuelve $true si <Path> es un punto de montaje propio (no parte de / ni de otro fs padre). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    & findmnt --kernel $Path *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-CISMountOptions {
    <# Devuelve la lista de opciones de montaje activas para <Path>, o $null si no esta montado. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )
    $raw = (& findmnt -n -o OPTIONS --target $Path 2>$null)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
        return $null
    }
    return ($raw.Trim() -split ',')
}

function Test-CISMountOption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('nodev', 'nosuid', 'noexec')][string]$Option
    )
    $options = Get-CISMountOptions -Path $Path
    if ($null -eq $options) {
        return $false
    }
    return ($options -contains $Option)
}

function Set-CISFstabMountOption {
    <#
        Agrega <Option> a la linea de /etc/fstab del punto de montaje <Path>
        (si existe una entrada) y remonta para aplicarlo ya. No crea
        particiones nuevas -- eso queda fuera del alcance de una remediacion
        automatica y el control correspondiente se marca ManualReviewRequired.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('nodev', 'nosuid', 'noexec')][string]$Option
    )

    $fstab = '/etc/fstab'
    if (-not (Test-Path $fstab)) {
        throw "No existe $fstab."
    }

    $lines = Get-Content -Path $fstab
    $targetIndex = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ($line -match '^\s*#' -or [string]::IsNullOrWhiteSpace($line)) { continue }
        $fields = $line -split '\s+'
        if ($fields.Count -ge 2 -and $fields[1] -eq $Path) {
            $targetIndex = $i
            break
        }
    }

    if ($targetIndex -lt 0) {
        Write-Warning "No se encontro una entrada para '$Path' en $fstab; agregar la opcion '$Option' requiere editar fstab manualmente."
        return
    }

    if (-not $PSCmdlet.ShouldProcess($fstab, "Agregar opcion '$Option' al mount point '$Path'")) {
        return
    }

    Copy-Item -Path $fstab -Destination "$fstab.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

    $fields = $lines[$targetIndex] -split '\s+'
    $existingOptions = $fields[3] -split ','
    if ($existingOptions -notcontains $Option) {
        $fields[3] = (($existingOptions + $Option) -join ',')
        $lines[$targetIndex] = ($fields -join ' ')
        Set-Content -Path $fstab -Value $lines
    }

    & mount -o "remount,$Option" $Path 2>$null | Out-Null
}
