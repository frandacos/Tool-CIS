<#
    Motor para los controles 1.1.1.x del benchmark Debian 10 (deshabilitar
    modulos de filesystem/red no usados: cramfs, freevxfs, squashfs, udf,
    usb-storage, etc.). Replica en PowerShell nativo, contra el kernel que
    esta corriendo ahora mismo, la logica que el benchmark describe en sus
    scripts bash de Audit/Remediation:
      - el modulo no debe ser cargable (install <mod> /bin/false)
      - el modulo no debe estar cargado (lsmod)
      - el modulo debe estar en la denylist (blacklist <mod>)
    Si el modulo no existe en el arbol de modulos del kernel actual, no hace
    falta ninguna configuracion adicional (el benchmark lo trata como Pass).
#>

function Test-CISKernelModuleDisabled {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Module,
        [ValidateSet('fs', 'drivers', 'net')][string]$Type = 'fs',
        # Directorio del modulo bajo kernel/<Type>/ cuando no coincide con el nombre
        # (Debian 13: overlay -> 'overlayfs', firewire-core -> 'firewire').
        [string]$DirName
    )

    $probeName = $Module -replace '-', '_'
    if (-not $DirName) { $DirName = $Module -replace '-', '/' }
    $kernelRelease = (& uname -r).Trim()
    $moduleDir = "/lib/modules/$kernelRelease/kernel/$Type/$DirName"
    # El benchmark (Debian 13) exige que el directorio exista Y no este vacio.
    $existsInRunningKernel = (Test-Path -Path $moduleDir) -and
        ($null -ne (Get-ChildItem -Path $moduleDir -Force -ErrorAction SilentlyContinue | Select-Object -First 1))

    $isLoadable = $false
    $isLoaded = $false
    if ($existsInRunningKernel) {
        $loadableRaw = (& modprobe -n -v $Module 2>$null) -join "`n"
        # "install /bin/true" o "install /bin/false" en la salida de modprobe -n -v
        # significa que el modulo esta explicitamente deshabilitado.
        $isLoadable = -not [bool]($loadableRaw -match 'install\s+(/usr)?/bin/(true|false)')

        $loadedRaw = (& lsmod 2>$null) -join "`n"
        $isLoaded = [bool]($loadedRaw -match "(?m)^$([regex]::Escape($probeName))\s")
    }

    $showConfig = (& modprobe --showconfig 2>$null) -join "`n"
    $isBlacklisted = [bool]($showConfig -match "(?m)^\s*blacklist\s+$([regex]::Escape($probeName))\b")

    $disabled = if ($existsInRunningKernel) {
        (-not $isLoadable) -and (-not $isLoaded) -and $isBlacklisted
    }
    else {
        # El benchmark solo exige blacklist si el modulo existe en ALGUN
        # kernel instalado; si ni siquiera existe en el que esta corriendo,
        # asumimos Pass salvo que este cargado igual (caso raro pero posible).
        -not $isLoaded
    }

    [pscustomobject]@{
        Module                = $Module
        Disabled              = $disabled
        ExistsInRunningKernel = $existsInRunningKernel
        Loadable              = $isLoadable
        Loaded                = $isLoaded
        Blacklisted           = $isBlacklisted
    }
}

function Disable-CISKernelModule {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Module,
        [ValidateSet('fs', 'drivers', 'net')][string]$Type = 'fs'
    )

    $probeName = $Module -replace '-', '_'
    $confPath = "/etc/modprobe.d/$probeName.conf"

    if (-not $PSCmdlet.ShouldProcess($confPath, "Blacklist y deshabilitar modulo '$Module'")) {
        return
    }

    if (Test-Path $confPath) {
        Copy-Item -Path $confPath -Destination "$confPath.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" -ErrorAction SilentlyContinue
    }

    $lines = @()
    if (Test-Path $confPath) { $lines = Get-Content -Path $confPath }
    if ($lines -notmatch "^\s*install\s+$([regex]::Escape($Module))\s+/bin/false") {
        $lines += "install $Module /bin/false"
    }
    if ($lines -notmatch "^\s*blacklist\s+$([regex]::Escape($probeName))\b") {
        $lines += "blacklist $probeName"
    }
    Set-Content -Path $confPath -Value $lines

    $loadedRaw = (& lsmod 2>$null) -join "`n"
    if ($loadedRaw -match "(?m)^$([regex]::Escape($probeName))\s") {
        & modprobe -r $Module 2>$null | Out-Null
    }
}
