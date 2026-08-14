<#
    Motor de servicios systemd. Usado por el timer/cron de AIDE (1.3.x) y por
    AppArmor (1.6.x).
#>

function Test-CISServiceEnabled {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $raw = (& systemctl is-enabled $Name 2>$null)
    return ($LASTEXITCODE -eq 0 -and $raw.Trim() -eq 'enabled')
}

function Test-CISServiceActive {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    $raw = (& systemctl is-active $Name 2>$null)
    return ($LASTEXITCODE -eq 0 -and $raw.Trim() -eq 'active')
}

function Enable-CISService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Now
    )
    if ($PSCmdlet.ShouldProcess($Name, 'systemctl enable')) {
        if ($Now) { & systemctl enable --now $Name } else { & systemctl enable $Name }
    }
}

function Disable-CISService {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Now
    )
    if ($PSCmdlet.ShouldProcess($Name, 'systemctl disable')) {
        if ($Now) { & systemctl disable --now $Name } else { & systemctl disable $Name }
    }
}

function Set-CISServiceMasked {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name)
    if ($PSCmdlet.ShouldProcess($Name, 'systemctl mask')) {
        & systemctl mask $Name
    }
}
