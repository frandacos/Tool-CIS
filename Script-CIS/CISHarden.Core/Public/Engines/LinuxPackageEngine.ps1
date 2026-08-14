<#
    Motor de paquetes via dpkg/apt-get. Usado por AIDE (1.3.x), prelink
    (1.5.x) y AppArmor (1.6.x).
#>

function Test-CISPackageInstalled {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)
    & dpkg -s $Name *> $null
    return ($LASTEXITCODE -eq 0)
}

function Install-CISPackage {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name)
    if ($PSCmdlet.ShouldProcess($Name, 'apt-get install -y')) {
        & apt-get install -y $Name
    }
}

function Remove-CISPackage {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Name,
        [switch]$Purge
    )
    $verb = if ($Purge) { 'purge' } else { 'remove' }
    if ($PSCmdlet.ShouldProcess($Name, "apt-get $verb -y")) {
        & apt-get $verb -y $Name
    }
}
