function Get-CISLinuxProfile {
    <#
        Heuristica para decidir si el equipo aplica como perfil 'Server' o
        'Workstation' del benchmark CIS (no hay una senal 100% confiable en
        Linux como el ProductType de WMI en Windows). Se considera
        'Workstation' si hay un display manager activo o si el paquete
        xserver-xorg esta instalado; en cualquier otro caso, 'Server'
        (el perfil mas restrictivo, y el default razonable para un servidor
        endurecido).
    #>
    [CmdletBinding()]
    param()

    $displayManagers = @('gdm3', 'gdm', 'lightdm', 'sddm', 'xdm')
    foreach ($dm in $displayManagers) {
        $active = & systemctl is-active $dm 2>$null
        if ($LASTEXITCODE -eq 0 -and $active -eq 'active') {
            return 'Workstation'
        }
    }

    & dpkg -s xserver-xorg *> $null
    if ($LASTEXITCODE -eq 0) {
        return 'Workstation'
    }

    return 'Server'
}

function Invoke-CISLinuxCommand {
    <#
        Wrapper fino sobre bash -c para los pocos casos donde no vale la pena
        reimplementar el parsing en PowerShell puro. Devuelve un objeto
        consistente (Output/ExitCode/Success) en vez de depender de
        $LASTEXITCODE disperso por todo el codigo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Command
    )

    $output = & bash -c $Command 2>&1
    [pscustomobject]@{
        Output   = $output
        ExitCode = $LASTEXITCODE
        Success  = ($LASTEXITCODE -eq 0)
    }
}
