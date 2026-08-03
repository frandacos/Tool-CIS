# Motor compartido para los 48 controles de 2.2 User Rights Assignment.
# Todos mapean 1 a 1 a un "user right"/privilegio nativo de Windows
# ([Privilege Rights] en la salida de secedit). Los nombres SeXxxPrivilege /
# SeXxxLogonRight son las constantes oficiales de Microsoft, estables desde
# hace mas de una decada y usadas por el propio benchmark/CIS-CAT — no son un
# valor inventado para esta implementacion.
#
# Los principals esperados (Administrators, LOCAL SERVICE, NT SERVICE\...,
# etc.) se resuelven a SID en tiempo de ejecucion contra el servidor real
# (no se hardcodean SIDs), para que funcione igual en DC y en Member Server y
# no se rompa si un SID bien conocido varia.

function Get-CISPrivilegeRights {
    <#
        Exporta [Privilege Rights] via secedit y devuelve un hashtable
        Right -> string[] de SIDs (sin el prefijo '*').
    #>
    [CmdletBinding()]
    param()

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "cis_rights_$([guid]::NewGuid()).cfg"
    try {
        $null = secedit /export /cfg $tmp /areas USER_RIGHTS 2>&1
        if (-not (Test-Path $tmp)) {
            throw "secedit /export /areas USER_RIGHTS no genero el archivo esperado ($tmp)."
        }

        $content = Get-Content -Path $tmp -Encoding Unicode
        $rights = @{}
        $inSection = $false
        foreach ($line in $content) {
            if ($line -match '^\[Privilege Rights\]') { $inSection = $true; continue }
            if ($line -match '^\[') { $inSection = $false; continue }
            if (-not $inSection) { continue }
            if ($line -match '^\s*([A-Za-z0-9]+)\s*=\s*(.*)\s*$') {
                $right = $matches[1].Trim()
                $sids = @()
                if ($matches[2].Trim()) {
                    $sids = $matches[2].Trim().Split(',') | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ }
                }
                $rights[$right] = $sids
            }
        }
        return $rights
    }
    finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }
}

$script:CISPrincipalSidCache = @{}

function Resolve-CISPrincipalToSid {
    <#
        Traduce un nombre de principal (Administrators, LOCAL SERVICE,
        NT SERVICE\WdiServiceHost, IIS_IUSRS, etc.) a su SID en ESTE
        servidor. Si el principal no existe (ej. IIS_IUSRS sin IIS instalado)
        devuelve $null en vez de tirar excepcion, para que el control se
        marque Fail/Error con una nota clara en vez de romper toda la
        auditoria.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name)

    if ($script:CISPrincipalSidCache.ContainsKey($Name)) {
        return $script:CISPrincipalSidCache[$Name]
    }

    try {
        $sid = (New-Object System.Security.Principal.NTAccount($Name)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        $script:CISPrincipalSidCache[$Name] = $sid
        return $sid
    }
    catch {
        Write-Warning "No se pudo resolver el principal '$Name' a SID en este servidor: $($_.Exception.Message)"
        $script:CISPrincipalSidCache[$Name] = $null
        return $null
    }
}

function Test-CISUserRight {
    <#
    .PARAMETER MustInclude
        Para los "Deny *" rights: alcanza con que los principals esperados
        esten incluidos en la lista actual (puede haber otros adicionales).
        Sin este switch se exige coincidencia EXACTA del conjunto (para los
        rights de tipo "is set to").
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$RightConstant,
        [string[]]$ExpectedPrincipals = @(),
        [switch]$MustInclude
    )

    $rights = Get-CISPrivilegeRights
    # @($rights[$RightConstant]) por si solo: si el right no aparece en el
    # export de secedit (caso 'No One', que es el estado deseado en varios
    # controles), $rights[$RightConstant] es $null y @($null) da un array de
    # UN elemento null (.Count = 1), no un array vacio. Sin este filtro,
    # todos los controles 'No One' correctamente configurados se marcaban
    # Fail. Filtrar $null es lo que corrige el .Count real a 0.
    $actualSids = @(@($rights[$RightConstant]) | Where-Object { $_ })

    if ($ExpectedPrincipals.Count -eq 0) {
        # Caso 'No One': el right no debe tener ningun principal asignado.
        $status = if ($actualSids.Count -eq 0) { 'Pass' } else { 'Fail' }
        return New-CISResult -ControlId $ControlId -Title $Title -Status $status `
            -ExpectedValue 'No One' -ActualValue ($actualSids -join ', ')
    }

    $expectedSids = @()
    $unresolved = @()
    foreach ($p in $ExpectedPrincipals) {
        $sid = Resolve-CISPrincipalToSid -Name $p
        if ($null -eq $sid) { $unresolved += $p } else { $expectedSids += $sid }
    }

    if ($unresolved.Count -gt 0) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'Error' `
            -ExpectedValue ($ExpectedPrincipals -join ', ') -ActualValue ($actualSids -join ', ') `
            -Notes "No se pudieron resolver estos principals en este servidor (¿falta un rol/feature?): $($unresolved -join ', ')"
    }

    if ($MustInclude) {
        $missing = $expectedSids | Where-Object { $_ -notin $actualSids }
        $status = if ($missing.Count -eq 0) { 'Pass' } else { 'Fail' }
    }
    else {
        $diff = Compare-Object -ReferenceObject $expectedSids -DifferenceObject $actualSids
        $status = if (-not $diff) { 'Pass' } else { 'Fail' }
    }

    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue ($ExpectedPrincipals -join ', ') -ActualValue ($actualSids -join ', ')
}

function Set-CISUserRight {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$RightConstant,
        [string[]]$ExpectedPrincipals = @(),
        [switch]$MustInclude
    )

    $rights = Get-CISPrivilegeRights
    # Mismo filtro de $null que en Test-CISUserRight (ver comentario ahi).
    $actualSids = @(@($rights[$RightConstant]) | Where-Object { $_ })

    $expectedSids = @()
    foreach ($p in $ExpectedPrincipals) {
        $sid = Resolve-CISPrincipalToSid -Name $p
        if ($null -eq $sid) {
            throw "No se pudo resolver el principal '$p' en este servidor; no se puede remediar $RightConstant de forma segura."
        }
        $expectedSids += $sid
    }

    $finalSids = if ($MustInclude) {
        @($actualSids + $expectedSids | Select-Object -Unique)
    }
    else {
        $expectedSids
    }

    $sidList = ($finalSids | ForEach-Object { "*$_" }) -join ','

    $tmpInf = Join-Path ([System.IO.Path]::GetTempPath()) "cis_rights_set_$([guid]::NewGuid()).inf"
    $tmpDb  = Join-Path ([System.IO.Path]::GetTempPath()) "cis_rights_set_$([guid]::NewGuid()).sdb"

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$RightConstant = $sidList
"@

    if ($PSCmdlet.ShouldProcess($RightConstant, "Set to $sidList via secedit")) {
        Backup-CISSecurityPolicy | Out-Null
        Set-Content -Path $tmpInf -Value $inf -Encoding Unicode
        $null = secedit /configure /db $tmpDb /cfg $tmpInf /areas USER_RIGHTS /quiet 2>&1
    }

    Remove-Item -Path $tmpInf, $tmpDb -ErrorAction SilentlyContinue
}
