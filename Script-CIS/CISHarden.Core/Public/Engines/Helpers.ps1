function Get-CISServerRole {
    <#
        Devuelve 'DC' o 'MS' segun el rol real del servidor, para que cada
        Test-CIS_*/Set-CIS_* pueda decidir si el control marcado
        (DC only)/(MS only) aplica o no (Not Applicable).
    #>
    [CmdletBinding()]
    param()

    $productType = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).ProductType
    # ProductType: 1 = Workstation, 2 = Domain Controller, 3 = Server (member)
    switch ($productType) {
        2 { return 'DC' }
        default { return 'MS' }
    }
}

function New-CISResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Pass', 'Fail', 'NotApplicable', 'ManualReviewRequired', 'Error')]
        [string]$Status,
        [string]$ExpectedValue,
        [string]$ActualValue,
        [string]$Notes
    )

    [pscustomobject]@{
        ControlId     = $ControlId
        Title         = $Title
        Status        = $Status
        ExpectedValue = $ExpectedValue
        ActualValue   = $ActualValue
        Notes         = $Notes
        Hostname      = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { [System.Net.Dns]::GetHostName() }
        Timestamp     = (Get-Date).ToString('o')
    }
}

function Get-CISSecurityPolicy {
    <#
        Exporta la Local Security Policy actual via secedit y devuelve un
        hashtable con las claves de la seccion [System Access] (Password
        Policy / Account Lockout Policy). Es la unica forma soportada de leer
        estos valores sin depender de la GUI.
    #>
    [CmdletBinding()]
    param()

    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) "cis_secedit_$([guid]::NewGuid()).cfg"
    try {
        $null = secedit /export /cfg $tmp /areas SECURITYPOLICY 2>&1
        if (-not (Test-Path $tmp)) {
            throw "secedit /export no genero el archivo esperado ($tmp)."
        }

        $content = Get-Content -Path $tmp -Encoding Unicode
        $policy = @{}
        foreach ($line in $content) {
            if ($line -match '^\s*([^=;\[][^=]*)\s*=\s*(.*)\s*$') {
                $policy[$matches[1].Trim()] = $matches[2].Trim()
            }
        }
        return $policy
    }
    finally {
        Remove-Item -Path $tmp -ErrorAction SilentlyContinue
    }
}

function Backup-CISSecurityPolicy {
    <#
        Backup completo de la security policy actual antes de remediar
        cualquier control de secedit. Se guarda en Reports/backups con
        timestamp para poder revertir (secedit /configure /db ... /cfg <este
        archivo> /overwrite).
    #>
    [CmdletBinding()]
    param(
        [string]$BackupDir = (Join-Path $PSScriptRoot '..\..\Reports\backups')
    )

    if (-not (Test-Path $BackupDir)) {
        New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $backupFile = Join-Path $BackupDir "secedit_backup_$stamp.cfg"
    $null = secedit /export /cfg $backupFile /areas SECURITYPOLICY 2>&1

    if (-not (Test-Path $backupFile)) {
        throw "No se pudo crear el backup de secedit antes de remediar."
    }

    return $backupFile
}

function Set-CISSecurityPolicyValue {
    <#
        Aplica un unico valor de [System Access] via secedit /configure,
        generando un INF minimo que solo toca la clave pedida (secedit
        siempre necesita un INF completo con seccion [Version], pero solo
        aplica las claves presentes en [System Access]).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )

    $tmpInf = Join-Path ([System.IO.Path]::GetTempPath()) "cis_set_$([guid]::NewGuid()).inf"
    $tmpDb  = Join-Path ([System.IO.Path]::GetTempPath()) "cis_set_$([guid]::NewGuid()).sdb"

    $inf = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[System Access]
$Key = $Value
"@

    if ($PSCmdlet.ShouldProcess("System Access\$Key", "Set to $Value via secedit")) {
        Set-Content -Path $tmpInf -Value $inf -Encoding Unicode
        $null = secedit /configure /db $tmpDb /cfg $tmpInf /areas SECURITYPOLICY /quiet 2>&1
    }

    Remove-Item -Path $tmpInf, $tmpDb -ErrorAction SilentlyContinue
}
