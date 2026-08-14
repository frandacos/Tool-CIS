# CIS Debian Linux 10 Benchmark v2.0.0 - Capitulo 1.2 Filesystem Integrity
# Checking (AIDE) y 1.3 Configure Software and Patch Management.
# 5 controles: 1.2.1-1.2.2 (Automated), 1.3.1-1.3.3 (Manual -- dependen de
# politica/procedimiento del sitio, no de un valor verificable en el
# sistema). Fuente: cis_debian_10.md, paginas 129-141.

# --- 1.2.1 Ensure AIDE is installed ------------------------------------------

function Test-CIS_Debian10_1_2_1 {
    [CmdletBinding()]
    param()
    $aide = Test-CISPackageInstalled -Name 'aide'
    $aideCommon = Test-CISPackageInstalled -Name 'aide-common'
    $status = if ($aide -and $aideCommon) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.2.1' -Title 'Ensure AIDE is installed' -Status $status `
        -ExpectedValue 'aide y aide-common instalados' -ActualValue "aide=$aide; aide-common=$aideCommon"
}

function Set-CIS_Debian10_1_2_1 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if ($PSCmdlet.ShouldProcess('aide, aide-common', 'apt-get install -y')) {
        Install-CISPackage -Name 'aide'
        Install-CISPackage -Name 'aide-common'
    }
}

# --- 1.2.2 Ensure filesystem integrity is regularly checked -----------------
# El benchmark acepta DOS mecanismos equivalentes: un cron job que corra
# aide --check, o el par de unidades systemd aidecheck.service/.timer
# habilitadas. Se verifican ambos y se aprueba si cualquiera esta presente.

function Test-CIS_Debian10_1_2_2 {
    [CmdletBinding()]
    param()

    $extraCronFiles = @(Get-ChildItem -Path '/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/cron.weekly', '/etc/cron.monthly' -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
    $cronFiles = @('/etc/crontab') + $extraCronFiles
    $cronHasAide = $false
    foreach ($f in $cronFiles) {
        if (Test-CISFileContains -Path $f -Pattern 'aide(\.wrapper)?\s+.*(--check|\$AIDEARGS)') {
            $cronHasAide = $true
            break
        }
    }

    $timerOk = (Test-CISServiceEnabled -Name 'aidecheck.service') -and (Test-CISServiceEnabled -Name 'aidecheck.timer') -and (Test-CISServiceActive -Name 'aidecheck.timer')

    $status = if ($cronHasAide -or $timerOk) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId '1.2.2' -Title 'Ensure filesystem integrity is regularly checked' -Status $status `
        -ExpectedValue 'cron job con aide --check, o aidecheck.service/.timer habilitados y timer activo' `
        -ActualValue "CronConAide=$cronHasAide; AidecheckTimerOk=$timerOk"
}

function Set-CIS_Debian10_1_2_2 {
    <#
        Remedia via el mecanismo systemd (mas verificable que editar
        crontab a ciegas): crea aidecheck.service/.timer corriendo aide
        --check diario a las 05:00, tal como especifica la Remediation del
        benchmark, y los habilita+arranca.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $servicePath = '/etc/systemd/system/aidecheck.service'
    $timerPath = '/etc/systemd/system/aidecheck.timer'

    if (-not $PSCmdlet.ShouldProcess('aidecheck.service/.timer', 'Crear y habilitar')) {
        return
    }

    $serviceContent = @'
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check

[Install]
WantedBy=multi-user.target
'@

    $timerContent = @'
[Unit]
Description=Aide check every day at 5AM

[Timer]
OnCalendar=*-*-* 05:00:00

[Install]
WantedBy=multi-user.target
'@

    Set-Content -Path $servicePath -Value $serviceContent
    Set-Content -Path $timerPath -Value $timerContent
    & systemctl daemon-reload
    Enable-CISService -Name 'aidecheck.service'
    Enable-CISService -Name 'aidecheck.timer' -Now
}

# --- 1.3.x Configure Software and Patch Management (todos Manual) ----------
# El benchmark exige revisar politica de actualizaciones, configuracion de
# repositorios y llaves GPG del sitio -- no hay un valor unico y objetivo
# que verificar desde el sistema sin conocer esa politica, asi que se
# marcan ManualReviewRequired (regla del sistema: nunca inventar una
# heuristica para un control que el propio benchmark declara Manual).

function Test-CIS_Debian10_1_3_1 {
    New-CISResult -ControlId '1.3.1' -Title 'Ensure updates, patches, and additional security software are installed' -Status 'ManualReviewRequired' `
        -Notes 'Requiere verificar contra la politica de actualizaciones del sitio (apt list --upgradable); no automatizable como Pass/Fail objetivo.'
}
function Set-CIS_Debian10_1_3_1 { Write-Warning '1.3.1: sin remediacion automatizada -- revisar/instalar actualizaciones segun politica del sitio (apt update && apt upgrade).' }

function Test-CIS_Debian10_1_3_2 {
    New-CISResult -ControlId '1.3.2' -Title 'Ensure package manager repositories are configured' -Status 'ManualReviewRequired' `
        -Notes 'Requiere verificar /etc/apt/sources.list y /etc/apt/sources.list.d/ contra los repositorios aprobados por el sitio.'
}
function Set-CIS_Debian10_1_3_2 { Write-Warning '1.3.2: sin remediacion automatizada -- configurar repositorios apt segun politica del sitio.' }

function Test-CIS_Debian10_1_3_3 {
    New-CISResult -ControlId '1.3.3' -Title 'Ensure GPG keys are configured' -Status 'ManualReviewRequired' `
        -Notes 'Requiere verificar apt-key list / /etc/apt/trusted.gpg.d contra las llaves aprobadas por el sitio.'
}
function Set-CIS_Debian10_1_3_3 { Write-Warning '1.3.3: sin remediacion automatizada -- importar/validar llaves GPG segun politica del sitio.' }
