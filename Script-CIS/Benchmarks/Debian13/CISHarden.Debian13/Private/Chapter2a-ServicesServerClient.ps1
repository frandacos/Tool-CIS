# CIS Debian Linux 13 Benchmark v1.0.0 - 2.1 Configure Server Services y 2.2
# Configure Client Services. 29 controles. Fuente: cis_debian_13.md, paginas 254-321.
#
# 2.1.x "services are not in use": Pass si ninguno de los paquetes esta
# instalado, o si estan instalados pero sus unidades no estan enabled ni active
# (caso "paquete requerido como dependencia" del benchmark). El Set-* aplica la
# variante NO destructiva del benchmark (stop + mask de las unidades); la
# desinstalacion del paquete (apt purge) solo se hace con -Purge.

# --- Helpers privados (mockeables) ------------------------------------------------

function Get-Debian13InstalledPackages {
    # Nombres de paquetes instalados que coinciden con los patrones (admite comodines).
    param([Parameter(Mandatory)][string[]]$Patterns)
    foreach ($p in $Patterns) {
        (& dpkg-query -W -f='${Package} ${Status}\n' $p 2>$null) |
            Where-Object { $_ -match ' install ok installed$' } | ForEach-Object { ($_ -split ' ')[0] }
    }
}

function Invoke-Debian13Systemctl { param([Parameter(ValueFromRemainingArguments)][string[]]$Arguments) & systemctl @Arguments 2>&1 | Out-Null }

function Get-Debian13UnitStates {
    # Por unidad: UnitFileState y ActiveState (systemctl show). Unidad inexistente => not-found.
    param([Parameter(Mandatory)][string[]]$Units)
    foreach ($u in $Units) {
        $props = @{}
        (& systemctl show $u -p UnitFileState,ActiveState 2>$null) | ForEach-Object { $k, $v = $_ -split '=', 2; $props[$k] = $v }
        [pscustomobject]@{ Unit = $u; UnitFileState = $props['UnitFileState']; ActiveState = $props['ActiveState'] }
    }
}

function Test-Debian13ServiceNotInUse {
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string[]]$Packages, [Parameter(Mandatory)][string[]]$Units
    )
    $installed = @(Get-Debian13InstalledPackages -Patterns $Packages)
    if ($installed.Count -eq 0) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'Pass' -ExpectedValue 'Paquete no instalado, o servicios no enabled ni active' -ActualValue 'paquete no instalado'
    }
    $inUse = @(Get-Debian13UnitStates -Units $Units | Where-Object { $_.UnitFileState -eq 'enabled' -or $_.ActiveState -eq 'active' })
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($inUse.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Paquete no instalado, o servicios no enabled ni active' `
        -ActualValue $(if ($inUse.Count) { "instalado ($($installed -join ', ')); en uso: " + (($inUse | ForEach-Object { "$($_.Unit) [$($_.UnitFileState)/$($_.ActiveState)]" }) -join ', ') } else { "instalado ($($installed -join ', ')) pero sin servicios enabled/active" })
}

function Set-Debian13ServiceNotInUse {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string[]]$Packages, [Parameter(Mandatory)][string[]]$Units,
        [switch]$Purge
    )
    if (@(Get-Debian13InstalledPackages -Patterns $Packages).Count -eq 0) { return }
    if ($PSCmdlet.ShouldProcess(($Units -join ', '), "$ControlId - systemctl stop + mask")) {
        Invoke-Debian13Systemctl stop @Units
        Invoke-Debian13Systemctl mask @Units
    }
    if ($Purge -and $PSCmdlet.ShouldProcess(($Packages -join ', '), "$ControlId - apt purge")) {
        foreach ($p in @(Get-Debian13InstalledPackages -Patterns $Packages)) { Remove-CISPackage -Name $p -Purge }
    }
}

function Test-Debian13ClientNotInstalled {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string[]]$Packages)
    $installed = @(Get-Debian13InstalledPackages -Patterns $Packages)
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($installed.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue "No instalado: $($Packages -join ', ')" -ActualValue $(if ($installed.Count) { "instalado: $($installed -join ', ')" } else { 'no instalado' })
}
function Set-Debian13ClientNotInstalled {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string[]]$Packages)
    foreach ($p in @(Get-Debian13InstalledPackages -Patterns $Packages)) {
        if ($PSCmdlet.ShouldProcess($p, "$ControlId - apt purge")) { Remove-CISPackage -Name $p -Purge }
    }
}

# --- 2.1.x Server services ---------------------------------------------------------

function Test-CIS_Debian13_2_1_1 { Test-Debian13ServiceNotInUse -ControlId '2.1.1' -Title 'Ensure autofs services are not in use' -Packages 'autofs' -Units 'autofs.service' }
function Set-CIS_Debian13_2_1_1 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.1' -Packages 'autofs' -Units 'autofs.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_2 { Test-Debian13ServiceNotInUse -ControlId '2.1.2' -Title 'Ensure avahi daemon services are not in use' -Packages 'avahi-daemon' -Units 'avahi-daemon.socket', 'avahi-daemon.service' }
function Set-CIS_Debian13_2_1_2 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.2' -Packages 'avahi-daemon' -Units 'avahi-daemon.socket', 'avahi-daemon.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_3 { Test-Debian13ServiceNotInUse -ControlId '2.1.3' -Title 'Ensure dhcp server services are not in use' -Packages 'kea*' -Units 'kea-dhcp-ddns-server.service', 'kea-dhcp4-server.service', 'kea-dhcp6-server.service' }
function Set-CIS_Debian13_2_1_3 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.3' -Packages 'kea*' -Units 'kea-dhcp-ddns-server.service', 'kea-dhcp4-server.service', 'kea-dhcp6-server.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_4 { Test-Debian13ServiceNotInUse -ControlId '2.1.4' -Title 'Ensure dns server services are not in use' -Packages 'bind9' -Units 'named.service' }
function Set-CIS_Debian13_2_1_4 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.4' -Packages 'bind9' -Units 'named.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_5 { Test-Debian13ServiceNotInUse -ControlId '2.1.5' -Title 'Ensure dnsmasq services are not in use' -Packages 'dnsmasq' -Units 'dnsmasq.service' }
function Set-CIS_Debian13_2_1_5 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.5' -Packages 'dnsmasq' -Units 'dnsmasq.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_6 { Test-Debian13ServiceNotInUse -ControlId '2.1.6' -Title 'Ensure ftp server services are not in use' -Packages 'vsftpd' -Units 'vsftpd.service' }
function Set-CIS_Debian13_2_1_6 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.6' -Packages 'vsftpd' -Units 'vsftpd.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_7 { Test-Debian13ServiceNotInUse -ControlId '2.1.7' -Title 'Ensure ldap server services are not in use' -Packages 'slapd' -Units 'slapd.service' }
function Set-CIS_Debian13_2_1_7 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.7' -Packages 'slapd' -Units 'slapd.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_8 { Test-Debian13ServiceNotInUse -ControlId '2.1.8' -Title 'Ensure message access server services are not in use' -Packages 'dovecot-imapd', 'dovecot-pop3d' -Units 'dovecot.socket', 'dovecot.service' }
function Set-CIS_Debian13_2_1_8 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.8' -Packages 'dovecot-imapd', 'dovecot-pop3d' -Units 'dovecot.socket', 'dovecot.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_9 { Test-Debian13ServiceNotInUse -ControlId '2.1.9' -Title 'Ensure network file system services are not in use' -Packages 'nfs-kernel-server' -Units 'nfs-server.service' }
function Set-CIS_Debian13_2_1_9 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.9' -Packages 'nfs-kernel-server' -Units 'nfs-server.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_10 { Test-Debian13ServiceNotInUse -ControlId '2.1.10' -Title 'Ensure nis server services are not in use' -Packages 'ypserv' -Units 'ypserv.service' }
function Set-CIS_Debian13_2_1_10 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.10' -Packages 'ypserv' -Units 'ypserv.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_11 { Test-Debian13ServiceNotInUse -ControlId '2.1.11' -Title 'Ensure print server services are not in use' -Packages 'cups' -Units 'cups.socket', 'cups.service' }
function Set-CIS_Debian13_2_1_11 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.11' -Packages 'cups' -Units 'cups.socket', 'cups.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_12 { Test-Debian13ServiceNotInUse -ControlId '2.1.12' -Title 'Ensure rpcbind services are not in use' -Packages 'rpcbind' -Units 'rpcbind.socket', 'rpcbind.service' }
function Set-CIS_Debian13_2_1_12 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.12' -Packages 'rpcbind' -Units 'rpcbind.socket', 'rpcbind.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_13 { Test-Debian13ServiceNotInUse -ControlId '2.1.13' -Title 'Ensure rsync services are not in use' -Packages 'rsync' -Units 'rsync.service' }
function Set-CIS_Debian13_2_1_13 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.13' -Packages 'rsync' -Units 'rsync.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_14 { Test-Debian13ServiceNotInUse -ControlId '2.1.14' -Title 'Ensure samba file server services are not in use' -Packages 'samba' -Units 'smbd.service' }
function Set-CIS_Debian13_2_1_14 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.14' -Packages 'samba' -Units 'smbd.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_15 { Test-Debian13ServiceNotInUse -ControlId '2.1.15' -Title 'Ensure snmp services are not in use' -Packages 'snmpd' -Units 'snmpd.service' }
function Set-CIS_Debian13_2_1_15 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.15' -Packages 'snmpd' -Units 'snmpd.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_16 { Test-Debian13ServiceNotInUse -ControlId '2.1.16' -Title 'Ensure telnet-server services are not in use' -Packages 'telnetd', 'telnetd-ssl' -Units 'inetutils-inetd.service' }
function Set-CIS_Debian13_2_1_16 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.16' -Packages 'telnetd', 'telnetd-ssl' -Units 'inetutils-inetd.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_17 { Test-Debian13ServiceNotInUse -ControlId '2.1.17' -Title 'Ensure tftp server services are not in use' -Packages 'tftpd-hpa' -Units 'tftpd-hpa.service' }
function Set-CIS_Debian13_2_1_17 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.17' -Packages 'tftpd-hpa' -Units 'tftpd-hpa.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_18 { Test-Debian13ServiceNotInUse -ControlId '2.1.18' -Title 'Ensure web proxy server services are not in use' -Packages 'squid' -Units 'squid.service' }
function Set-CIS_Debian13_2_1_18 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.18' -Packages 'squid' -Units 'squid.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_19 { Test-Debian13ServiceNotInUse -ControlId '2.1.19' -Title 'Ensure web server services are not in use' -Packages 'apache2', 'nginx' -Units 'apache2.socket', 'apache2.service', 'nginx.service' }
function Set-CIS_Debian13_2_1_19 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.19' -Packages 'apache2', 'nginx' -Units 'apache2.socket', 'apache2.service', 'nginx.service' -Purge:$Purge }

function Test-CIS_Debian13_2_1_20 { Test-Debian13ServiceNotInUse -ControlId '2.1.20' -Title 'Ensure xinetd services are not in use' -Packages 'xinetd' -Units 'xinetd.service' }
function Set-CIS_Debian13_2_1_20 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '2.1.20' -Packages 'xinetd' -Units 'xinetd.service' -Purge:$Purge }

# 2.1.21 (Level 2 - Server): el benchmark solo audita el paquete xserver-common.
function Test-CIS_Debian13_2_1_21 {
    $t = 'Ensure X window server services are not in use'
    if ((Get-CISLinuxProfile) -eq 'Workstation') {
        return New-CISResult -ControlId '2.1.21' -Title $t -Status 'NotApplicable' -Notes 'Control Level 2 - Server unicamente; este equipo se detecto como Workstation.'
    }
    Test-Debian13ClientNotInstalled -ControlId '2.1.21' -Title $t -Packages 'xserver-common'
}
function Set-CIS_Debian13_2_1_21 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ((Get-CISLinuxProfile) -eq 'Workstation') { Write-Warning '2.1.21 es Level 2 - Server: no se aplica en una Workstation.'; return }
    Set-Debian13ClientNotInstalled -ControlId '2.1.21' -Packages 'xserver-common'
}

# 2.1.22 MTA solo en loopback. Deviacion consciente respecto del script del
# benchmark: alli "0.0.0.0" figura como valor aceptable, pero 0.0.0.0 significa
# TODAS las interfaces; aqui solo se aceptan loopback-only/loopback/127.0.0.1/::1/localhost.
function Get-Debian13SsListening { @(& ss -plntu 2>$null) }
function Get-Debian13MtaInterfaces {
    if (Get-Command postconf -ErrorAction SilentlyContinue) { return (& postconf -n inet_interfaces 2>$null) -join ' ' }
    if (Get-Command exim -ErrorAction SilentlyContinue) { return (& exim -bP local_interfaces 2>$null) -join ' ' }
    if ((Get-Command sendmail -ErrorAction SilentlyContinue) -and (Test-Path /etc/mail/sendmail.cf)) {
        return ((Select-String -Path /etc/mail/sendmail.cf -Pattern 'O DaemonPortOptions=' | ForEach-Object { if ($_.Line -match 'Addr=([^,+]+)') { $Matches[1] } } |
                Where-Object { $_ -ne '127.0.0.1' }) -join ' ')
    }
    $null
}
function Test-CIS_Debian13_2_1_22 {
    $t = 'Ensure mail transfer agents are configured for local-only mode'
    $problems = @()
    $ss = Get-Debian13SsListening
    foreach ($port in 25, 465, 587) {
        $lines = @($ss | Where-Object { $_ -match ":$port\b" })
        if ($lines | Where-Object { $_ -notmatch "\s(127\.0\.0\.1|\[?::1\]?):$port\b" }) { $problems += "puerto $port escuchando en interfaz no loopback" }
    }
    $if = Get-Debian13MtaInterfaces
    if ($if) {
        $val = ($if -replace '^\s*inet_interfaces\s*=\s*', '').Trim()
        if ($val -match '\ball\b') { $problems += 'MTA enlazado a todas las interfaces' }
        elseif ($val -notmatch '^(loopback-only|loopback|127\.0\.0\.1|::1|localhost)([,\s]+(loopback-only|loopback|127\.0\.0\.1|::1|localhost))*$') { $problems += "MTA enlazado a: $val" }
    }
    New-CISResult -ControlId '2.1.22' -Title $t -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'MTA solo en loopback (puertos 25/465/587 y interfaces)' `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { $(if ($if) { "interfaces: $if" } else { 'MTA no detectado o sin uso' }) })
}
function Set-CIS_Debian13_2_1_22 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not (Get-Command postconf -ErrorAction SilentlyContinue)) {
        Write-Warning '2.1.22: MTA distinto de postfix (o no instalado): configurar el equivalente a mano segun la documentacion del MTA.'; return
    }
    if ($PSCmdlet.ShouldProcess('/etc/postfix/main.cf', '2.1.22 - inet_interfaces = loopback-only y reiniciar postfix')) {
        Backup-CISFile -Path '/etc/postfix/main.cf' | Out-Null
        & postconf -e 'inet_interfaces = loopback-only'
        & systemctl restart postfix 2>&1 | Out-Null
    }
}

# 2.1.23 Manual: los servicios "aprobados" dependen de la politica del sitio.
function Test-CIS_Debian13_2_1_23 {
    New-CISResult -ControlId '2.1.23' -Title 'Ensure only approved services are listening on a network interface' -Status 'ManualReviewRequired' `
        -Notes "Revisar 'ss -plntu' y confirmar que cada servicio en escucha esta aprobado por la politica del sitio."
}
function Set-CIS_Debian13_2_1_23 { Write-Warning '2.1.23: sin remediacion automatizada -- detener/enmascarar (o desinstalar) los servicios no aprobados.' }

# --- 2.2.x Client services -----------------------------------------------------------

function Test-CIS_Debian13_2_2_1 { Test-Debian13ClientNotInstalled -ControlId '2.2.1' -Title 'Ensure nis client is not installed' -Packages 'nis' }
function Set-CIS_Debian13_2_2_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13ClientNotInstalled -ControlId '2.2.1' -Packages 'nis' }

function Test-CIS_Debian13_2_2_2 { Test-Debian13ClientNotInstalled -ControlId '2.2.2' -Title 'Ensure rsh client is not installed' -Packages 'rsh-client' }
function Set-CIS_Debian13_2_2_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13ClientNotInstalled -ControlId '2.2.2' -Packages 'rsh-client' }

function Test-CIS_Debian13_2_2_3 { Test-Debian13ClientNotInstalled -ControlId '2.2.3' -Title 'Ensure talk client is not installed' -Packages 'talk' }
function Set-CIS_Debian13_2_2_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13ClientNotInstalled -ControlId '2.2.3' -Packages 'talk' }

function Test-CIS_Debian13_2_2_4 { Test-Debian13ClientNotInstalled -ControlId '2.2.4' -Title 'Ensure telnet client is not installed' -Packages 'telnet', 'inetutils-telnet' }
function Set-CIS_Debian13_2_2_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13ClientNotInstalled -ControlId '2.2.4' -Packages 'telnet', 'inetutils-telnet' }

function Test-CIS_Debian13_2_2_5 { Test-Debian13ClientNotInstalled -ControlId '2.2.5' -Title 'Ensure ldap client is not installed' -Packages 'ldap-utils' }
function Set-CIS_Debian13_2_2_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13ClientNotInstalled -ControlId '2.2.5' -Packages 'ldap-utils' }

function Test-CIS_Debian13_2_2_6 { Test-Debian13ClientNotInstalled -ControlId '2.2.6' -Title 'Ensure ftp client is not installed' -Packages 'ftp', 'tnftp' }
function Set-CIS_Debian13_2_2_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13ClientNotInstalled -ControlId '2.2.6' -Packages 'ftp', 'tnftp' }
