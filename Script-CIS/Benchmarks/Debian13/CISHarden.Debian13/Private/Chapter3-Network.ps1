# CIS Debian Linux 13 Benchmark v1.0.0 - 3.1 Configure Network Devices, 3.2
# Configure Network Kernel Modules y 3.3 Configure Network Kernel Parameters.
# 35 controles. Fuente: cis_debian_13.md, paginas 369-507.
#
# RIESGO al remediar 3.3.x: deshabilitar el forwarding rompe routers, VPN,
# Docker/Kubernetes y muchos hosts en nube. Simular siempre con -WhatIf y
# revisar los controles 3.3.1.1-3.3.1.3 y 3.3.2.1-3.3.2.2 antes de aplicar.

# --- 3.1 Network devices --------------------------------------------------------------

function Test-Debian13Ipv6Enabled {
    # Criterio del benchmark (3.1.1): IPv6 activo si /sys/module/ipv6/parameters/disable vale 0.
    $f = '/sys/module/ipv6/parameters/disable'
    (Test-Path $f) -and ((Get-Content $f -ErrorAction SilentlyContinue | Select-Object -First 1) -match '^\s*0\b')
}

# Manual: solo se debe identificar si IPv6 esta en uso segun politica del sitio.
function Test-CIS_Debian13_3_1_1 {
    New-CISResult -ControlId '3.1.1' -Title 'Ensure IPv6 status is identified' -Status 'ManualReviewRequired' `
        -ActualValue "IPv6 $(if (Test-Debian13Ipv6Enabled) { 'habilitado' } else { 'deshabilitado' })" `
        -Notes 'Confirmar que el estado de IPv6 sigue la politica del sitio (los controles 3.3.2.x solo aplican si IPv6 esta habilitado).'
}
function Set-CIS_Debian13_3_1_1 { Write-Warning '3.1.1: sin remediacion automatizada -- habilitar o deshabilitar IPv6 segun politica del sitio.' }

function Get-Debian13WirelessDriverModules {
    # Modulos de kernel de las interfaces inalambricas presentes (/sys/class/net/*/wireless).
    foreach ($d in @(Get-ChildItem /sys/class/net -Directory -ErrorAction SilentlyContinue)) {
        if (Test-Path (Join-Path $d.FullName 'wireless')) {
            $m = (& readlink -f (Join-Path $d.FullName 'device/driver/module') 2>$null)
            if ($m) { Split-Path $m -Leaf }
        }
    }
}
function Get-Debian13ModuleState {
    param([Parameter(Mandatory)][string]$Name)
    $probe = $Name -replace '-', '_'
    $load = (& modprobe -n -v $Name 2>$null) -join "`n"
    [pscustomobject]@{
        Module      = $Name
        Loadable    = -not [bool]($load -match '(?m)^\s*install\s+(/usr)?/bin/(true|false)')
        Loaded      = [bool]((& lsmod 2>$null) -join "`n" -match "(?m)^$([regex]::Escape($probe))\s")
        Blacklisted = [bool]((& modprobe --showconfig 2>$null) -join "`n" -match "(?m)^\s*blacklist\s+$([regex]::Escape($probe))\b")
    }
}

function Test-CIS_Debian13_3_1_2 {
    $t = 'Ensure wireless interfaces are not available'
    $bad = @(Get-Debian13WirelessDriverModules | Sort-Object -Unique | ForEach-Object { Get-Debian13ModuleState -Name $_ } |
            Where-Object { $_.Loadable -or $_.Loaded -or -not $_.Blacklisted })
    New-CISResult -ControlId '3.1.2' -Title $t -Status $(if ($bad.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'Sin interfaces inalambricas, o sus modulos no cargables, no cargados y en denylist' `
        -ActualValue $(if ($bad.Count) { ($bad | ForEach-Object { "$($_.Module) (loadable=$($_.Loadable); loaded=$($_.Loaded); blacklisted=$($_.Blacklisted))" }) -join '; ' } else { 'sin interfaces inalambricas activas, o deshabilitadas' })
}
function Set-CIS_Debian13_3_1_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $conf = '/etc/modprobe.d/blacklist-wireless.conf'
    $dir = "/lib/modules/$((& uname -r).Trim())/kernel/drivers/net/wireless"
    if (-not (Test-Path $dir)) { return }
    if ($PSCmdlet.ShouldProcess($conf, '3.1.2 - install /bin/false + blacklist de todos los drivers wireless del kernel')) {
        if (Test-Path $conf) { Backup-CISFile -Path $conf | Out-Null }
        foreach ($ko in Get-ChildItem $dir -Recurse -Filter '*.ko*' -File) {
            $n = $ko.Name -replace '\.ko(\..+)?$', ''
            Add-Content -Path $conf -Value @("install $n /bin/false", "blacklist $n", '')
        }
    }
}

function Test-CIS_Debian13_3_1_3 { Test-Debian13ServiceNotInUse -ControlId '3.1.3' -Title 'Ensure bluetooth services are not in use' -Packages 'bluez' -Units 'bluetooth.service' }
function Set-CIS_Debian13_3_1_3 { [CmdletBinding(SupportsShouldProcess)] param([switch]$Purge) Set-Debian13ServiceNotInUse -ControlId '3.1.3' -Packages 'bluez' -Units 'bluetooth.service' -Purge:$Purge }

# --- 3.2 Network kernel modules -----------------------------------------------------------

function Test-CIS_Debian13_3_2_1 { Test-Debian13KernelModuleControl -ControlId '3.2.1' -Title 'Ensure atm kernel module is not available' -Module 'atm' -Type net }
function Set-CIS_Debian13_3_2_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '3.2.1' -Module 'atm' -Type net }

function Test-CIS_Debian13_3_2_2 { Test-Debian13KernelModuleControl -ControlId '3.2.2' -Title 'Ensure can kernel module is not available' -Module 'can' -Type net }
function Set-CIS_Debian13_3_2_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '3.2.2' -Module 'can' -Type net }

function Test-CIS_Debian13_3_2_3 { Test-Debian13KernelModuleControl -ControlId '3.2.3' -Title 'Ensure dccp kernel module is not available' -Module 'dccp' -Type net }
function Set-CIS_Debian13_3_2_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '3.2.3' -Module 'dccp' -Type net }

function Test-CIS_Debian13_3_2_4 { Test-Debian13KernelModuleControl -ControlId '3.2.4' -Title 'Ensure rds kernel module is not available' -Module 'rds' -Type net }
function Set-CIS_Debian13_3_2_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '3.2.4' -Module 'rds' -Type net }

function Test-CIS_Debian13_3_2_5 { Test-Debian13KernelModuleControl -ControlId '3.2.5' -Title 'Ensure sctp kernel module is not available' -Module 'sctp' -Type net }
function Set-CIS_Debian13_3_2_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '3.2.5' -Module 'sctp' -Type net }

function Test-CIS_Debian13_3_2_6 { Test-Debian13KernelModuleControl -ControlId '3.2.6' -Title 'Ensure tipc kernel module is not available' -Module 'tipc' -Type net }
function Set-CIS_Debian13_3_2_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '3.2.6' -Module 'tipc' -Type net }

# --- 3.3 Network kernel parameters (sysctl: valor en ejecucion + persistido) ------------------

function Test-Debian13NetSysctlControl {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Value, [switch]$Ipv6)
    if ($Ipv6 -and -not (Test-Debian13Ipv6Enabled)) {
        return New-CISResult -ControlId $ControlId -Title $Title -Status 'NotApplicable' -ExpectedValue "$Key = $Value si IPv6 esta habilitado" -ActualValue 'IPv6 deshabilitado'
    }
    Test-Debian13SysctlControl -ControlId $ControlId -Title $Title -Key $Key -Accept $Value
}
function Set-Debian13NetSysctlControl {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Key, [Parameter(Mandatory)][string]$Value, [switch]$Ipv6)
    if ($Ipv6 -and -not (Test-Debian13Ipv6Enabled)) { return }
    Set-Debian13SysctlControl -Key $Key -Value $Value
}

# 3.3.1.1 (Workstation L1 / Server L2): net.ipv4.ip_forward. El benchmark permite omitirlo si
# net.ipv4.conf.all.forwarding y net.ipv4.conf.default.forwarding ya estan en 0.
function Test-CIS_Debian13_3_3_1_1 {
    $t = 'Ensure net.ipv4.ip_forward is configured'
    $r = Test-Debian13NetSysctlControl -ControlId '3.3.1.1' -Title $t -Key 'net.ipv4.ip_forward' -Value '0'
    if ($r.Status -ne 'Pass' -and (Test-CISSysctlSetting -Key 'net.ipv4.conf.all.forwarding' -Value '0').Compliant -and (Test-CISSysctlSetting -Key 'net.ipv4.conf.default.forwarding' -Value '0').Compliant) {
        return New-CISResult -ControlId '3.3.1.1' -Title $t -Status 'Pass' -ExpectedValue 'net.ipv4.ip_forward = 0, o forwarding all/default = 0' `
            -ActualValue $r.ActualValue -Notes 'Cubierto por net.ipv4.conf.all.forwarding = 0 y net.ipv4.conf.default.forwarding = 0 (omision permitida por el benchmark).'
    }
    $r
}
function Set-CIS_Debian13_3_3_1_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.ip_forward' -Value '0' }

function Test-CIS_Debian13_3_3_1_2 { Test-Debian13NetSysctlControl -ControlId '3.3.1.2' -Title 'Ensure net.ipv4.conf.all.forwarding is configured' -Key 'net.ipv4.conf.all.forwarding' -Value '0' }
function Set-CIS_Debian13_3_3_1_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.forwarding' -Value '0' }

function Test-CIS_Debian13_3_3_1_3 { Test-Debian13NetSysctlControl -ControlId '3.3.1.3' -Title 'Ensure net.ipv4.conf.default.forwarding is configured' -Key 'net.ipv4.conf.default.forwarding' -Value '0' }
function Set-CIS_Debian13_3_3_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.forwarding' -Value '0' }

function Test-CIS_Debian13_3_3_1_4 { Test-Debian13NetSysctlControl -ControlId '3.3.1.4' -Title 'Ensure net.ipv4.conf.all.send_redirects is configured' -Key 'net.ipv4.conf.all.send_redirects' -Value '0' }
function Set-CIS_Debian13_3_3_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.send_redirects' -Value '0' }

function Test-CIS_Debian13_3_3_1_5 { Test-Debian13NetSysctlControl -ControlId '3.3.1.5' -Title 'Ensure net.ipv4.conf.default.send_redirects is configured' -Key 'net.ipv4.conf.default.send_redirects' -Value '0' }
function Set-CIS_Debian13_3_3_1_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.send_redirects' -Value '0' }

function Test-CIS_Debian13_3_3_1_6 { Test-Debian13NetSysctlControl -ControlId '3.3.1.6' -Title 'Ensure net.ipv4.icmp_ignore_bogus_error_responses is configured' -Key 'net.ipv4.icmp_ignore_bogus_error_responses' -Value '1' }
function Set-CIS_Debian13_3_3_1_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.icmp_ignore_bogus_error_responses' -Value '1' }

function Test-CIS_Debian13_3_3_1_7 { Test-Debian13NetSysctlControl -ControlId '3.3.1.7' -Title 'Ensure net.ipv4.icmp_echo_ignore_broadcasts is configured' -Key 'net.ipv4.icmp_echo_ignore_broadcasts' -Value '1' }
function Set-CIS_Debian13_3_3_1_7 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.icmp_echo_ignore_broadcasts' -Value '1' }

function Test-CIS_Debian13_3_3_1_8 { Test-Debian13NetSysctlControl -ControlId '3.3.1.8' -Title 'Ensure net.ipv4.conf.all.accept_redirects is configured' -Key 'net.ipv4.conf.all.accept_redirects' -Value '0' }
function Set-CIS_Debian13_3_3_1_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.accept_redirects' -Value '0' }

function Test-CIS_Debian13_3_3_1_9 { Test-Debian13NetSysctlControl -ControlId '3.3.1.9' -Title 'Ensure net.ipv4.conf.default.accept_redirects is configured' -Key 'net.ipv4.conf.default.accept_redirects' -Value '0' }
function Set-CIS_Debian13_3_3_1_9 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.accept_redirects' -Value '0' }

function Test-CIS_Debian13_3_3_1_10 { Test-Debian13NetSysctlControl -ControlId '3.3.1.10' -Title 'Ensure net.ipv4.conf.all.secure_redirects is configured' -Key 'net.ipv4.conf.all.secure_redirects' -Value '0' }
function Set-CIS_Debian13_3_3_1_10 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.secure_redirects' -Value '0' }

function Test-CIS_Debian13_3_3_1_11 { Test-Debian13NetSysctlControl -ControlId '3.3.1.11' -Title 'Ensure net.ipv4.conf.default.secure_redirects is configured' -Key 'net.ipv4.conf.default.secure_redirects' -Value '0' }
function Set-CIS_Debian13_3_3_1_11 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.secure_redirects' -Value '0' }

function Test-CIS_Debian13_3_3_1_12 { Test-Debian13NetSysctlControl -ControlId '3.3.1.12' -Title 'Ensure net.ipv4.conf.all.rp_filter is configured' -Key 'net.ipv4.conf.all.rp_filter' -Value '1' }
function Set-CIS_Debian13_3_3_1_12 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.rp_filter' -Value '1' }

function Test-CIS_Debian13_3_3_1_13 { Test-Debian13NetSysctlControl -ControlId '3.3.1.13' -Title 'Ensure net.ipv4.conf.default.rp_filter is configured' -Key 'net.ipv4.conf.default.rp_filter' -Value '1' }
function Set-CIS_Debian13_3_3_1_13 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.rp_filter' -Value '1' }

function Test-CIS_Debian13_3_3_1_14 { Test-Debian13NetSysctlControl -ControlId '3.3.1.14' -Title 'Ensure net.ipv4.conf.all.accept_source_route is configured' -Key 'net.ipv4.conf.all.accept_source_route' -Value '0' }
function Set-CIS_Debian13_3_3_1_14 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.accept_source_route' -Value '0' }

function Test-CIS_Debian13_3_3_1_15 { Test-Debian13NetSysctlControl -ControlId '3.3.1.15' -Title 'Ensure net.ipv4.conf.default.accept_source_route is configured' -Key 'net.ipv4.conf.default.accept_source_route' -Value '0' }
function Set-CIS_Debian13_3_3_1_15 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.accept_source_route' -Value '0' }

function Test-CIS_Debian13_3_3_1_16 { Test-Debian13NetSysctlControl -ControlId '3.3.1.16' -Title 'Ensure net.ipv4.conf.all.log_martians is configured' -Key 'net.ipv4.conf.all.log_martians' -Value '1' }
function Set-CIS_Debian13_3_3_1_16 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.all.log_martians' -Value '1' }

function Test-CIS_Debian13_3_3_1_17 { Test-Debian13NetSysctlControl -ControlId '3.3.1.17' -Title 'Ensure net.ipv4.conf.default.log_martians is configured' -Key 'net.ipv4.conf.default.log_martians' -Value '1' }
function Set-CIS_Debian13_3_3_1_17 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.conf.default.log_martians' -Value '1' }

function Test-CIS_Debian13_3_3_1_18 { Test-Debian13NetSysctlControl -ControlId '3.3.1.18' -Title 'Ensure net.ipv4.tcp_syncookies is configured' -Key 'net.ipv4.tcp_syncookies' -Value '1' }
function Set-CIS_Debian13_3_3_1_18 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv4.tcp_syncookies' -Value '1' }

function Test-CIS_Debian13_3_3_2_1 { Test-Debian13NetSysctlControl -ControlId '3.3.2.1' -Title 'Ensure net.ipv6.conf.all.forwarding is configured' -Key 'net.ipv6.conf.all.forwarding' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.all.forwarding' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_2 { Test-Debian13NetSysctlControl -ControlId '3.3.2.2' -Title 'Ensure net.ipv6.conf.default.forwarding is configured' -Key 'net.ipv6.conf.default.forwarding' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.default.forwarding' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_3 { Test-Debian13NetSysctlControl -ControlId '3.3.2.3' -Title 'Ensure net.ipv6.conf.all.accept_redirects is configured' -Key 'net.ipv6.conf.all.accept_redirects' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.all.accept_redirects' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_4 { Test-Debian13NetSysctlControl -ControlId '3.3.2.4' -Title 'Ensure net.ipv6.conf.default.accept_redirects is configured' -Key 'net.ipv6.conf.default.accept_redirects' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.default.accept_redirects' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_5 { Test-Debian13NetSysctlControl -ControlId '3.3.2.5' -Title 'Ensure net.ipv6.conf.all.accept_source_route is configured' -Key 'net.ipv6.conf.all.accept_source_route' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.all.accept_source_route' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_6 { Test-Debian13NetSysctlControl -ControlId '3.3.2.6' -Title 'Ensure net.ipv6.conf.default.accept_source_route is configured' -Key 'net.ipv6.conf.default.accept_source_route' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.default.accept_source_route' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_7 { Test-Debian13NetSysctlControl -ControlId '3.3.2.7' -Title 'Ensure net.ipv6.conf.all.accept_ra is configured' -Key 'net.ipv6.conf.all.accept_ra' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_7 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.all.accept_ra' -Value '0' -Ipv6 }

function Test-CIS_Debian13_3_3_2_8 { Test-Debian13NetSysctlControl -ControlId '3.3.2.8' -Title 'Ensure net.ipv6.conf.default.accept_ra is configured' -Key 'net.ipv6.conf.default.accept_ra' -Value '0' -Ipv6 }
function Set-CIS_Debian13_3_3_2_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13NetSysctlControl -Key 'net.ipv6.conf.default.accept_ra' -Value '0' -Ipv6 }
