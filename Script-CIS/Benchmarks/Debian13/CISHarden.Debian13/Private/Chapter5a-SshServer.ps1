# CIS Debian Linux 13 Benchmark v1.0.0 - 5.1 Configure SSH Server. 23 controles.
# Fuente: cis_debian_13.md, paginas 522-574.
#
# Audit sobre la configuracion efectiva (`sshd -T`); remediacion con un drop-in
# 00-cis-hardening.conf validado con `sshd -t` (ver LinuxSshdEngine en Core).
# Sin openssh-server instalado los controles dan NotApplicable.
# RIESGO al remediar: PermitRootLogin/AllowUsers/cifrados pueden dejar fuera a
# usuarios o clientes; probar desde una segunda sesion antes de cerrar la actual.

function Get-Debian13SshdConfig { Get-CISSshdConfig }
function Get-Debian13SshdVersion { Get-CISSshdVersion }

function New-Debian13SshNotInstalledResult {
    param([string]$ControlId, [string]$Title)
    New-CISResult -ControlId $ControlId -Title $Title -Status 'NotApplicable' -Notes 'openssh-server no esta instalado (sshd no encontrado).'
}

function Test-Debian13SshdControl {
    <# -Check recibe el array de valores de la palabra clave (o $null si no aparece) y devuelve $true si cumple. #>
    param(
        [Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string]$Keyword,
        [Parameter(Mandatory)][scriptblock]$Check, [Parameter(Mandatory)][string]$Expected
    )
    $cfg = Get-Debian13SshdConfig
    if ($null -eq $cfg) { return New-Debian13SshNotInstalledResult $ControlId $Title }
    $v = $cfg[$Keyword.ToLowerInvariant()]
    $ok = [bool](& $Check $v)
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($ok) { 'Pass' } else { 'Fail' }) -ExpectedValue $Expected `
        -ActualValue $(if ($null -ne $v) { "$($Keyword.ToLowerInvariant()) $($v -join ' | ')" } else { "$Keyword no definido" })
}

function Set-Debian13SshdOption {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Keyword, [Parameter(Mandatory)][string]$Value)
    if (-not (Get-CISSshdPath)) { Write-Warning 'openssh-server no esta instalado: nada que remediar.'; return }
    Set-CISSshdOption -Keyword $Keyword -Value $Value
}

# --- 5.1.1-5.1.3 permisos ---------------------------------------------------------------

function Get-Debian13SshdConfFiles { @('/etc/ssh/sshd_config') + @(Get-Debian13FilesIn -Directory '/etc/ssh/sshd_config.d' -Filter '*.conf') }
function Get-Debian13SshHostKeys { param([switch]$Public)
    $cfg = Get-Debian13SshdConfig; if ($null -eq $cfg) { return @() }
    @($cfg['hostkey'] | Where-Object { $_ } | ForEach-Object { if ($Public) { "$_.pub" } else { $_ } } | Where-Object { Test-Path $_ })
}

function Test-CIS_Debian13_5_1_1 {
    Test-Debian13FilesControl -ControlId '5.1.1' -Title 'Ensure access to /etc/ssh/sshd_config is configured' -Paths @(Get-Debian13SshdConfFiles) -MaxMode '600'
}
function Set-CIS_Debian13_5_1_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13FilesControl -ControlId '5.1.1' -Paths @(Get-Debian13SshdConfFiles) -MaxMode '600' -SymbolicMode 'u-x,og-rwx'
}

function Test-CIS_Debian13_5_1_2 {
    if ($null -eq (Get-Debian13SshdConfig)) { return New-Debian13SshNotInstalledResult '5.1.2' 'Ensure access to SSH private host key files is configured' }
    Test-Debian13FilesControl -ControlId '5.1.2' -Title 'Ensure access to SSH private host key files is configured' -Paths @(Get-Debian13SshHostKeys) -MaxMode '600'
}
function Set-CIS_Debian13_5_1_2 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13FilesControl -ControlId '5.1.2' -Paths @(Get-Debian13SshHostKeys) -MaxMode '600' -SymbolicMode 'u-x,og-rwx'
}

function Test-CIS_Debian13_5_1_3 {
    if ($null -eq (Get-Debian13SshdConfig)) { return New-Debian13SshNotInstalledResult '5.1.3' 'Ensure access to SSH public host key files is configured' }
    Test-Debian13FilesControl -ControlId '5.1.3' -Title 'Ensure access to SSH public host key files is configured' -Paths @(Get-Debian13SshHostKeys -Public) -MaxMode '644'
}
function Set-CIS_Debian13_5_1_3 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13FilesControl -ControlId '5.1.3' -Paths @(Get-Debian13SshHostKeys -Public) -MaxMode '644' -SymbolicMode 'u-x,go-wx'
}

# --- 5.1.4 AllowUsers/AllowGroups/DenyUsers/DenyGroups (politica del sitio) ------------------

function Test-CIS_Debian13_5_1_4 {
    $t = 'Ensure sshd access is configured'
    $cfg = Get-Debian13SshdConfig
    if ($null -eq $cfg) { return New-Debian13SshNotInstalledResult '5.1.4' $t }
    $found = @('allowusers', 'allowgroups', 'denyusers', 'denygroups' | Where-Object { $cfg[$_] -and ($cfg[$_] -join ' ').Trim() })
    New-CISResult -ControlId '5.1.4' -Title $t -Status $(if ($found.Count) { 'Pass' } else { 'Fail' }) -ExpectedValue 'Al menos uno de AllowUsers/AllowGroups/DenyUsers/DenyGroups' `
        -ActualValue $(if ($found.Count) { ($found | ForEach-Object { "$_ $($cfg[$_] -join ' ')" }) -join '; ' } else { 'ninguno definido' }) -Notes 'Revisar que las listas cumplan la politica del sitio.'
}
function Set-CIS_Debian13_5_1_4 {
    [CmdletBinding(SupportsShouldProcess)] param([string]$AllowUsers, [string]$AllowGroups)
    if (-not $AllowUsers -and -not $AllowGroups) {
        Write-Warning "5.1.4: las listas de acceso dependen de la politica del sitio -- reintentar con -AllowUsers '<u1> <u2>' y/o -AllowGroups '<g1>'. Incluir al usuario con el que se administra el host."; return
    }
    if ($AllowUsers) { Set-Debian13SshdOption -Keyword 'AllowUsers' -Value $AllowUsers }
    if ($AllowGroups) { Set-Debian13SshdOption -Keyword 'AllowGroups' -Value $AllowGroups }
}

# --- 5.1.5 Banner ---------------------------------------------------------------------------

function Test-CIS_Debian13_5_1_5 {
    $t = 'Ensure sshd Banner is configured'
    $cfg = Get-Debian13SshdConfig
    if ($null -eq $cfg) { return New-Debian13SshNotInstalledResult '5.1.5' $t }
    $b = ($cfg['banner'] | Select-Object -First 1)
    $problems = @()
    if (-not $b -or $b -notmatch '^/') { $problems += 'Banner no apunta a un archivo' }
    elseif (-not (Test-Path $b)) { $problems += "$b no existe" }
    elseif (@(Get-Debian13BannerLeaks -Files $b).Count) { $problems += "$b contiene informacion del sistema (\v \r \m \s o ID del SO)" }
    New-CISResult -ControlId '5.1.5' -Title $t -Status $(if ($problems.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue 'Banner /ruta/archivo sin informacion del SO' `
        -ActualValue $(if ($problems.Count) { $problems -join '; ' } else { "banner $b" }) -Notes 'Verificar que el contenido cumple la politica de avisos legales del sitio.'
}
function Set-CIS_Debian13_5_1_5 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13SshdOption -Keyword 'Banner' -Value '/etc/issue.net'
    Set-Debian13BannerControl -ControlId '5.1.5' -Path '/etc/issue.net'
}

# --- 5.1.6-5.1.19 tabla de opciones -------------------------------------------------------------

function Test-Debian13SshdListHasNone {
    # $true si ninguno de los valores debiles aparece en la lista efectiva (una linea "kw a,b,c").
    param($Values, [string[]]$Weak)
    $items = @(($Values -join ',') -split ',' | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ })
    -not ($items | Where-Object { $Weak -contains $_ })
}

$script:Debian13WeakCiphers = '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'arcfour128', 'arcfour256', 'rijndael-cbc@lysator.liu.se'
$script:Debian13WeakKex = 'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1'
$script:Debian13WeakMacs = 'hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1-96', 'umac-64@openssh.com', 'hmac-md5-etm@openssh.com', 'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com'

function Test-CIS_Debian13_5_1_6 {
    Test-Debian13SshdControl -ControlId '5.1.6' -Title 'Ensure sshd Ciphers are configured' -Keyword 'ciphers' -Expected 'Sin cifrados debiles (3des/blowfish/cast128/aes-cbc/arcfour/rijndael-cbc)' `
        -Check { param($v) Test-Debian13SshdListHasNone -Values $v -Weak $script:Debian13WeakCiphers }
}
# Nota: el benchmark propone crypto-policies (RHEL); en Debian se usa la sintaxis de exclusion de sshd. chacha20-poly1305 se conserva (CVE-2023-48795: revisar que el sistema este parcheado).
function Set-CIS_Debian13_5_1_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'Ciphers' -Value '-3des-cbc,blowfish-cbc,cast128-cbc,aes128-cbc,aes192-cbc,aes256-cbc,arcfour,arcfour128,arcfour256,rijndael-cbc@lysator.liu.se' }

function Test-CIS_Debian13_5_1_7 {
    Test-Debian13SshdControl -ControlId '5.1.7' -Title 'Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured' -Keyword 'clientaliveinterval' -Expected 'ClientAliveInterval > 0 y ClientAliveCountMax > 0' `
        -Check { param($v) $c = (Get-Debian13SshdConfig)['clientalivecountmax']; ([int]($v | Select-Object -First 1) -gt 0) -and ([int]($c | Select-Object -First 1) -gt 0) }
}
function Set-CIS_Debian13_5_1_7 {
    [CmdletBinding(SupportsShouldProcess)] param()
    Set-Debian13SshdOption -Keyword 'ClientAliveInterval' -Value '15'; Set-Debian13SshdOption -Keyword 'ClientAliveCountMax' -Value '3'
}

function Test-CIS_Debian13_5_1_8 { Test-Debian13SshdControl -ControlId '5.1.8' -Title 'Ensure sshd DisableForwarding is enabled' -Keyword 'disableforwarding' -Expected 'yes' -Check { param($v) "$v" -eq 'yes' } }
function Set-CIS_Debian13_5_1_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'DisableForwarding' -Value 'yes' }
function Test-CIS_Debian13_5_1_9 { Test-Debian13SshdControl -ControlId '5.1.9' -Title 'Ensure sshd GSSAPIAuthentication is disabled' -Keyword 'gssapiauthentication' -Expected 'no' -Check { param($v) "$v" -eq 'no' } }
function Set-CIS_Debian13_5_1_9 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'GSSAPIAuthentication' -Value 'no' }
function Test-CIS_Debian13_5_1_10 { Test-Debian13SshdControl -ControlId '5.1.10' -Title 'Ensure sshd HostbasedAuthentication is disabled' -Keyword 'hostbasedauthentication' -Expected 'no' -Check { param($v) "$v" -eq 'no' } }
function Set-CIS_Debian13_5_1_10 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'HostbasedAuthentication' -Value 'no' }
function Test-CIS_Debian13_5_1_11 { Test-Debian13SshdControl -ControlId '5.1.11' -Title 'Ensure sshd IgnoreRhosts is enabled' -Keyword 'ignorerhosts' -Expected 'yes' -Check { param($v) "$v" -eq 'yes' } }
function Set-CIS_Debian13_5_1_11 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'IgnoreRhosts' -Value 'yes' }

function Test-CIS_Debian13_5_1_12 {
    Test-Debian13SshdControl -ControlId '5.1.12' -Title 'Ensure sshd KexAlgorithms is configured' -Keyword 'kexalgorithms' -Expected 'Sin algoritmos de intercambio debiles (dh-group1/group14/group-exchange sha1)' `
        -Check { param($v) Test-Debian13SshdListHasNone -Values $v -Weak $script:Debian13WeakKex }
}
function Set-CIS_Debian13_5_1_12 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'KexAlgorithms' -Value '-diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1' }

function Test-CIS_Debian13_5_1_13 {
    $t = 'Ensure sshd post-quantum cryptography key exchange algorithms are configured'
    $cfg = Get-Debian13SshdConfig
    if ($null -eq $cfg) { return New-Debian13SshNotInstalledResult '5.1.13' $t }
    $kex = @(($cfg['kexalgorithms'] -join ',') -split ',' | ForEach-Object { $_.Trim() })
    $ver = Get-Debian13SshdVersion
    $missing = @()
    if ($kex -notcontains 'sntrup761x25519-sha512') { $missing += 'sntrup761x25519-sha512' }
    if ($ver -and $ver -ge [version]'9.9' -and $kex -notcontains 'mlkem768x25519-sha256') { $missing += 'mlkem768x25519-sha256' }
    New-CISResult -ControlId '5.1.13' -Title $t -Status $(if ($missing.Count) { 'Fail' } else { 'Pass' }) `
        -ExpectedValue 'sntrup761x25519-sha512 (y mlkem768x25519-sha256 si OpenSSH >= 9.9) en KexAlgorithms' `
        -ActualValue $(if ($missing.Count) { "OpenSSH $ver; faltan: $($missing -join ', ')" } else { "OpenSSH $ver; PQC presente" })
}
function Set-CIS_Debian13_5_1_13 {
    [CmdletBinding(SupportsShouldProcess)] param()
    $ver = Get-Debian13SshdVersion
    $list = 'sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521'
    if ($ver -and $ver -ge [version]'9.9') { $list = "mlkem768x25519-sha256,$list" }
    Set-Debian13SshdOption -Keyword 'KexAlgorithms' -Value $list
}

function Test-CIS_Debian13_5_1_14 { Test-Debian13SshdControl -ControlId '5.1.14' -Title 'Ensure sshd LoginGraceTime is configured' -Keyword 'logingracetime' -Expected 'LoginGraceTime entre 1 y 60 segundos' -Check { param($v) $n = [int]($v | Select-Object -First 1); $n -ge 1 -and $n -le 60 } }
function Set-CIS_Debian13_5_1_14 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'LoginGraceTime' -Value '60' }
function Test-CIS_Debian13_5_1_15 { Test-Debian13SshdControl -ControlId '5.1.15' -Title 'Ensure sshd LogLevel is configured' -Keyword 'loglevel' -Expected 'VERBOSE o INFO' -Check { param($v) "$v" -in 'VERBOSE', 'INFO' } }
function Set-CIS_Debian13_5_1_15 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'LogLevel' -Value 'VERBOSE' }

function Test-CIS_Debian13_5_1_16 {
    Test-Debian13SshdControl -ControlId '5.1.16' -Title 'Ensure sshd MACs are configured' -Keyword 'macs' -Expected 'Sin MACs debiles (md5, 96-bit, ripemd160, umac-64/128-etm)' `
        -Check { param($v) Test-Debian13SshdListHasNone -Values $v -Weak $script:Debian13WeakMacs }
}
function Set-CIS_Debian13_5_1_16 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'MACs' -Value ('-' + ($script:Debian13WeakMacs -join ',')) }

function Test-CIS_Debian13_5_1_17 { Test-Debian13SshdControl -ControlId '5.1.17' -Title 'Ensure sshd MaxAuthTries is configured' -Keyword 'maxauthtries' -Expected 'MaxAuthTries <= 4' -Check { param($v) $n = [int]($v | Select-Object -First 1); $n -ge 1 -and $n -le 4 } }
function Set-CIS_Debian13_5_1_17 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'MaxAuthTries' -Value '4' }

function Get-Debian13MaxSessionsOverLimit {
    # Segundo paso del Audit: lineas MaxSessions > 10 en sshd_config y sshd_config.d (incluye bloques Match).
    @(Get-Debian13SshdConfFiles | Where-Object { Test-Path $_ } | ForEach-Object { Select-String -Path $_ -Pattern '^\s*MaxSessions\s+"?(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\b' } | ForEach-Object { "$($_.Path): $($_.Line.Trim())" })
}
function Test-CIS_Debian13_5_1_18 {
    $r = Test-Debian13SshdControl -ControlId '5.1.18' -Title 'Ensure sshd MaxSessions is configured' -Keyword 'maxsessions' -Expected 'MaxSessions <= 10 (tambien en bloques Match)' -Check { param($v) $n = [int]($v | Select-Object -First 1); $n -ge 1 -and $n -le 10 }
    if ($r.Status -eq 'Pass') {
        $over = @(Get-Debian13MaxSessionsOverLimit)
        if ($over.Count) { $r.Status = 'Fail'; $r.ActualValue = "$($r.ActualValue); con valor > 10 en: $($over -join ' | ')" }
    }
    $r
}
function Set-CIS_Debian13_5_1_18 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'MaxSessions' -Value '10' }

function Test-CIS_Debian13_5_1_19 {
    Test-Debian13SshdControl -ControlId '5.1.19' -Title 'Ensure sshd MaxStartups is configured' -Keyword 'maxstartups' -Expected 'MaxStartups 10:30:60 o mas restrictivo' `
        -Check { param($v) $p = ("$($v | Select-Object -First 1)" -split ':'); ($p.Count -eq 3) -and ([int]$p[0] -le 10) -and ([int]$p[1] -le 30) -and ([int]$p[2] -le 60) }
}
function Set-CIS_Debian13_5_1_19 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'MaxStartups' -Value '10:30:60' }

# --- 5.1.20-5.1.23 ------------------------------------------------------------------------------------

function Test-CIS_Debian13_5_1_20 { Test-Debian13SshdControl -ControlId '5.1.20' -Title 'Ensure sshd PermitEmptyPasswords is disabled' -Keyword 'permitemptypasswords' -Expected 'no' -Check { param($v) "$v" -eq 'no' } }
function Set-CIS_Debian13_5_1_20 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'PermitEmptyPasswords' -Value 'no' }
function Test-CIS_Debian13_5_1_21 { Test-Debian13SshdControl -ControlId '5.1.21' -Title 'Ensure sshd PermitRootLogin is disabled' -Keyword 'permitrootlogin' -Expected 'no' -Check { param($v) "$v" -eq 'no' } }
function Set-CIS_Debian13_5_1_21 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'PermitRootLogin' -Value 'no' }
function Test-CIS_Debian13_5_1_22 { Test-Debian13SshdControl -ControlId '5.1.22' -Title 'Ensure sshd PermitUserEnvironment is disabled' -Keyword 'permituserenvironment' -Expected 'no' -Check { param($v) "$v" -eq 'no' } }
function Set-CIS_Debian13_5_1_22 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'PermitUserEnvironment' -Value 'no' }
function Test-CIS_Debian13_5_1_23 { Test-Debian13SshdControl -ControlId '5.1.23' -Title 'Ensure sshd UsePAM is enabled' -Keyword 'usepam' -Expected 'yes' -Check { param($v) "$v" -eq 'yes' } }
function Set-CIS_Debian13_5_1_23 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13SshdOption -Keyword 'UsePAM' -Value 'yes' }
