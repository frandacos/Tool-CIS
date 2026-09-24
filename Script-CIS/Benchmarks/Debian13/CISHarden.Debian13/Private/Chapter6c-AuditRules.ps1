# CIS Debian Linux 13 Benchmark v1.0.0 - 6.2.3 Configure auditd Rules. 37 controles
# (36 Automated + 6.2.3.37 Manual). Fuente: cis_debian_13.md, paginas 777-928.
#
# Las reglas esperadas de 33 controles salen de inventory/auditd_rules.json
# (extraidas de la seccion Remediation de cada control, con {ARCH} y {UID_MIN}
# sustituidos). 6.2.3.10 (comandos privilegiados) se genera dinamicamente; 6.2.3.35
# (-c) y 6.2.3.36 (-e 2) se tratan en codigo.
#
# Audit (como el benchmark): la regla debe estar EN DISCO (/etc/audit/rules.d/*.rules)
# y CARGADA (`auditctl -l`). Se compara por semantica, no por texto: mismos campos
# -F (sin -k), syscalls contenidas, `path`/`dir` equivalentes a `-w`, y normalizando
# lo que auditctl reescribe (exit=-EACCES -> -13, auid!=unset -> auid!=-1, a0=0x0 -> 0).
# La regla cargada solo se exige si el path/dir vigilado existe (auditctl no puede
# cargar vigilancias de rutas inexistentes; por eso 6.2.3.35 escribe `-c` primero).
# RIESGO: 6.2.3.36 (-e 2) vuelve inmutable la configuracion hasta el reinicio.

$script:Debian13AuditRulesData = $null
function Get-Debian13AuditRulesData {
    if (-not $script:Debian13AuditRulesData) { $script:Debian13AuditRulesData = (Get-Content (Join-Path $PSScriptRoot '../inventory/auditd_rules.json') -Raw | ConvertFrom-Json).controls }
    $script:Debian13AuditRulesData
}
function Get-Debian13AuditArch { if ((& uname -m 2>$null) -match '64|s390x') { 'b64' } else { 'b32' } }
function Get-Debian13AuditRulesDir { Join-Path $script:Debian13AuditDir 'rules.d' }

# --- modelo de reglas ------------------------------------------------------------------------

function ConvertTo-Debian13AuditField {
    # "auid>=1000" -> @{Key; Op; Val} con valores normalizados como los muestra auditctl -l
    param([string]$Text)
    if ($Text -notmatch '^([A-Za-z0-9_]+)(!=|>=|<=|=|>|<)(.*)$') { return $null }
    $k = $Matches[1].ToLowerInvariant(); $op = $Matches[2]; $v = $Matches[3].Trim()
    switch -Regex ($v) { '^unset$|^4294967295$' { $v = '-1' } '^-?EACCES$' { $v = '-13' } '^-?EPERM$' { $v = '-1' } '^0x[0-9a-fA-F]+$' { $v = [string][Convert]::ToInt64($v, 16) } }
    if ($k -in 'path', 'dir') { $v = $v.TrimEnd('/'); if ($v -eq '') { $v = '/' } }
    [pscustomobject]@{ Key = $k; Op = $op; Val = $v; Text = "$k$op$v" }
}
function ConvertTo-Debian13AuditRule {
    <# Analiza una linea de regla (-a/-A o -w). $null si no es una regla de archivo/syscall. #>
    param([Parameter(Mandatory)][string]$Line)
    $t = @($Line.Trim() -split '\s+')
    $m = [ordered]@{ Action = $null; Arch = $null; Syscalls = [System.Collections.Generic.HashSet[string]]::new(); Fields = [System.Collections.Generic.HashSet[string]]::new(); Watch = $null }
    if ($t[0] -eq '-w') {
        $perms = if ($Line -match '\s-p\s+(\S+)') { $Matches[1] } else { 'rwxa' }
        $p = $t[1].TrimEnd('/'); $m.Action = 'watch'; $m.Syscalls.Add('all') | Out-Null; $m.Watch = $p
        $m.Fields.Add("perm=$(($perms.ToCharArray() | Sort-Object) -join '')") | Out-Null
        return [pscustomobject]$m
    }
    if ($t[0] -notin '-a', '-A') { return $null }
    $m.Action = $t[1] -replace 'exit,always', 'always,exit'
    for ($i = 2; $i -lt $t.Count; $i++) {
        switch ($t[$i]) {
            '-S' { foreach ($s in $t[++$i] -split ',') { $m.Syscalls.Add($s.ToLowerInvariant()) | Out-Null } }
            { $_ -in '-F', '-C' } {
                $f = ConvertTo-Debian13AuditField -Text $t[++$i]
                if ($f.Key -eq 'arch') { $m.Arch = $f.Val } elseif ($f.Key -eq 'key') { } elseif ($f.Key -eq 'perm') { $m.Fields.Add("perm=$((($f.Val).ToCharArray() | Sort-Object) -join '')") | Out-Null } else { $m.Fields.Add($f.Text) | Out-Null }
            }
            '-k' { $i++ }
        }
    }
    if (-not $m.Syscalls.Count) { $m.Syscalls.Add('all') | Out-Null }
    [pscustomobject]$m
}
function Get-Debian13AuditRuleTarget {
    # Ruta vigilada (path=/dir=/-w), o $null si es una regla de syscalls.
    param($Rule)
    if ($Rule.Watch) { return $Rule.Watch }
    foreach ($f in $Rule.Fields) { if ($f -match '^(path|dir)=(.+)$') { return $Matches[2] } }
}
function Test-Debian13AuditRuleMatch {
    param([Parameter(Mandatory)]$Expected, [Parameter(Mandatory)]$Actual)
    if ($Expected.Action -ne $Actual.Action -and -not ($Actual.Action -eq 'watch')) { return $false }
    if ($Expected.Arch -and $Actual.Arch -and $Expected.Arch -ne $Actual.Arch) { return $false }
    $et = Get-Debian13AuditRuleTarget $Expected
    if ($et) {
        $at = Get-Debian13AuditRuleTarget $Actual
        if ($at -ne $et) { return $false }
        $ep = @($Expected.Fields | Where-Object { $_ -like 'perm=*' }); $ap = @($Actual.Fields | Where-Object { $_ -like 'perm=*' })
        if ($ep.Count -and (-not $ap.Count -or -not (@($ep[0].Substring(5).ToCharArray() | Where-Object { $ap[0].Substring(5) -notmatch [regex]::Escape($_) }).Count -eq 0))) { return $false }
        $rest = @($Expected.Fields | Where-Object { $_ -notlike 'perm=*' -and $_ -notmatch '^(path|dir)=' })
        foreach ($f in $rest) { if (-not $Actual.Fields.Contains($f)) { return $false } }
        return $true
    }
    if (-not $Actual.Syscalls.Contains('all')) { foreach ($s in $Expected.Syscalls) { if (-not $Actual.Syscalls.Contains($s)) { return $false } } }
    foreach ($f in $Expected.Fields) { if (-not $Actual.Fields.Contains($f)) { return $false } }
    $true
}

# --- lectura del estado ------------------------------------------------------------------------

function Get-Debian13AuditRuleFiles { @(Get-ChildItem (Get-Debian13AuditRulesDir) -Filter '*.rules' -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object FullName) }
function Get-Debian13OnDiskAuditRules {
    foreach ($f in @(Get-Debian13AuditRuleFiles)) { foreach ($l in @(Get-Content $f -ErrorAction SilentlyContinue)) { if ($l -match '^\s*-(a|A|w)\s') { $r = ConvertTo-Debian13AuditRule -Line $l; if ($r) { $r } } } }
}
function Get-Debian13AuditctlList { @(& auditctl -l 2>$null) }
function Get-Debian13RunningAuditRules {
    foreach ($l in @(Get-Debian13AuditctlList)) { if ($l -match '^\s*-(a|A|w)\s') { $r = ConvertTo-Debian13AuditRule -Line $l; if ($r) { $r } } }
}
function Get-Debian13UidMin { $v = Get-Debian13LoginDefs -Key 'UID_MIN'; if ($v) { $v } else { '1000' } }
function Expand-Debian13AuditRuleText { param([string]$Text) $Text.Replace('{ARCH}', (Get-Debian13AuditArch)).Replace('{UID_MIN}', (Get-Debian13UidMin)) }

function Test-Debian13AuditRulesControl {
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][string]$Title, [Parameter(Mandatory)][string[]]$RuleTexts)
    $disk = @(Get-Debian13OnDiskAuditRules); $run = @(Get-Debian13RunningAuditRules)
    $missingDisk = @(); $missingRun = @()
    foreach ($txt in $RuleTexts) {
        $e = ConvertTo-Debian13AuditRule -Line $txt
        if (-not ($disk | Where-Object { Test-Debian13AuditRuleMatch -Expected $e -Actual $_ })) { $missingDisk += $txt }
        $target = Get-Debian13AuditRuleTarget $e
        if ($target -and -not (Test-Path $target)) { continue }   # no se puede cargar una vigilancia de una ruta inexistente
        if (-not ($run | Where-Object { Test-Debian13AuditRuleMatch -Expected $e -Actual $_ })) { $missingRun += $txt }
    }
    $prob = @()
    if ($missingDisk.Count) { $prob += "sin regla en disco ($($missingDisk.Count)): $($missingDisk[0])$(if ($missingDisk.Count -gt 1) { ' ...' })" }
    if ($missingRun.Count) { $prob += "sin regla cargada ($($missingRun.Count)): $($missingRun[0])$(if ($missingRun.Count -gt 1) { ' ...' })" }
    New-CISResult -ControlId $ControlId -Title $Title -Status $(if ($prob.Count) { 'Fail' } else { 'Pass' }) -ExpectedValue "$($RuleTexts.Count) regla(s) en /etc/audit/rules.d y en auditctl -l" `
        -ActualValue $(if ($prob.Count) { $prob -join '; ' } else { 'reglas en disco y cargadas' })
}

function Add-Debian13AuditRules {
    # Agrega a <File> (bajo rules.d) las reglas que falten (comparacion textual normalizada de la linea).
    param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)][string[]]$RuleTexts)
    $dir = Get-Debian13AuditRulesDir; $path = Join-Path $dir $File
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $have = @(Get-Content $path -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() })
    $new = @($RuleTexts | Where-Object { $_ -notin $have })
    if (-not $new.Count) { return $false }
    if (Test-Path $path) { Copy-Item $path "$path.bak_$(Get-Date -Format 'yyyyMMdd_HHmmss')" }
    Add-Content -Path $path -Value (@('') + $new)
    $true
}
function Invoke-Debian13AugenrulesLoad {
    & augenrules --load 2>&1 | Out-Null
    $s = (& auditctl -s 2>$null) -join ' '
    if ($s -match 'enabled\s+2') { Write-Warning 'auditd esta en modo inmutable (-e 2): las reglas nuevas se aplicaran tras reiniciar el sistema.' }
}

function Set-Debian13AuditRulesControl {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$ControlId, [Parameter(Mandatory)][object[]]$Blocks)
    if (-not $PSCmdlet.ShouldProcess((Get-Debian13AuditRulesDir), "$ControlId - agregar reglas faltantes y augenrules --load")) { return }
    $changed = $false
    foreach ($b in $Blocks) { if (Add-Debian13AuditRules -File $b.file -RuleTexts @($b.rules | ForEach-Object { Expand-Debian13AuditRuleText $_ })) { $changed = $true } }
    if ($changed) { Invoke-Debian13AugenrulesLoad }
}

# --- generacion de funciones para los 33 controles del JSON --------------------------------------------------

$script:Debian13AuditRuleTitles = @{}
foreach ($r in @(Import-Csv (Join-Path $PSScriptRoot '../inventory/cis_debian13_controls_master.csv') | Where-Object { $_.control_id -like '6.2.3.*' })) { $script:Debian13AuditRuleTitles[$r.control_id] = ($r.title -replace '\s*\((Automated|Manual)\)\s*$', '') }

foreach ($id in @((Get-Debian13AuditRulesData).PSObject.Properties.Name)) {
    $suffix = $id -replace '\.', '_'
    Set-Item -Path "function:script:Test-CIS_Debian13_$suffix" -Value ([scriptblock]::Create(@"
`$texts = @((Get-Debian13AuditRulesData).'$id' | ForEach-Object { `$_.rules } | ForEach-Object { Expand-Debian13AuditRuleText `$_ })
Test-Debian13AuditRulesControl -ControlId '$id' -Title `$script:Debian13AuditRuleTitles['$id'] -RuleTexts `$texts
"@))
    Set-Item -Path "function:script:Set-CIS_Debian13_$suffix" -Value ([scriptblock]::Create("[CmdletBinding(SupportsShouldProcess)] param() Set-Debian13AuditRulesControl -ControlId '$id' -Blocks @((Get-Debian13AuditRulesData).'$id')"))
}

# --- 6.2.3.10 comandos privilegiados (dinamico) -----------------------------------------------------------------------

function Get-Debian13PrivilegedFiles {
    # setuid/setgid en las particiones no noexec/nosuid (como el script del benchmark).
    $fs = (Get-Content /proc/filesystems -ErrorAction SilentlyContinue | Where-Object { $_ -match 'nodev' } | ForEach-Object { ($_ -split '\s+')[-1] }) -join ','
    $parts = @(& findmnt -n -l -k -it $fs 2>$null | Where-Object { $_ -notmatch 'noexec|nosuid' } | ForEach-Object { ($_ -split '\s+')[0] })
    foreach ($p in $parts) { & find $p -xdev -perm /6000 -type f 2>$null }
}
function Get-Debian13PrivilegedRuleTexts {
    $arch = Get-Debian13AuditArch; $uid = Get-Debian13UidMin
    @(Get-Debian13PrivilegedFiles | Sort-Object -Unique | ForEach-Object { "-a always,exit -F arch=$arch -S all -F path=$_ -F perm=x -F auid>=$uid -F auid!=unset -k privileged" })
}
function Test-CIS_Debian13_6_2_3_10 {
    $texts = @(Get-Debian13PrivilegedRuleTexts)
    if (-not $texts.Count) { return New-CISResult -ControlId '6.2.3.10' -Title $script:Debian13AuditRuleTitles['6.2.3.10'] -Status 'Pass' -ActualValue 'sin archivos setuid/setgid en las particiones evaluadas' }
    Test-Debian13AuditRulesControl -ControlId '6.2.3.10' -Title $script:Debian13AuditRuleTitles['6.2.3.10'] -RuleTexts $texts
}
function Set-CIS_Debian13_6_2_3_10 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if (-not $PSCmdlet.ShouldProcess((Get-Debian13AuditRulesDir), '6.2.3.10 - reglas para cada binario setuid/setgid y augenrules --load')) { return }
    if (Add-Debian13AuditRules -File '50-privileged.rules' -RuleTexts @(Get-Debian13PrivilegedRuleTexts)) { Invoke-Debian13AugenrulesLoad }
}

# --- 6.2.3.35 (-c) y 6.2.3.36 (-e 2) -----------------------------------------------------------------------------------

function Get-Debian13AuditDirectives {
    # Directivas sueltas (-c, -e N, -f N) en orden de carga (archivos ordenados): @{File; Text}
    foreach ($f in @(Get-Debian13AuditRuleFiles)) { foreach ($l in @(Get-Content $f -ErrorAction SilentlyContinue)) { if ($l -match '^\s*(-c|-e\s+\d|-f\s+\d)\b') { [pscustomobject]@{ File = $f; Text = ($l.Trim() -replace '\s+', ' ') } } } }
}
function Test-CIS_Debian13_6_2_3_35 {
    $c = @(Get-Debian13AuditDirectives | Where-Object { $_.Text -eq '-c' })
    New-CISResult -ControlId '6.2.3.35' -Title $script:Debian13AuditRuleTitles['6.2.3.35'] -Status $(if ($c.Count) { 'Pass' } else { 'Fail' }) -ExpectedValue '-c en /etc/audit/rules.d/*.rules' -ActualValue $(if ($c.Count) { "en $($c[-1].File)" } else { '-c no configurado' })
}
function Set-CIS_Debian13_6_2_3_35 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess((Join-Path (Get-Debian13AuditRulesDir) '01-initialize.rules'), '6.2.3.35 - agregar -c')) { Add-Debian13AuditRules -File '01-initialize.rules' -RuleTexts '-c' | Out-Null }
}
function Test-CIS_Debian13_6_2_3_36 {
    $e = @(Get-Debian13AuditDirectives | Where-Object { $_.Text -like '-e *' })
    $last = if ($e.Count) { $e[-1].Text } else { $null }
    New-CISResult -ControlId '6.2.3.36' -Title $script:Debian13AuditRuleTitles['6.2.3.36'] -Status $(if ($last -eq '-e 2') { 'Pass' } else { 'Fail' }) -ExpectedValue 'La ultima directiva -e es "-e 2"' -ActualValue $(if ($last) { $last } else { 'sin directiva -e' })
}
function Set-CIS_Debian13_6_2_3_36 {
    [CmdletBinding(SupportsShouldProcess)] param([switch]$AcceptImmutable)
    if (-not $AcceptImmutable) { Write-Warning '6.2.3.36: -e 2 vuelve INMUTABLE la configuracion de auditd hasta el proximo reinicio (no se podran cargar mas reglas). Aplicar primero todas las demas reglas de 6.2.3.x y reintentar con -AcceptImmutable.'; return }
    if ($PSCmdlet.ShouldProcess((Join-Path (Get-Debian13AuditRulesDir) '99-finalize.rules'), '6.2.3.36 - agregar -e 2 (se aplica en la proxima carga/reinicio)')) { Add-Debian13AuditRules -File '99-finalize.rules' -RuleTexts '-e 2' | Out-Null }
}

# --- 6.2.3.37 (Manual) -----------------------------------------------------------------------------------------------------

function Test-CIS_Debian13_6_2_3_37 {
    New-CISResult -ControlId '6.2.3.37' -Title $script:Debian13AuditRuleTitles['6.2.3.37'] -Status 'ManualReviewRequired' -Notes '"augenrules --check" debe decir "No change" y las reglas cargadas (auditctl -l) coincidir con /etc/audit/audit.rules.'
}
function Set-CIS_Debian13_6_2_3_37 { Write-Warning '6.2.3.37: sin remediacion automatizada -- ejecutar "augenrules --load" y reiniciar si auditd esta en modo inmutable.' }
