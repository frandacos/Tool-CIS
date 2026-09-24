# CIS Debian Linux 13 Benchmark v1.0.0 - Capitulo 1.1 Filesystem
# 37 controles: 1.1.1.1-1.1.1.10 (modulos de kernel de filesystem/drivers no
# disponibles), 1.1.1.11 (Manual), 1.1.2.x (particiones y opciones
# nodev/nosuid/noexec de /tmp, /dev/shm, /home, /var, /var/tmp, /var/log,
# /var/log/audit). Fuente: cis_debian_13.md, paginas 22-122.

# --- Helpers privados ---

function Test-Debian13KernelModuleControl {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Module,
        [ValidateSet('fs', 'drivers', 'net')][string]$Type = 'fs',
        [string]$DirName
    )
    $splat = @{ Module = $Module; Type = $Type }
    if ($DirName) { $splat.DirName = $DirName }
    $r = Test-CISKernelModuleDisabled @splat
    $status = if ($r.Disabled) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue 'Modulo no disponible, o no cargado, en denylist y con install /bin/false|true' `
        -ActualValue "Disponible=$($r.ExistsInRunningKernel); Loadable=$($r.Loadable); Loaded=$($r.Loaded); Blacklisted=$($r.Blacklisted)"
}

function Set-Debian13KernelModuleControl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Module,
        [ValidateSet('fs', 'drivers', 'net')][string]$Type = 'fs'
    )
    if ($PSCmdlet.ShouldProcess($Module, "$ControlId - Descargar, deshabilitar y denylistear modulo de kernel")) {
        Disable-CISKernelModule -Module $Module -Type $Type
    }
}

function Get-Debian13TmpMountUnitState { (& systemctl is-enabled tmp.mount 2>$null | Select-Object -First 1) }

function Test-Debian13PartitionControl {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$MountPoint
    )
    $exists = Test-CISPartitionExists -Path $MountPoint
    $status = if ($exists) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue "$MountPoint es un punto de montaje propio (tmpfs o particion separada)" `
        -ActualValue $(if ($exists) { 'montado' } else { 'no es un punto de montaje propio' })
}

function Set-Debian13PartitionControl {
    param([Parameter(Mandatory)][string]$ControlId, [string]$MountPoint)
    Write-Warning "$ControlId requiere crear una particion separada o una entrada tmpfs en /etc/fstab para $MountPoint (reparticionar/mover datos) -- el benchmark lo trata como cambio manual, no se automatiza aca."
}

function Test-Debian13MountOptionControl {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$MountPoint,
        [Parameter(Mandatory)][ValidateSet('nodev', 'nosuid', 'noexec')][string]$Option
    )
    $isSet = Test-CISMountOption -Path $MountPoint -Option $Option
    $status = if ($isSet) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue $Option -ActualValue $(if ($isSet) { $Option } else { 'no configurada' }) `
        -Notes $(if (-not (Test-CISPartitionExists -Path $MountPoint)) { "$MountPoint no es una particion separada; ver control de particion correspondiente." })
}

function Set-Debian13MountOptionControl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$MountPoint,
        [Parameter(Mandatory)][ValidateSet('nodev', 'nosuid', 'noexec')][string]$Option
    )
    if ($PSCmdlet.ShouldProcess($MountPoint, "$ControlId - Agregar opcion '$Option' en fstab y remontar")) {
        Set-CISFstabMountOption -Path $MountPoint -Option $Option
    }
}

function Test-CIS_Debian13_1_1_1_1 { Test-Debian13KernelModuleControl -ControlId '1.1.1.1' -Title 'Ensure cramfs kernel module is not available' -Module 'cramfs' -Type fs }
function Set-CIS_Debian13_1_1_1_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.1' -Module 'cramfs' -Type fs }

function Test-CIS_Debian13_1_1_1_2 { Test-Debian13KernelModuleControl -ControlId '1.1.1.2' -Title 'Ensure freevxfs kernel module is not available' -Module 'freevxfs' -Type fs }
function Set-CIS_Debian13_1_1_1_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.2' -Module 'freevxfs' -Type fs }

function Test-CIS_Debian13_1_1_1_3 { Test-Debian13KernelModuleControl -ControlId '1.1.1.3' -Title 'Ensure hfs kernel module is not available' -Module 'hfs' -Type fs }
function Set-CIS_Debian13_1_1_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.3' -Module 'hfs' -Type fs }

function Test-CIS_Debian13_1_1_1_4 { Test-Debian13KernelModuleControl -ControlId '1.1.1.4' -Title 'Ensure hfsplus kernel module is not available' -Module 'hfsplus' -Type fs }
function Set-CIS_Debian13_1_1_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.4' -Module 'hfsplus' -Type fs }

function Test-CIS_Debian13_1_1_1_5 { Test-Debian13KernelModuleControl -ControlId '1.1.1.5' -Title 'Ensure jffs2 kernel module is not available' -Module 'jffs2' -Type fs }
function Set-CIS_Debian13_1_1_1_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.5' -Module 'jffs2' -Type fs }

function Test-CIS_Debian13_1_1_1_6 { Test-Debian13KernelModuleControl -ControlId '1.1.1.6' -Title 'Ensure overlay kernel module is not available' -Module 'overlay' -Type fs -DirName 'overlayfs' }
function Set-CIS_Debian13_1_1_1_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.6' -Module 'overlay' -Type fs }

function Test-CIS_Debian13_1_1_1_7 { Test-Debian13KernelModuleControl -ControlId '1.1.1.7' -Title 'Ensure squashfs kernel module is not available' -Module 'squashfs' -Type fs }
function Set-CIS_Debian13_1_1_1_7 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.7' -Module 'squashfs' -Type fs }

function Test-CIS_Debian13_1_1_1_8 { Test-Debian13KernelModuleControl -ControlId '1.1.1.8' -Title 'Ensure udf kernel module is not available' -Module 'udf' -Type fs }
function Set-CIS_Debian13_1_1_1_8 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.8' -Module 'udf' -Type fs }

function Test-CIS_Debian13_1_1_1_9 { Test-Debian13KernelModuleControl -ControlId '1.1.1.9' -Title 'Ensure firewire-core kernel module is not available' -Module 'firewire-core' -Type drivers -DirName 'firewire' }
function Set-CIS_Debian13_1_1_1_9 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.9' -Module 'firewire-core' -Type drivers }

function Test-CIS_Debian13_1_1_1_10 { Test-Debian13KernelModuleControl -ControlId '1.1.1.10' -Title 'Ensure usb-storage kernel module is not available' -Module 'usb-storage' -Type drivers }
function Set-CIS_Debian13_1_1_1_10 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13KernelModuleControl -ControlId '1.1.1.10' -Module 'usb-storage' -Type drivers }

# Manual: el benchmark pide revisar cada modulo de kernel/fs contra la politica del
# sitio (deshabilitar uno en uso puede ser FATAL). No hay heuristica objetiva.
function Test-CIS_Debian13_1_1_1_11 {
    New-CISResult -ControlId '1.1.1.11' -Title 'Ensure unused filesystems kernel modules are not available' -Status 'ManualReviewRequired' `
        -Notes 'Revisar modulos de /lib/modules/*/kernel/fs cargados/montados/cargables segun politica del sitio (ver Audit del benchmark).'
}
function Set-CIS_Debian13_1_1_1_11 { Write-Warning '1.1.1.11: sin remediacion automatizada -- deshabilitar solo los filesystems no usados tras revisar manualmente.' }

# Ademas del montaje, el benchmark exige que tmp.mount no este masked/disabled.
function Test-CIS_Debian13_1_1_2_1_1 {
    $r = Test-Debian13PartitionControl -ControlId '1.1.2.1.1' -Title 'Ensure /tmp is tmpfs or a separate partition' -MountPoint '/tmp'
    $state = Get-Debian13TmpMountUnitState
    if ($r.Status -eq 'Pass' -and $state -in @('masked', 'disabled')) {
        $r.Status = 'Fail'; $r.ActualValue = "montado, pero tmp.mount=$state"
    }
    $r
}
function Set-CIS_Debian13_1_1_2_1_1 {
    [CmdletBinding(SupportsShouldProcess)] param()
    if ($PSCmdlet.ShouldProcess('tmp.mount', '1.1.2.1.1 - systemctl unmask tmp.mount')) { & systemctl unmask tmp.mount 2>$null | Out-Null }
    if (-not (Test-CISPartitionExists -Path '/tmp')) { Set-Debian13PartitionControl -ControlId '1.1.2.1.1' -MountPoint '/tmp' }
}

function Test-CIS_Debian13_1_1_2_1_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.1.2' -Title 'Ensure nodev option set on /tmp partition' -MountPoint '/tmp' -Option nodev }
function Set-CIS_Debian13_1_1_2_1_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.1.2' -MountPoint '/tmp' -Option nodev }

function Test-CIS_Debian13_1_1_2_1_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.1.3' -Title 'Ensure nosuid option set on /tmp partition' -MountPoint '/tmp' -Option nosuid }
function Set-CIS_Debian13_1_1_2_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.1.3' -MountPoint '/tmp' -Option nosuid }

function Test-CIS_Debian13_1_1_2_1_4 { Test-Debian13MountOptionControl -ControlId '1.1.2.1.4' -Title 'Ensure noexec option set on /tmp partition' -MountPoint '/tmp' -Option noexec }
function Set-CIS_Debian13_1_1_2_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.1.4' -MountPoint '/tmp' -Option noexec }

function Test-CIS_Debian13_1_1_2_2_1 { Test-Debian13PartitionControl -ControlId '1.1.2.2.1' -Title 'Ensure /dev/shm is tmpfs or a separate partition' -MountPoint '/dev/shm' }
function Set-CIS_Debian13_1_1_2_2_1 { Set-Debian13PartitionControl -ControlId '1.1.2.2.1' -MountPoint '/dev/shm' }

function Test-CIS_Debian13_1_1_2_2_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.2.2' -Title 'Ensure nodev option set on /dev/shm partition' -MountPoint '/dev/shm' -Option nodev }
function Set-CIS_Debian13_1_1_2_2_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.2.2' -MountPoint '/dev/shm' -Option nodev }

function Test-CIS_Debian13_1_1_2_2_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.2.3' -Title 'Ensure nosuid option set on /dev/shm partition' -MountPoint '/dev/shm' -Option nosuid }
function Set-CIS_Debian13_1_1_2_2_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.2.3' -MountPoint '/dev/shm' -Option nosuid }

function Test-CIS_Debian13_1_1_2_2_4 { Test-Debian13MountOptionControl -ControlId '1.1.2.2.4' -Title 'Ensure noexec option set on /dev/shm partition' -MountPoint '/dev/shm' -Option noexec }
function Set-CIS_Debian13_1_1_2_2_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.2.4' -MountPoint '/dev/shm' -Option noexec }

function Test-CIS_Debian13_1_1_2_3_1 { Test-Debian13PartitionControl -ControlId '1.1.2.3.1' -Title 'Ensure separate partition exists for /home' -MountPoint '/home' }
function Set-CIS_Debian13_1_1_2_3_1 { Set-Debian13PartitionControl -ControlId '1.1.2.3.1' -MountPoint '/home' }

function Test-CIS_Debian13_1_1_2_3_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.3.2' -Title 'Ensure nodev option set on /home partition' -MountPoint '/home' -Option nodev }
function Set-CIS_Debian13_1_1_2_3_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.3.2' -MountPoint '/home' -Option nodev }

function Test-CIS_Debian13_1_1_2_3_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.3.3' -Title 'Ensure nosuid option set on /home partition' -MountPoint '/home' -Option nosuid }
function Set-CIS_Debian13_1_1_2_3_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.3.3' -MountPoint '/home' -Option nosuid }

function Test-CIS_Debian13_1_1_2_4_1 { Test-Debian13PartitionControl -ControlId '1.1.2.4.1' -Title 'Ensure separate partition exists for /var' -MountPoint '/var' }
function Set-CIS_Debian13_1_1_2_4_1 { Set-Debian13PartitionControl -ControlId '1.1.2.4.1' -MountPoint '/var' }

function Test-CIS_Debian13_1_1_2_4_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.4.2' -Title 'Ensure nodev option set on /var partition' -MountPoint '/var' -Option nodev }
function Set-CIS_Debian13_1_1_2_4_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.4.2' -MountPoint '/var' -Option nodev }

function Test-CIS_Debian13_1_1_2_4_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.4.3' -Title 'Ensure nosuid option set on /var partition' -MountPoint '/var' -Option nosuid }
function Set-CIS_Debian13_1_1_2_4_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.4.3' -MountPoint '/var' -Option nosuid }

function Test-CIS_Debian13_1_1_2_5_1 { Test-Debian13PartitionControl -ControlId '1.1.2.5.1' -Title 'Ensure separate partition exists for /var/tmp' -MountPoint '/var/tmp' }
function Set-CIS_Debian13_1_1_2_5_1 { Set-Debian13PartitionControl -ControlId '1.1.2.5.1' -MountPoint '/var/tmp' }

function Test-CIS_Debian13_1_1_2_5_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.5.2' -Title 'Ensure nodev option set on /var/tmp partition' -MountPoint '/var/tmp' -Option nodev }
function Set-CIS_Debian13_1_1_2_5_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.5.2' -MountPoint '/var/tmp' -Option nodev }

function Test-CIS_Debian13_1_1_2_5_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.5.3' -Title 'Ensure nosuid option set on /var/tmp partition' -MountPoint '/var/tmp' -Option nosuid }
function Set-CIS_Debian13_1_1_2_5_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.5.3' -MountPoint '/var/tmp' -Option nosuid }

function Test-CIS_Debian13_1_1_2_5_4 { Test-Debian13MountOptionControl -ControlId '1.1.2.5.4' -Title 'Ensure noexec option set on /var/tmp partition' -MountPoint '/var/tmp' -Option noexec }
function Set-CIS_Debian13_1_1_2_5_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.5.4' -MountPoint '/var/tmp' -Option noexec }

function Test-CIS_Debian13_1_1_2_6_1 { Test-Debian13PartitionControl -ControlId '1.1.2.6.1' -Title 'Ensure separate partition exists for /var/log' -MountPoint '/var/log' }
function Set-CIS_Debian13_1_1_2_6_1 { Set-Debian13PartitionControl -ControlId '1.1.2.6.1' -MountPoint '/var/log' }

function Test-CIS_Debian13_1_1_2_6_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.6.2' -Title 'Ensure nodev option set on /var/log partition' -MountPoint '/var/log' -Option nodev }
function Set-CIS_Debian13_1_1_2_6_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.6.2' -MountPoint '/var/log' -Option nodev }

function Test-CIS_Debian13_1_1_2_6_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.6.3' -Title 'Ensure nosuid option set on /var/log partition' -MountPoint '/var/log' -Option nosuid }
function Set-CIS_Debian13_1_1_2_6_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.6.3' -MountPoint '/var/log' -Option nosuid }

function Test-CIS_Debian13_1_1_2_6_4 { Test-Debian13MountOptionControl -ControlId '1.1.2.6.4' -Title 'Ensure noexec option set on /var/log partition' -MountPoint '/var/log' -Option noexec }
function Set-CIS_Debian13_1_1_2_6_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.6.4' -MountPoint '/var/log' -Option noexec }

function Test-CIS_Debian13_1_1_2_7_1 { Test-Debian13PartitionControl -ControlId '1.1.2.7.1' -Title 'Ensure separate partition exists for /var/log/audit' -MountPoint '/var/log/audit' }
function Set-CIS_Debian13_1_1_2_7_1 { Set-Debian13PartitionControl -ControlId '1.1.2.7.1' -MountPoint '/var/log/audit' }

function Test-CIS_Debian13_1_1_2_7_2 { Test-Debian13MountOptionControl -ControlId '1.1.2.7.2' -Title 'Ensure nodev option set on /var/log/audit partition' -MountPoint '/var/log/audit' -Option nodev }
function Set-CIS_Debian13_1_1_2_7_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.7.2' -MountPoint '/var/log/audit' -Option nodev }

function Test-CIS_Debian13_1_1_2_7_3 { Test-Debian13MountOptionControl -ControlId '1.1.2.7.3' -Title 'Ensure nosuid option set on /var/log/audit partition' -MountPoint '/var/log/audit' -Option nosuid }
function Set-CIS_Debian13_1_1_2_7_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.7.3' -MountPoint '/var/log/audit' -Option nosuid }

function Test-CIS_Debian13_1_1_2_7_4 { Test-Debian13MountOptionControl -ControlId '1.1.2.7.4' -Title 'Ensure noexec option set on /var/log/audit partition' -MountPoint '/var/log/audit' -Option noexec }
function Set-CIS_Debian13_1_1_2_7_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian13MountOptionControl -ControlId '1.1.2.7.4' -MountPoint '/var/log/audit' -Option noexec }
