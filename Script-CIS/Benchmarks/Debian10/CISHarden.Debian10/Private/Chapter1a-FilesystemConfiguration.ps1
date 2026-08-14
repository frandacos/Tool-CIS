# CIS Debian Linux 10 Benchmark v2.0.0 - Capitulo 1.1 Filesystem Configuration
# 34 controles: 1.1.1.1-1.1.1.7 (modulos de filesystem no usados),
# 1.1.2.x-1.1.8.x (particiones separadas y opciones nodev/nosuid/noexec de
# /tmp, /var, /var/tmp, /var/log, /var/log/audit, /home, /dev/shm),
# 1.1.9 (automount) y 1.1.10 (usb-storage). Fuente: cis_debian_10.md,
# paginas 22-127. Todos Level 1 o 2, Server y Workstation por igual.

# --- Helpers privados (no se exportan; los usan los Test-CIS_Debian10_*/Set-CIS_Debian10_* de abajo) ---

function Test-Debian10KernelModuleControl {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Module,
        [ValidateSet('fs', 'drivers', 'net')][string]$Type = 'fs'
    )
    $r = Test-CISKernelModuleDisabled -Module $Module -Type $Type
    $status = if ($r.Disabled) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue 'Modulo no cargable, no cargado y en denylist' `
        -ActualValue "Loadable=$($r.Loadable); Loaded=$($r.Loaded); Blacklisted=$($r.Blacklisted); ExisteEnKernelActual=$($r.ExistsInRunningKernel)"
}

function Set-Debian10KernelModuleControl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Module,
        [ValidateSet('fs', 'drivers', 'net')][string]$Type = 'fs'
    )
    if ($PSCmdlet.ShouldProcess($Module, "$ControlId - Deshabilitar y denylistear modulo de kernel")) {
        Disable-CISKernelModule -Module $Module -Type $Type
    }
}

function Test-Debian10PartitionControl {
    param(
        [Parameter(Mandatory)][string]$ControlId,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$MountPoint
    )
    $exists = Test-CISPartitionExists -Path $MountPoint
    $status = if ($exists) { 'Pass' } else { 'Fail' }
    New-CISResult -ControlId $ControlId -Title $Title -Status $status `
        -ExpectedValue "$MountPoint es un punto de montaje propio" `
        -ActualValue $(if ($exists) { 'particion separada' } else { 'no es una particion separada' })
}

function Set-Debian10PartitionControl {
    param([Parameter(Mandatory)][string]$ControlId)
    Write-Warning "$ControlId requiere crear una particion separada (reparticionar/mover datos) -- el benchmark lo trata como cambio manual, no se automatiza aca."
}

function Test-Debian10MountOptionControl {
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

function Set-Debian10MountOptionControl {
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

# --- 1.1.1.x Disable unused filesystems -----------------------------------

function Test-CIS_Debian10_1_1_1_1 { Test-Debian10KernelModuleControl -ControlId '1.1.1.1' -Title "Ensure mounting of cramfs filesystems is disabled" -Module 'cramfs' -Type fs }
function Set-CIS_Debian10_1_1_1_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.1' -Module 'cramfs' -Type fs }

function Test-CIS_Debian10_1_1_1_2 { Test-Debian10KernelModuleControl -ControlId '1.1.1.2' -Title "Ensure mounting of freevxfs filesystems is disabled" -Module 'freevxfs' -Type fs }
function Set-CIS_Debian10_1_1_1_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.2' -Module 'freevxfs' -Type fs }

function Test-CIS_Debian10_1_1_1_3 { Test-Debian10KernelModuleControl -ControlId '1.1.1.3' -Title "Ensure mounting of jffs2 filesystems is disabled" -Module 'jffs2' -Type fs }
function Set-CIS_Debian10_1_1_1_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.3' -Module 'jffs2' -Type fs }

function Test-CIS_Debian10_1_1_1_4 { Test-Debian10KernelModuleControl -ControlId '1.1.1.4' -Title "Ensure mounting of hfs filesystems is disabled" -Module 'hfs' -Type fs }
function Set-CIS_Debian10_1_1_1_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.4' -Module 'hfs' -Type fs }

function Test-CIS_Debian10_1_1_1_5 { Test-Debian10KernelModuleControl -ControlId '1.1.1.5' -Title "Ensure mounting of hfsplus filesystems is disabled" -Module 'hfsplus' -Type fs }
function Set-CIS_Debian10_1_1_1_5 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.5' -Module 'hfsplus' -Type fs }

function Test-CIS_Debian10_1_1_1_6 { Test-Debian10KernelModuleControl -ControlId '1.1.1.6' -Title "Ensure mounting of squashfs filesystems is disabled" -Module 'squashfs' -Type fs }
function Set-CIS_Debian10_1_1_1_6 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.6' -Module 'squashfs' -Type fs }

function Test-CIS_Debian10_1_1_1_7 { Test-Debian10KernelModuleControl -ControlId '1.1.1.7' -Title "Ensure mounting of udf filesystems is disabled" -Module 'udf' -Type fs }
function Set-CIS_Debian10_1_1_1_7 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.1.7' -Module 'udf' -Type fs }

# --- 1.1.2.x Configure /tmp -------------------------------------------------

function Test-CIS_Debian10_1_1_2_1 { Test-Debian10PartitionControl -ControlId '1.1.2.1' -Title 'Ensure /tmp is a separate partition' -MountPoint '/tmp' }
function Set-CIS_Debian10_1_1_2_1 { Set-Debian10PartitionControl -ControlId '1.1.2.1' }

function Test-CIS_Debian10_1_1_2_2 { Test-Debian10MountOptionControl -ControlId '1.1.2.2' -Title 'Ensure nodev option set on /tmp partition' -MountPoint '/tmp' -Option nodev }
function Set-CIS_Debian10_1_1_2_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.2.2' -MountPoint '/tmp' -Option nodev }

function Test-CIS_Debian10_1_1_2_3 { Test-Debian10MountOptionControl -ControlId '1.1.2.3' -Title 'Ensure noexec option set on /tmp partition' -MountPoint '/tmp' -Option noexec }
function Set-CIS_Debian10_1_1_2_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.2.3' -MountPoint '/tmp' -Option noexec }

function Test-CIS_Debian10_1_1_2_4 { Test-Debian10MountOptionControl -ControlId '1.1.2.4' -Title 'Ensure nosuid option set on /tmp partition' -MountPoint '/tmp' -Option nosuid }
function Set-CIS_Debian10_1_1_2_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.2.4' -MountPoint '/tmp' -Option nosuid }

# --- 1.1.3.x Configure /var -------------------------------------------------

function Test-CIS_Debian10_1_1_3_1 { Test-Debian10PartitionControl -ControlId '1.1.3.1' -Title 'Ensure separate partition exists for /var' -MountPoint '/var' }
function Set-CIS_Debian10_1_1_3_1 { Set-Debian10PartitionControl -ControlId '1.1.3.1' }

function Test-CIS_Debian10_1_1_3_2 { Test-Debian10MountOptionControl -ControlId '1.1.3.2' -Title 'Ensure nodev option set on /var partition' -MountPoint '/var' -Option nodev }
function Set-CIS_Debian10_1_1_3_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.3.2' -MountPoint '/var' -Option nodev }

function Test-CIS_Debian10_1_1_3_3 { Test-Debian10MountOptionControl -ControlId '1.1.3.3' -Title 'Ensure nosuid option set on /var partition' -MountPoint '/var' -Option nosuid }
function Set-CIS_Debian10_1_1_3_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.3.3' -MountPoint '/var' -Option nosuid }

# --- 1.1.4.x Configure /var/tmp --------------------------------------------

function Test-CIS_Debian10_1_1_4_1 { Test-Debian10PartitionControl -ControlId '1.1.4.1' -Title 'Ensure separate partition exists for /var/tmp' -MountPoint '/var/tmp' }
function Set-CIS_Debian10_1_1_4_1 { Set-Debian10PartitionControl -ControlId '1.1.4.1' }

function Test-CIS_Debian10_1_1_4_2 { Test-Debian10MountOptionControl -ControlId '1.1.4.2' -Title 'Ensure nodev option set on /var/tmp partition' -MountPoint '/var/tmp' -Option nodev }
function Set-CIS_Debian10_1_1_4_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.4.2' -MountPoint '/var/tmp' -Option nodev }

function Test-CIS_Debian10_1_1_4_3 { Test-Debian10MountOptionControl -ControlId '1.1.4.3' -Title 'Ensure noexec option set on /var/tmp partition' -MountPoint '/var/tmp' -Option noexec }
function Set-CIS_Debian10_1_1_4_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.4.3' -MountPoint '/var/tmp' -Option noexec }

function Test-CIS_Debian10_1_1_4_4 { Test-Debian10MountOptionControl -ControlId '1.1.4.4' -Title 'Ensure nosuid option set on /var/tmp partition' -MountPoint '/var/tmp' -Option nosuid }
function Set-CIS_Debian10_1_1_4_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.4.4' -MountPoint '/var/tmp' -Option nosuid }

# --- 1.1.5.x Configure /var/log ---------------------------------------------

function Test-CIS_Debian10_1_1_5_1 { Test-Debian10PartitionControl -ControlId '1.1.5.1' -Title 'Ensure separate partition exists for /var/log' -MountPoint '/var/log' }
function Set-CIS_Debian10_1_1_5_1 { Set-Debian10PartitionControl -ControlId '1.1.5.1' }

function Test-CIS_Debian10_1_1_5_2 { Test-Debian10MountOptionControl -ControlId '1.1.5.2' -Title 'Ensure nodev option set on /var/log partition' -MountPoint '/var/log' -Option nodev }
function Set-CIS_Debian10_1_1_5_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.5.2' -MountPoint '/var/log' -Option nodev }

function Test-CIS_Debian10_1_1_5_3 { Test-Debian10MountOptionControl -ControlId '1.1.5.3' -Title 'Ensure noexec option set on /var/log partition' -MountPoint '/var/log' -Option noexec }
function Set-CIS_Debian10_1_1_5_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.5.3' -MountPoint '/var/log' -Option noexec }

function Test-CIS_Debian10_1_1_5_4 { Test-Debian10MountOptionControl -ControlId '1.1.5.4' -Title 'Ensure nosuid option set on /var/log partition' -MountPoint '/var/log' -Option nosuid }
function Set-CIS_Debian10_1_1_5_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.5.4' -MountPoint '/var/log' -Option nosuid }

# --- 1.1.6.x Configure /var/log/audit ---------------------------------------

function Test-CIS_Debian10_1_1_6_1 { Test-Debian10PartitionControl -ControlId '1.1.6.1' -Title 'Ensure separate partition exists for /var/log/audit' -MountPoint '/var/log/audit' }
function Set-CIS_Debian10_1_1_6_1 { Set-Debian10PartitionControl -ControlId '1.1.6.1' }

function Test-CIS_Debian10_1_1_6_2 { Test-Debian10MountOptionControl -ControlId '1.1.6.2' -Title 'Ensure nodev option set on /var/log/audit partition' -MountPoint '/var/log/audit' -Option nodev }
function Set-CIS_Debian10_1_1_6_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.6.2' -MountPoint '/var/log/audit' -Option nodev }

function Test-CIS_Debian10_1_1_6_3 { Test-Debian10MountOptionControl -ControlId '1.1.6.3' -Title 'Ensure noexec option set on /var/log/audit partition' -MountPoint '/var/log/audit' -Option noexec }
function Set-CIS_Debian10_1_1_6_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.6.3' -MountPoint '/var/log/audit' -Option noexec }

function Test-CIS_Debian10_1_1_6_4 { Test-Debian10MountOptionControl -ControlId '1.1.6.4' -Title 'Ensure nosuid option set on /var/log/audit partition' -MountPoint '/var/log/audit' -Option nosuid }
function Set-CIS_Debian10_1_1_6_4 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.6.4' -MountPoint '/var/log/audit' -Option nosuid }

# --- 1.1.7.x Configure /home -------------------------------------------------

function Test-CIS_Debian10_1_1_7_1 { Test-Debian10PartitionControl -ControlId '1.1.7.1' -Title 'Ensure separate partition exists for /home' -MountPoint '/home' }
function Set-CIS_Debian10_1_1_7_1 { Set-Debian10PartitionControl -ControlId '1.1.7.1' }

function Test-CIS_Debian10_1_1_7_2 { Test-Debian10MountOptionControl -ControlId '1.1.7.2' -Title 'Ensure nodev option set on /home partition' -MountPoint '/home' -Option nodev }
function Set-CIS_Debian10_1_1_7_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.7.2' -MountPoint '/home' -Option nodev }

function Test-CIS_Debian10_1_1_7_3 { Test-Debian10MountOptionControl -ControlId '1.1.7.3' -Title 'Ensure nosuid option set on /home partition' -MountPoint '/home' -Option nosuid }
function Set-CIS_Debian10_1_1_7_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.7.3' -MountPoint '/home' -Option nosuid }

# --- 1.1.8.x Configure /dev/shm ----------------------------------------------
# /dev/shm es tmpfs montado por systemd por defecto; no requiere control de
# "particion separada" propio (por eso el benchmark no trae un 1.1.8.0).

function Test-CIS_Debian10_1_1_8_1 { Test-Debian10MountOptionControl -ControlId '1.1.8.1' -Title 'Ensure nodev option set on /dev/shm partition' -MountPoint '/dev/shm' -Option nodev }
function Set-CIS_Debian10_1_1_8_1 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.8.1' -MountPoint '/dev/shm' -Option nodev }

function Test-CIS_Debian10_1_1_8_2 { Test-Debian10MountOptionControl -ControlId '1.1.8.2' -Title 'Ensure noexec option set on /dev/shm partition' -MountPoint '/dev/shm' -Option noexec }
function Set-CIS_Debian10_1_1_8_2 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.8.2' -MountPoint '/dev/shm' -Option noexec }

function Test-CIS_Debian10_1_1_8_3 { Test-Debian10MountOptionControl -ControlId '1.1.8.3' -Title 'Ensure nosuid option set on /dev/shm partition' -MountPoint '/dev/shm' -Option nosuid }
function Set-CIS_Debian10_1_1_8_3 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10MountOptionControl -ControlId '1.1.8.3' -MountPoint '/dev/shm' -Option nosuid }

# --- 1.1.9 Disable Automounting ----------------------------------------------

function Test-CIS_Debian10_1_1_9 {
    [CmdletBinding()]
    param()
    if (-not (Test-CISPackageInstalled -Name 'autofs')) {
        return New-CISResult -ControlId '1.1.9' -Title 'Ensure autofs is not enabled' -Status 'Pass' `
            -ExpectedValue 'autofs no instalado o deshabilitado' -ActualValue 'paquete autofs no instalado'
    }
    $enabled = Test-CISServiceEnabled -Name 'autofs'
    $status = if ($enabled) { 'Fail' } else { 'Pass' }
    New-CISResult -ControlId '1.1.9' -Title 'Ensure autofs is not enabled' -Status $status `
        -ExpectedValue 'servicio autofs deshabilitado' -ActualValue $(if ($enabled) { 'enabled' } else { 'disabled' })
}

function Set-CIS_Debian10_1_1_9 {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    if (-not (Test-CISPackageInstalled -Name 'autofs')) { return }
    if ($PSCmdlet.ShouldProcess('autofs', 'systemctl disable --now')) {
        Disable-CISService -Name 'autofs' -Now
    }
}

# --- 1.1.10 Disable USB Storage ----------------------------------------------

function Test-CIS_Debian10_1_1_10 { Test-Debian10KernelModuleControl -ControlId '1.1.10' -Title 'Ensure USB storage is disabled' -Module 'usb-storage' -Type drivers }
function Set-CIS_Debian10_1_1_10 { [CmdletBinding(SupportsShouldProcess)] param() Set-Debian10KernelModuleControl -ControlId '1.1.10' -Module 'usb-storage' -Type drivers }
