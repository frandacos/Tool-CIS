# CIS Debian Linux 13 Benchmark v1.0.0 - Capitulo 1.1 Filesystem (puerto bash).
# Espejo funcional de Script-CIS/Benchmarks/Debian13/CISHarden.Debian13/Private/
# Chapter1a-FilesystemConfiguration.ps1 (PowerShell). 37 controles:
# 1.1.1.1-1.1.1.10 (modulos de kernel), 1.1.1.11 (Manual), 1.1.2.x (particiones
# y opciones nodev/nosuid/noexec de /tmp, /dev/shm, /home, /var, /var/tmp,
# /var/log, /var/log/audit). Fuente: cis_debian_13.md, paginas 22-122.
#
# Cada control define test_<id> (Test-*) y set_<id> (Set-*), igual patron que
# el lado PowerShell, generadas con helpers _km/_partition/_mountopt para no
# repetir la logica 26+ veces.

# --- 1.1.1.x modulos de kernel de filesystem/drivers no disponibles -----------

# _km <id> <title> <module> <type> [dirname]
_km() {
    local id="$1" title="$2" module="$3" type="$4" dirn="${5:-}"
    local suffix="${id//./_}"
    eval "test_${suffix}() {
        if kernel_module_disabled '${module}' '${type}' '${dirn}'; then
            cis_result '${id}' '${title}' Pass 'Modulo no disponible, o no cargado, en denylist' \"\${KERNEL_MODULE_INFO:-}\"
        else
            cis_result '${id}' '${title}' Fail 'Modulo no disponible, o no cargado, en denylist' \"\${KERNEL_MODULE_INFO:-}\"
        fi
    }"
    eval "set_${suffix}() { kernel_module_disable '${module}' '${type}'; }"
}

_km 1.1.1.1  "Ensure cramfs kernel module is not available"        cramfs        fs
_km 1.1.1.2  "Ensure freevxfs kernel module is not available"      freevxfs      fs
_km 1.1.1.3  "Ensure hfs kernel module is not available"           hfs           fs
_km 1.1.1.4  "Ensure hfsplus kernel module is not available"       hfsplus       fs
_km 1.1.1.5  "Ensure jffs2 kernel module is not available"         jffs2         fs
_km 1.1.1.6  "Ensure overlay kernel module is not available"       overlay       fs      overlayfs
_km 1.1.1.7  "Ensure squashfs kernel module is not available"      squashfs      fs
_km 1.1.1.8  "Ensure udf kernel module is not available"           udf           fs
_km 1.1.1.9  "Ensure firewire-core kernel module is not available" firewire-core drivers firewire
_km 1.1.1.10 "Ensure usb-storage kernel module is not available"   usb-storage   drivers

# Manual: revisar cada modulo de kernel/fs cargado/montado/cargable segun
# politica del sitio -- deshabilitar uno en uso puede ser FATAL, no se automatiza.
test_1_1_1_11() {
    cis_result 1.1.1.11 "Ensure unused filesystems kernel modules are not available" \
        ManualReviewRequired "" "" \
        "Revisar modulos de /lib/modules/*/kernel/fs cargados/montados/cargables segun politica del sitio."
}
set_1_1_1_11() {
    echo "1.1.1.11: sin remediacion automatizada -- deshabilitar solo los filesystems no usados tras revisar manualmente." >&2
}

# --- 1.1.2.x particiones separadas y opciones de montaje ----------------------

# _partition <id> <title> <mountpoint>
_partition() {
    local id="$1" title="$2" mp="$3"
    local suffix="${id//./_}"
    eval "test_${suffix}() {
        if partition_exists '${mp}'; then
            cis_result '${id}' '${title}' Pass '${mp} es un punto de montaje propio (tmpfs o particion separada)' montado
        else
            cis_result '${id}' '${title}' Fail '${mp} es un punto de montaje propio (tmpfs o particion separada)' 'no es un punto de montaje propio'
        fi
    }"
    eval "set_${suffix}() {
        echo '${id} requiere crear una particion separada o una entrada tmpfs en /etc/fstab para ${mp} (reparticionar/mover datos) -- no se automatiza.' >&2
    }"
}

# _mountopt <id> <title> <mountpoint> <option>
_mountopt() {
    local id="$1" title="$2" mp="$3" opt="$4"
    local suffix="${id//./_}"
    eval "test_${suffix}() {
        if mount_option_set '${mp}' '${opt}'; then
            cis_result '${id}' '${title}' Pass '${opt}' '${opt}'
        else
            local notes=''
            partition_exists '${mp}' || notes='${mp} no es una particion separada; ver el control de particion correspondiente.'
            cis_result '${id}' '${title}' Fail '${opt}' 'no configurada' \"\$notes\"
        fi
    }"
    eval "set_${suffix}() { fstab_add_option '${mp}' '${opt}'; }"
}

# /tmp: ademas del montaje, systemd no debe tener tmp.mount enmascarado/disabled.
test_1_1_2_1_1() {
    local title="Ensure /tmp is tmpfs or a separate partition"
    local mounted=1
    partition_exists /tmp && mounted=0
    local state
    state="$(systemctl is-enabled tmp.mount 2>/dev/null | head -n1)"
    if [[ "$mounted" -eq 0 && "$state" != "masked" && "$state" != "disabled" ]]; then
        cis_result 1.1.2.1.1 "$title" Pass "$mp es un punto de montaje propio; tmp.mount habilitado" "montado; tmp.mount=${state}"
    else
        cis_result 1.1.2.1.1 "$title" Fail "/tmp es un punto de montaje propio; tmp.mount habilitado" \
            "montado=$([[ $mounted -eq 0 ]] && echo si || echo no); tmp.mount=${state}"
    fi
}
set_1_1_2_1_1() {
    systemctl unmask tmp.mount 2>/dev/null || true
    partition_exists /tmp || echo "1.1.2.1.1 requiere crear una particion separada o una entrada tmpfs en /etc/fstab para /tmp -- no se automatiza." >&2
}

_mountopt 1.1.2.1.2 "Ensure nodev option set on /tmp partition"   /tmp nodev
_mountopt 1.1.2.1.3 "Ensure nosuid option set on /tmp partition"  /tmp nosuid
_mountopt 1.1.2.1.4 "Ensure noexec option set on /tmp partition"  /tmp noexec

_partition 1.1.2.2.1 "Ensure /dev/shm is tmpfs or a separate partition" /dev/shm
_mountopt  1.1.2.2.2 "Ensure nodev option set on /dev/shm partition"    /dev/shm nodev
_mountopt  1.1.2.2.3 "Ensure nosuid option set on /dev/shm partition"   /dev/shm nosuid
_mountopt  1.1.2.2.4 "Ensure noexec option set on /dev/shm partition"   /dev/shm noexec

_partition 1.1.2.3.1 "Ensure separate partition exists for /home" /home
_mountopt  1.1.2.3.2 "Ensure nodev option set on /home partition" /home nodev
_mountopt  1.1.2.3.3 "Ensure nosuid option set on /home partition" /home nosuid

_partition 1.1.2.4.1 "Ensure separate partition exists for /var" /var
_mountopt  1.1.2.4.2 "Ensure nodev option set on /var partition" /var nodev
_mountopt  1.1.2.4.3 "Ensure nosuid option set on /var partition" /var nosuid

_partition 1.1.2.5.1 "Ensure separate partition exists for /var/tmp" /var/tmp
_mountopt  1.1.2.5.2 "Ensure nodev option set on /var/tmp partition" /var/tmp nodev
_mountopt  1.1.2.5.3 "Ensure nosuid option set on /var/tmp partition" /var/tmp nosuid
_mountopt  1.1.2.5.4 "Ensure noexec option set on /var/tmp partition" /var/tmp noexec

_partition 1.1.2.6.1 "Ensure separate partition exists for /var/log" /var/log
_mountopt  1.1.2.6.2 "Ensure nodev option set on /var/log partition" /var/log nodev
_mountopt  1.1.2.6.3 "Ensure nosuid option set on /var/log partition" /var/log nosuid
_mountopt  1.1.2.6.4 "Ensure noexec option set on /var/log partition" /var/log noexec

_partition 1.1.2.7.1 "Ensure separate partition exists for /var/log/audit" /var/log/audit
_mountopt  1.1.2.7.2 "Ensure nodev option set on /var/log/audit partition" /var/log/audit nodev
_mountopt  1.1.2.7.3 "Ensure nosuid option set on /var/log/audit partition" /var/log/audit nosuid
_mountopt  1.1.2.7.4 "Ensure noexec option set on /var/log/audit partition" /var/log/audit noexec
