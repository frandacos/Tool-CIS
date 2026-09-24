# Motor de modulos de kernel (deshabilitar/denylist). Puerto de
# LinuxKernelModuleEngine.ps1 (Script-CIS/CISHarden.Core).

# kernel_module_disabled <module> [type=fs] [dirname]
# Devuelve 0 (Pass) si el modulo esta deshabilitado: no cargable, no cargado y
# en denylist. Si el modulo no existe en el arbol del kernel actual, Pass salvo
# que este cargado igual (caso raro). <dirname> es el subdirectorio real bajo
# kernel/<type>/ cuando no coincide con el nombre del modulo (ej. overlay ->
# overlayfs, firewire-core -> firewire). Deja detalle legible en $KERNEL_MODULE_INFO.
kernel_module_disabled() {
    local module="$1" type="${2:-fs}" dirn="${3:-}"
    local probe="${module//-/_}"
    [[ -z "$dirn" ]] && dirn="${module//-//}"
    local krel moduledir exists=0
    krel="$(uname -r)"
    moduledir="/lib/modules/${krel}/kernel/${type}/${dirn}"
    if [[ -d "$moduledir" ]] && [[ -n "$(ls -A "$moduledir" 2>/dev/null)" ]]; then
        exists=1
    fi

    local loadable=0 loaded=0 blacklisted=0
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$probe"; then
        loaded=1
    fi

    if [[ "$exists" -eq 1 ]]; then
        if ! modprobe -n -v "$module" 2>/dev/null | grep -Eq '^[[:space:]]*install[[:space:]]+(/usr)?/bin/(true|false)'; then
            loadable=1
        fi
        if modprobe --showconfig 2>/dev/null | grep -Eq "^[[:space:]]*blacklist[[:space:]]+${probe}\b"; then
            blacklisted=1
        fi
        KERNEL_MODULE_INFO="existe=1 loadable=${loadable} loaded=${loaded} blacklisted=${blacklisted}"
        [[ "$loadable" -eq 0 && "$loaded" -eq 0 && "$blacklisted" -eq 1 ]]
        return $?
    else
        KERNEL_MODULE_INFO="existe=0 loaded=${loaded}"
        [[ "$loaded" -eq 0 ]]
        return $?
    fi
}

# kernel_module_disable <module> [type=fs]
# Descarga el modulo (si esta cargado) y lo deja no cargable + en denylist en
# /etc/modprobe.d/<modulo>.conf. Hace backup del .conf si ya existia.
kernel_module_disable() {
    local module="$1" type="${2:-fs}"
    local probe="${module//-/_}"
    local conf="/etc/modprobe.d/${probe}.conf"
    [[ -f "$conf" ]] && cis_backup_file "$conf" >/dev/null
    grep -Eq "^[[:space:]]*install[[:space:]]+${module}[[:space:]]+/bin/false" "$conf" 2>/dev/null \
        || echo "install ${module} /bin/false" >>"$conf"
    grep -Eq "^[[:space:]]*blacklist[[:space:]]+${probe}\b" "$conf" 2>/dev/null \
        || echo "blacklist ${probe}" >>"$conf"
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$probe"; then
        modprobe -r "$module" 2>/dev/null || true
    fi
}
