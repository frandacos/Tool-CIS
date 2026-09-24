# Motor de parametros de kernel via sysctl. Puerto de LinuxSysctlEngine.ps1.

sysctl_value() { sysctl -n "$1" 2>/dev/null; }

# sysctl_set <key> <value>
# Persiste <key>=<value> en /etc/sysctl.d/60-cis-bash.conf (reemplazando una
# definicion previa de esa clave en ese archivo) y lo aplica en caliente.
sysctl_set() {
    local key="$1" value="$2" conf="/etc/sysctl.d/60-cis-bash.conf"
    mkdir -p /etc/sysctl.d 2>/dev/null
    [[ -f "$conf" ]] && cis_backup_file "$conf" >/dev/null
    if [[ -f "$conf" ]] && grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$conf"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$conf"
    else
        echo "${key} = ${value}" >>"$conf"
    fi
    sysctl -w "${key}=${value}" >/dev/null 2>&1 || true
}
