# Motor de particiones/opciones de montaje. Puerto de LinuxFstabEngine.ps1.
# Usa findmnt (util-linux, presente en cualquier Debian) para reflejar el
# estado real montado, no lo que dice /etc/fstab en el papel.

# partition_exists <mountpoint>
# 0 (true) si <mountpoint> es un punto de montaje propio (no parte de / u otro).
partition_exists() {
    findmnt --kernel "$1" >/dev/null 2>&1
}

# mount_option_set <mountpoint> <option>
mount_option_set() {
    local mp="$1" option="$2" opts
    opts="$(findmnt -n -o OPTIONS --target "$mp" 2>/dev/null)" || return 1
    [[ -z "$opts" ]] && return 1
    [[ ",${opts}," == *",${option},"* ]]
}

# fstab_add_option <mountpoint> <option>
# Agrega <option> a la entrada de <mountpoint> en /etc/fstab (si existe una) y
# remonta para aplicarla ya. No crea particiones nuevas. Hace backup de fstab.
# Limitacion: reconstruye la linea con espacios simples entre campos (puede
# perder alineacion visual del archivo original, no el contenido).
fstab_add_option() {
    local mp="$1" option="$2" fstab="/etc/fstab"
    if [[ ! -f "$fstab" ]]; then
        echo "No existe ${fstab}." >&2
        return 1
    fi
    if ! grep -Eq "^[^#][^[:space:]]*[[:space:]]+${mp//\//\\/}[[:space:]]" "$fstab"; then
        echo "No se encontro una entrada para '${mp}' en ${fstab}; agregar '${option}' requiere editar fstab manualmente." >&2
        return 1
    fi
    cis_backup_file "$fstab" >/dev/null
    local tmp
    tmp="$(mktemp)"
    while IFS= read -r line; do
        if [[ "$line" =~ ^[^#] ]]; then
            # shellcheck disable=SC2206
            local f=($line)
            if [[ "${#f[@]}" -ge 4 && "${f[1]}" == "$mp" ]]; then
                if [[ ",${f[3]}," != *",${option},"* ]]; then
                    f[3]="${f[3]},${option}"
                fi
                line="${f[*]}"
            fi
        fi
        printf '%s\n' "$line" >>"$tmp"
    done <"$fstab"
    mv "$tmp" "$fstab"
    mount -o "remount,${option}" "$mp" 2>/dev/null || true
}
