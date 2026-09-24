# Motor de archivos: permisos, propietario, contenido. Puerto de
# LinuxFileEngine.ps1.

file_mode_octal() { stat -c '%a' "$1" 2>/dev/null; }
file_owner() { stat -c '%U:%G' "$1" 2>/dev/null; }

file_set_mode() { chmod "$2" "$1"; }
file_set_owner() { chown "$2" "$1"; }

# file_contains <path> <ere>
file_contains() {
    [[ -f "$1" ]] || return 1
    grep -Eq "$2" "$1" 2>/dev/null
}

# path_access_ok <path> <max_octal_mode> <owner1[,owner2,...]>
# 0 (Pass) si <path> no existe (nada que proteger), o si su modo no tiene
# ningun bit fuera de <max_octal_mode> Y su owner:group esta en la lista.
# Equivalente de Test-CISPathAccess (Script-CIS/CISHarden.Core).
path_access_ok() {
    local path="$1" maxmode="$2" ownercsv="${3:-root:root}"
    [[ -e "$path" ]] || return 0
    local mode owner extra
    mode="$(file_mode_octal "$path")"
    owner="$(file_owner "$path")"
    [[ -z "$mode" ]] && return 0
    extra=$(( 8#$mode & ~(8#$maxmode) & 8#777 ))
    local IFS=','
    local o
    for o in $ownercsv; do
        [[ "$owner" == "$o" ]] && { [[ "$extra" -eq 0 ]]; return $?; }
    done
    return 1
}

# path_access_detail <path>
# Imprime "owner=<u:g>; mode=<octal>" (o "no existe") para el campo ActualValue.
path_access_detail() {
    local path="$1"
    if [[ ! -e "$path" ]]; then
        echo "no existe"
        return
    fi
    echo "owner=$(file_owner "$path"); mode=$(file_mode_octal "$path")"
}
