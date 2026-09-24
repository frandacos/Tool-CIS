# CISHarden-Bash Core - motor generico de auditoria/remediacion CIS para Linux.
# Puerto en bash de CISHarden.Core (PowerShell, en Script-CIS). Proyecto PARALELO
# e independiente: no comparte codigo ni estado con Script-CIS. Misma idea (un
# Test-*/Set-* por control, orquestador con alcance explicito, CSV de salida
# compatible con CIS-Dashboard), reescrita para no depender de pwsh.
#
# Requiere bash 4+ (Debian 13 trae bash 5.x por defecto). No usar en macOS con
# el /bin/bash de sistema (3.2) para EJECUTAR controles reales -- si sirve para
# chequeos de sintaxis (bash -n) y para correr tests/smoke_test.sh.

CIS_HOSTNAME="$(hostname -f 2>/dev/null || hostname)"

# --- CSV ----------------------------------------------------------------------

_cis_csv_escape() {
    # Envuelve en comillas y duplica comillas internas si el campo tiene coma,
    # comilla o salto de linea (RFC4180 basico).
    local field="$1"
    if [[ "$field" == *,* || "$field" == *'"'* || "$field" == *$'\n'* ]]; then
        field="${field//\"/\"\"}"
        printf '"%s"' "$field"
    else
        printf '%s' "$field"
    fi
}

cis_csv_header() {
    echo "ControlId,Title,Status,ExpectedValue,ActualValue,Notes,Hostname,Timestamp"
}

# Emite una fila de resultado (misma forma que New-CISResult del lado PowerShell,
# y mismas columnas que espera CIS-Dashboard al importar una corrida). Uso:
#   cis_result <control_id> <title> <status> [expected] [actual] [notes]
# status: Pass | Fail | NotApplicable | ManualReviewRequired | Error
cis_result() {
    local control_id="$1" title="$2" status="$3"
    local expected="${4:-}" actual="${5:-}" notes="${6:-}"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$(_cis_csv_escape "$control_id")" "$(_cis_csv_escape "$title")" "$(_cis_csv_escape "$status")" \
        "$(_cis_csv_escape "$expected")" "$(_cis_csv_escape "$actual")" "$(_cis_csv_escape "$notes")" \
        "$(_cis_csv_escape "$CIS_HOSTNAME")" "$(_cis_csv_escape "$ts")"
}

# Extrae el campo <n> (1-indexado) de una fila CSV ya generada por cis_result.
# No es un parser CSV general -- alcanza para leer el Status que la propia
# funcion acaba de imprimir (sin comas embebidas en ese campo).
cis_csv_field() {
    local row="$1" n="$2"
    awk -F',' -v n="$n" '{print $n}' <<<"$row"
}

# --- Backups (antes de tocar un archivo real) ----------------------------------

CIS_BACKUP_DIR="${CIS_BACKUP_DIR:-/var/lib/cisharden-bash/backups}"

cis_backup_file() {
    # Copia <path> a CIS_BACKUP_DIR con timestamp; no hace nada si no existe.
    # Imprime la ruta del backup por stdout.
    local path="$1"
    [[ -e "$path" ]] || return 0
    mkdir -p "$CIS_BACKUP_DIR" 2>/dev/null
    local stamp base dest
    stamp="$(date +%Y%m%d_%H%M%S)"
    base="$(basename "$path")"
    dest="${CIS_BACKUP_DIR}/${base}_backup_${stamp}"
    cp -a "$path" "$dest" && printf '%s\n' "$dest"
}

# --- Perfil Server/Workstation (heuristica, igual espiritu que Get-CISLinuxProfile) --

cis_linux_profile() {
    # Heuristica simple: si hay entorno grafico (paquete xserver-common o
    # gdm3/gdm instalado) se asume Workstation; si no, Server. Sin GUI perfecta
    # (igual que el lado PowerShell, documentar la limitacion si hace falta).
    if command -v dpkg-query >/dev/null 2>&1; then
        if dpkg-query -W -f='${Status}' xserver-common 2>/dev/null | grep -q '^install ok installed$'; then
            echo Workstation
            return
        fi
    fi
    echo Server
}

# --- Utilidad comun a varios controles: reemplazar/agregar "clave = valor" ----
# en un archivo de configuracion simple (una asignacion por linea). Comenta
# lineas no comentadas que no coincidan con <value> y agrega la linea correcta
# si no existe ya una correcta. Hace backup antes de tocar el archivo.
cis_conf_set_kv() {
    local file="$1" key="$2" value="$3" sep="${4:- = }"
    local dir
    dir="$(dirname "$file")"
    mkdir -p "$dir" 2>/dev/null
    if [[ -f "$file" ]]; then
        cis_backup_file "$file" >/dev/null
    fi
    local tmp
    tmp="$(mktemp)"
    local found=0
    if [[ -f "$file" ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*# ]]; then
                printf '%s\n' "$line" >>"$tmp"
                continue
            fi
            if [[ "$line" =~ ^[[:space:]]*${key}[[:space:]]*= ]]; then
                if [[ "$found" -eq 0 && "$line" =~ =[[:space:]]*${value}[[:space:]]*$ ]]; then
                    printf '%s\n' "$line" >>"$tmp"
                    found=1
                else
                    printf '# %s\n' "$line" >>"$tmp"
                fi
                continue
            fi
            printf '%s\n' "$line" >>"$tmp"
        done <"$file"
    fi
    if [[ "$found" -eq 0 ]]; then
        printf '%s%s%s\n' "$key" "$sep" "$value" >>"$tmp"
    fi
    mv "$tmp" "$file"
}
