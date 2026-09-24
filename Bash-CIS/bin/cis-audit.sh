#!/usr/bin/env bash
# Orquestador de auditoria (equivalente bash de Invoke-CISAudit). Recorre
# inventory/cis_debian13_controls_master.csv y ejecuta test_<control_id> por
# cada fila si existe esa funcion. Solo lee el sistema, no modifica nada.
#
# Uso:
#   bin/cis-audit.sh [--chapter N] [--control-id ID] [--output archivo.csv] [--report-coverage]
#
# Sin --output escribe el CSV a stdout; los avisos de cobertura van a stderr.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

# shellcheck source=/dev/null
for f in "${ROOT}"/lib/*.sh; do source "$f"; done
# shellcheck source=/dev/null
for f in "${ROOT}"/controls/debian13/*.sh; do source "$f"; done

INVENTORY="${ROOT}/inventory/cis_debian13_controls_master.csv"
CHAPTER="" CONTROL_ID="" OUTPUT="" REPORT_COVERAGE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --chapter) CHAPTER="$2"; shift 2 ;;
        --control-id) CONTROL_ID="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --report-coverage) REPORT_COVERAGE=1; shift ;;
        -h|--help)
            sed -n '2,13p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) echo "Argumento desconocido: $1" >&2; exit 1 ;;
    esac
done

if [[ -n "$OUTPUT" ]]; then
    cis_csv_header >"$OUTPUT"
    exec 3>>"$OUTPUT"
else
    exec 3>&1
fi

total=0 implemented=0
missing=()

# Nota: split simple por coma -- alcanza porque control_id/title/chapter del
# inventario no llevan comas embebidas. No es un parser CSV general.
while IFS=',' read -r control_id title page chapter _rest; do
    [[ "$control_id" == "control_id" ]] && continue
    [[ -z "$control_id" ]] && continue
    [[ -n "$CHAPTER" && "$chapter" != "$CHAPTER" ]] && continue
    [[ -n "$CONTROL_ID" && "$control_id" != "$CONTROL_ID" ]] && continue

    total=$((total + 1))
    fn="test_${control_id//./_}"
    if declare -F "$fn" >/dev/null; then
        implemented=$((implemented + 1))
        "$fn" >&3
    else
        missing+=("$control_id")
    fi
done <"$INVENTORY"

if [[ "$REPORT_COVERAGE" -eq 1 ]]; then
    echo "Cobertura (Debian13-bash): ${implemented}/${total} controles implementados en este alcance." >&2
    if [[ "${#missing[@]}" -gt 0 ]]; then
        echo "Sin Test-* implementada (${#missing[@]}): ${missing[*]:0:20}$([[ ${#missing[@]} -gt 20 ]] && echo ' ...')" >&2
    fi
fi
