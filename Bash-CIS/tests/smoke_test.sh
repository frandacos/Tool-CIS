#!/usr/bin/env bash
# Smoke test: sin necesitar una Debian real. Corre en cualquier bash (incluido
# el /bin/bash 3.2 de macOS) porque solo chequea sintaxis y que existan las
# funciones test_*/set_*, sin llamarlas.
#   1) bash -n sobre todos los .sh (sintaxis).
#   2) Cobertura del inventario: cuantos control_id tienen test_<id> definida.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

fail=0
for f in "${ROOT}"/lib/*.sh "${ROOT}"/controls/debian13/*.sh "${ROOT}"/bin/*.sh; do
    if ! bash -n "$f"; then
        echo "SYNTAX ERROR: $f"
        fail=1
    fi
done
[[ "$fail" -eq 0 ]] && echo "Sintaxis OK en todos los .sh"

# shellcheck source=/dev/null
for f in "${ROOT}"/lib/*.sh "${ROOT}"/controls/debian13/*.sh; do source "$f"; done

total=0 impl_test=0 impl_set=0
missing=()
while IFS=',' read -r control_id title page chapter _rest; do
    [[ "$control_id" == "control_id" ]] && continue
    [[ -z "$control_id" ]] && continue
    total=$((total + 1))
    tfn="test_${control_id//./_}"
    sfn="set_${control_id//./_}"
    if declare -F "$tfn" >/dev/null; then
        impl_test=$((impl_test + 1))
    else
        missing+=("$control_id")
    fi
    declare -F "$sfn" >/dev/null && impl_set=$((impl_set + 1))
done <"${ROOT}/inventory/cis_debian13_controls_master.csv"

echo "Cobertura Test-*: ${impl_test}/${total}"
echo "Cobertura Set-*:  ${impl_set}/${total}"
if [[ "${#missing[@]}" -gt 0 && "${#missing[@]}" -lt 15 ]]; then
    echo "Pendientes: ${missing[*]}"
fi

exit "$fail"
