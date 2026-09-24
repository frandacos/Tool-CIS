#!/usr/bin/env bash
# Orquestador de remediacion (equivalente bash de Invoke-CISRemediate). Exige
# un alcance explicito (nunca "remediar todo" por default). Solo remedia
# controles que la auditoria marco Fail (nunca Pass/NotApplicable/Manual).
#
# Uso:
#   bin/cis-remediate.sh --control-id ID [--dry-run]
#   bin/cis-remediate.sh --chapter N [--dry-run] [--force]
#   bin/cis-remediate.sh --all --force [--dry-run]
#   [--log archivo.csv] para el detalle de cada control
#
# Regla de oro: corre primero con --dry-run y revisa la salida antes de
# aplicar de verdad, sobre todo con --chapter/--all.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

# shellcheck source=/dev/null
for f in "${ROOT}"/lib/*.sh; do source "$f"; done
# shellcheck source=/dev/null
for f in "${ROOT}"/controls/debian13/*.sh; do source "$f"; done

INVENTORY="${ROOT}/inventory/cis_debian13_controls_master.csv"
CHAPTER="" CONTROL_ID="" ALL=0 DRY_RUN=0 FORCE=0 LOG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --chapter) CHAPTER="$2"; shift 2 ;;
        --control-id) CONTROL_ID="$2"; shift 2 ;;
        --all) ALL=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --force) FORCE=1; shift ;;
        --log) LOG="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,13p' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) echo "Argumento desconocido: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$CHAPTER" && -z "$CONTROL_ID" && "$ALL" -ne 1 ]]; then
    echo "Especifica un alcance explicito: --control-id ID, --chapter N o --all." >&2
    exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Este script debe correrse como root (o con sudo)." >&2
    exit 1
fi

targets=()
while IFS=',' read -r control_id title page chapter _rest; do
    [[ "$control_id" == "control_id" ]] && continue
    [[ -z "$control_id" ]] && continue
    [[ -n "$CHAPTER" && "$chapter" != "$CHAPTER" ]] && continue
    [[ -n "$CONTROL_ID" && "$control_id" != "$CONTROL_ID" ]] && continue
    targets+=("$control_id")
done <"$INVENTORY"

echo "Se van a evaluar ${#targets[@]} control(es); se remedian los que esten en Fail." >&2
if [[ "$FORCE" -ne 1 && "$DRY_RUN" -ne 1 ]]; then
    read -r -p "¿Continuar? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { echo "Cancelado."; exit 0; }
fi

[[ -n "$LOG" ]] && echo "ControlId,Action,PostStatus" >"$LOG"

for control_id in "${targets[@]}"; do
    test_fn="test_${control_id//./_}"
    set_fn="set_${control_id//./_}"

    if ! declare -F "$test_fn" >/dev/null; then
        echo "  ${control_id}: sin Test-* -- SkippedNoFunction"
        [[ -n "$LOG" ]] && echo "${control_id},SkippedNoFunction," >>"$LOG"
        continue
    fi

    row="$("$test_fn")"
    status="$(cis_csv_field "$row" 3)"
    if [[ "$status" != "Fail" ]]; then
        continue
    fi

    if ! declare -F "$set_fn" >/dev/null; then
        echo "  ${control_id}: Fail pero sin Set-* -- SkippedNoFunction"
        [[ -n "$LOG" ]] && echo "${control_id},SkippedNoFunction," >>"$LOG"
        continue
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "  [dry-run] ${control_id}: se remediaria"
        [[ -n "$LOG" ]] && echo "${control_id},WhatIf," >>"$LOG"
        continue
    fi

    if "$set_fn"; then
        post_row="$("$test_fn")"
        post_status="$(cis_csv_field "$post_row" 3)"
        echo "  ${control_id}: remediado -- estado post = ${post_status}"
        [[ -n "$LOG" ]] && echo "${control_id},Remediated,${post_status}" >>"$LOG"
    else
        echo "  ${control_id}: FALLO al remediar (ver stderr arriba)" >&2
        [[ -n "$LOG" ]] && echo "${control_id},Failed," >>"$LOG"
    fi
done
