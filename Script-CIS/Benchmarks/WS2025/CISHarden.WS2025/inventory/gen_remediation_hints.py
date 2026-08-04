"""Genera remediation_hints.csv a partir de las funciones Set-CIS_WS2025_*
de Private/*.ps1: un resumen legible por humanos de que toca cada control
al remediarlo (clave de registro, politica local, user right, subcategoria
de auditoria, o el cuerpo crudo de la funcion si no matchea ningun patron
conocido). Pensado para importarse en CIS-Dashboard y mostrarse en un boton
de info por control -- no reemplaza leer el .ps1 si hace falta el detalle
exacto.

Uso: python3 gen_remediation_hints.py
Escribe remediation_hints.csv al lado de este script.
"""
import csv
import re
from pathlib import Path

PRIVATE_DIR = Path(__file__).parent.parent / "Private"
OUT_CSV = Path(__file__).parent / "remediation_hints.csv"

FUNC_RE = re.compile(r"function\s+(Test|Set)-CIS_WS2025_(\S+?)\s*\{")
CONTROL_ID_RE = re.compile(r"-ControlId\s+'([^']+)'")


def extract_functions(text):
    """Devuelve (kind, suffix, body) para cada function Test/Set-CIS_WS2025_*,
    con el body extraido por conteo de llaves (no por regex de cierre)."""
    funcs = []
    for m in FUNC_RE.finditer(text):
        kind, suffix = m.group(1), m.group(2)
        start = m.end()
        depth = 1
        i = start
        while i < len(text) and depth > 0:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        funcs.append((kind, suffix, text[start:i - 1]))
    return funcs


def get_param(text, name):
    for pattern in (
        rf"(?<![\w-])-{name}\s+'([^']*)'",
        rf'(?<![\w-])-{name}\s+"([^"]*)"',
        rf"(?<![\w-])-{name}\s+(\([^)]*\))",
        rf"(?<![\w-])-{name}\s+(\$[\w:.]+)",
        rf"(?<![\w-])-{name}\s+([^\s]+)",
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).strip()
    return None


def resolve_var(body, value):
    """Si value es una referencia a un parametro (ej. '$Value'), busca su
    default dentro del param(...) del propio body y lo devuelve resuelto."""
    if not value or not value.startswith("$"):
        return value
    varname = value.lstrip("$")
    m = re.search(rf"\${varname}\s*=\s*'([^']*)'", body)
    if m:
        return m.group(1)
    m = re.search(rf'\${varname}\s*=\s*"([^"]*)"', body)
    if m:
        return m.group(1)
    m = re.search(rf"\${varname}\s*=\s*([^,\)\s]+)", body)
    if m:
        return m.group(1)
    return value


def make_hint(body):
    b = " ".join(body.split())

    if "Set-CISRegistryValue" in b:
        path = resolve_var(b, get_param(b, "Path"))
        name = get_param(b, "Name")
        type_ = get_param(b, "Type")
        value = resolve_var(b, get_param(b, "Value"))
        return f"Registro: {path}\\{name} = {value} (tipo {type_})"

    if "Set-CISSecurityPolicyValue" in b:
        key = get_param(b, "Key")
        value = resolve_var(b, get_param(b, "Value"))
        return f"Directiva de seguridad local (secedit, System Access): {key} = {value}"

    if "Set-CISScopedUserRight" in b or "Set-CISUserRight" in b:
        right = get_param(b, "RightConstant")
        principals_m = re.search(r"-ExpectedPrincipals\s+(.+?)(?=\s+-\w|\s*$)", b)
        principals = principals_m.group(1) if principals_m else "No One (sin principals asignados)"
        scope = get_param(b, "Scope")
        scope_txt = f" (solo aplica a rol {scope})" if scope else ""
        mode_txt = " (debe incluir al menos estos, puede haber otros)" if "-MustInclude" in b else ""
        return f"User Rights Assignment (secedit): se otorga el derecho '{right}' a: {principals}{mode_txt}{scope_txt}"

    if "Set-CISAuditPolicyForMode" in b:
        sub = get_param(b, "Subcategory")
        mode = get_param(b, "Mode")
        scope = get_param(b, "Scope")
        scope_txt = f" (solo aplica a rol {scope})" if scope else ""
        return f"Advanced Audit Policy (auditpol): subcategoria '{sub}' en modo {mode}{scope_txt}"

    if "New-ItemProperty" in b:
        path = resolve_var(b, get_param(b, "Path"))
        name = get_param(b, "Name")
        type_ = get_param(b, "PropertyType")
        value = resolve_var(b, get_param(b, "Value"))
        return f"Registro: {path}\\{name} = {value} (tipo {type_})"

    if "Remove-CISRegistryValue" in b:
        path = resolve_var(b, get_param(b, "Path"))
        name = get_param(b, "Name")
        scope = get_param(b, "Scope")
        scope_txt = f" (solo aplica a rol {scope})" if scope else ""
        return f"Registro: se elimina el valor {path}\\{name}{scope_txt}"

    if "Set-Service" in b and "Stop-Service" in b:
        svc = get_param(b, "Name")
        startup = get_param(b, "StartupType")
        return f"Servicio de Windows: detiene y pasa '{svc}' a inicio '{startup}'"

    if re.match(r"^\[CmdletBinding[^\]]*\]\s*param\(\)\s*Write-Warning", b) or b.strip().startswith("Write-Warning"):
        m = re.search(r"Write-Warning\s+'([^']+)'", b)
        msg = m.group(1) if m else b[:300]
        return f"Sin remediacion automatizada (revisar manualmente): {msg}"

    return f"Sin patron reconocido, ver Set-CIS_WS2025_* en el modulo: {b[:300]}"


def sort_key(control_id):
    parts = control_id.split(".")
    return [int(p) if p.isdigit() else p for p in parts]


def build_hints():
    test_map = {}
    set_map = {}
    for f in sorted(PRIVATE_DIR.glob("*.ps1")):
        text = f.read_text(encoding="utf-8")
        for kind, suffix, body in extract_functions(text):
            if kind == "Test":
                m = CONTROL_ID_RE.search(body)
                if m:
                    test_map[suffix] = m.group(1)
            else:
                set_map[suffix] = body

    rows = []
    for suffix, control_id in test_map.items():
        body = set_map.get(suffix)
        if body is None:
            continue  # sin Set- correspondiente -> ManualReviewRequired, no hay hint que dar
        rows.append((control_id, make_hint(body)))

    rows.sort(key=lambda r: sort_key(r[0]))
    return rows


def main():
    rows = build_hints()
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["control_id", "remediation_hint"])
        writer.writerows(rows)
    print(f"Escritas {len(rows)} filas en {OUT_CSV}")


if __name__ == "__main__":
    main()
