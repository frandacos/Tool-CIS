"""Extrae la seccion oficial "Remediation:" de cada control desde
Benchmarks/WS2025/cis2025.md (el benchmark CIS original, UTF-16) y la
vuelca a manual_remediation.csv (control_id, manual_remediation) -- el
procedimiento manual via GPO (UI Path) tal cual lo publica CIS, sin pasar
por Set-CIS_WS2025_*. Complementa a remediation_hints.csv (que dice que
toca el Set- automatizado); este CSV dice como hacerlo a mano.

Uso: python3 gen_manual_remediation.py
Escribe manual_remediation.csv al lado de este script.
"""
import csv
import re
from pathlib import Path

SOURCE_MD = Path(__file__).parent.parent.parent / "cis2025.md"
OUT_CSV = Path(__file__).parent / "manual_remediation.csv"

HEADER_RE = re.compile(r"^(\d+(?:\.\d+){1,7})\s+(.+?)\((Automated|Manual)\)\s*$", re.DOTALL)
PAGE_RE = re.compile(r"^Page \d+$")
STOP_SECTIONS = {"Default Value:", "References:", "CIS Controls:", "Additional Information:"}


def split_paragraphs(text):
    sep_re = re.compile(r"\r?\n\s*\r?\n+")
    paras = []
    last = 0
    for m in sep_re.finditer(text):
        paras.append(text[last:m.start()])
        last = m.end()
    paras.append(text[last:])
    return paras


def extract(paras):
    results = {}
    i = 0
    while i < len(paras):
        if paras[i].strip() == "Remediation:":
            control_id = None
            for j in range(i - 1, max(i - 60, -1), -1):
                m = HEADER_RE.match(paras[j].strip())
                if m and j + 1 < len(paras) and paras[j + 1].strip() == "Profile Applicability:":
                    control_id = m.group(1)
                    break
            body_paras = []
            k = i + 1
            while k < len(paras):
                s = paras[k].strip()
                if s in STOP_SECTIONS or HEADER_RE.match(s):
                    break
                if s and not PAGE_RE.match(s):
                    body_paras.append(" ".join(s.split()))
                k += 1
            if control_id:
                results[control_id] = "\n\n".join(body_paras).strip()
        i += 1
    return results


def sort_key(control_id):
    return [int(p) if p.isdigit() else p for p in control_id.split(".")]


def main():
    text = SOURCE_MD.read_text(encoding="utf-16")
    paras = split_paragraphs(text)
    results = extract(paras)
    rows = sorted(results.items(), key=lambda r: sort_key(r[0]))
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["control_id", "manual_remediation"])
        writer.writerows(rows)
    print(f"Escritas {len(rows)} filas en {OUT_CSV}")


if __name__ == "__main__":
    main()
