"""
Recorre el CUERPO (no el TOC) del benchmark buscando, para cada control
hoja "<id> <titulo> (Automated|Manual)", su bloque "Profile Applicability:"
para extraer Level 1/2 x Server/Workstation.

Uso: python3 parse_levels.py <md_utf8> <out_csv> [body_start_heading] [body_end_heading]
"""
import re
import csv
import sys

path = sys.argv[1]
out_path = sys.argv[2]
body_start_heading = sys.argv[3] if len(sys.argv) > 3 else None
body_end_heading = sys.argv[4] if len(sys.argv) > 4 else None

with open(path, encoding='utf-8') as f:
    lines = [l.rstrip('\n') for l in f]

start_idx = 0
if body_start_heading:
    for i, l in enumerate(lines):
        if l.strip() == body_start_heading:
            start_idx = i
            break

end_idx = len(lines)
if body_end_heading:
    for i in range(start_idx + 1, len(lines)):
        if lines[i].strip() == body_end_heading:
            end_idx = i
            break

heading_re = re.compile(r'^(\d+(?:\.\d+){1,6})\s+\S')
tag_re = re.compile(r'^\((Automated|Manual)\)\s*$')
inline_tag_re = re.compile(r'\((Automated|Manual)\)\s*$')

results = {}
i = start_idx
n = end_idx
while i < n:
    m = heading_re.match(lines[i])
    is_control_heading = False
    if m:
        # El tag "(Automated)"/"(Manual)" puede venir pegado al titulo, en la
        # siguiente linea no vacia (titulo corto), o al final de una segunda
        # linea cuando el titulo se envuelve (titulo largo) -- el benchmark
        # mezcla los tres formatos. Distingue el heading real de coincidencias
        # numericas sueltas (ej. mapeos de CIS Controls v7/v8).
        for look in range(i, min(i + 3, n)):
            if inline_tag_re.search(lines[look].strip()):
                is_control_heading = True
                break
    if is_control_heading:
        cid = m.group(1)
        window_end = min(i + 40, n)
        found_pa = False
        levels = set()
        j = i + 1
        while j < window_end:
            if heading_re.match(lines[j]) and j != i:
                break
            if lines[j].strip() == 'Profile Applicability:':
                found_pa = True
            elif found_pa:
                lm = re.search(r'Level\s*([12])\s*-\s*(Server|Workstation)', lines[j])
                if lm:
                    levels.add(f"L{lm.group(1)}-{lm.group(2)}")
                if lines[j].strip() == 'Description:':
                    break
            j += 1
        if found_pa and levels:
            results[cid] = sorted(levels)
    i += 1

with open(out_path, 'w', newline='', encoding='utf-8') as out:
    w = csv.writer(out)
    w.writerow(['id', 'levels'])
    for cid, lv in sorted(results.items(), key=lambda kv: [int(p) for p in kv[0].split('.')]):
        w.writerow([cid, ';'.join(lv)])

print(f"Total controles con Profile Applicability detectado: {len(results)}", file=sys.stderr)
