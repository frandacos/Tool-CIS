"""
Parsea cis_debian_13.md (TOC + cuerpo) y genera el CSV maestro de inventario
que consume CISHarden.Core, con las mismas columnas que el de Debian10:

  control_id,title,page,chapter,profile_scope,level,automated,
  status_impl,status_tested,status_validated,notes

- Controles = lineas del TOC que terminan en "(Automated)" o "(Manual)" + pagina.
  Los titulos que el TOC parte en dos lineas se reconstruyen uniendo la linea previa.
- Niveles/perfiles = bloque "Profile Applicability:" de cada control en el cuerpo.
- 'level' es el nivel minimo (para el filtro -Level de Core); 'profile_scope'
  guarda el detalle por perfil ("Server:Level 1;Workstation:Level 2").

Uso: python3 build_master_csv.py ../../cis_debian_13.md cis_debian13_controls_master.csv
"""
import csv, re, sys

md_path, out_path = sys.argv[1:3]
lines = open(md_path, encoding='utf-8').read().splitlines()

leaf_re = re.compile(r'^(\d+(?:\.\d+)+)\s+(.*?)\s*\((Automated|Manual)\)\s*\.*\s*(\d+)\s*$')
start_re = re.compile(r'^(\d+(?:\.\d+)+)\s+(\S.*)$')
dots_page_re = re.compile(r'^(.*?)\s*\.{3,}\s*(\d+)\s*$')

# --- TOC: termina cuando aparece el Appendix
controls, order = {}, []
i = 0
while i < len(lines):
    ln = lines[i].strip()
    if ln.startswith('Appendix: Summary Table'):
        break
    m = leaf_re.match(ln)
    if not m:
        # titulo partido: "ID texto..." sin "(Automated)" y la linea siguiente lo cierra
        s = start_re.match(ln)
        if s and not dots_page_re.match(ln) and i + 1 < len(lines):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            joined = f"{ln} {lines[j].strip()}"
            m = leaf_re.match(joined)
            if m:
                i = j
    if m and m.group(1) not in controls:
        cid, title, kind, page = m.groups()
        controls[cid] = dict(title=re.sub(r'\s+', ' ', title), automated=kind, page=page)
        order.append(cid)
    i += 1

# --- Cuerpo: perfiles por control (primer "Profile Applicability" tras el header)
body_start = next(k for k, l in enumerate(lines) if l.strip() == 'Recommendations' and k > 400)
levels = {}
cur = None
k = body_start
while k < len(lines):
    ln = lines[k].strip()
    m = start_re.match(ln)
    if m and m.group(1) in controls and '....' not in ln:
        cur = m.group(1)
    elif ln == 'Profile Applicability:' and cur and cur not in levels:
        bits = []
        k += 1
        while k < len(lines) and not lines[k].strip().startswith('Description'):
            b = re.match(r'^[•\-\*]\s*Level\s*(\d)\s*-\s*(\w+)', lines[k].strip())
            if b:
                bits.append(f"{b.group(2)}:Level {b.group(1)}")
            k += 1
        levels[cur] = bits
        continue
    k += 1

order.sort(key=lambda c: [int(p) for p in c.split('.')])
with open(out_path, 'w', newline='', encoding='utf-8') as f:
    w = csv.writer(f)
    w.writerow(['control_id','title','page','chapter','profile_scope','level','automated',
                'status_impl','status_tested','status_validated','notes'])
    for cid in order:
        c = controls[cid]
        bits = levels.get(cid, [])
        nums = [int(b[-1]) for b in bits]
        w.writerow([cid, f"{c['title']} ({c['automated']})", c['page'], cid.split('.')[0],
                    ';'.join(bits) if bits else 'Server;Workstation',
                    f"Level {min(nums)}" if nums else 'Level 1', c['automated'], '', '', '', ''])
missing = [c for c in order if c not in levels]
print(f"{len(order)} controles; sin perfil: {len(missing)} {missing[:10]}", file=sys.stderr)
