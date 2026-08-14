"""
Combina <toc_csv> (id,title,automated,page) + <levels_csv> (id,levels) en el
CSV maestro de inventario que consume CISHarden.Core (mismas columnas que
cis2025_controls_master.csv de WS2025, mas 'automated'):

  control_id, title, page, chapter, profile_scope, level,
  automated, status_impl, status_tested, status_validated, notes

'level' es el nivel MINIMO en el que el control aplica a algun perfil (para
que el filtro -Level de Invoke-CISAudit, que compara igualdad exacta contra
'Level 1'/'Level 2', siga funcionando tal cual esta escrito hoy en Core).
'profile_scope' guarda el detalle completo por perfil (ej.
"Server:Level 1;Workstation:Level 2") para que cada Test-CIS_Debian10_* sepa
exactamente que nivel/perfil corresponde a cada combinacion.

Uso: python3 build_master_csv.py <toc_csv> <levels_csv> <chapter_num> <out_csv>
"""
import csv
import sys

toc_path, levels_path, chapter_num, out_path = sys.argv[1:5]

levels_by_id = {}
with open(levels_path, encoding='utf-8') as f:
    for row in csv.DictReader(f):
        levels_by_id[row['id']] = row['levels']

rows = []
with open(toc_path, encoding='utf-8') as f:
    for row in csv.DictReader(f):
        cid = row['id']
        raw_levels = levels_by_id.get(cid, '')
        # raw_levels: 'L1-Server;L2-Workstation' -> profile_scope +
        # nivel minimo global para el filtro -Level de Core.
        parts = [p for p in raw_levels.split(';') if p]
        profile_scope_bits = []
        min_level = None
        for p in parts:
            lvl, profile = p.split('-', 1)
            lvl_num = int(lvl[1:])
            profile_scope_bits.append(f"{profile}:Level {lvl_num}")
            if min_level is None or lvl_num < min_level:
                min_level = lvl_num
        rows.append({
            'control_id': cid,
            'title': f"{row['title']} ({row['automated']})",
            'page': row['page'],
            'chapter': chapter_num,
            'profile_scope': ';'.join(profile_scope_bits) if profile_scope_bits else 'Server;Workstation',
            'level': f"Level {min_level}" if min_level else 'Level 1',
            'automated': row['automated'],
            'status_impl': '',
            'status_tested': '',
            'status_validated': '',
            'notes': '',
        })

rows.sort(key=lambda r: [int(p) for p in r['control_id'].split('.')])

with open(out_path, 'w', newline='', encoding='utf-8') as out:
    fieldnames = ['control_id', 'title', 'page', 'chapter', 'profile_scope', 'level',
                  'automated', 'status_impl', 'status_tested', 'status_validated', 'notes']
    w = csv.DictWriter(out, fieldnames=fieldnames)
    w.writeheader()
    for r in rows:
        w.writerow(r)

print(f"Total filas: {len(rows)}", file=sys.stderr)
