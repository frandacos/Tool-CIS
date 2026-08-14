"""
Extrae del indice (Table of Contents) del benchmark CIS Debian 10 los
controles hoja de un capitulo dado (los que traen "(Automated)" o
"(Manual)" pegado al titulo -- las secciones intermedias como "1.1
Filesystem Configuration" no lo tienen y se descartan).

Uso: python3 parse_toc.py <md_utf8> <chapter_start_heading> <chapter_end_heading> <out_csv>
Ej.: python3 parse_toc.py cis_debian_10_utf8.md "1 Initial Setup" "2 Services" chapter1_toc_raw.csv
"""
import re
import csv
import sys

path, start_heading, end_heading, out_path = sys.argv[1:5]

with open(path, encoding='utf-8') as f:
    lines = [l.rstrip('\n') for l in f]

start = None
end = None
for i, l in enumerate(lines):
    if start is None and l.strip().startswith(start_heading + ' ') and '.' in l and re.search(r'\d+\s*$', l):
        start = i
    if start is not None and i > start and l.strip().startswith(end_heading + ' '):
        end = i
        break

if start is None or end is None:
    print(f"No se pudo delimitar el capitulo (start={start}, end={end})", file=sys.stderr)
    sys.exit(1)

print(f"TOC capitulo: lineas {start}-{end}", file=sys.stderr)
toc = lines[start:end]

entry_re = re.compile(
    r'^(?P<id>\d+(?:\.\d+){1,6})\s+(?P<title>.+?)\s*\((?P<tag>Automated|Manual)\)\s*\.*\s*(?P<page>\d+)\s*$'
)

entries = []
for l in toc:
    l = l.strip()
    if not l:
        continue
    m = entry_re.match(l)
    if m:
        entries.append((m.group('id'), m.group('title').strip(), m.group('tag'), m.group('page')))

with open(out_path, 'w', newline='', encoding='utf-8') as out:
    w = csv.writer(out)
    w.writerow(['id', 'title', 'automated', 'page'])
    for e in entries:
        w.writerow(e)

print(f"Total controles hoja: {len(entries)}", file=sys.stderr)
