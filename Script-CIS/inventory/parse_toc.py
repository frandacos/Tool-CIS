import re, csv, sys

path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    raw_lines = f.readlines()

# Strip control chars (form feed, etc.) that break start-of-line matching
lines = [l.replace('\f', '').replace('\x0b','') for l in raw_lines]

start = None
end = None
for i, l in enumerate(lines):
    if re.match(r'^1 Account Policies\s*\.', l.strip()):
        if start is None:
            start = i
    if start is not None and re.match(r'^1 Account Policies\s*$', l.strip()) and i > start:
        end = i
        break

print("start", start, "end", end, file=sys.stderr)

toc = lines[start:end]

entry_re = re.compile(r'^(\d+(?:\.\d+){0,8})\s+(.*)$')
dots_page_re = re.compile(r'\.{3,}\s*(\d+)\s*$')

entries = []
cur_id = None
cur_title_parts = []
cur_page = None

def flush():
    global cur_id, cur_title_parts, cur_page
    if cur_id is not None:
        title = ' '.join(cur_title_parts).strip()
        title = re.sub(r'\.{3,}.*$', '', title).strip()
        entries.append((cur_id, title, cur_page))
    cur_id = None
    cur_title_parts = []
    cur_page = None

for raw in toc:
    l = raw.rstrip('\n')
    if not l.strip():
        continue
    if l.strip() == 'Page' or re.match(r'^Page\s+\d+$', l.strip()):
        continue
    m = entry_re.match(l)
    if m:
        flush()
        cur_id = m.group(1)
        rest = m.group(2)
        cur_title_parts = [rest]
    else:
        if cur_id is not None:
            cur_title_parts.append(l.strip())
    pm = dots_page_re.search(l)
    if pm and cur_id is not None:
        cur_page = pm.group(1)
        flush()

flush()

with open(sys.argv[2], 'w', newline='', encoding='utf-8') as out:
    w = csv.writer(out)
    w.writerow(['id','title','page'])
    for e in entries:
        w.writerow(e)

print(f"Total entries: {len(entries)}", file=sys.stderr)
