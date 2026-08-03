import re, csv, sys

path = sys.argv[1]
with open(path, encoding='utf-8') as f:
    lines = [l.replace('\f','').rstrip('\n') for l in f]

heading_re = re.compile(r'^(\d+(?:\.\d+){1,6})\s+\S')

results = {}
i = 0
n = len(lines)
while i < n:
    m = heading_re.match(lines[i])
    if m:
        cid = m.group(1)
        # buscar 'Profile Applicability:' dentro de las proximas 20 lineas,
        # y cortar si aparece otro heading antes (evita falsos positivos del TOC)
        window_end = min(i + 25, n)
        found_pa = False
        levels = set()
        j = i + 1
        while j < window_end:
            if heading_re.match(lines[j]) and j != i:
                break
            if 'Profile Applicability' in lines[j]:
                found_pa = True
            if found_pa:
                lm = re.search(r'Level\s*([12])\s*-\s*(Domain Controller|Member Server)', lines[j])
                if lm:
                    levels.add(f"L{lm.group(1)}-{'DC' if 'Domain' in lm.group(2) else 'MS'}")
                if 'Description:' in lines[j]:
                    break
            j += 1
        if found_pa and levels:
            results[cid] = sorted(levels)
    i += 1

with open(sys.argv[2], 'w', newline='', encoding='utf-8') as out:
    w = csv.writer(out)
    w.writerow(['control_id', 'levels'])
    for cid, lv in sorted(results.items()):
        w.writerow([cid, ';'.join(lv)])

print(f"Total controles con Profile Applicability detectado: {len(results)}", file=sys.stderr)
