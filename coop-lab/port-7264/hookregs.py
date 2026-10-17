"""Register check 0931 -> 7264 at every code address of the 0931 release (boot-log format, read-only).

For each address: the instruction there and the next N, old vs aligned new. A site is 'gleich' when the
register text (numbers masked) is identical, 'Register' when registers differ, 'fehlt' without alignment.
  hookregs.py [N]   -> out/hookregs.md
"""
import json, re, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent; ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / '.tools/python')]
import pefile, capstone
N = int(sys.argv[1]) if len(sys.argv) > 1 else 4
HEX = re.compile(r'0x[0-9a-f]+|\b\d+\b')
log = lambda tag, text: print(f'[{tag:^6}] {text}', flush=True)
t = time.time()
log(' .... ', 'Registerprüfung an allen Code-Adressen')
m = json.loads((HERE / 'map-7264.json').read_text())
old = pefile.PE(r'D:\Azeroth Survivors Together Port 0931\AzerothSurvivors.exe', fast_load=True)
new = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
text = next(s for s in old.sections if s.Name.startswith(b'.text'))
lo, hi = text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize
rel = json.loads((ROOT / 'reconstruction/release-0315cf38.json').read_text())
sites = {}
def walk(v, path):
    if isinstance(v, dict):
        for k, x in v.items(): walk(x, path + [str(k)])
    elif isinstance(v, list):
        for i, x in enumerate(v): walk(x, path + [str(i)])
    elif isinstance(v, int) and not isinstance(v, bool) and lo <= v < hi and 'reference' not in path and 'required_inputs' not in path:
        sites.setdefault(v, '/'.join(path[-3:]))
    elif isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]+', v) and lo <= int(v, 16) < hi:
        sites.setdefault(int(v, 16), '/'.join(path[-3:]))
walk(rel, [])
sys.path.insert(0, str(ROOT / 'reconstruction'))
import updated_layout as ul
for k, v in ul.FAMILY['0931'].items():
    for x in (v if isinstance(v, tuple) else (v,)):
        for y in (x if isinstance(x, tuple) else (x,)):
            if lo <= y < hi: sites.setdefault(y, f'FAMILY.{k}')
def ins(pe, a, n):
    return list(md.disasm(pe.get_data(a, 16 * n), a))[:n]
rows, stats = [], {'gleich': 0, 'Register': 0, 'fehlt': 0}
for a in sorted(sites):
    row = m['instructions'].get(hex(a))
    if not row:
        stats['fehlt'] += 1; rows.append(f'## {a:#x} ({sites[a]}): fehlt\n'); continue
    b = int(row[0], 16)
    oi, ni = ins(old, a, N + 1), ins(new, b, N + 1)
    lines, diff = [], False
    for o, n in zip(oi, ni):
        ot, nt = f'{o.mnemonic} {o.op_str}', f'{n.mnemonic} {n.op_str}'
        d = HEX.sub('N', ot) != HEX.sub('N', nt)
        diff |= d
        lines.append(f'    {"!!" if d else "  "} {o.address:#x} {ot:44} | {n.address:#x} {nt}')
    kind = 'Register' if diff else 'gleich'
    stats[kind] += 1
    if diff: rows.append(f'## {a:#x} -> {b:#x} ({sites[a]}): {kind}\n' + '\n'.join(lines) + '\n')
(HERE / 'out/hookregs.md').write_text(f'# Registerprüfung 0931 -> 7264 (je Stelle {N + 1} Befehle)\n\n' + '\n'.join(rows), encoding='utf-8')
log('  OK  ', f'Registerprüfung ({time.time() - t:.1f} s, {len(sites)} Stellen: {stats})')
