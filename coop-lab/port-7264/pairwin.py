"""Side-by-side 0.93.1 / 7264 instructions around 0931 addresses (uses map-7264.json):  pairwin.py 0xADDR[:before:after] ..."""
import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent; ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / '.tools/python')]
import pefile, capstone
m = json.loads((HERE / 'map-7264.json').read_text())
old = pefile.PE(r'D:\Azeroth Survivors Together Port 0931\AzerothSurvivors.exe', fast_load=True); new = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
def ins(pe, a):
    return next(md.disasm(pe.get_data(a, 16), a))
for arg in sys.argv[1:]:
    parts = arg.split(':'); a = int(parts[0], 16); before = int(parts[1]) if len(parts) > 1 else 4; after = int(parts[2]) if len(parts) > 2 else 8
    # walk back 'before' instructions using the map keys
    keys = sorted(int(k, 16) for k in m['instructions'])
    import bisect
    i = bisect.bisect_left(keys, a)
    print(f'== {arg}')
    for k in keys[max(0, i - before): i + after]:
        n, kind = m['instructions'][hex(k)]
        o, w = ins(old, k), ins(new, int(n, 16))
        ot, nt = f'{o.mnemonic} {o.op_str}', f'{w.mnemonic} {w.op_str}'
        mark = '  ' if ot == nt else '!!'
        print(f'{mark} {k:#x} {ot:45} | {int(n,16):#x} {nt}{"" if kind=="same" else "  ("+kind+")"}')
    if a not in m['instructions'] and hex(a) not in m['instructions']:
        print('   (Adresse selbst ohne Befehlseintrag)')
