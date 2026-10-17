"""Register renames 0931 -> 7264 inside one function (aligned instruction pairs of equal mnemonic), read-only.
  regrename.py 0xOLDFN [0xFROM 0xTO]   -> counts of old->new register pairs (optionally only in an old address range)
"""
import json, re, sys, collections
from pathlib import Path
HERE = Path(__file__).resolve().parent; ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / '.tools/python')]
import pefile, capstone
m = json.loads((HERE / 'map-7264.json').read_text())
old = pefile.PE(r'D:\Azeroth Survivors Together Port 0931\AzerothSurvivors.exe', fast_load=True)
new = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
REG = re.compile(r'\b([re]?[abcd]x|[re]?[sd]il?|[re]?[sb]pl?|r\d+[dwb]?|xmm\d+|[abcd]l)\b')
fn = int(sys.argv[1], 16); info = m['functions'][hex(fn)]
lo, hi = (int(sys.argv[2], 16), int(sys.argv[3], 16)) if len(sys.argv) > 3 else (fn, fn + info['size'])
pairs = collections.Counter()
for k, (v, kind) in m['instructions'].items():
    a = int(k, 16)
    if not lo <= a < hi: continue
    o = next(md.disasm(old.get_data(a, 16), a)); n = next(md.disasm(new.get_data(int(v, 16), 16), int(v, 16)))
    if o.mnemonic != n.mnemonic: continue
    ro, rn = REG.findall(o.op_str), REG.findall(n.op_str)
    if len(ro) == len(rn):
        for x, y in zip(ro, rn):
            if x != y and x not in ('rbp', 'rsp', 'rip'): pairs[(x, y)] += 1
for (x, y), c in pairs.most_common(40): print(f'{x:>6} -> {y:<6} {c}')
