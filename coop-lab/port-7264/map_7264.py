"""Instruction-level map 0315cf38 (0.93.1) -> 7264d50b for every function the co-op profile touches.

Read-only. Boot-log format. Output coop-lab/port-7264/map-7264.json:
  functions: old start -> {new, ratio, second, exact}
  instructions: old address -> [new address, kind]   kind 'same' (identical shape) or 'shape' (same length block)
  data: old RIP target -> {new target: votes}
  disps: "<class>:<old disp>" -> {new disp: votes}   class = frame (rbp/rsp) | struct
  rip_pairs_by_fn / disp_pairs: kept per function for review

  map_7264.py [--extra 0x5474190,...]   extra 0931 code addresses whose functions are mapped too
"""
import argparse
import bisect
import collections
import difflib
import json
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(ROOT / '.tools/python'), str(ROOT / 'analysis')]
OLD = Path(r'D:\Azeroth Survivors Together Port 0931\AzerothSurvivors.exe')
NEW = ROOT / 'AzerothSurvivors.exe'
HEX = re.compile(r'0x[0-9a-f]+|\b\d+\b')
MEM = re.compile(r'\[([a-z][a-z0-9]*)(?: \+ ([a-z][a-z0-9]*)(?:\*\d)?)?(?: ([+-]) (0x[0-9a-f]+))?\]')


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def threads():
    import ctypes
    from ctypes import wintypes
    k = ctypes.windll.kernel32
    k.GetCurrentProcess.restype = wintypes.HANDLE
    k.GetProcessAffinityMask.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t))
    a, b = ctypes.c_size_t(), ctypes.c_size_t()
    return max(1, min(16, bin(a.value).count('1'))) if k.GetProcessAffinityMask(k.GetCurrentProcess(), ctypes.byref(a), ctypes.byref(b)) else 4


_cache = {}


def image(path):
    if path not in _cache:
        import pefile
        import map_build_functions as mbf
        pe = pefile.PE(str(path), fast_load=True)
        _cache[path] = (pe, sorted(set(mbf.unwind_ranges(pe))))
    return _cache[path]


def function_of(path, address):
    _, ranges = image(path)
    i = bisect.bisect_right([a for a, _ in ranges], address) - 1
    return ranges[i] if i >= 0 and ranges[i][0] <= address < ranges[i][1] else None


def decode(path, start, end):
    import capstone
    pe, _ = image(path)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    rows = []
    for i in md.disasm(pe.get_data(start, end - start), start):
        rip = None
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                rip = i.address + i.size + op.mem.disp
        target = None
        if i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL):
            for op in i.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    target = op.imm
        imms = tuple(op.imm for op in i.operands if op.type == capstone.x86.X86_OP_IMM)
        rows.append((i.address, i.size, i.mnemonic, i.op_str, rip, target, imms))
    return rows


def loose(row):
    return row[2] + ' ' + HEX.sub('N', row[3])


def pair(job):
    """Find the 0.93.1 counterpart of one 0931 function and align it."""
    (a, b), cands = job
    old = decode(OLD, a, b)
    ot = [loose(r) for r in old]
    exact_text = [r[2] + ' ' + (HEX.sub('N', r[3]) if (r[4] or r[5]) else r[3]) for r in old]
    scored = []
    for c in cands:
        new = decode(NEW, *c)
        nt = [loose(r) for r in new]
        scored.append((difflib.SequenceMatcher(None, ot, nt, autojunk=False).quick_ratio(), c, new, nt))
    scored.sort(key=lambda s: -s[0])
    if not scored:
        return dict(old=a, new=None)
    best = []
    for q, c, new, nt in scored[:3]:
        sm = difflib.SequenceMatcher(None, ot, nt, autojunk=False)
        best.append((sm.ratio(), c, new, nt, sm))
    best.sort(key=lambda s: -s[0])
    ratio, c, new, nt, sm = best[0]
    second = best[1][0] if len(best) > 1 else 0.0
    exact = exact_text == [r[2] + ' ' + (HEX.sub('N', r[3]) if (r[4] or r[5]) else r[3]) for r in new]
    instructions, data, disps, branches, imms = {}, [], [], [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == 'equal' or (tag == 'replace' and i2 - i1 == j2 - j1):
            for k in range(i2 - i1):
                o, n = old[i1 + k], new[j1 + k]
                kind = 'same' if tag == 'equal' else 'shape'
                instructions[o[0]] = (n[0], kind)
                if kind == 'same' and o[4] is not None and n[4] is not None:
                    data.append((o[4], n[4]))
                if kind == 'same' and o[5] is None and o[6] != n[6]:
                    imms.append((o[2], list(o[6]), list(n[6]), o[0]))
                if kind == 'same' and o[5] is not None and n[5] is not None:
                    branches.append((o[5], n[5]))
                if kind == 'same':
                    for (ob, oi, osg, od), (nb, ni, nsg, nd) in zip(MEM.findall(o[3]), MEM.findall(n[3])):
                        if ob != 'rip' and ob == nb and oi == ni:
                            ov = (int(od, 16) if od else 0) * (-1 if osg == '-' else 1)
                            nv = (int(nd, 16) if nd else 0) * (-1 if nsg == '-' else 1)
                            disps.append(('frame' if ob in ('rbp', 'rsp') else 'struct', ob, ov, nv, o[0]))
    return dict(old=a, end=b, new=c[0], new_end=c[1], ratio=round(ratio, 4), second=round(second, 4), exact=exact,
                instructions={str(k): v for k, v in instructions.items()}, data=data, disps=disps, branches=branches, imms=imms)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--extra', default='')
    args = ap.parse_args()
    workers = threads()
    log(' INFO ', f'{workers} Threads (aus der aktuellen Affinität)')
    t = time.time()
    log(' .... ', 'Code-Adressen aus dem 0931-Profil sammeln')
    release = json.loads((ROOT / 'reconstruction/release-0315cf38.json').read_text())
    pe_old, old_ranges = image(OLD)
    text = next(s for s in pe_old.sections if s.Name.startswith(b'.text'))
    lo, hi = text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize
    seen = set()

    def walk(v, path):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, path + [str(k)])
        elif isinstance(v, list):
            for i, x in enumerate(v):
                walk(x, path + [str(i)])
        else:
            n = v if isinstance(v, int) and not isinstance(v, bool) else (
                int(v, 16) if isinstance(v, str) and re.fullmatch(r'0x[0-9a-fA-F]+', v) else None)
            if n is not None and lo <= n < hi and 'reference' not in path and 'required_inputs' not in path:
                seen.add(n)
    walk(release, [])
    seen |= {int(x, 16) for x in args.extra.split(',') if x}
    functions = sorted({f for f in (function_of(OLD, s) for s in seen) if f})
    log('  OK  ', f'Code-Adressen sammeln ({time.time() - t:.1f} s, {len(seen)} Adressen in {len(functions)} Funktionen)')

    t = time.time()
    log(' .... ', 'Gegenstücke in 7264 suchen und ausrichten')
    _, new_ranges = image(NEW)
    jobs = []
    for a, b in functions:
        size = b - a
        cands = [(x, y) for x, y in new_ranges if abs((y - x) - size) <= max(64, size // 8) and -0x40000 < x - a < 0x40000]
        jobs.append(((a, b), cands))
    results = []
    with ProcessPoolExecutor(workers) as pool:
        for n, r in enumerate(pool.map(pair, jobs), 1):
            results.append(r)
            if n % 10 == 0 or n == len(jobs):
                log(f'{100 * n // len(jobs):3d} %', f'{n}/{len(jobs)} Funktionen ausgerichtet')
    log('  OK  ', f'Ausrichten ({time.time() - t:.1f} s, {len(jobs) / max(time.time() - t, .01):.1f} Funktionen/s)')

    # Second pass: aligned CALL/JMP targets of other functions name the counterpart of a moved or duplicated
    # function directly; re-pair wherever those votes are unanimous and disagree with the first choice.
    votes = collections.defaultdict(collections.Counter)
    for r in results:
        for o, n in r.get('branches', ()):
            votes[o][n] += 1
    redo = []
    for i, r in enumerate(results):
        vote = votes.get(r['old'])
        if vote and len(vote) == 1:
            target = next(iter(vote))
            if target != r.get('new'):
                fn = function_of(NEW, target)
                if fn and fn[0] == target:
                    redo.append((i, ((r['old'], jobs[i][0][1]), [fn])))
    if redo:
        with ProcessPoolExecutor(workers) as pool:
            for (i, _), r in zip(redo, pool.map(pair, [job for _, job in redo])):
                r['by_branch_votes'] = True
                results[i] = r
        log(' INFO ', f'{len(redo)} Funktionen über Aufrufziele neu zugeordnet: ' +
            ', '.join(f'{hex(results[i]["old"])}->{hex(results[i]["new"])}' for i, _ in redo))

    out = dict(functions={}, instructions={}, data={}, disps={}, branches={}, disp_sites=collections.defaultdict(list))
    data_votes = collections.defaultdict(collections.Counter)
    disp_votes = collections.defaultdict(collections.Counter)
    for r in results:
        if r.get('new') is None:
            out['functions'][hex(r['old'])] = None
            continue
        out['functions'][hex(r['old'])] = dict(new=hex(r['new']), ratio=r['ratio'], second=r['second'], exact=r['exact'], by_branch_votes=r.get('by_branch_votes', False),
                                               size=r['end'] - r['old'], new_size=r['new_end'] - r['new'])
        for k, (v, kind) in r['instructions'].items():
            out['instructions'][hex(int(k))] = [hex(v), kind]
        for o, n in r['data']:
            data_votes[o][n] += 1
        for o, n in r['branches']:
            out['branches'].setdefault(hex(o), collections.Counter())[hex(n)] += 1
        for cls, base, ov, nv, site in r['disps']:
            disp_votes[f'{cls}:{hex(ov) if ov >= 0 else "-" + hex(-ov)}'][hex(nv) if nv >= 0 else '-' + hex(-nv)] += 1
    out['data'] = {hex(o): {hex(n): c for n, c in v.most_common()} for o, v in sorted(data_votes.items())}
    out['disps'] = {k: dict(v.most_common()) for k, v in sorted(disp_votes.items())}
    frames = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for r in results:
        for cls, base, ov, nv, site in r.get('disps', ()):
            if cls == 'frame':
                frames[hex(r['old'])][f'{base}:{ov:#x}' if ov >= 0 else f'{base}:-{-ov:#x}'][hex(nv) if nv >= 0 else '-' + hex(-nv)] += 1
    out['immediates'] = {hex(r['old']): r.get('imms', []) for r in results if r.get('imms')}
    out['frames'] = {fn: {k: dict(v.most_common()) for k, v in sorted(d.items())} for fn, d in frames.items()}
    out['branches'] = {k: dict(v) for k, v in out['branches'].items()}
    out.pop('disp_sites')
    (HERE / 'map-7264.json').write_text(json.dumps(out, indent=1))
    weak = sum(1 for f in out['functions'].values() if f and (f['ratio'] < .8 or f['second'] > .5))
    log(' INFO ', f'Zusammenfassung: {len(out["functions"])} Funktionen, davon exakt {sum(1 for f in out["functions"].values() if f and f["exact"])}, '
                  f'unsicher {weak}; {len(out["instructions"])} Befehle, {len(out["data"])} Datenziele, {len(out["disps"])} Offsets')


if __name__ == '__main__':
    main()
