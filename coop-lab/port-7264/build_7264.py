"""Build out/release-7264d50b.json (game 7264d50b) from the verified 0.93.1 release 0315cf38 (boot-log format).

Every 0931 value is translated by an explicit rule with evidence from map-7264.json:
  code    instruction map (aligned, identical shape) or a mapped function start
  data    unanimous RIP-target votes of aligned instructions
  frame   per-function frame-slot votes (dominant >= 90 %)
  struct  struct displacement votes (dominant >= 90 %), Game layout and others
Manual decisions with evidence live in decisions_7264.py (MANUAL); they win over the automatic rules.
Anything without proof stays None and is listed in out/UNRESOLVED-7264.md; the release is not written then.
"""
import copy
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / '.tools/python')]
NEW_SHA = '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30'
OLD_SHA = '0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66'
# 0931 function starts (map-0931.json: 47e4 0x5474190/0x549e650/0x53e5b70 -> these)
FRAME_OF = {'game_update_frame': 0x5476220, 'enemy_frame': 0x54A06F0, 'batch_frame': 0x53E55A0}


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


class Translator:
    def __init__(self, m, manual):
        self.m, self.manual, self.unresolved, self.evidence = m, manual, [], {}
        import pefile
        self.new = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
        self.old = pefile.PE(r'D:\Azeroth Survivors Together Port 0931\AzerothSurvivors.exe', fast_load=True)

    def miss(self, what, why):
        self.unresolved.append(f'{what}: {why}')
        return None

    def code(self, addr, what):
        key = f'code:{addr:#x}'
        if key in self.manual:
            self.evidence[what] = 'manuell: ' + self.manual[key][1]
            return self.manual[key][0]
        row = self.m['instructions'].get(hex(addr))
        if row and row[1] == 'same':
            self.evidence[what] = f'Befehl ausgerichtet {addr:#x}->{row[0]}'
            return int(row[0], 16)
        fn = self.m['functions'].get(hex(addr))
        if fn:
            self.evidence[what] = f'Funktionsanfang {addr:#x}->{fn["new"]} (ratio {fn["ratio"]})'
            return int(fn['new'], 16)
        votes = self.m['branches'].get(hex(addr))
        if votes and len(votes) == 1:
            new, n = next(iter(votes.items()))
            self.evidence[what] = f'Sprung-/Aufrufziel {addr:#x}->{new} ({n} ausgerichtete Aufrufe)'
            return int(new, 16)
        text = next(s for s in self.old.sections if s.Name.startswith(b'.text'))
        if not text.VirtualAddress <= addr < text.VirtualAddress + text.Misc_VirtualSize:
            return self.data(addr, what)
        return self.miss(what, f'Code {addr:#x} ohne gleichgeformten ausgerichteten Befehl' +
                         (f' (nur Form {row})' if row else ''))

    def data(self, addr, what):
        key = f'data:{addr:#x}'
        if key in self.manual:
            self.evidence[what] = 'manuell: ' + self.manual[key][1]
            return self.manual[key][0]
        votes = self.m['data'].get(hex(addr))
        if votes and len(votes) == 1:
            new, n = next(iter(votes.items()))
            self.evidence[what] = f'RIP-Ziel {addr:#x}->{new} ({n} Stimmen)'
            return int(new, 16)
        return self.miss(what, f'Daten {addr:#x} Stimmen {votes}')

    def _dominant(self, votes, what, label):
        if not votes:
            return self.miss(what, f'{label}: keine Stimmen')
        total = sum(votes.values())
        best, n = max(votes.items(), key=lambda kv: kv[1])
        if n / total < .9:
            return self.miss(what, f'{label}: uneinig {votes}')
        self.evidence[what] = f'{label} -> {best} ({n}/{total})'
        return int(best, 16) if not best.startswith('-') else -int(best[1:], 16)

    def frame(self, fn, off, what):
        key = f'frame:{fn:#x}:{off:#x}'
        if key in self.manual:
            self.evidence[what] = 'manuell: ' + self.manual[key][1]
            return self.manual[key][0]
        votes = self.m['frames'].get(hex(fn), {}).get(f'rbp:{off:#x}' if off >= 0 else f'rbp:-{-off:#x}')
        return self._dominant(votes, what, f'Frame {fn:#x} rbp{off:+#x}')

    def struct(self, off, what):
        key = f'struct:{off:#x}'
        if key in self.manual:
            self.evidence[what] = 'manuell: ' + self.manual[key][1]
            return self.manual[key][0]
        return self._dominant(self.m['disps'].get(f'struct:{off:#x}'), what, f'Struktur +{off:#x}')

    def bytes_at(self, old_addr, new_addr, length, what):
        """New bytes covering the same instructions as the old span (instruction count preserved)."""
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        old = list(md.disasm(self.old.get_data(old_addr, length + 16), old_addr))
        count, used = 0, 0
        while used < length:
            used += old[count].size
            count += 1
        if used != length:
            return self.miss(what, f'alte Spanne {old_addr:#x}+{length} endet nicht auf einer Befehlsgrenze')
        new = list(md.disasm(self.new.get_data(new_addr, length + 64), new_addr))[:count]
        for o, n in zip(old, new):
            if o.mnemonic != n.mnemonic:
                return self.miss(what, f'Befehl {o.mnemonic} {o.op_str} -> {n.mnemonic} {n.op_str}')
        span = sum(n.size for n in new)
        return self.new.get_data(new_addr, span).hex()


def main():
    t = time.time()
    m = json.loads((HERE / 'map-7264.json').read_text())
    try:
        from decisions_7264 import MANUAL
    except ImportError:
        MANUAL = {}
    tr = Translator(m, MANUAL)
    release = json.loads((ROOT / 'reconstruction/release-0315cf38.json').read_text())
    out = copy.deepcopy(release)
    p = out['adapter_profile']
    log(' .... ', 'Adressen, Felder, Patches übersetzen')
    addr_of = {}
    for row in p['addresses']:
        old = row['candidate']
        row['candidate'] = tr.code(old, f'Adresse {row["reference"]:#x} (0931 {old:#x})')
        addr_of[row['reference']] = (old, row['candidate'])
    for f in p['fields']:
        what = f'Feld {f["domain"]}+{f["reference"]:#x} (0931 {f["candidate"]:#x})'
        if f['domain'] in FRAME_OF:
            f['candidate'] = tr.frame(FRAME_OF[f['domain']], f['candidate'], what)
        elif f['domain'] in ('game', 'game_extent', 'map', 'server'):
            key = f'field:{f["domain"]}:{f["candidate"]:#x}'
            if key in MANUAL:
                tr.evidence[what] = 'manuell: ' + MANUAL[key][1]
                f['candidate'] = MANUAL[key][0]
            elif f['domain'] == 'game_extent':
                f['candidate'] = tr.miss(what, 'Game-Größe braucht einen eigenen Beleg')
            else:
                f['candidate'] = tr.struct(f['candidate'], what)
        else:
            f['candidate'] = tr.miss(what, 'unbekannte Domäne')
    for patch in p['patches']:
        what = f'Patch {patch["reference"]:#x}'
        old, new = addr_of.get(patch['reference'], (None, None))
        old_bytes = bytes.fromhex(patch['candidate_bytes'])
        if old is None or new is None:
            patch['candidate_bytes'] = tr.miss(what, 'Adresse fehlt')
            continue
        key = f'patch:{patch["reference"]:#x}'
        if key in MANUAL:
            patch['candidate_bytes'] = MANUAL[key][0]
            tr.evidence[what] = 'manuell: ' + MANUAL[key][1]
            continue
        if tr.old.get_data(old, len(old_bytes)) != old_bytes:
            patch['candidate_bytes'] = tr.miss(what, '0931-Vorbedingung passt nicht zur 0931-exe')
            continue
        patch['candidate_bytes'] = tr.bytes_at(old, new, len(old_bytes), what)
        if patch['candidate_bytes']:
            tr.evidence[what] = f'{old:#x}+{len(old_bytes)} -> {new:#x}: {patch["candidate_bytes"]}'

    log(' .... ', 'Verträge übersetzen')
    live = p['native_live_contracts']
    tick = 0x53E55A0
    live['hud']['rva'] = hex(tr.code(int(live['hud']['rva'], 16), 'hud.rva') or 0)
    for k in ('server_stack_offset', 'buffer_stack_offset', 'length_stack_offset'):
        live['hud'][k] = tr.frame(tick, live['hud'][k], f'hud.{k}')
    for k in ('receiver_field', 'vtable_field'):
        live['hud'][k] = tr.struct(live['hud'][k], f'hud.{k}')
    for k in ('call_rva', 'return_rva', 'serializer_rva'):
        live['batch'][k] = hex(tr.code(int(live['batch'][k], 16), f'batch.{k}') or 0)
    for k in ('packet_buffer_stack_offset', 'packet_length_stack_offset'):
        live['batch'][k] = tr.frame(tick, live['batch'][k], f'batch.{k}')
    for k in ('capacity', 'pointer', 'count'):
        live['batch']['ui_vector'][k] = tr.frame(tick, live['batch']['ui_vector'][k], f'batch.ui_vector.{k}')
    live['batch']['queue_field'] = tr.struct(live['batch']['queue_field'], 'batch.queue_field')
    live['connection']['server_stack_offset'] = tr.frame(tick, live['connection']['server_stack_offset'], 'connection.server_stack_offset')
    for k in ('capacity_field', 'pointer_field', 'count_field', 'receive_queue_field'):
        live['connection'][k] = tr.struct(live['connection'][k], f'connection.{k}')
    for g in p['dispatch_guards']:
        g['rva'] = tr.code(g['rva'], f'guard {g["kind"]}.rva')
        g['continuation_rva'] = tr.code(g['continuation_rva'], f'guard {g["kind"]}.continuation')
        g['table_rva'] = tr.data(g['table_rva'], f'guard {g["kind"]}.table')
        if g['rva']:
            g['expected'] = tr.new.get_data(g['rva'], len(bytes.fromhex(g['expected']))).hex()
    for name in ('damage_guard', 'effect_guard'):
        g = p[name]
        old = g['rva']
        g['rva'] = tr.code(old, f'{name}.rva')
        if g['rva']:
            new_bytes = tr.new.get_data(g['rva'], g['length']).hex()
            tr.evidence[f'{name}.expected'] = f'{g["expected"]} -> {new_bytes}'
            g['expected'] = new_bytes
    if p['damage_guard']['rva']:
        p['damage_guard']['offset'] = tr.struct(p['damage_guard']['offset'], 'damage_guard.offset')

    prog = out['progression_call_contract']
    prog['sha256'] = NEW_SHA
    for k in ('CHOOSE', 'AWARD_XP'):
        prog['entries'][k]['entry'] = tr.code(prog['entries'][k]['entry'], f'progression.{k}')
    prog['ability_contract']['definitions_rva'] = tr.data(prog['ability_contract']['definitions_rva'], 'progression.definitions')
    for name, spec in prog['fields'].items():
        spec['offset'] = tr.struct(spec['offset'], f'progression.field.{name}')

    menu = out['menu_contract']
    menu['sha256'] = NEW_SHA
    menu['ui_command'] = tr.code(menu['ui_command'], 'menu.ui_command')
    if 'menu:command_tags' in MANUAL:
        menu['command_tags'], why = MANUAL['menu:command_tags']
        tr.evidence['menu.command_tags'] = 'manuell: ' + why
    else:
        menu['command_tags'] = {k: tr.code(v, f'menu.command_tags.{k}') for k, v in menu['command_tags'].items()}
    if 'menu:enter_tag' in MANUAL:
        menu['enter_tag'], why = MANUAL['menu:enter_tag']
        tr.evidence['menu.enter_tag'] = 'manuell: ' + why
    menu['map_select'] = tr.code(menu['map_select'], 'menu.map_select')
    ms = menu['map_selection']
    ms['candidate'] = tr.code(ms['candidate'], 'menu.map_selection.candidate')
    ms['candidate_layout']['table'] = tr.data(ms['candidate_layout']['table'], 'menu.map_selection.table')
    menu['host_map_return'] = tr.code(menu['host_map_return'], 'menu.host_map_return')
    ec = menu['enter_contract']
    enter_fn = 0x53F2F20
    for k in ('call', 'return_site', 'map_select'):
        ec[k] = tr.code(ec[k], f'menu.enter.{k}')
    ec['account_server_offset'] = tr.struct(ec['account_server_offset'], 'menu.enter.account_server_offset')
    for k in ('config_stack_offset', 'result_stack_offset'):
        ec[k] = tr.frame(enter_fn, ec[k], f'menu.enter.{k}')
    lp = menu['login_predicate']
    lp['entry'] = tr.code(lp['entry'], 'menu.login_predicate.entry')
    lp['map_index'] = tr.code(lp['map_index'], 'menu.login_predicate.map_index')
    lg = menu['login']
    login_fn = lg['function']
    for k in ('function', 'predicate', 'call', 'branch', 'continuation'):
        lg[k] = tr.code(lg[k], f'menu.login.{k}')
    if lg['branch']:
        actual = tr.new.get_data(lg['branch'], 2).hex()
        if actual != lg['expected']:
            tr.miss('menu.login.expected', f'{lg["expected"]} -> {actual}')
    for k in ('account_server_offset', 'connection_vector_server_offset'):
        lg[k] = tr.struct(lg[k], f'menu.login.{k}')
    for k in ('class_stack_offset', 'requested_length_stack'):
        lg[k] = tr.frame(login_fn, lg[k], f'menu.login.{k}')
    cd = menu['command_destructor']
    cd['entry'] = tr.code(cd['entry'], 'menu.command_destructor.entry')
    cd['equivalent_aliases'] = [tr.code(a, f'menu.command_destructor.alias {a:#x}') for a in cd['equivalent_aliases']]
    if cd['entry']:
        cd['expected'] = tr.new.get_data(cd['entry'], len(bytes.fromhex(cd['expected']))).hex()
    mc = menu['map_clamp']
    old_site = mc['site']
    mc['site'] = tr.code(mc['site'], 'menu.map_clamp.site')
    mc['allocation_path'] = tr.code(mc['allocation_path'], 'menu.map_clamp.allocation_path')
    if mc['site'] and 'menu:map_clamp.expected' in MANUAL:
        value, why = MANUAL['menu:map_clamp.expected']
        if tr.new.get_data(mc['site'], len(bytes.fromhex(value))).hex() != value:
            tr.miss('menu.map_clamp.expected', 'manuelle Bytes passen nicht zur exe')
        mc['expected'] = value
        tr.evidence['menu.map_clamp.expected'] = 'manuell: ' + why
    elif mc['site'] and tr.old.get_data(old_site, len(bytes.fromhex(mc['expected']))) == tr.new.get_data(mc['site'], len(bytes.fromhex(mc['expected']))):
        tr.evidence['menu.map_clamp.expected'] = f'{len(bytes.fromhex(mc["expected"]))} Bytes bei {mc["site"]:#x} identisch zu 0931 {old_site:#x}'
    elif mc['site']:
        mc['expected'] = tr.bytes_at(old_site, mc['site'], len(bytes.fromhex(mc['expected'])), 'menu.map_clamp.expected')

    p.update(sha256=NEW_SHA, release_version='7264d50b-candidate',
             review_method='0.93.1 (0315cf38) -> 7264d50b durch Befehlsausrichtung (coop-lab/port-7264/map_7264.py, build_7264.py, '
                           'decisions_7264.py); Code-Varianten Familie 47e4; native Abnahme ausstehend')
    log('  OK  ' if not tr.unresolved else 'FAILED', f'Übersetzen ({time.time() - t:.1f} s, {len(tr.evidence)} belegt, {len(tr.unresolved)} offen)')
    lines = ['# Offene Punkte 0.93.1 -> 7264d50b\n'] + [f'- {u}' for u in tr.unresolved] + ['\n# Belege\n'] + \
        [f'- {k}: {v}' for k, v in tr.evidence.items()]
    (HERE / 'out').mkdir(exist_ok=True)
    (HERE / 'out/UNRESOLVED-7264.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    if tr.unresolved:
        for u in tr.unresolved:
            log(' INFO ', u[:200])
        return 1
    (HERE / 'out/release-7264d50b.json').write_text(json.dumps(out, indent=1) + '\n', encoding='utf-8')
    log('  OK  ', 'out/release-7264d50b.json geschrieben')
    return 0


if __name__ == '__main__':
    sys.exit(main())
