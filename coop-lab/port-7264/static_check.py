"""Static check of the 0.95.0 (7264d50b) port without starting the game (boot-log format).

Loads release-7264d50b.json through the mod's isolated candidate path
(COOP_CANDIDATE_PROFILE in a disposable coop-lab/compatibility-tests dir),
which verifies every address, field and patch precondition against the exe.
Then every generated native code fragment is built and disassembled, and
every hook / patch site's expected bytes are compared with the executable.
No process is started, nothing is written outside the disposable directory.
"""
import json
import os
import struct
import sys
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
T0 = time.time()
RESULTS = []


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def step(name, fn):
    log(' .... ', name)
    t = time.time()
    try:
        info = fn()
    except Exception as error:
        log('FAILED', f'{name}: {type(error).__name__}: {error}')
        for line in traceback.format_exc().splitlines()[-6:]:
            log(' INFO ', line)
        RESULTS.append((name, False))
        return None
    log('  OK  ', f'{name} ({time.time() - t:.2f} s{", " + info if isinstance(info, str) else ""})')
    RESULTS.append((name, True))
    return info


def main():
    home = ROOT / 'coop-lab/compatibility-tests/static-7264'
    home.mkdir(parents=True, exist_ok=True)
    sys.path.insert(0, str(ROOT / '.tools/python'))
    sys.path.insert(0, str(ROOT / 'reconstruction'))
    import build_hooks
    release = json.loads((ROOT / 'reconstruction/release-7264d50b.json').read_text())
    exe = ROOT / 'AzerothSurvivors.exe'

    def candidate():
        release['adapter_profile']['identity'] = build_hooks.probe_identity(exe)
        (home / 'candidate.json').write_text(json.dumps(release))
        return f'identity für {len(release["adapter_profile"]["identity"]["sources"])} Quelldateien'
    step('Kandidat mit aktueller Quell-Identität schreiben', candidate)

    os.environ.update(COOP_CANDIDATE_PROFILE=str(home / 'candidate.json'), COOP_CANDIDATE_HOME=str(home),
                      COOP_BUILD='updated')

    def load():
        global native_probe
        import native_probe
        return f'IMAGE_SIZE {native_probe.IMAGE_SIZE:#x}, TICK {native_probe.TICK:#x}, Variante ' + \
            __import__('updated_layout').build_variant()
    step('Profil isoliert laden (RuntimeAddresses prüft Adressen, Felder, Patch-Bytes)', load)

    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    base = 0x140000000

    def dis(name, code):
        """Disassemble generated code; absolute_jump (ff25 00000000 + 8-byte target) carries inline data."""
        lines, offset = [], 0
        while offset < len(code):
            if code[offset:offset + 6] == bytes.fromhex('ff2500000000') and offset + 14 <= len(code):
                lines.append(f'{offset:4x}: jmp qword ptr [rip] -> {int.from_bytes(code[offset + 6:offset + 14], "little"):#x}')
                offset += 14
                continue
            ins = next(md.disasm(code[offset:offset + 15], offset), None)
            if ins is None:
                raise ValueError(f'{name}: undekodierbares Byte bei +{offset:#x}')
            lines.append(f'{ins.address:4x}: {ins.mnemonic} {ins.op_str}')
            offset += ins.size
        (home / f'{name}.asm').write_text('\n'.join(lines) + '\n', encoding='utf-8')
        return f'{name} {len(code)} B'

    def hooks():
        import native_probe as np
        from updated_layout import reviewed_bytes
        pe = __import__('pefile').PE(str(exe), fast_load=True)
        bad = []
        names = ('TICK', 'SERIALIZE', 'WRITE', 'PAUSE', 'RESUME', 'START', 'AWARD_XP', 'CHOOSE', 'MOVE', 'DAMAGE', 'HURT',
                 'SPAWN', 'SPAWN_BOSS', 'FIND_SPAWN', 'SPAWN_LOOT', 'REMOVE_LOOT', 'OFFER_CHOICES', 'APPLY_EFFECT',
                 'DEFEAT_UI', 'UI_COMMAND', 'ENEMY_AOE', 'GROUND_AOE', 'ENEMY_TARGET', 'HUD_DELIVER', 'APPLY_DOT',
                 'MAP_SELECT', 'BOSS_DEATH')
        for name in names:
            rva = getattr(np, name)
            expected = b'\x41\x57' if rva == np.SERIALIZE else b'\x41\x56' if rva == np.FIND_SPAWN else b'\x55'
            special = dict(ENEMY_AOE='0f82c7f3ffff', GROUND_AOE='7215', ENEMY_TARGET='f2410f108998040000',
                           HUD_DELIVER='ff5020', BOSS_DEATH='488b8578010000')
            if name in special:
                expected = bytes.fromhex(special[name])
            try:
                actual = reviewed_bytes(np._hook_reference[rva], expected)
            except ValueError:
                actual = None  # entry hooks without a patch precondition keep their native bytes
                continue
            if pe.get_data(rva, len(actual)) != actual:
                bad.append(name)
        if bad:
            raise ValueError('Hook-Bytes passen nicht: ' + ', '.join(bad))
        return f'{len(names)} Hooks geprüft'
    step('Hook-Stellen: erwartete Bytes gegen exe', hooks)

    def fragments():
        import visibility_bridge as vb
        import boss_rewards as br
        from updated_layout import phase_gate, expected_bytes
        out = []
        out.append(dis('world_containers', vb.world_containers_code()))
        out.append(dis('downed_world', vb.downed_world_code(base, 0x1000)))
        out.append(dis('downed_hazards', vb.downed_hazards_code(base)))
        out.append(dis('pursuit', vb.pursuit_code(base, 0x2000, 1, game=0x3000, guard=0x4000)))
        out.append(dis('reward_code', br.reward_code(base)))
        for i, contract in enumerate(native_probe._profile['adapter_profile']['dispatch_guards']):
            out.append(dis(f'dispatch_guard_{contract["kind"]}', vb.dispatch_guard_code(base, contract)))
        for offset, original, replacement in vb.guest_damage_patches():
            if len(original) != len(replacement):
                raise ValueError(f'Gast-Schaden-Patch {offset:#x}: Länge {len(original)} != {len(replacement)}')
            dis(f'guest_damage_{offset:x}', replacement)
        out.append(f'Gast-Schaden {len(vb.guest_damage_patches())} Patches')
        out.append(f'Phasen-Weiche {phase_gate().hex()}')
        return '; '.join(out)
    step('Code-Fragmente erzeugen und disassemblieren', fragments)

    def patch_sites():
        import pefile
        pe = pefile.PE(str(exe), fast_load=True)
        rt = __import__('updated_layout')._runtime
        bad = [hex(old) for (old, expected), actual in rt.patch_preconditions.items()
               if pe.get_data(rt.rva(old), len(actual)) != actual]
        if bad:
            raise ValueError('Patch-Vorbedingungen weichen ab: ' + ', '.join(bad))
        return f'{len(rt.patch_preconditions)} Patch-Vorbedingungen gleich der exe'
    step('Patch-Vorbedingungen gegen exe', patch_sites)

    def patch_boundaries():
        rt = __import__('updated_layout')._runtime
        bad = []
        for (old, expected), actual in rt.patch_preconditions.items():
            consumed = sum(i.size for i in md.disasm(actual, rt.rva(old)))
            if consumed != len(actual):
                bad.append(f'{old:#x} ({consumed}/{len(actual)} Bytes)')
        if bad:
            raise ValueError('Patch-Spannen enden nicht auf Befehlsgrenzen: ' + ', '.join(bad))
        return f'{len(rt.patch_preconditions)} Spannen auf ganzen Befehlen'
    step('Patch-Spannen auf Befehlsgrenzen', patch_boundaries)

    def family_sites():
        import pefile
        import visibility_bridge as vb
        from updated_layout import family
        pe = pefile.PE(str(exe), fast_load=True)
        site, resume, skip = family('path_field')
        walls, path, game_slot, target = family('path_field_slots')
        head = vb.rbp_operand(bytes.fromhex('4883'), 7, walls) + bytes.fromhex('ff')
        expected = head + bytes.fromhex('0f84') + struct.pack('<i', skip - (site + len(head) + 6)) + vb.rbp_operand(bytes.fromhex('488b'), 2, path)
        if pe.get_data(site, len(expected)) != expected:
            raise ValueError(f'Wegfeld-Stelle {site:#x}: {pe.get_data(site, len(expected)).hex()} != {expected.hex()}')
        for (s, after, select), regs in zip(family('recycle'), ((1, 2, 3), (0, 1, 3))):
            exp = vb.recycle_distance_original(*regs[:2]) + bytes.fromhex('0f87') + struct.pack('<i', select - (s + 29))
            if pe.get_data(s, len(exp)) != exp:
                raise ValueError(f'Recycle-Stelle {s:#x} weicht ab')
            dis(f'recycle_{s:x}', vb.recycle_distance_code(0x1000, 3, *regs, base + select, base + after))
        ret = family('impact_return')
        call = next(md.disasm(pe.get_data(ret - 5, 5), ret - 5))
        if call.mnemonic != 'call':
            raise ValueError(f'Treffer-Rücksprung {ret:#x} folgt keinem call')
        return f'Wegfeld {site:#x}, Recycle {[hex(x[0]) for x in family("recycle")]}, Treffer {ret:#x} nach {call.mnemonic} {call.op_str}'
    step('Familien-Stellen (Wegfeld, Recycle, Treffer) gegen exe', family_sites)

    ok = sum(1 for _, passed in RESULTS if passed)
    log('INFO', f'Zusammenfassung: {ok}/{len(RESULTS)} bestanden ({time.time() - T0:.1f} s); Ausgaben in {home}')
    return 0 if ok == len(RESULTS) else 1


if __name__ == '__main__':
    sys.exit(main())
