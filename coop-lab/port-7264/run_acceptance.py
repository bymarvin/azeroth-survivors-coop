"""Native 4-client acceptance for the 0.95.0 (7264d50b) candidate, suite by suite (disposable saves only).

Same suites, arguments and environment as reconstruction/build_hooks.test_adapter_candidate.
Every run gets a fresh coop-lab/compatibility-tests/<suite>-* directory (disposable saves).
Writes coop-lab/port-7264/out/acceptance-7264.json; the official binding run is the full
suite list (all 20 cases incl. druid_forms, surrender), after which analysis/active-hooks.json can be written.

  run_acceptance.py [--suites movement,pause-revival,...]   (default: all, in the official order)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.tools/python'))
sys.path.insert(0, str(ROOT / 'reconstruction'))
os.chdir(ROOT)
import build_hooks  # noqa: E402
from native_test_process import run_verifier  # noqa: E402
from coop_transport import create_pairing  # noqa: E402

SUITES = (
    ('pause-revival', 'verify_group_online.py', ['--verify-coop'],
     ('pause_resume', 'revival', 'shared_xp', 'four_player_combat', 'independent_talents')),
    ('boss-rewards', 'verify_network_boss.py', [], ('bosses', 'independent_loot', 'map_progression', 'saves')),
    ('room-menus', 'verify_room_launch.py', ['--players', '4', '--automatic-menus',
     '--expect-classes', '1', '8', '3', '4', '--expect-map', 'duskwood',
     '--guest-request-map', 'elwynn', '--observe-gear'], ('concurrent_menus', 'host_map')),
    ('room-gear', 'verify_room_launch.py', ['--players', '4', '--automatic-gear'], ('class_gear_selection',)),
    ('menu-departure', 'verify_room_departure.py', ['--players', '4', '--automatic'], ('guest_departure', 'host_shutdown')),
    ('movement', 'verify_group_online.py', ['--require-movement'], ('four_player_movement',)),
    ('economy', 'verify_group_online.py', ['--verify-economy'], ('shared_gold',)),
    ('victory-continue', 'verify_network_boss.py', ['--victory-command', '8'], ('victory_keep_fighting',)),
    ('victory-new-hero', 'verify_network_boss.py', ['--victory-command', '9'], ('victory_new_hero',)),
    # 0.95.0: druid Cat/Dire Bear forms (display model) of host and guest reach every client.
    ('druid-forms', 'verify_druid_forms.py', [], ('druid_forms',)),
    # 0.95.0: menu "give up" - a guest leaves alone, the host ends the run for everyone.
    ('surrender', 'verify_surrender.py', [], ('surrender',)),
    # Diagnostic only (not part of the 20 required cases): guest walks away, spawns/markers observed.
    ('split', 'verify_split_spawns.py', [], ()),
)


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--suites', default=','.join(s[0] for s in SUITES if s[0] != 'split'))
    ap.add_argument('--boss-home', help='earlier passed boss-rewards directory (for room-menus/room-gear)')
    args = ap.parse_args()
    wanted = args.suites.split(',')
    binary = ROOT / 'AzerothSurvivors.exe'
    release = json.loads((ROOT / 'reconstruction/release-7264d50b.json').read_text())
    release['adapter_profile']['identity'] = build_hooks.probe_identity(binary)
    candidate = ROOT / 'coop-lab/port-7264/out/candidate-7264d50b.json'
    candidate.write_text(json.dumps(release))
    build_hooks.load_isolated_adapter_profile(binary, candidate)
    identity = release['adapter_profile']['identity']
    log('  OK  ', f'Kandidat geladen und an {len(identity["sources"])} Quelldateien gebunden')
    out = ROOT / ('coop-lab/port-7264/out/acceptance-split.json' if 'split' in wanted
                  else 'coop-lab/port-7264/out/acceptance-7264.json')
    if 'split' in wanted and len(wanted) > 1:
        log('FAILED', 'split ist eine Diagnose und läuft nur allein')
        return 2
    result = json.loads(out.read_text()) if out.exists() else dict(runs=[], cases={}, failures=[])
    result['identity'] = identity
    parent = ROOT / 'coop-lab/compatibility-tests'
    boss_home = Path(args.boss_home) if args.boss_home else None
    for name, script, arguments, cases in SUITES:
        if name not in wanted:
            continue
        if build_hooks.probe_identity(binary) != identity:
            log('FAILED', 'Spiel- oder Quelldateien während der Abnahme geändert')
            return 2
        home = Path(tempfile.mkdtemp(prefix=name + '-', dir=parent))
        create_pairing(home / 'pairing')
        snapshot = home / 'candidate-profile.json'
        shutil.copyfile(candidate, snapshot)
        env = dict(os.environ, COOP_EXECUTABLE=str(binary.resolve()), COOP_BUILD='updated',
                   COOP_CANDIDATE_PROFILE=str(snapshot), COOP_CANDIDATE_HOME=str(home), COOP_TEST_WINDOW_CORNERS='1')
        # verify_boss_replication / verify_party_combat need world_captured/world_delivered and boss_hud_delivered
        # records, which OnlineBridge only writes with COOP_TRACE_PACKETS=1 (stricter evidence, no behaviour change).
        env['COOP_TRACE_PACKETS'] = '1'
        if name == 'movement':
            env['WOW_ROGUE_KEY'] = 'w@3'
            env['COOP_VERIFY_NATIVE_MOVEMENT'] = '1'
        extra = []
        if name == 'room-menus':
            if boss_home is None:
                log('FAILED', f'{name}: braucht einen bestandenen boss-rewards-Ordner (--boss-home)')
                continue
            extra = ['--profile-save', f'1:{boss_home / "player-1/characters.txt"}']
        elif name == 'room-gear':
            if boss_home is None:
                log('FAILED', f'{name}: braucht einen bestandenen boss-rewards-Ordner (--boss-home)')
                continue
            fixture = build_hooks.earned_gear_fixture(boss_home)
            extra = [v for n in range(1, 5) for v in ('--profile-save', f'{n}:{fixture}')]
        log(' .... ', f'{name}: {script} {" ".join(arguments + extra)} (Ordner {home.name})')
        t = time.time()
        timed_out = False
        with (home / 'verification.log').open('w', encoding='utf-8') as output:
            try:
                tested = run_verifier([str(ROOT / 'reconstruction' / script), *arguments, *extra], cwd=ROOT, env=env,
                                      stdout=output, timeout=1200 if name == 'boss-rewards' else 420)
                passed = tested.returncode == 0
            except subprocess.TimeoutExpired:
                passed, timed_out = False, True
            except ValueError as error:
                output.write(str(error) + '\n')
                passed = False
        patterns = (('room-player-*.jsonl',) if script.startswith('verify_room_') else
                    ('group-online-*.jsonl', 'network-boss-*.txt' if script == 'verify_network_boss.py' else 'group-network-*.txt'))
        for pattern in patterns:
            for source in (ROOT / 'analysis').glob(pattern):
                shutil.copyfile(source, home / source.name)
        result['runs'] = [r for r in result['runs'] if r['name'] != name] + [
            dict(name=name, passed=passed, evidence=str(home.relative_to(ROOT)), seconds=round(time.time() - t))]
        if passed:
            result['cases'].update(dict.fromkeys(cases, 'passed'))
            if name == 'boss-rewards':
                boss_home = home
            log('  OK  ', f'{name} ({time.time() - t:.0f} s)')
        else:
            tail = (home / 'verification.log').read_text(encoding='utf-8', errors='replace').splitlines()[-8:]
            log('FAILED' if not timed_out else ' KILL ', f'{name} ({time.time() - t:.0f} s){" Zeitlimit" if timed_out else ""}')
            for line in tail:
                log(' INFO ', line[:200])
        result['failures'] = [f'{r["name"]} failed; see {r["evidence"]}' for r in result['runs'] if not r['passed']]
        out.write_text(json.dumps(result, indent=1))
        if timed_out:
            break
    passed = sum(r['passed'] for r in result['runs'])
    log('INFO', f'Zusammenfassung: {passed}/{len(result["runs"])} Suiten bestanden, Fälle {sorted(result["cases"])}')
    return 0 if not result['failures'] else 1


if __name__ == '__main__':
    sys.exit(main())
