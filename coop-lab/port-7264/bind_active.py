"""Bind the passed 0.95.0 (7264d50b) native acceptance into analysis/active-hooks.json (boot-log format).

Writes {adapter_profile: release profile + identity + native_acceptance, menu_contract, progression_call_contract}
only when every one of the 21 required cases (18 + druid_forms, surrender, fall_revival_unlock) passed with the current source identity, keeps a backup of the
previous file, then loads the game through the normal (non-isolated) launch path as a check.
"""
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / '.tools/python'))
sys.path.insert(0, str(ROOT / 'reconstruction'))
REQUIRED = {'concurrent_menus', 'class_gear_selection', 'host_map', 'four_player_movement', 'four_player_combat',
            'bosses', 'shared_xp', 'shared_gold', 'independent_talents', 'independent_loot', 'pause_resume',
            'revival', 'saves', 'guest_departure', 'host_shutdown', 'victory_keep_fighting', 'victory_new_hero',
            'map_progression', 'druid_forms', 'surrender', 'fall_revival_unlock'}


def log(tag, text):
    print(f'[{tag:^6}] {text}', flush=True)


def main():
    import build_hooks
    exe = ROOT / 'AzerothSurvivors.exe'
    t = time.time()
    log(' .... ', 'Abnahme prüfen')
    release = json.loads((ROOT / 'reconstruction/release-7264d50b.json').read_text())
    acceptance = json.loads((ROOT / 'coop-lab/port-7264/out/acceptance-7264.json').read_text())
    identity = build_hooks.probe_identity(exe)
    missing = sorted(c for c in REQUIRED if acceptance.get('cases', {}).get(c) != 'passed')
    failed = [r['name'] for r in acceptance.get('runs', []) if r.get('passed') is not True]
    if acceptance.get('identity') != identity or missing or failed or acceptance.get('failures'):
        log('FAILED', f'Abnahme prüfen: identity gleich={acceptance.get("identity") == identity}, fehlend={missing}, '
                      f'fehlgeschlagen={failed}')
        return 1
    log('  OK  ', f'Abnahme prüfen ({time.time() - t:.1f} s, {len(REQUIRED)} Fälle, {len(acceptance["runs"])} Läufe)')

    t = time.time()
    log(' .... ', 'active-hooks.json schreiben')
    target = ROOT / 'analysis/active-hooks.json'
    if target.exists():
        backup = ROOT / 'coop-lab/port-7264/backup-active-hooks.before-7264.json'
        if not backup.exists():
            shutil.copyfile(target, backup)
            log(' INFO ', f'Sicherung {backup.relative_to(ROOT)}')
    profile = dict(release['adapter_profile'], identity=identity,
                   native_acceptance=dict(identity=identity, runs=acceptance['runs'],
                                          cases=acceptance['cases'], failures=[]))
    target.write_text(json.dumps(dict(release, adapter_profile=profile), indent=1) + '\n', encoding='utf-8')
    log('  OK  ', f'active-hooks.json schreiben ({time.time() - t:.1f} s)')

    t = time.time()
    log(' .... ', 'normaler Startpfad (resolve_reviewed_profile, nicht isoliert)')
    report = build_hooks.resolve_reviewed_profile(exe)
    if report.get('status') != 'verified_adapter' or not report.get('automatic_activation_allowed'):
        log('FAILED', f'normaler Startpfad: Status {report.get("status")}')
        return 1
    log('  OK  ', f'normaler Startpfad ({time.time() - t:.1f} s, Status {report["status"]})')
    return 0


if __name__ == '__main__':
    sys.exit(main())
