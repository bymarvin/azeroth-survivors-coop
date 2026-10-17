"""'Next run' acceptance (0.0.16): four real launchers (RoomClient, local directory) play two runs in a row.

  verify_next_run.py [--defeat] [--relay]

Run 1 (Elwynn, diagnostic autostart): boss victory and the host's "New hero" (--defeat: every player falls at
once, team defeat). The host presses Next run: a new private room with the same host connection, the invitation
over the pinned game channels, every guest confirms, the games close, the guests rejoin by themselves and the
host's launcher starts run 2 as soon as all are back. Run 2 restarts every game: the host picks Duskwood (just
unlocked by run 1; --defeat: Elwynn again) through the native menu, the guests follow, combat and world
replication, boss victory. Checked: invitations and confirmations, the same party and slots in a new room, map,
replication, and the native saves: run 2 started with run 1's unlock and its victory unlocked the next map.
Disposable candidate saves only (COOP_CANDIDATE_HOME); every log stays in analysis/room-player-N[-run2].jsonl.
--relay: every guest connects through a local relay/server.py (throwaway certificate, as coop-lab/server/
test_us_lobby.py): the host publishes an unreachable address, the guests' direct attempt fails. After New hero the
host waits RELAY_HOLD s (more than one relay re-check of the room) before Next run: in 0.0.16 the directory's
"menu" phase made the relay close every tunnel there (user report, guest 2 over the EU relay).
"""
import argparse
import json
import multiprocessing as mp
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ('', '-run2')
RELAY_PORT = 47771      # The routes' relay port (relay/routing.Routes default).
RELAY_HOLD = 20         # > AUTH_SECONDS (15) of relay/server.py: a closed tunnel would show here.
UNREACHABLE = '192.0.2.1'  # TEST-NET-1: the guests' direct attempt fails, the relay takes over.


def member(url, number, pipe, defeat, relay=False):
    import group_online
    import native_probe
    from native_probe import HURT, MAP_SELECT, q
    from room_client import RoomClient
    from verify_network_boss import NetworkBossVerification
    from verify_network_coop import NetworkCoopVerification
    from verify_room_launch import native_menu_taps
    from verify_save_staging import native_unlocks
    base = group_online.GroupOnlineBridge  # Kept: the name is replaced by RunVerification below.

    class RunVerification(NetworkBossVerification):
        """Boss run of verify_network_boss inside the launcher's game; the launcher, not the test, ends run 1."""
        run_index = 0

        def poll_network(self):
            base.poll_network(self)  # Not the boss test's own stop after New hero.

        def before_batch(self, client, context):
            if defeat and self.run_index == 1 and client.number in self.ready:
                phase = self.native_states[client.number][0]
                if (phase == 1 and not getattr(self, 'defeat_hit', False) and self.ready == set(self.members)
                        and self.enemy_snapshot and self.host_clock >= 20):
                    game = client.server + 0x10
                    if NetworkCoopVerification.lethal_guard_buffs(self, client, game):
                        return base.before_batch(self, client, context)
                    self.defeat_hit = True
                    self.record(event='network_lethal_hit', player=client.number)
                    def completed():
                        if client.memory(game + native_probe.game_field(0x8BF), 1)[0] == 1:
                            self.defeat_hit = False  # A guard buff ignored it: again next batch.
                    client.call_before(context, HURT, game, next(iter(self.enemy_snapshot)), damage=10 ** 7,
                                       after=completed)
                    return True
                if phase == 2:
                    return super().before_batch(client, context)  # Level-up: talent choice as in the boss test.
                if phase != 1:
                    return base.before_batch(self, client, context)  # No boss kill.
            return super().before_batch(client, context)

    group_online.GroupOnlineBridge = RunVerification  # play() builds its game on this class.
    original_run = native_probe.run
    runs = []

    def bounded_run(seconds, players, bridge, **kwargs):
        runs.append(bridge)
        bridge.run_index = len(runs)
        bridge.command = 9 if bridge.run_index == 1 and not defeat else 0  # Run 1 New hero, run 2 ends after victory.
        folder = native_probe._candidate_home / f'player-{number}'
        callback = bridge
        if bridge.run_index == 2 and not defeat:
            # The host chooses the map unlocked by run 1; guests pick their class and follow the host.
            class_id = runs[0].result_class
            if class_id not in (1, 8, 3, 4):
                raise ValueError(f'Native menu taps cover Warrior, Mage, Hunter and Rogue, not class {class_id}')
            taps = native_menu_taps(class_id, number != 1, 'duskwood' if number == 1 else 'elwynn')
            os.environ['WOW_ROGUE_TAPS'] = taps
            bridge.autostart, bridge.host_map = False, None
            native_probe.ensure_windowed(folder)
            from verify_native_input import NativeMenuDiagnostic
            callback = NativeMenuDiagnostic(bridge, taps)
        original_call = type(bridge).__call__

        def observed(self, client, rva, context):
            # The party menu consumes MAP_SELECT: take the unlock baseline of this run before it.
            if rva == MAP_SELECT and not getattr(self, 'baseline_recorded', False) and client.number not in self.ready:
                self.baseline_recorded = True
                # Same record as verify_network_boss: verify_save_staging requires hash and before_gameplay.
                self.record(event='native_progression_baseline', player=client.number, run=self.run_index,
                            sha256=native_probe.ACTIVE_HASH, before_gameplay=True,
                            classes=native_unlocks(client, q(context, 136)))
            return original_call(self, client, rva, context)
        type(bridge).__call__ = observed
        original_record = bridge.record

        def record(**event):
            if event.get('event') == 'network_boss_result':
                bridge.result_class = event['class_id']
            original_record(**event)
        bridge.record = record
        # One run() per run (run 1 until its session ends, run 2 after Next run), within the candidate bound.
        return original_run(360, players, callback, **kwargs)

    native_probe.run = bounded_run
    client = RoomClient(url, diagnostic_autostart=True, isolated_profile=True)
    routes = []  # Route evidence of every run: direct_connected / relay_connected (network diagnostics).
    network_event = client.network_event

    def observed_network(**event):
        if event.get('event') in ('direct_connected', 'relay_connected', 'direct_failed'):
            routes.append(event['event'])
        network_event(**event)
    client.network_event = observed_network
    if number != 1:
        # The directory gives slots in join order; the disposable saves are per slot (player-N): join 2, 3, 4.
        join_next_run = client.join_next_run

        def ordered_join():
            time.sleep(4 * (number - 2))
            join_next_run()
        client.join_next_run = ordered_join
    rooms = []
    try:
        if number == 1:
            with socket.create_server(('127.0.0.1', 0)) as available:
                port = available.getsockname()[1]
            client.create('Next run test', 'Host', False, UNREACHABLE if relay else '127.0.0.1', port, 'eu')
            pipe.send(client.room['id'])
            assert pipe.recv() == 'start'
            client.action('start')
        else:
            client.join(f'Guest {number}', pipe.recv(), region='eu')
            pipe.send('joined')
        rooms.append(client.room['id'])
        threading.Thread(target=client.heartbeat, daemon=True).start()
        deadline = time.monotonic() + 900
        if number == 1:
            while not client.state()['next_run']['available'] and not client.error and time.monotonic() < deadline:
                time.sleep(.2)
            assert client.error is None and client.state()['next_run']['available'], f'Run 1 did not end: {client.error}'
            held = 0
            if relay:
                # Every guest must still be connected after the relay re-checked the room (New hero is over).
                started = time.monotonic()
                time.sleep(RELAY_HOLD)
                held = time.monotonic() - started
                bridge = client.bridge
                assert bridge is not None and not bridge.departed, f'Guests left during the hold: {getattr(bridge, "departed", None)}'
                assert all(not c.closed and c.error is None for c in bridge.channels.values()), 'A relay channel ended'
            client.log_suffix = RUNS[1]
            client.action('next_run')
        else:
            while not client.next_invite and not client.error and time.monotonic() < deadline:
                time.sleep(.2)
            assert client.next_invite and client.error is None, f'No next-run invitation: {client.error}'
            client.log_suffix = RUNS[1]
        while len(runs) < 2 and not client.error and time.monotonic() < deadline:
            time.sleep(.2)
        assert len(runs) == 2, f'Run 2 did not start: {client.error} / {client.status}'
        rooms.append(client.room['id'])
        while client.worker and client.worker.is_alive() and time.monotonic() < deadline:
            time.sleep(.2)
        assert client.worker and not client.worker.is_alive(), 'Run 2 timed out'
        assert client.error is None, client.error
        pipe.send(json.dumps(dict(passed=True, rooms=rooms, slot=runs[1].number, routes=routes,
                                  held=held if number == 1 else 0)))
    except Exception as error:
        pipe.send(json.dumps(dict(passed=False, error=str(error))))
        raise
    finally:
        client.stopped.set()
        client.cancel.set()


def rows(number, run):
    return [json.loads(line) for line in (ROOT / f'analysis/room-player-{number}{RUNS[run]}.jsonl').read_text().splitlines()]


def verify(defeat, results, relay=False):
    """Both runs from the launchers' logs and the native saves (four players)."""
    first, second = ([rows(n, run) for n in range(1, 5)] for run in (0, 1))
    assert len({r['rooms'][0] for r in results}) == 1 and len({r['rooms'][1] for r in results}) == 1, results
    assert results[0]['rooms'][0] != results[0]['rooms'][1], 'Run 2 reused the first room'
    assert [r['slot'] for r in results] == [1, 2, 3, 4], results  # Same party, same slots.
    host = first[0]
    offered = next(e for e in host if e['event'] == 'next_run_offered')
    assert next(e for e in host if e['event'] == 'next_run_closing')['confirmed'] == [2, 3, 4], host
    assert results[0]['rooms'][1] == offered['room']
    for number, events in enumerate(first[1:], 2):
        assert [e['room'] for e in events if e['event'] == 'next_run_invited'] == [offered['room']], number
    if defeat:
        assert all(any(e['event'] == 'team_defeat_shown' for e in events) for events in first), 'No team defeat'
        assert not any(e['event'] == 'network_boss_result' for events in first for e in events), 'Run 1 was won'
    else:
        assert all(any(e['event'] == 'network_boss_result' for e in events) for events in first), 'Run 1 not won'
        assert all(any(e['event'] == 'victory_action_applied' and e['command'] == 9 for e in events) for events in first)
    zone = 'elwynn' if defeat else 'duskwood'
    for number, events in enumerate(second, 1):
        loaded = [e['zone'] for e in events if e['event'] == 'party_map_loaded']
        assert loaded and set(loaded) == {zone}, (number, loaded)
        assert any(e['event'] == 'network_boss_result' for e in events), (number, 'Run 2 not won')
    summaries = [next(e for e in reversed(events) if e['event'] == 'summary') for events in second]
    assert summaries[0]['world_captured'] > 0 and summaries[0]['world_delivered'] == summaries[0]['world_captured']
    assert sum(s['world_delivered'] for s in summaries[1:]) == summaries[0]['world_delivered'], summaries
    import native_probe
    for number, events in enumerate(second, 1):
        baseline = next(e for e in events if e['event'] == 'native_progression_baseline')
        result = next(e for e in events if e['event'] == 'network_boss_result')
        cls = str(result['class_id'])
        start = 1 if defeat else 2  # Run 1's victory unlocked Duskwood (map 2) before run 2.
        assert baseline['classes'].get(cls, 1) == start, (number, baseline)
        folder = native_probe._candidate_home / f'player-{number}'
        (folder / 'progression-before.json').write_text(json.dumps(baseline))
        output = folder / 'progression-reload.txt'
        with output.open('w') as stream:
            subprocess.run([sys.executable, str(ROOT / 'reconstruction/verify_save_staging.py'), '--automatic',
                            '--character', 'Hero', '--reference', str(folder / 'characters.txt'),
                            '--before-observation', str(folder / 'progression-before.json'),
                            '--require-unlock', cls, str(start + 1)],
                           stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=420)
        records = [json.loads(line) for line in output.read_text().splitlines() if line.startswith('{')]
        complete = [r for r in records if r.get('event') == 'disposable_staging_complete']
        # As verify_network_boss.check_unlock_records: the next map is open in the reloaded save, newly in run 2.
        assert complete and all(complete[-1].get(k) for k in ('native_unlock_reload_verified', 'expected_unlock_verified',
                                                               'newly_awarded_progression_verified')), (number, complete)
        print(f'[  OK  ] unlock_verified player {number} (class {cls}: map {start + 1} open in the reloaded save)', flush=True)
    if relay:
        for number, result in enumerate(results[1:], 2):
            # Both runs through the relay, never directly.
            assert result['routes'].count('relay_connected') >= 2 and 'direct_connected' not in result['routes'], \
                (number, result['routes'])
        assert results[0]['held'] >= RELAY_HOLD, results[0]
        for number, events in enumerate(first, 1):
            # Run 1 ends through Next run only: no channel failed while the relay re-checked the room.
            lost = [(e['event'], e.get('reason')) for e in events if e['event'] == 'transport_failure' or
                    e['event'] in ('host_departed', 'guest_departed') and e.get('reason') != 'left']
            assert not lost, (number, lost)
    return dict(next_run='passed', variant='team_defeat' if defeat else 'victory', run2_zone=zone, relay=relay,
                rooms=results[0]['rooms'], world_deliveries=summaries[0]['world_delivered'])


def start_relay(directory_port):
    """The unchanged relay/server.py on the routes' port, with a throwaway certificate trusted only here."""
    import tempfile
    sys.path.insert(0, str(ROOT / 'coop-lab/server'))
    from test_us_lobby import make_certificate
    work = Path(tempfile.mkdtemp(prefix='next-run-relay-'))
    make_certificate(work)
    os.environ['SSL_CERT_FILE'] = str(work / 'ca.pem')  # Inherited by the four launchers (relay client: default context).
    with socket.socket() as probe:
        if probe.connect_ex(('127.0.0.1', RELAY_PORT)) == 0:
            raise SystemExit(f'Port {RELAY_PORT} is in use; the relay test needs it')
    relay = subprocess.Popen([sys.executable, '-E', '-s', str(ROOT / 'relay/server.py'), '--bind', '127.0.0.1',
                              '--port', str(RELAY_PORT), '--directory', f'http://127.0.0.1:{directory_port}',
                              '--cert', str(work / 'fullchain.pem'), '--key', str(work / 'key.pem')],
                             cwd=ROOT / 'relay', stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1', RELAY_PORT), 1):
                return relay
        except OSError:
            time.sleep(.1)
    relay.terminate()
    raise SystemExit('The local relay did not start')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--defeat', action='store_true', help='run 1 ends in a team defeat instead of a victory')
    parser.add_argument('--relay', action='store_true', help='guests connect through a local relay/server.py')
    args = parser.parse_args()
    import native_probe
    from lobby_server import server
    # Local test lobby only: its crash/completion reports stay with the disposable candidate run.
    app = server(('127.0.0.1', 0), collected_logs=(native_probe._candidate_home or ROOT / 'coop-lab') / 'collected-logs')
    threading.Thread(target=app.serve_forever, daemon=True).start()
    processes, pipes = [], []
    relay = None
    try:
        url = f'http://127.0.0.1:{app.server_port}'
        if args.relay:
            relay = start_relay(app.server_port)
            url = f'http://localhost:{app.server_port}'  # The routes take the relay host from the directory URL.
        for number in range(1, 5):
            parent, child = mp.Pipe()
            process = mp.Process(target=member, args=(url, number, child, args.defeat, args.relay))
            process.start()
            processes.append(process)
            pipes.append(parent)
            if number == 1:
                assert parent.poll(60), 'Host did not create the room'
                room_id = parent.recv()
            else:
                parent.send(room_id)  # In order: guests keep slots 2, 3, 4 in both rooms.
                assert parent.poll(60) and parent.recv() == 'joined'
        pipes[0].send('start')
        results = []
        for pipe in pipes:
            assert pipe.poll(960), 'Launcher timed out'
            results.append(json.loads(pipe.recv()))
        assert all(r['passed'] for r in results), results
        for process in processes:
            process.join(15)
            assert process.exitcode == 0
        print(json.dumps(verify(args.defeat, results, args.relay)), flush=True)
    finally:
        if relay is not None:
            relay.terminate()
            relay.wait(10)
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(10)
        app.shutdown()
        app.server_close()


if __name__ == '__main__':
    main()
