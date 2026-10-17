"""Bounded native-call smoke check; no keyboard input or forced game-state edits."""
import json
import struct
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'reconstruction'))
from native_probe import ROOT, WRITE, PAUSE, RESUME, q, run
from visibility_bridge import Bridge


class Probe(Bridge):
    def __init__(self, output):
        super().__init__(output, shared_world=True)
        self.checks = {}

    def __call__(self, client, rva, context):
        if rva == WRITE and client.number in self.server_states:
            pointer, count = struct.unpack('<QQ', client.memory(client.server + 0x908, 16))
            if count == 1 and q(context, 128) == q(client.memory(pointer + 0x90, 8)) + 0x10:
                stage = self.checks.get(client.number, 0)
                if stage < 3:
                    phase = client.memory(client.server + 0x8CF, 1)[0]
                    self.record(event='native_control_probe', player=client.number, stage=stage, phase=phase)
                    self.checks[client.number] = stage + 1
                    if stage < 2:
                        client.call_before(context, (PAUSE, RESUME)[stage], client.server + 0x10)
                        return
        super().__call__(client, rva, context)


if __name__ == '__main__':
    with (ROOT / 'analysis/native-controls-check.jsonl').open('w', encoding='utf-8') as output:
        probe = Probe(output)
        try:
            run(35, 2, probe)
        finally:
            probe.record(event='summary', **probe.counts, checks=probe.checks)
            print(json.dumps(probe.checks))
