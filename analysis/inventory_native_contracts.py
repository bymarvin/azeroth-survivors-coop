"""Baseline source contract inventory; evidence for review, never activation."""
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = ('native_probe.py', 'visibility_bridge.py', 'native_guest_combat.py',
         'boss_rewards.py', 'party_menu.py', 'group_online.py')


def inventory():
    rows, sources = [], {}
    for name in FILES:
        path = ROOT / 'reconstruction' / name
        source = path.read_text(encoding='utf-8')
        sources[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        tree = ast.parse(source)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = ast.unparse(node.func)
            kind = ('native_memory' if target in ('client.memory', 'client.put', 'client.patch',
                                                 'self.memory', 'self.put', 'self.patch') else
                    'game_field' if target == 'game_field' else
                    'typed_field' if target == 'field' else
                    'typed_code' if target in ('code_fields', 'game_code', 'game_frame_code') else
                    'reviewed_address' if target in ('relocated', 'rva', 'reviewed_rva', 'reviewed_bytes',
                                                      'expected_bytes', 'reviewed_branch', 'branch') else
                    'binary_layout' if target in ('struct.pack', 'struct.pack_into', 'struct.unpack',
                                                  'struct.unpack_from', 'q') else
                    'generated_bytes' if target in ('bytes.fromhex', 'emit') else None)
            if kind is None:
                continue
            owner, cursor = [], node
            while cursor in parents:
                cursor = parents[cursor]
                if isinstance(cursor, (ast.FunctionDef, ast.ClassDef)):
                    owner.append(cursor.name)
            rows.append(dict(file=name, line=node.lineno, owner='.'.join(reversed(owner)),
                             kind=kind, expression=ast.get_source_segment(source, node),
                             status='classification_required'))
    return dict(reference_sha256='20d4ce5fb1232dac64bc00a4d8c9f2bcae43fb8373ea3fa95350ab8c4f20d618',
                automatic_activation_allowed=False, source_hashes=sources, occurrences=rows,
                scope='Production native access sites, binary layouts and generated-code emitters; '
                      'semantic ownership and dynamically assembled byte strings still require contract review')


def runtime_inputs():
    """Exercise real patch builders against the reviewed PE, without a process.

    This inventories consumed translation inputs, not their compatibility.
    Runtime-only object accesses remain in the source/typed-contract inventory.
    """
    import io
    import os
    import struct
    from unittest.mock import patch
    sys.path.insert(0, str(ROOT / 'reconstruction'))
    from build_hooks import UPDATED_HASH, probe_identity, compatibility_report, resolve_reviewed_profile as public_resolver
    reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
    data = reference.read_bytes()
    if hashlib.sha256(data).hexdigest() != UPDATED_HASH:
        raise ValueError('Patch input reference changed')
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    profile = compatibility_report(reference, manifest)
    if profile['sha256'] != UPDATED_HASH or not profile['automatic_activation_allowed']:
        raise ValueError('Offline input capture requires the exact verified reference')
    def reviewed_only(binary, **kwargs):
        if (Path(binary).resolve() != reference.resolve() or
                hashlib.sha256(reference.read_bytes()).hexdigest() != UPDATED_HASH):
            raise ValueError('Offline input capture cannot resolve another executable')
        return profile
    # The parent resolver owns the workspace lock. This subprocess only reads
    # the reviewed baseline and executes builders against the fake PE client.
    # It must neither recurse discovery nor launch a native process.
    with patch.dict(os.environ, COOP_BUILD='updated', COOP_EXECUTABLE=str(reference), COOP_PLAYERS='4'), \
            patch('build_hooks.resolve_reviewed_profile', side_effect=reviewed_only), \
            patch('build_hooks.write_report', side_effect=AssertionError('Offline inventory cannot publish profiles')), \
            patch('subprocess.Popen', side_effect=AssertionError('Offline inventory cannot launch a process')):
        os.environ.pop('COOP_CANDIDATE_PROFILE', None)
        os.environ.pop('COOP_CANDIDATE_HOME', None)
        import native_probe as native
        native.resolve_reviewed_profile = public_resolver
        import updated_layout as layout
        import visibility_bridge as visibility
        import native_guest_combat as combat
        from boss_rewards import reward_code
        if native.ACTIVE_HASH != UPDATED_HASH or not layout.UPDATED:
            raise ValueError('Patch input capture must run in a reviewed-build subprocess')
        import pefile
        image = pefile.PE(data=data, fast_load=True)
        addresses, fields, preconditions, writes = set(), set(), {}, []
        # Include runtime-only literal consumers as well as executed builders.
        # Dynamic expressions remain visible for explicit review below.
        import boss_rewards
        import party_menu
        modules = {module.__name__ + '.py': module for module in
                   (native, visibility, combat, boss_rewards, party_menu)}
        dynamic = []
        for name in FILES:
            source = (ROOT / 'reconstruction' / name).read_text(encoding='utf-8')
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                    continue
                target = node.func.id
                if target not in ('field', 'game_field', 'relocated', 'reviewed_rva'):
                    continue
                values = []
                for arg in node.args:
                    try:
                        values.append(ast.literal_eval(arg))
                    except ValueError:
                        value = getattr(modules.get(name), arg.id, None) if isinstance(arg, ast.Name) else None
                        values.append(value)
                if None in values:
                    enclosing = [v for v in ast.walk(tree) if isinstance(v, ast.FunctionDef)
                                 and v.lineno <= node.lineno <= v.end_lineno]
                    function = min(enclosing, key=lambda v: v.end_lineno - v.lineno).name if enclosing else None
                    dynamic.append(dict(file=name, line=node.lineno, function=function,
                                        expression=ast.get_source_segment(source, node)))
                elif target == 'field':
                    fields.add(tuple(values))
                elif target == 'game_field':
                    fields.add(('game', values[0] + 0x10))
                else:
                    addresses.add(layout._reviewed(values[0]) if target == 'relocated' else values[0])
        # Native hook globals are already resolved before the recorder installs;
        # injected calls also consume entries that are not breakpoint sites.
        addresses.update(native._hook_reference.values())
        # This reviewed translation catalog also covers branch destinations
        # selected only at runtime (both AOE outcomes and pause UI paths).
        addresses.update(layout.ADDRESSES.values())
        baseline = json.loads((ROOT / 'analysis/native-contract-baseline.json').read_text())
        if baseline['reference_sha256'] != UPDATED_HASH:
            raise ValueError('Native field inventory belongs to a different baseline')
        for domain in ('game', 'server', 'batch_frame'):
            for name, value in baseline['structures'][domain].items():
                if isinstance(value, list) and not name.endswith('_size'):
                    fields.add((domain, int(value[0], 16)))
        class Recorder:
            profile = {'runtime_equivalent': True}
            def rva(self, address):
                addresses.add(address)
                return address
            def field(self, domain, offset):
                fields.add((domain, offset))
                return offset
            def expected_bytes(self, address, expected):
                addresses.add(address)
                if image.get_data(address, len(expected)) != expected:
                    raise ValueError(f'Reviewed patch precondition disagrees at {address:x}')
                preconditions[address, expected.hex()] = True
                return expected
            def relative_branch(self, source, target, **kwargs):
                return layout.branch_bytes(self.rva(source), self.rva(target), **kwargs)
        class Client:
            def __init__(self, number):
                self.number, self.base, self.server, self.handle = number, 0x140000000, 0, None
                self.allocated = self.base + image.OPTIONAL_HEADER.SizeOfImage + 0x10000
                self.overlay, self.owned = {}, {}
                self.breakpoints, self.disable_hooks, self.extra_hooks = {}, set(), ()
            def allocate(self, handle, address, size, *_):
                result = self.allocated
                self.allocated += ((size + 0xfff) // 0x1000) * 0x1000
                self.owned[result] = bytearray(size)
                return result
            def memory(self, address, size):
                if self.base <= address < self.base + image.OPTIONAL_HEADER.SizeOfImage:
                    body = bytearray(image.get_data(address - self.base, size))
                    for start, value in self.overlay.items():
                        low, high = max(address, start), min(address + size, start + len(value))
                        if low < high:
                            body[low-address:high-address] = value[low-start:high-start]
                    return bytes(body)
                for start, value in self.owned.items():
                    if start <= address and address + size <= start + len(value):
                        return bytes(value[address-start:address-start+size])
                raise ValueError('Input capture attempted an unmodelled native heap read')
            def patch(self, address, value):
                writes.append(dict(player=self.number, reference=address-self.base, size=len(value)))
                self.overlay[address] = value
            def put(self, address, value):
                for start, buffer in self.owned.items():
                    if start <= address and address + len(value) <= start + len(buffer):
                        buffer[address-start:address-start+len(value)] = value
                        return
                raise ValueError('Input capture attempted a write outside owned scratch memory')
            def executable_buffer(self, value):
                address = self.allocate(None, None, len(value))
                self.owned[address][:] = value
                return address
        with patch.object(layout, '_runtime', Recorder()):
            class RoomBridge(party_menu.PartyMenu, combat.NativeCombatBridge):
                pass
            for number in (1, 2):
                client = Client(number)
                with patch.object(visibility, 'allocate', client.allocate), patch.object(combat, 'allocate', client.allocate):
                    bridge = RoomBridge(io.StringIO())
                    client.extra_hooks = bridge.extra_hooks
                    native.Native.install(client)
                    context = bytearray(1232)
                    struct.pack_into('<Q', context, 128, 0x10000)
                    bridge(client, native.TICK, context)
            list(visibility.guest_damage_patches())
            reward_code(0x140000000)
            native.defeat_ui_code(0x140000000)
        return dict(reference_sha256=UPDATED_HASH, automatic_activation_allowed=False,
            identity=probe_identity(reference), dynamic_source_inputs=dynamic,
            addresses=sorted(addresses), fields=sorted(fields), patches=sorted(preconditions),
            installer_writes=writes,
            scope='Actual reviewed host/guest hook and patch builders; not a complete runtime-field or behavior proof')


if __name__ == '__main__':
    runtime = '--runtime-inputs' in sys.argv
    report = runtime_inputs() if runtime else inventory()
    name = 'native-runtime-inputs.json' if runtime else 'native-contract-occurrences.json'
    (ROOT / 'analysis' / name).write_text(json.dumps(report, indent=2) + '\n')
    print(f"{len(report['addresses'])} runtime addresses captured" if runtime else
          f"{len(report['occurrences'])} source contract occurrences inventoried")
