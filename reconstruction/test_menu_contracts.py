from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis'))
import menu_contracts
import native_probe
from party_menu import PartyMenu


class MenuContractTests(unittest.TestCase):
    def contract(self):
        return dict(variant='borrowed_map_predicate', menu_contract_verified=True,
                    sha256=native_probe.ACTIVE_HASH, ui_command=native_probe.UI_COMMAND,
                    map_select=native_probe.MAP_SELECT, host_map_return=0x800,
                    map_clamp=dict(site=0x400, expected=('90' * 19), allocation_path=0x500),
                    login=dict(branch=0x600, expected='7510', continuation=0x612,
                               requested_map_register='r15', requested_length_stack=0x30),
                    command_destructor=dict(entry=0x700, expected='41565657534883ec28'))

    def menu(self, contract):
        class Parent:
            def __init__(self): self.extra_hooks, self.menu_players = (), set()
            def record(self, **event): self.event = event
        class Menu(PartyMenu, Parent): pass
        with patch.object(native_probe, 'MENU_CONTRACT', contract), patch.object(
                native_probe, 'MENU_LOGIN', contract['login']['branch']):
            return Menu()

    def test_candidate_menu_rejects_wrong_build_hooks_and_unverified_contract(self):
        for key, value in [('sha256', 'wrong'), ('menu_contract_verified', False),
                           ('ui_command', -1), ('variant', 'unknown')]:
            contract = self.contract()
            contract[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'does not match'):
                self.menu(contract)

    def test_guest_map_patch_does_not_permanently_bypass_login(self):
        contract = self.contract()
        memory = {0x400: b'\x90' * 19, 0x600: b'\x75\x10', 0x900: bytes(8)}
        patches = []
        client = SimpleNamespace(base=0, number=2, memory=lambda address, size: memory[address],
                                 patch=lambda address, data: patches.append((address, data)))
        context = bytearray(1248)
        struct.pack_into('<Q', context, 152, 0x900)
        menu = self.menu(contract)
        menu.host_map = 'duskwood'
        menu(client, native_probe.MAP_SELECT, context)
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0][1][:5], b'\xb8\x01\0\0\0')
        patches.clear()
        client.number = 1
        menu(client, native_probe.MAP_SELECT, context)
        self.assertEqual(patches, [])

    def test_unknown_map_and_inconsistent_branch_target_fail_closed(self):
        contract = self.contract()
        contract['login']['continuation'] += 1
        with self.assertRaisesRegex(ValueError, 'inconsistent'):
            self.menu(contract)
        menu = self.menu(self.contract())
        menu.host_map = 'unknown'
        client = SimpleNamespace(base=0, number=2, memory=lambda address, size: b'\x90' * size)
        with self.assertRaisesRegex(ValueError, 'Guest cannot load'):
            menu(client, native_probe.MAP_SELECT, bytearray(1248))

    def test_guest_login_checks_actual_borrowed_map_before_continuing(self):
        menu = self.menu(self.contract())
        menu.host_map = 'duskwood'
        context = bytearray(1248)
        struct.pack_into('<Q', context, 160, 0x1000)
        struct.pack_into('<Q', context, 240, 0x2000)
        memory = {0x1030: struct.pack('<Q', 8), 0x2000: b'duskwood'}
        client = SimpleNamespace(number=2, base=0x4000, memory=lambda a, n: memory[a][:n])
        original = bytes(context)
        menu(client, 0x600, context)
        self.assertEqual(native_probe.q(context, 248), 0x4612)
        self.assertEqual(context[:248], original[:248])
        self.assertEqual(context[256:], original[256:])
        self.assertEqual(memory[0x2000], b'duskwood')
        for length, name, error in [(6, b'elwynn', 'different login map'), (17, b'duskwood', 'map length')]:
            memory.update({0x1030: struct.pack('<Q', length), 0x2000: name})
            context[:] = original
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                menu(client, 0x600, context)
            self.assertEqual(bytes(context), original)

    def test_host_defensive_login_emulates_original_jne_without_reading_map(self):
        menu = self.menu(self.contract())
        def no_read(*args): raise AssertionError('Host must use native predicate')
        client = SimpleNamespace(number=1, base=0x4000, memory=no_read)
        for flags, target in [(0x40, 0x4602), (0, 0x4612)]:
            context = bytearray(1248)
            struct.pack_into('<I', context, 68, flags)
            menu(client, 0x600, context)
            self.assertEqual(native_probe.q(context, 248), target)
            self.assertEqual(struct.unpack_from('<I', context, 68)[0], flags)

    def test_login_breakpoint_installed_only_on_guest_with_exact_instruction(self):
        contract = self.contract()
        for number, original, fails in [(1, b'\x74\x10', False), (2, b'\x75\x10', False),
                                        (2, b'\x74\x10', True)]:
            client = object.__new__(native_probe.Native)
            client.number, client.base, client.extra_hooks = number, 0, (0x600,)
            client.breakpoints = {}
            client.memory = lambda a, n: original if a == 0x600 else b'\x41\x57' if a == native_probe.SERIALIZE else b'\x55'
            patches = []
            client.patch = lambda a, data: patches.append(a)
            with patch.object(native_probe, 'MENU_CONTRACT', contract), patch.object(native_probe, 'MENU_LOGIN', 0x600):
                if fails:
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected instruction'):
                        client.install()
                else:
                    client.install()
            self.assertEqual(0x600 in patches, number == 2 and not fails)

    def test_unique_candidate_helper_rejects_ambiguity(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            menu_contracts.unique([1, 2], 'Menu')
        with self.assertRaisesRegex(ValueError, 'missing'):
            menu_contracts.unique([], 'Menu')

    def test_predicate_template_rejects_changed_unlock_rules(self):
        import pefile
        # Inspect the current executable without launching or changing it.
        image = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
        matches = menu_contracts.login_predicates(image)
        if not matches:
            self.skipTest('Current executable does not contain this optional predicate variant')
        entry = menu_contracts.unique(matches, 'Predicate')['entry']
        data = bytearray(image.__data__)
        before = image.get_data(entry, len(menu_contracts.PREDICATE))
        offset = before.index(bytes.fromhex('ba09000000'))
        data[image.get_offset_from_rva(entry + offset) + 1] = 10
        changed = pefile.PE(data=bytes(data), fast_load=True)
        self.assertEqual(menu_contracts.login_predicates(changed), [])

    def test_login_extractor_requires_predicate_result_dead_at_continuation(self):
        import pefile
        image = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
        predicates = menu_contracts.login_predicates(image)
        if not predicates:
            self.skipTest('Current executable does not contain this optional predicate variant')
        predicate = menu_contracts.unique(predicates, 'Predicate')
        callers = menu_contracts.login_callers(image, predicate)
        if not callers:
            self.skipTest('Current release uses the separately tested map-predicate fallback')
        login = menu_contracts.unique(callers, 'Login')
        data = bytearray(image.__data__)
        offset = image.get_offset_from_rva(login['continuation'])
        self.assertEqual(data[offset:offset + 2], b'\x48\xb8')
        data[offset + 1] = 0xb9  # MOV RCX leaves the predicate's RAX live.
        changed = pefile.PE(data=bytes(data), fast_load=True)
        self.assertEqual(menu_contracts.login_callers(changed, predicate), [])

    def test_login_fallback_uses_the_proved_record_stride(self):
        import json
        import pefile
        from build_hooks import UPDATED_HASH
        old = pefile.PE(str(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'), fast_load=True)
        image = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
        predicates = menu_contracts.login_predicates(image)
        if not predicates:
            self.skipTest('Current executable does not contain this optional predicate variant')
        manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
        reference = manifest['hooks']['MAP_SELECT']['reference_rva']
        from map_build_functions import structural_relocations
        structural = structural_relocations(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
                                            ROOT / 'AzerothSurvivors.exe', [reference])
        candidate = int(menu_contracts.unique(structural[hex(reference)]['candidates'], 'Map')['rva'], 16)
        layout = menu_contracts.map_selection_contract(old, reference, image, candidate)['candidate_layout']
        predicate = menu_contracts.unique(predicates, 'Predicate')
        self.assertEqual(len(menu_contracts.login_callers(image, predicate, map_layout=layout)), 1)
        self.assertEqual(menu_contracts.login_callers(image, predicate,
                         map_layout=dict(layout, stride=layout['stride'] + 8)), [])


if __name__ == '__main__':
    unittest.main()
