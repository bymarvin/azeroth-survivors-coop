import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from party_menu import PartyMenu, host_zone
from native_probe import MAP_SELECT, UI_COMMAND


# Native Enter tag of the loaded release (10 up to 0.93.1, 11 in 0.95.0); ENTER + 1 is a non-Enter command.
ENTER = (getattr(__import__('native_probe'), 'MENU_CONTRACT', None) or {}).get('enter_tag', 10)


class MenuTests(unittest.TestCase):
    def test_guest_can_configure_before_host_map_but_cannot_enter(self):
        class Parent:
            def __init__(self):
                self.extra_hooks, self.menu_players, self.forwarded = (), set(), []
                self.number, self.polls = 2, 0
            def record(self, **event): self.event = event
            def __call__(self, client, rva, context): self.forwarded.append(rva)
            def poll_network(self):
                self.polls += 1
                if self.polls == 2:
                    self.host_map = 'duskwood'
        class Menu(PartyMenu, Parent): pass
        menu = Menu()
        memory = {0x100: struct.pack('<I', ENTER), 0x200: struct.pack('<Q', 0x345),
                  0x546f050: bytes.fromhex('41565657534883ec28')}
        client = SimpleNamespace(number=2, base=0, memory=lambda address, size: memory[address])
        context = bytearray(1248)
        struct.pack_into('<Q', context, 136, 0x100)
        struct.pack_into('<Q', context, 152, 0x200)
        menu(client, MAP_SELECT, context)  # Startup previews need no host map.
        original = bytes(context)
        menu(client, UI_COMMAND, context)
        self.assertEqual(menu.event['event'], 'party_enter_resumed')
        self.assertEqual(menu.polls, 2)
        self.assertEqual(bytes(context), original)  # Original command ownership/context retained.
        self.assertEqual(menu.forwarded, [UI_COMMAND])
        memory[0x100] = struct.pack('<I', ENTER + 1)
        menu(client, UI_COMMAND, context)  # Other menu commands stay native.
        self.assertEqual(menu.forwarded, [UI_COMMAND, UI_COMMAND])
        memory[0x100] = struct.pack('<I', ENTER)
        menu.host_map = 'duskwood'
        menu(client, UI_COMMAND, context)
        self.assertEqual(menu.forwarded, [UI_COMMAND] * 3)

    def test_waiting_enter_cancellation_and_timeout_never_forward(self):
        class Parent:
            def __init__(self):
                self.extra_hooks, self.menu_players, self.forwarded = (), set(), []
                self.number = 2
            def record(self, **event): pass
            def __call__(self, *args): self.forwarded.append(args)
        class Menu(PartyMenu, Parent): pass
        client = SimpleNamespace(number=2, memory=lambda address, size: struct.pack('<I', ENTER))
        context = bytearray(1248)
        for flag in ('stop_requested', 'restart_requested', 'peer_finished', 'host_closing'):
            for before_poll in (True, False):
                menu = Menu()
                def poll():
                    menu.host_map = 'elwynn'
                    setattr(menu, flag, True)
                menu.poll_network = poll
                setattr(menu, flag, before_poll)
                with self.assertRaises(ConnectionError):
                    menu(client, UI_COMMAND, context)
                self.assertEqual(menu.forwarded, [])
        menu = Menu()
        menu.poll_network = lambda: None
        with patch('party_menu.time.monotonic', side_effect=[0, 301]):
            with self.assertRaises(TimeoutError):
                menu(client, UI_COMMAND, context)
        self.assertEqual(menu.forwarded, [])

    def test_new_hero_cannot_enter_a_world_with_the_finished_session(self):
        class Parent:
            def __init__(self):
                self.extra_hooks = ()
                self.menu_players = {2}
            def record(self, **event): self.event = event
        class Menu(PartyMenu, Parent): pass
        menu = Menu()
        memory = {0x100: struct.pack('<I', ENTER), 0x200: struct.pack('<Q', 0x345),
                  0x546f050: bytes.fromhex('41565657534883ec28')}
        client = SimpleNamespace(number=2, base=0, memory=lambda address, size: memory[address])
        context = bytearray(1248)
        struct.pack_into('<Q', context, 136, 0x100)
        struct.pack_into('<Q', context, 152, 0x200)
        menu(client, UI_COMMAND, context)
        self.assertEqual(struct.unpack_from('<Q', context, 248)[0], 0x546f050)
        self.assertEqual(struct.unpack_from('<Q', context, 128)[0], 0x100)
        self.assertEqual(struct.unpack_from('<Q', context, 152)[0], 0x200)
        self.assertEqual(menu.event['event'], 'party_restart_requires_lobby')

    def test_host_unlock_clamp_and_early_guest_enforcement(self):
        memory = {0x120: struct.pack('<QQ', 0x300, 8), 0x138: b'\x08',
                  0x220: struct.pack('<QQ', 0x400, 1), 0x300: b'duskwood',
                  0x400: struct.pack('<B7xQ', 8, 1)}
        client = SimpleNamespace(memory=lambda address, size: memory[address])
        self.assertEqual(host_zone(client, 0x200, 0x100), 'elwynn')
        memory[0x400] = struct.pack('<B7xQ', 8, 2)
        self.assertEqual(host_zone(client, 0x200, 0x100), 'duskwood')
        class Parent:
            def __init__(self): self.extra_hooks = ()
            def record(self, **event): pass
        class Menu(PartyMenu, Parent): pass
        menu = Menu()
        menu.host_map = 'duskwood'
        patches = []
        client.number, client.base = 2, 0
        memory[MAP_SELECT + 0x39] = bytes.fromhex('488b4b20488b532848c1e2044531c00f1f8400')
        memory[0x53be2ba] = bytes.fromhex('4981fcffffff0048898d801f0000488995081f00000f8475080000')
        memory[0x53bead1] = b'\x74\x2d'
        memory[0x500] = bytes(8)
        client.patch = lambda address, data: patches.append((address, data))
        context = bytearray(1248)
        struct.pack_into('<Q', context, 152, 0x500)
        menu(client, MAP_SELECT, context)
        menu(client, MAP_SELECT, context)
        self.assertEqual(len(patches), 3)
        self.assertEqual(patches[0][1][:5], b'\xb8\x01\x00\x00\x00')

    def test_defeated_party_cannot_enter_a_second_world_from_the_menu(self):
        # Crash 15.10.2026 (v11): team defeat -> menu -> Enter built a new native
        # world whose server cipher no longer matched this session.
        from updated_layout import reviewed_rva, reviewed_bytes

        class Parent:
            def __init__(self):
                self.extra_hooks, self.menu_players, self.forwarded, self.events = (), set(), [], []
                self.ready, self.number, self.host_map = {1, 2}, 1, 'duskwood'
            def record(self, **event): self.events.append(event)
            def __call__(self, client, rva, context): self.forwarded.append(rva)
        class Menu(PartyMenu, Parent): pass
        for number in (1, 2):
            with self.subTest(player=number):
                menu = Menu()
                menu.number, menu.host_map = number, 'duskwood'  # The finished run's confirmed map.
                destructor = menu.menu_contract['command_destructor'] if menu.menu_contract else None
                drop = destructor['entry'] if destructor else reviewed_rva(0x546f050)
                expected = (bytes.fromhex(destructor['expected']) if destructor else
                            reviewed_bytes(0x546f050, bytes.fromhex('41565657534883ec28')))
                client = SimpleNamespace(number=number, base=0, memory=lambda address, size:
                                         struct.pack('<I', ENTER) if address == 0x100 else expected)
                context = bytearray(1248)
                struct.pack_into('<Q', context, 136, 0x100)
                menu(client, UI_COMMAND, context)
                self.assertEqual(menu.forwarded, [])  # Enter never reaches native world construction.
                self.assertEqual(struct.unpack_from('<Q', context, 248)[0], drop)
                self.assertEqual(menu.events, [dict(event='party_restart_requires_lobby', player=number)])
                menu.ready.discard(number)  # Before the first world, Enter stays native.
                context = bytearray(1248)
                struct.pack_into('<Q', context, 136, 0x100)
                menu(client, UI_COMMAND, context)
                self.assertEqual(menu.forwarded, [UI_COMMAND])


if __name__ == '__main__':
    unittest.main()
