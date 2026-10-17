"""Native hook install/context emulation against a proven relocated PE image."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import native_probe
import updated_layout
from runtime_addresses import RuntimeAddresses
from test_runtime_addresses import executable, MOVES


class NativeRuntimeMappingTests(unittest.TestCase):
    def test_moved_hooks_install_and_resume_at_actual_instruction_address(self):
        before = bytearray(executable())
        before[0x400:0x410] = b'\x55\x5d\xc3' + b'\x90' * 13
        before[0x410:0x420] = b'\x41\x57\x41\x5f\xc3' + b'\x90' * 11
        before[0x420:0x428] = b'\x55\xe8' + struct.pack('<i', 0x1000 - 0x1026) + b'\x5d\xc3'
        for index, (start, length) in enumerate(((0x1000, 3), (0x1010, 5), (0x1020, 8))):
            struct.pack_into('<III', before, 0x800 + index * 12, start, start + length, 0x2008)
        after = bytearray(before)
        after[0x400:0x410], after[0x410:0x420] = after[0x410:0x420], after[0x400:0x410]
        struct.pack_into('<i', after, 0x422, 0x1010 - 0x1026)
        struct.pack_into('<Q', after, 0x600, 0x140001010)
        for index, (start, length) in enumerate(((0x1000, 5), (0x1010, 3), (0x1020, 8))):
            struct.pack_into('<III', after, 0x800 + index * 12, start, start + length, 0x2008)
        with tempfile.TemporaryDirectory() as directory:
            reference, candidate = Path(directory) / 'before.exe', Path(directory) / 'after.exe'
            reference.write_bytes(before)
            candidate.write_bytes(after)
            with patch('runtime_addresses.UPDATED_HASH', hashlib.sha256(before).hexdigest()):
                runtime = RuntimeAddresses(reference, candidate, MOVES)
            client = object.__new__(native_probe.Native)
            client.base = 0x140000000
            memory = bytearray(runtime.candidate.get_memory_mapped_image())
            client.memory = lambda address, size: bytes(memory[address - client.base:address - client.base + size])
            client.patch = lambda address, data: memory.__setitem__(slice(address - client.base, address - client.base + len(data)), data)
            client.extra_hooks, client.breakpoints, client.disable_hooks = (), {}, set()
            client.threads = {1: 1}
            context = bytearray(1232)
            struct.pack_into('<Q', context, 152, 0x10000)
            struct.pack_into('<Q', context, 240, 0x12345678)
            writes = {}
            client.put = lambda address, data: writes.__setitem__(address, data)
            client.context = lambda tid: context
            with patch.object(updated_layout, 'UPDATED', True), patch.object(updated_layout, '_runtime', runtime), \
                    patch.object(native_probe, 'BUILD', 'updated'), patch.object(native_probe, 'TICK', 0x1010), \
                    patch.object(native_probe, 'SERIALIZE', 0x1000), patch.object(native_probe, 'WRITE', 0x1020), \
                    patch.object(native_probe, '_hook_reference', {0x1010: 0x1000, 0x1000: 0x1010, 0x1020: 0x1020}, create=True), \
                    patch.object(native_probe, 'set_context', return_value=True):
                client.install()
                self.assertEqual(client.breakpoints[client.base + 0x1000], b'\x41\x57')
                client.breakpoint(1, client.base + 0x1000, lambda *_: None)
            self.assertEqual(native_probe.q(context, 248), client.base + 0x1002)
            self.assertEqual(native_probe.q(context, 152), 0xFFF8)
            self.assertEqual(writes[0xFFF8], struct.pack('<Q', 0x12345678))


if __name__ == '__main__':
    unittest.main()
