import ctypes as C
import os
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from native_probe import game_field
from updated_layout import UPDATED, field, rva
from visibility_bridge import pursuit_code, validate_live_game, dispatch_guard_code


class LiveGuardTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Exercises generated Windows x64 guards')
    def test_dispatch_guards_execute_all_cases_and_reject_out_of_range(self):
        alloc, free = C.windll.kernel32.VirtualAlloc, C.windll.kernel32.VirtualFree
        alloc.argtypes, alloc.restype = [C.c_void_p,C.c_size_t,C.c_uint32,C.c_uint32],C.c_void_p
        free.argtypes, free.restype = [C.c_void_p,C.c_size_t,C.c_uint32],C.c_int
        base = alloc(None,0x5000,0x3000,0x40)
        self.assertTrue(base)
        try:
            table = 0x4000
            for modern,kind,count in [(v,k,n) for v in (False,True) for k,n in [('cast_tag',5),('loot_tag',7)]]:
                expected = (bytes.fromhex('89d24c8d15')+struct.pack('<i',table-(0x3000-16+9))+
                            bytes.fromhex('496314924c01d2') if kind=='cast_tag' else bytes.fromhex('89f849634485004c01e8ffe0'))
                contract = dict(kind=kind,maximum=count-1,expected=expected.hex(),rva=0x3000-16,
                                table_rva=table,continuation_rva=0x3000)
                if modern:
                    expected = (bytes.fromhex('89d24c8d0d')+struct.pack('<i',table-(0x3000-16+9))+
                                bytes.fromhex('496314914c01ca') if kind=='cast_tag' else bytes.fromhex('89f8496304844c01e0ffe0'))
                    contract['expected'] = expected.hex()
                with patch('visibility_bridge.release_0843', return_value=modern):
                    code = dispatch_guard_code(base,contract)
                self.assertEqual(code[-2:],b'\x0f\x0b')
                # Test-only failure return replaces fatal UD2 so the test can
                # assert the exact taken path without crashing its own process.
                code = code[:-2]+bytes.fromhex('b8ffffffffc3')
                C.memmove(base+0x1000,code,len(code))
                C.memmove(base+0x3000,bytes.fromhex('ffe2'),2)
                for tag in range(count):
                    target=0x2000+tag*16
                    C.memmove(base+target,b'\xb8'+struct.pack('<I',tag+100)+b'\xc3',6)
                    C.memmove(base+table+tag*4,struct.pack('<i',target-table),4)
                wrapper=bytearray(bytes.fromhex('4154574883ec28' if modern else '4155574883ec28')) # SaveR13/RDI, align call.
                wrapper.extend(bytes.fromhex('89ca') if kind=='cast_tag' else bytes.fromhex('89cf4989d4' if modern else '89cf4989d5'))
                wrapper.extend(b'\xe8'+struct.pack('<i',0x1000-(len(wrapper)+5)))
                wrapper.extend(bytes.fromhex('4883c4285f415cc3' if modern else '4883c4285f415dc3'))
                C.memmove(base,bytes(wrapper),len(wrapper))
                call=C.CFUNCTYPE(C.c_int,C.c_uint32,C.c_void_p)(base)
                for tag in range(count):
                    self.assertEqual(call(tag,base+table),100+tag)
                for tag in (count,0xffffffff):
                    self.assertEqual(call(tag,base+table),-1)
                if kind=='loot_tag':
                    self.assertEqual(call(0,base+table+4),-1)
        finally:
            self.assertTrue(free(base,0,0x8000))

    def test_interior_guard_rejects_wrong_owner_and_unaligned_enemy(self):
        memory = bytearray(0x3000)
        context = bytearray(1232)
        game, frame, enemy = 0x100, 0x1000, 0x2000
        struct.pack_into('<QQ', memory, game + game_field(0x568), enemy, 1)
        struct.pack_into('<Q', memory, frame + (field('game_update_frame', 0x3e0) if UPDATED else 0x3d0), game)
        for offset, value in ((160, frame), (192, game), (128, enemy)):
            struct.pack_into('<Q', context, offset, value)
        client = SimpleNamespace(server=game-16, memory=lambda a, n: bytes(memory[a:a+n]))
        self.assertEqual(validate_live_game(client, context, 192, enemy_offset=128), game)
        struct.pack_into('<Q', context, 128, enemy+1)
        with self.assertRaisesRegex(ValueError, 'Enemy ownership'):
            validate_live_game(client, context, 192, enemy_offset=128)
        struct.pack_into('<Q', context, 192, game+8)
        with self.assertRaisesRegex(ValueError, 'Game ownership'):
            validate_live_game(client, context, 192)

    @unittest.skipUnless(os.name == 'nt', 'Exercises generated Windows x64 guard')
    def test_actual_pursuit_guard_accepts_owned_cursor_and_rejects_bad_inputs(self):
        alloc, free = C.windll.kernel32.VirtualAlloc, C.windll.kernel32.VirtualFree
        alloc.argtypes, alloc.restype = [C.c_void_p, C.c_size_t, C.c_uint32, C.c_uint32], C.c_void_p
        free.argtypes, free.restype = [C.c_void_p, C.c_size_t, C.c_uint32], C.c_int
        base = alloc(None, 0x4000, 0x3000, 0x40)
        self.assertTrue(base)
        try:
            game, enemies = C.create_string_buffer(0x1000), C.create_string_buffer(0x148)
            guest, status, xy = C.create_string_buffer(16), C.create_string_buffer(16), C.create_string_buffer(8)
            game_address, enemy_address = C.addressof(game), C.addressof(enemies)
            struct.pack_into('<QQ', game, game_field(0x568), enemy_address, 1)
            code = pursuit_code(base+0x3000-rva(0x53E371B), C.addressof(guest),
                                game=game_address, guard=C.addressof(status))
            C.memmove(base+0x1000, code, len(code))
            C.memmove(base+0x3000, b'\xc3', 1)
            # Preserve the nonvolatile registers used by the native continuation.
            wrapper = bytearray(bytes.fromhex('55564881ec280500004889e5'
                '440f118d80040000440f11ad90040000440f11bda0040000'
                '0f11bdb0040000440f11b5c00400000f57ff450f57f64889d6'))
            wrapper.extend(b'\x48\x89\x8d' + struct.pack('<I', field('game_update_frame', 0x3e0) if UPDATED else 0x3d0))
            wrapper.extend(bytes.fromhex('f2450f1038'))
            wrapper.extend(b'\xe8' + struct.pack('<i', 0x1000-(len(wrapper)+5)))
            wrapper.extend(bytes.fromhex('440f108d80040000440f10ad90040000440f10bda0040000'
                                         '0f10bdb0040000440f10b5c0040000'
                                         '4881c4280500005e5dc3'))
            C.memmove(base, bytes(wrapper), len(wrapper))
            call = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_void_p)(base)
            for wrong_game, cursor_delta, position, count, expected in (
                    (False, 0, (1., 2.), 1, (0, 1)),
                    (True, 0, (1., 2.), 1, (1, 0)),
                    (False, 1, (1., 2.), 1, (1, 0)),
                    (False, 0, (float('nan'), 2.), 1, (1, 0)),
                    (False, 0, (1., float('inf')), 1, (1, 0)),
                    (False, 0, (1., 2.), 3001, (1, 0))):
                C.memset(C.addressof(status), 0, 16)
                struct.pack_into('<Q', game, game_field(0x568)+8, count)
                struct.pack_into('<ff', xy, 0, *position)
                call(game_address+int(wrong_game), enemy_address+cursor_delta, C.addressof(xy))
                self.assertEqual(struct.unpack('<QQ', status), expected)
            C.memset(C.addressof(status), 0, 16)
            struct.pack_into('<Q', game, game_field(0x568)+8, 1)
            struct.pack_into('<f', game, game_field(0x85C), 1.)
            struct.pack_into('<ff', xy, 0, 1., 2.)
            call(game_address, enemy_address, C.addressof(xy))
            self.assertEqual(struct.unpack('<QQ', status), (1, 0))  # Native time register disagrees.
        finally:
            self.assertTrue(free(base, 0, 0x8000))


if __name__ == '__main__':
    unittest.main()
