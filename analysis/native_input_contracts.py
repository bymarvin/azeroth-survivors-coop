"""Isolated movement test through the game's existing native key diagnostic."""
import bisect
import hashlib
from pathlib import Path
import re
import struct

import build_hooks  # Existing bundled disassembler dependencies.
import capstone
import pefile
from map_build_functions import compare_function_layout, unwind_ranges


def native_key_code(image, name=b'KeyW'):
    """Read the tag written by native named-key deserializers, not an SDK guess."""
    ranges = unwind_ranges(image)
    starts = [a for a, _ in ranges]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    evidence = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        body = section.get_data()
        for match in re.finditer(rb'\x81[\x38\x39]' + re.escape(name) + rb'\x0f\x84', body):
            address = section.VirtualAddress + match.start()
            compare, jump = list(decoder.disasm(image.get_data(address, 12), address))
            target = jump.operands[0].imm
            index = bisect.bisect_right(starts, address) - 1
            if index < 0 or not ranges[index][0] <= target < ranges[index][1]:
                raise ValueError('Native named-key branch left its function')
            store = next(decoder.disasm(image.get_data(target, 15), target))
            if (store.mnemonic != 'mov' or len(store.operands) != 2 or
                    store.operands[0].type != capstone.x86.X86_OP_MEM or store.operands[0].size != 4 or
                    store.operands[1].type != capstone.x86.X86_OP_IMM):
                raise ValueError('Native named-key decoder no longer writes a scalar enum')
            evidence.append(dict(compare=address, store=target, value=store.operands[1].imm))
    values = {row['value'] for row in evidence}
    if len(evidence) < 2 or len(values) != 1:
        raise ValueError('Native named-key enum is missing or inconsistent')
    return values.pop(), evidence


def key_function(image):
    data = bytes(image.__data__)
    literal = b'WOW_ROGUE_KEY'
    if data.count(literal) != 1:
        raise ValueError('Native key diagnostic string is missing or ambiguous')
    target = image.get_rva_from_offset(data.index(literal))
    ranges = unwind_ranges(image)
    starts = [a for a, _ in ranges]
    matches = []
    for section in image.sections:
        if not section.Characteristics & 0x20000000:
            continue
        body = section.get_data()
        for match in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', body):
            offset = match.start()
            address = section.VirtualAddress + offset
            if address + 7 + struct.unpack_from('<i', body, offset + 3)[0] == target:
                index = bisect.bisect_right(starts, address) - 1
                if index >= 0 and ranges[index][0] <= address < ranges[index][1]:
                    matches.append(ranges[index])
    if len(matches) != 1:
        raise ValueError('Native key diagnostic function is missing or ambiguous')
    start, end = matches[0]
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    decoded = list(decoder.disasm(image.get_data(start, end - start), start))
    return start, end, decoded


def release_cleanup(decoded):
    hits = [n for n, ins in enumerate(decoded) if
            (ins.mnemonic, ins.op_str) == ('cmp', 'byte ptr [r15 + 0x39], 0')]
    if len(hits) != 1 or decoded[hits[0] + 1].mnemonic != 'jne':
        raise ValueError('Native key no-event cleanup branch changed')
    target = decoded[hits[0] + 1].operands[0].imm
    matches = [n for n, ins in enumerate(decoded) if ins.address == target]
    if len(matches) != 1:
        raise ValueError('Native key cleanup is not an instruction boundary')
    index = matches[0]
    if [(i.mnemonic, i.op_str) for i in decoded[index:index + 2]] != [
            ('mov', 'rdx, qword ptr [rbp + 0x2a8]'), ('test', 'rdx, rdx')]:
        raise ValueError('Native key owned-string cleanup changed')
    return index, dict(rva=target, expected=bytes(decoded[index].bytes).hex())


def repeat_press_entry(decoded):
    hits = [n for n, ins in enumerate(decoded) if
            (ins.mnemonic, ins.op_str) == ('cmp', 'byte ptr [r15 + 0x39], 0')]
    if len(hits) != 1:
        raise ValueError('Native press eligibility gate changed')
    gate = decoded[hits[0]:hits[0] + 10]
    shape = [(i.mnemonic, i.op_str) for i in gate]
    if ([i.mnemonic for i in gate] != ['cmp', 'jne', 'cmp', 'jne', 'shr', 'movd', 'movaps', 'subss', 'ucomiss', 'jae'] or
            shape[2] != ('cmp', 'byte ptr [rsi + 0xe8], 1') or
            shape[4:9] != [('shr', 'rdi, 0x20'), ('movd', 'xmm0, edi'),
                            ('movaps', 'xmm1, xmm6'), ('subss', 'xmm1, dword ptr [r15 + 0x28]'),
                            ('ucomiss', 'xmm1, xmm0')]):
        raise ValueError('Native press gate changes more than timing scratch registers')
    target = gate[-1].operands[0].imm
    indices = [n for n, ins in enumerate(decoded) if ins.address == target]
    if len(indices) != 1:
        raise ValueError('Native press target is not an instruction boundary')
    index = indices[0]
    producer = decoded[index:]
    if ([(i.mnemonic, i.op_str) for i in producer[:3]] != [
            ('mov', 'word ptr [r15 + 0x38], 0x101'),
            ('lea', 'rcx, [rbp + 0x120]'), ('lea', 'rdx, [rbp + 0x288]')] or
            producer[3].mnemonic != 'call' or
            [(i.mnemonic, i.op_str) for i in producer[4:9]] != [
                ('nop', ''), ('mov', 'eax, dword ptr [rbp + 0xfc]'),
                ('mov', 'rcx, qword ptr [rbp + 0xf0]'), ('mov', 'dword ptr [rcx], eax'),
                ('mov', 'rdi, qword ptr [rbp + 0xe0]')]):
        raise ValueError('Native press producer no longer reloads its window writer')
    # The gate modifies only volatile XMM0/1, flags and RDI. The native
    # constructor receives the same two frame arguments, and RDI is reloaded
    # before the producer uses it. No input/container field is supplied here.
    return index, dict(rva=target, expected=bytes(producer[0].bytes).hex())


def discover_native_key_diagnostic(reference, binary):
    after = Path(binary).read_bytes()
    exact_release = (not Path(reference).is_file() and hashlib.sha256(after).hexdigest() in
                     build_hooks.REVIEWED_RELEASES)
    # The shipped exact release is already pinned by its entire file hash.
    # Observe its diagnostic producer directly when the development-only older
    # EXE is absent; all enum, ownership, bounds and instruction checks below
    # still apply. This does not admit an unknown executable or a native call.
    before = after if exact_release else Path(reference).read_bytes()
    if not exact_release and hashlib.sha256(before).hexdigest() != build_hooks.UPDATED_HASH:
        raise ValueError('Native input test requires the reviewed reference')
    old, new = pefile.PE(data=before, fast_load=True), pefile.PE(data=after, fast_load=True)
    old_key, old_key_evidence = native_key_code(old)
    new_key, new_key_evidence = native_key_code(new)
    if old_key != new_key:
        raise ValueError('Native KeyW enum changed')
    a, b = key_function(old), key_function(new)
    proof = compare_function_layout(old.get_data(a[0], a[1] - a[0]), a[0],
                                    new.get_data(b[0], b[1] - b[0]), b[0])
    if not exact_release and (not proof['structure_equivalent'] or proof['field_changes'] or proof['instruction_changes']):
        raise ValueError('Native key diagnostic logic or layout changed')
    sites = []
    for _, _, decoded in (a, b):
        text = [(i.mnemonic, i.op_str) for i in decoded]
        pattern = [('mov', 'ebx, 0xffffffff'), ('mov', 'r14b, 1')]
        hits = [n for n in range(len(text) - 2) if text[n:n + 2] == pattern and text[n + 2][0] == 'jmp']
        if len(hits) != 1:
            raise ValueError('Unsupported-key fallback changed')
        # The diagnostic's supported tags are independently checked against
        # its reviewed body; KeyW comes from the native named-key decoders.
        if not all(('mov', f'ebx, {value}') in text for value in ('0x15', '0x16', '0x21', '0x23', '0x73')):
            raise ValueError('Native physical-key enum contract changed')
        index = hits[0]
        sites.append((index, decoded[index].address, bytes(decoded[index].bytes + decoded[index + 1].bytes)))
    if sites[0][0] != sites[1][0] or sites[0][2] != sites[1][2]:
        raise ValueError('Native key fallback no longer corresponds')
    probes = {}
    patterns = {'press': ('mov', 'word ptr [r15 + 0x38], 0x101'),
                'release': ('mov', 'byte ptr [r15 + 0x38], 0')}
    for name, pattern in patterns.items():
        old_matches = [n for n, ins in enumerate(a[2]) if (ins.mnemonic, ins.op_str) == pattern]
        new_matches = [n for n, ins in enumerate(b[2]) if (ins.mnemonic, ins.op_str) == pattern]
        if len(old_matches) != 1 or old_matches != new_matches:
            raise ValueError('Native key diagnostic event producer changed')
        ins = b[2][new_matches[0]]
        probes[name] = dict(rva=ins.address, expected=bytes(ins.bytes).hex())
    probes['entry'] = dict(rva=b[0], expected=bytes(b[2][0].bytes).hex())
    probes['parsed_key'] = dict(rva=sites[1][1], expected=(
        b'\xbb' + struct.pack('<I', new_key) + b'\x41\xb6\x00').hex())
    old_cleanup, new_cleanup = release_cleanup(a[2]), release_cleanup(b[2])
    if old_cleanup[0] != new_cleanup[0] or old_cleanup[1]['expected'] != new_cleanup[1]['expected']:
        raise ValueError('Native key cleanup correspondence changed')
    old_press, new_press = repeat_press_entry(a[2]), repeat_press_entry(b[2])
    if old_press[0] != new_press[0] or old_press[1]['expected'] != new_press[1]['expected']:
        raise ValueError('Native press producer correspondence changed')
    tap_sites = []
    release_sites = []
    for decoded in (a[2], b[2]):
        release = [n for n, ins in enumerate(decoded)
                   if (ins.mnemonic, ins.op_str) == ('mov', 'qword ptr [r15], 0')]
        if len(release) != 1:
            raise ValueError('Native pending-touch release is missing or ambiguous')
        release_index = release[0]
        if [(i.mnemonic, i.op_str) for i in decoded[release_index-3:release_index+2]] != [
                ('mov', 'rax, qword ptr [r15]'), ('movq', 'xmm8, qword ptr [r15 + 8]'),
                ('mov', 'rbx, qword ptr [r15 + 0x10]'), ('mov', 'qword ptr [r15], 0'),
                ('cmp', 'rax, 1')]:
            raise ValueError('Native pending-touch ownership changed')
        # Complete unchanged body comparison above also preserves the native
        # Started/Ended queue paths. Recognize their distinct phase stores.
        text = {(i.mnemonic, i.op_str) for i in decoded}
        if not {('mov', 'byte ptr [rax + rcx*8 + 0x38], 0'),
                ('mov', 'byte ptr [rax + rcx*8 + 0x38], 2'),
                ('mov', 'qword ptr [rax + rcx*8 + 0x30], rbx'),
                ('movq', 'qword ptr [rax + rcx*8 + 0x28], xmm8')} <= text:
            raise ValueError('Native touch release payload changed')
        release_sites.append((release_index, dict(rva=decoded[release_index].address,
            expected=bytes(decoded[release_index].bytes).hex(), next=decoded[release_index+1].address,
            state_register='r15', pending_tag=1, coordinates=8, finger_id=0x10,
            hold_seconds=0.2)))
        hits = [n for n, ins in enumerate(decoded) if (ins.mnemonic, ins.op_str) == ('ucomiss', 'xmm6, xmm7')]
        if len(hits) != 1:
            raise ValueError('Native tap timing comparison changed')
        index = hits[0]
        if (decoded[index + 1].mnemonic != 'jae' or
                (decoded[index + 2].mnemonic, decoded[index + 2].op_str) !=
                ('mov', 'rdx, qword ptr [rbp + 0x288]')):
            raise ValueError('Native tap no-event cleanup changed')
        prefix = [(i.mnemonic, i.op_str) for i in decoded[index-7:index]]
        if (prefix != [('mov', 'rax, qword ptr [r15 + 0x20]'),
                       ('cmp', 'rax, qword ptr [rbp + 0x298]'),
                       ('jae', hex(decoded[index + 2].address)),
                       ('xorps', 'xmm0, xmm0'), ('cvtsi2ss', 'xmm0, rax'),
                       ('addss', 'xmm0, xmm0'), ('addss', 'xmm7, xmm0')]):
            raise ValueError('Native tap index and bounds changed')
        producer = decoded[index + 1].operands[0].imm
        at = next(n for n, i in enumerate(decoded) if i.address == producer)
        if [(i.mnemonic, i.op_str) for i in decoded[at:at+10]] != [
                ('mov', 'qword ptr [rbp + 0x2d0], r12'),
                ('mov', 'qword ptr [rbp + 0x2c8], r14'),
                ('mov', 'qword ptr [rbp + 0x2d8], rsi'),
                ('mov', 'rcx, qword ptr [rbp + 0x290]'),
                ('movsd', 'xmm7, qword ptr [rcx + rax*8]'),
                ('lea', 'rcx, [rax + 7]'), ('inc', 'rax'),
                ('mov', 'qword ptr [r15 + 0x20], rax'),
                ('mov', 'qword ptr [r15], 1'),
                ('movsd', 'qword ptr [r15 + 8], xmm7')]:
            raise ValueError('Native tap coordinate/index producer changed')
        tap_sites.append((index, dict(rva=decoded[index].address, expected=bytes(decoded[index].bytes).hex(),
                                     cleanup=decoded[index + 2].address,
                                     cleanup_expected=bytes(decoded[index + 2].bytes).hex(),
                                     producer=producer, producer_expected=bytes(decoded[at].bytes).hex(),
                                     index_register='rax', frame_register='rbp', points_stack=0x290,
                                     count_stack=0x298, point_stride=8,
                                     elapsed_xmm=6, scheduled_xmm=7)))
    if tap_sites[0][0] != tap_sites[1][0] or tap_sites[0][1]['expected'] != tap_sites[1][1]['expected']:
        raise ValueError('Native tap timing correspondence changed')
    if release_sites[0][0] != release_sites[1][0] or release_sites[0][1]['expected'] != release_sites[1][1]['expected']:
        raise ValueError('Native touch release correspondence changed')
    return dict(reference_sha256=hashlib.sha256(before).hexdigest(), sha256=hashlib.sha256(after).hexdigest(),
                reference=sites[0][1], rva=sites[1][1], expected=sites[1][2].hex(),
                replacement=(b'\xbb' + struct.pack('<I', new_key) + b'\x41\xb6\x00').hex(),
                key_spec='w@3', isolated_only=True,
                native_key_decoders=dict(reference=old_key_evidence, candidate=new_key_evidence),
                probes=probes,
                release_cleanup=new_cleanup[1], hold_seconds=2.0,
                repeat_press=new_press[1],
                tap_gate=tap_sites[1][1],
                touch_release=release_sites[1][1],
                mechanism='Native KeyboardInput press/release; logical w and physical KeyW',
                movement_verified=False)
