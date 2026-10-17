"""Discover narrowly typed native menu contracts; never authorize a full build."""
import hashlib
import bisect
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / '.tools/python'), str(ROOT / 'reconstruction')]
import capstone
import pefile
from build_hooks import UPDATED_HASH, instruction_signature, signature_candidates
from map_build_functions import unwind_ranges, compare_function_layout, function_references, verify_function_relocation


def instructions(image, start, end):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    result = list(decoder.disasm(image.get_data(start, end - start), start))
    if sum(i.size for i in result) != end - start:
        raise ValueError('Menu function contains undecodable bytes')
    return result


def unique(rows, name):
    if len(rows) != 1:
        raise ValueError(f'{name} is missing or ambiguous ({len(rows)} candidates)')
    return rows[0]


def command_dispatch(image, start, end):
    """Recognize argument flow and resolve tags through the native jump table."""
    decoded = instructions(image, start, end)
    text = [(i.mnemonic, i.op_str) for i in decoded]
    prefix = [('mov', 'r9, rdx'), ('mov', 'eax, dword ptr [rdx]'), ('sub', 'eax, 2'),
              ('mov', 'edx, 0xa'), ('cmovae', 'edx, eax'), ('mov', 'rsi, rcx')]
    matches = [n for n in range(min(40, len(decoded) - 10)) if text[n:n + 6] == prefix]
    index = unique(matches, 'UI command argument/dispatch contract')
    load = decoded[index + 6]
    if (load.mnemonic != 'lea' or load.op_str.split(',')[0] != 'rax'
            or load.operands[1].type != capstone.x86.X86_OP_MEM
            or load.operands[1].mem.base != capstone.x86.X86_REG_RIP
            or text[index + 7:index + 10] != [('movsxd', 'rcx, dword ptr [rax + rdx*4]'),
                                             ('add', 'rcx, rax'), ('jmp', 'rcx')]):
        raise ValueError('UI command jump table shape changed')
    table = load.address + load.size + load.operands[1].mem.disp
    section = image.get_section_by_rva(table)
    if section is None or section.Characteristics & 0x80000000:
        raise ValueError('UI command jump table is not immutable image data')
    boundaries = {i.address for i in decoded}
    cases = {}
    for tag in (8, 9, 10):
        target = table + struct.unpack('<i', image.get_data(table + (tag - 2) * 4, 4))[0]
        if target not in boundaries:
            raise ValueError('UI command tag does not land on a function instruction')
        cases[tag] = target
    return dict(entry=start, end=end, server_register='rcx', command_register='rdx',
                tag_offset=0, jump_table=table, cases=cases,
                stack_frame=unique([i.operands[1].imm for i in decoded[:index]
                    if i.mnemonic == 'mov' and i.op_str.startswith('eax, 0x')], 'UI stack allocation'))


def victory_case_contract(old, before, new, after, tag):
    def block(image, dispatch):
        result = []
        for ins in instructions(image, dispatch['cases'][tag], dispatch['end']):
            result.append(ins)
            if ins.mnemonic == 'jmp':
                return result
        raise ValueError('Victory command has no bounded continuation')
    a, b = block(old, before), block(new, after)
    if len(a) != len(b):
        raise ValueError('Victory command instruction sequence changed')
    code = bytearray(b''.join(i.bytes for i in b))
    for aa, bb in zip(a, b):
        if aa.mnemonic == 'add' and aa.op_str.startswith('rsp, '):
            if (bb.mnemonic != 'add' or not bb.op_str.startswith('rsp, ')
                    or aa.operands[1].imm != before['stack_frame'] or bb.operands[1].imm != after['stack_frame']
                    or aa.imm_size != bb.imm_size):
                raise ValueError('Victory command does not restore its own native frame')
            offset = bb.address - b[0].address + bb.imm_offset
            code[offset:offset + bb.imm_size] = aa.bytes[aa.imm_offset:aa.imm_offset + aa.imm_size]
    proof = compare_function_layout(b''.join(i.bytes for i in a), a[0].address, bytes(code), b[0].address)
    if not proof['structure_equivalent']:
        raise ValueError('Victory command scalar logic or opcode sequence changed')
    return dict(tag=tag, before=a[0].address, after=b[0].address, structure=proof,
                dependencies=[dict(reference=x.operands[0].imm, candidate=y.operands[0].imm)
                    for x, y in zip(a, b) if x.mnemonic == 'call' or x.mnemonic == 'jmp'])


def enter_map_call(image, dispatch, map_select):
    """Enter copies the two-string payload and calls native config/map selectors."""
    decoded = instructions(image, dispatch['cases'][10], dispatch['end'])
    calls = [n for n, i in enumerate(decoded[:40]) if i.mnemonic == 'call'
             and i.operands[0].type == capstone.x86.X86_OP_IMM and i.operands[0].imm == map_select]
    n = unique(calls, 'Enter map selection call')
    if n != 16:
        raise ValueError('Enter argument construction changed')
    required = {0: ('movups', 'xmm0, xmmword ptr [r9 + 8]'),
                1: ('movups', 'xmm1, xmmword ptr [r9 + 0x18]'),
                2: ('movups', 'xmm2, xmmword ptr [r9 + 0x28]'),
                3: ('movups', 'xmm3, xmmword ptr [r9 + 0x38]'),
                10: ('lea', 'rdx, [rbp - 0x50]'), 11: ('mov', 'rcx, rbx'),
                14: ('mov', 'rdx, rdi'), 15: ('mov', 'r8, rbx')}
    if any((decoded[k].mnemonic, decoded[k].op_str) != v for k, v in required.items()):
        raise ValueError('Enter payload or map arguments changed')
    for k, destination, base in ((8, 'rdi', 'rsi'), (9, 'rbx', 'rbp'), (13, 'rcx', 'rbp')):
        ins = decoded[k]
        if (ins.mnemonic != 'lea' or ins.reg_name(ins.operands[0].reg) != destination
                or ins.operands[1].type != capstone.x86.X86_OP_MEM
                or ins.reg_name(ins.operands[1].mem.base) != base or ins.operands[1].mem.index):
            raise ValueError('Enter account/config ownership changed')
    call = decoded[n]
    return dict(call=call.address, return_site=call.address + call.size,
                map_select=map_select, account_server_offset=decoded[8].operands[1].mem.disp,
                config_stack_offset=decoded[9].operands[1].mem.disp,
                result_stack_offset=decoded[13].operands[1].mem.disp,
                arguments=dict(rcx='result', rdx='account', r8='config'))


# Semantic predicate template: map index < class unlock count clamped to1..9.
# Relative CALL is replaced with zero; internal branch distances describe this
# exact instruction sequence. No candidate function/data addresses are embedded.
PREDICATE = bytes.fromhex(
    '56534883ec2889d34889ce4c89c14c89cae800000000488b4e20488b562848c1e2044531c0'
    '66662e0f1f8400000000004c39c2742d4d8d481042381c014d89c875ee4a8b4c09f8'
    '4883f909ba09000000480f42d14885c9b901000000480f45caeb05b901000000'
    '4839c80f92c04883c4285b5ec3')


def login_predicates(image):
    ranges = dict(unwind_ranges(image))
    sections = [(s.VirtualAddress, s.get_data()) for s in image.sections if s.Characteristics & 0x20000000]
    pattern, mask = instruction_signature(PREDICATE, 0)
    candidates = signature_candidates(sections, pattern, mask)
    result = []
    for address in candidates:
        if ranges.get(address) != address + len(PREDICATE):
            continue
        code = image.get_data(address, len(PREDICATE))
        # Only the external map-index CALL may differ, never internal control flow.
        call_offset = 17
        expected = bytearray(PREDICATE)
        expected[call_offset + 1:call_offset + 5] = code[call_offset + 1:call_offset + 5]
        if bytes(expected) != code:
            continue
        callee = address + call_offset + 5 + struct.unpack_from('<i', code, call_offset + 1)[0]
        result.append(dict(entry=address, map_index=callee, arguments=dict(rcx='account', edx='class',
                     r8='map_pointer', r9='map_length'), result='al', unlock_pointer=0x20,
                     unlock_count=0x28, unlock_stride=16, maximum=9))
    return result


def login_callers(image, predicate, *, map_layout=None):
    """Find the scoped borrowed-string fallback bypass, preserving all ownership."""
    results = []
    for start, end in unwind_ranges(image):
        code = image.get_data(start, end - start)
        # Cheap reject before decoding unrelated native functions.
        if b'\x84\xc0' not in code or b'\x4d\x89\xf8\xe8' not in code:
            continue
        try:
            decoded = instructions(image, start, end)
        except ValueError:
            continue
        for index, call in enumerate(decoded):
            if (call.mnemonic != 'call' or call.operands[0].type != capstone.x86.X86_OP_IMM
                    or call.operands[0].imm != predicate['entry'] or index < 7):
                continue
            following = decoded[index + 1:index + 5]
            while following and following[0].mnemonic == 'nop':
                following = following[1:]
            if len(following) < 2 or (following[0].mnemonic, following[0].op_str) != ('test', 'al, al'):
                continue
            branch = following[1]
            if branch.mnemonic != 'jne' or len(branch.bytes) != 2:
                continue
            before = decoded[index - 4:index]
            if [(i.mnemonic, i.op_str) for i in before[2:]] != [('mov', 'edx, ebx'), ('mov', 'r8, r15')]:
                continue
            account, klass = before[:2]
            if (account.mnemonic != 'lea' or account.reg_name(account.operands[0].reg) != 'rcx'
                    or account.operands[1].type != capstone.x86.X86_OP_MEM
                    or account.reg_name(account.operands[1].mem.base) != 'rsi'
                    or klass.mnemonic != 'mov' or klass.reg_name(klass.operands[0].reg) != 'bl'
                    or klass.operands[1].type != capstone.x86.X86_OP_MEM
                    or klass.reg_name(klass.operands[1].mem.base) != 'rbp'):
                continue
            target = branch.operands[0].imm
            prefix = decoded[index - 15:index]
            borrowed = [('lea', 'rcx, [rdx + rax]'), ('add', 'rcx, 0x98'),
                        ('add', 'rax, rdx'), ('add', 'rax, 0xa0'),
                        ('mov', 'r15, qword ptr [rcx]'), ('mov', 'r9, qword ptr [rax]'),
                        ('cmp', 'r14, 0xffffff')]
            if [(i.mnemonic, i.op_str) for i in prefix[:7]] != borrowed:
                continue
            length = prefix[7]
            if (length.mnemonic != 'mov' or length.operands[0].type != capstone.x86.X86_OP_MEM
                    or length.reg_name(length.operands[0].mem.base) != 'rbp'
                    or length.op_str.split(', ')[1] != 'r9'
                    or prefix[8].mnemonic != 'jne' or prefix[8].operands[0].imm != account.address
                    or prefix[10].mnemonic != 'jmp' or prefix[10].operands[0].imm != target):
                continue
            connection = decoded[index - 16]
            if (connection.mnemonic != 'mov' or connection.reg_name(connection.operands[0].reg) != 'rdx'
                    or connection.operands[1].type != capstone.x86.X86_OP_MEM
                    or connection.reg_name(connection.operands[1].mem.base) != 'rsi'):
                continue
            between = [i for i in decoded if branch.address + branch.size <= i.address < target]
            # Fallback rewrites the borrowed map pointer/length from table, never
            # frees the requested strings. Require this explicit native shape.
            pointer_offset = map_layout['name_pointer'] if map_layout else 0
            loads = [n for n, ins in enumerate(between)
                     if ins.mnemonic == 'mov' and len(ins.operands) == 2
                     and ins.reg_name(ins.operands[0].reg) == 'r15'
                     and ins.operands[1].type == capstone.x86.X86_OP_MEM
                     and ins.operands[1].size == 8
                     and ins.operands[1].mem.base == capstone.x86.X86_REG_RAX
                     and ins.operands[1].mem.index == capstone.x86.X86_REG_RCX
                     and ins.operands[1].mem.scale == 1
                     and ins.operands[1].mem.disp == pointer_offset]
            if len(loads) != 1:
                continue
            if map_layout:
                n = loads[0]
                if n < 1:
                    continue
                table = between[n - 1]
                if (table.mnemonic != 'lea' or table.op_str.split(',')[0] != 'rcx'
                        or table.operands[1].type != capstone.x86.X86_OP_MEM
                        or table.operands[1].mem.base != capstone.x86.X86_REG_RIP
                        or table.address + table.size + table.operands[1].mem.disp != map_layout['table']):
                    continue
                indexing = [(ins.mnemonic, ins.op_str) for ins in between[max(0, n - 3):n - 1]]
                if not (indexing[-1:] == [('imul', f"rax, rax, {map_layout['stride']:#x}")]
                        or map_layout['stride'] == 160 and indexing ==
                        [('lea', 'rax, [rax + rax*4]'), ('shl', 'rax, 5')]):
                    continue
            continuation = [i for i in decoded if i.address >= target][:2]
            # The predicate's AL and TEST flags must be dead at the common
            # continuation. Require the observed native RNG initialization:
            # a complete RAX overwrite followed by a flag-writing multiply.
            if (len(continuation) != 2 or continuation[0].address != target
                    or continuation[0].mnemonic != 'movabs'
                    or continuation[0].reg_name(continuation[0].operands[0].reg) != 'rax'
                    or continuation[0].operands[1].type != capstone.x86.X86_OP_IMM
                    or continuation[1].mnemonic != 'imul'
                    or continuation[1].reg_name(continuation[1].operands[0].reg) != 'rax'
                    or continuation[1].operands[1].type != capstone.x86.X86_OP_MEM
                    or continuation[1].reg_name(continuation[1].operands[1].mem.base) != 'rsi'):
                continue
            results.append(dict(function=start, predicate=predicate['entry'], call=call.address,
                branch=branch.address, expected=branch.bytes.hex(), replacement=(b'\xeb' + branch.bytes[1:]).hex(),
                continuation=target, account_server_offset=account.operands[1].mem.disp,
                class_stack_offset=klass.operands[1].mem.disp, requested_map_register='r15',
                requested_length_stack=length.operands[0].mem.disp,
                connection_vector_server_offset=connection.operands[1].mem.disp,
                connection_map_pointer=0x98, connection_map_length=0xa0,
                ownership='borrowed native map strings; fallback bypass changes control flow only'))
    return results


def equivalent_switch(old, old_start, old_code, new, new_start, new_code, table_count):
    """Prove complete switch function plus signed table targets, not a prefix."""
    old_refs, new_refs = function_references(old_code, old_start)[1], function_references(new_code, new_start)[1]
    old_tables = [r[3] for r in old_refs if r[2] == 'rip']
    new_tables = [r[3] for r in new_refs if r[2] == 'rip']
    if len(old_tables) != 1 or len(new_tables) != 1:
        return False
    mapping = {old_tables[0]: new_tables[0]}
    for _, _, kind, target in old_refs:
        if kind == 'control' and not old_start <= target < old_start + len(old_code):
            # Native deallocator is image-local and unchanged, verified by caller
            # separately as a dependency; do not infer a relocated helper.
            mapping[target] = target
    proof = verify_function_relocation(old_code, old_start, new_code, new_start, mapping)
    if not proof['instructions_equivalent'] or not proof['references_verified']:
        return False
    for a, b, start_a, start_b, size in [(old_tables[0], new_tables[0], old_start, new_start, table_count)]:
        aa = [a + x[0] - start_a for x in struct.iter_unpack('<i', old.get_data(a, size * 4))]
        bb = [b + x[0] - start_b for x in struct.iter_unpack('<i', new.get_data(b, size * 4))]
        if aa != bb or any(not 0 <= offset < len(old_code) for offset in aa):
            return False
    return True


def leaf_bytes(image, address):
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    data = image.get_data(address, 1024)
    consumed = 0
    for ins in decoder.disasm(data, address):
        if ins.mnemonic == 'int3':
            return data[:consumed]
        consumed += ins.size
    raise ValueError('Unbounded leaf switch function')


def command_drop_paths(image, entry):
    """Decode both compiler switch forms over the 18 native command tags."""
    end = dict(unwind_ranges(image))[entry]
    stream = instructions(image, entry, end)
    prefix = [('push', 'r14'), ('push', 'rsi'), ('push', 'rdi'), ('push', 'rbx'),
              ('sub', 'rsp, 0x28'), ('mov', 'rsi, rcx'), ('mov', 'ecx, dword ptr [rcx]'),
              ('sub', 'ecx, 2'), ('mov', 'eax, 0xa'), ('cmovae', 'eax, ecx')]
    text = [(i.mnemonic, i.op_str) for i in stream]
    if text[:10] != prefix:
        raise ValueError('Command destructor argument/stack contract changed')
    shift = 8 if text[10] == ('add', 'eax, -8') else 0
    n = 11 if shift else 10
    if (text[n] != ('cmp', 'eax, 7' if shift else 'eax, 0xe')
            or stream[n + 1].mnemonic != 'ja'
            or stream[n + 2].mnemonic != 'lea'
            or stream[n + 2].op_str.split(',')[0] != 'rcx'
            or stream[n + 2].operands[1].mem.base != capstone.x86.X86_REG_RIP
            or text[n + 3:n + 6] != [('movsxd', 'rax, dword ptr [rcx + rax*4]'),
                                     ('add', 'rax, rcx'), ('jmp', 'rax')]):
        raise ValueError('Command destructor dispatch changed')
    lea = stream[n + 2]
    table = lea.address + lea.size + lea.operands[1].mem.disp
    count = 8 if shift else 15
    section = image.get_section_by_rva(table)
    if (section is None or section.Characteristics & (0x20000000 | 0x80000000)
            or table + count * 4 > section.VirtualAddress + section.Misc_VirtualSize):
        raise ValueError('Command destructor table is not bounded immutable data')
    targets = [table + value[0] for value in struct.iter_unpack('<i', image.get_data(table, count * 4))]
    cases = []
    for tag in range(18):
        index = ((tag - 2 if tag >= 2 else 10) - shift) & 0xffffffff
        cases.append(targets[index] if index < count else stream[n + 1].operands[0].imm)
    decoded = {i.address: i for i in stream}
    if any(address not in decoded for address in cases):
        raise ValueError('Command destructor case escapes its function')
    return decoded, cases


def equivalent_command_drop(old, old_entry, new, new_entry):
    models = [command_drop_paths(image, entry) for image, entry in ((old, old_entry), (new, new_entry))]
    def skip(decoded, address):
        seen = set()
        while address in decoded:
            ins = decoded[address]
            if address in seen:
                raise ValueError('Command destructor has an unconditional cycle')
            seen.add(address)
            if ins.mnemonic == 'nop':
                address += ins.size
            elif ins.mnemonic == 'jmp' and ins.operands[0].type == capstone.x86.X86_OP_IMM and ins.operands[0].imm in decoded:
                address = ins.operands[0].imm
            else:
                return address
        raise ValueError('Command destructor path escapes its function')
    pending = list(zip(models[0][1], models[1][1]))
    visited, dependencies = set(), set()
    while pending:
        a, b = (skip(model[0], address) for model, address in zip(models, pending.pop()))
        if (a, b) in visited:
            continue
        visited.add((a, b))
        x, y = models[0][0][a], models[1][0][b]
        if x.mnemonic != y.mnemonic:
            raise ValueError('Command destructor reachable instruction changed')
        if x.group(capstone.CS_GRP_JUMP) or x.group(capstone.CS_GRP_CALL):
            if any(i.operands[0].type != capstone.x86.X86_OP_IMM for i in (x, y)):
                raise ValueError('Command destructor indirect control flow changed')
            aa, bb = x.operands[0].imm, y.operands[0].imm
            if x.mnemonic == 'call' or x.mnemonic == 'jmp':
                if aa != bb or aa != 0x21d0:
                    raise ValueError('Command destructor deallocator changed')
                dependencies.add(aa)
            else:
                pending.append((aa, bb))
            if x.mnemonic != 'jmp':
                pending.append((a + x.size, b + y.size))
        else:
            if x.bytes != y.bytes:
                raise ValueError('Command destructor owned fields or cleanup changed')
            if x.mnemonic != 'ret':
                pending.append((a + x.size, b + y.size))
    if dependencies != {0x21d0}:
        raise ValueError('Command destructor lacks its deallocator')
    return dict(tags=list(range(18)), external_dependencies=sorted(dependencies),
                reachable_instruction_pairs=len(visited))


def command_destructor(old, new, old_entry):
    end = dict(unwind_ranges(old))[old_entry]
    before = old.get_data(old_entry, end - old_entry)
    pattern, mask = instruction_signature(before, old_entry)
    sections = [(s.VirtualAddress, s.get_data()) for s in new.sections if s.Characteristics & 0x20000000]
    ends = dict(unwind_ranges(new))
    equivalent = [a for a in signature_candidates(sections, pattern, mask)
                  if ends.get(a) == a + len(before) and equivalent_switch(
                      old, old_entry, before, new, a, new.get_data(a, len(before)), 15)]
    variant = None
    if not equivalent:
        # The compiler can trim no-op cases from the switch without changing
        # cleanup. Check every valid command tag and both arms of each branch.
        prefix = before[:25]
        for base, data in sections:
            cursor = 0
            while (offset := data.find(prefix, cursor)) >= 0:
                cursor = offset + 1
                address = base + offset
                if address not in ends:
                    continue
                try:
                    equivalent_command_drop(old, old_entry, new, address)
                except ValueError:
                    continue
                equivalent.append(address)
        if not equivalent:
            raise ValueError('Native command destructor has no equivalent complete implementation')
        variant = 'trimmed-command-switch'
    # Rust emits duplicate drop-glue implementations. Identical complete code,
    # table target mapping and external-call targets make these equivalent aliases.
    return dict(entry=min(equivalent), equivalent_aliases=sorted(equivalent), variant=variant,
                expected=new.get_data(min(equivalent), 9).hex(),
                external_dependencies=sorted({r[3] for r in function_references(before, old_entry)[1]
                    if r[2] == 'control' and not old_entry <= r[3] < end}))


def map_selection_contract(old, old_entry, new, new_entry):
    """Prove the bounded map-name lookup when the native record layout moves.

    Only the name pair is consumed here. This does not certify other map fields,
    enemy definitions, or the external allocator/map-index dependencies.
    """
    layouts, blocks, bodies = [], [], []
    for image, entry in ((old, old_entry), (new, new_entry)):
        end = dict(unwind_ranges(image))[entry]
        stream = instructions(image, entry, end)
        text = [(i.mnemonic, i.op_str) for i in stream]
        matches = []
        for n, ins in enumerate(stream):
            if text[n:n + 2] == [('lea', 'rax, [rax + rax*4]'), ('shl', 'rax, 5')]:
                stride, count = 160, 2
            elif (ins.mnemonic == 'imul' and len(ins.operands) == 3
                  and ins.op_str.startswith('rax, rax, ')
                  and ins.operands[2].type == capstone.x86.X86_OP_IMM):
                stride, count = ins.operands[2].imm, 1
            else:
                continue
            if not 16 <= stride <= 4096 or stride % 8 or n + count + 3 > len(stream):
                continue
            load, pointer, length = stream[n + count:n + count + 3]
            if (load.mnemonic != 'lea' or load.op_str.split(',')[0] != 'rcx'
                    or load.operands[1].type != capstone.x86.X86_OP_MEM
                    or load.operands[1].mem.base != capstone.x86.X86_REG_RIP):
                continue
            offsets = []
            for item, register in ((pointer, 'r15'), (length, 'rbx')):
                if (item.mnemonic != 'mov' or len(item.operands) != 2
                        or item.reg_name(item.operands[0].reg) != register
                        or item.operands[1].type != capstone.x86.X86_OP_MEM):
                    break
                operand = item.operands[1]
                if (operand.size != 8 or operand.mem.base != capstone.x86.X86_REG_RAX
                        or operand.mem.index != capstone.x86.X86_REG_RCX or operand.mem.scale != 1):
                    break
                offsets.append(operand.mem.disp)
            if len(offsets) != 2 or not 0 <= offsets[0] == offsets[1] - 8 <= stride - 16:
                continue
            matches.append((n, count + 3, dict(stride=stride, name_pointer=offsets[0],
                name_length=offsets[1], table=load.address + load.size + load.operands[1].mem.disp)))
        index, count, layout = unique(matches, 'Map-name record lookup')
        block = stream[index:index + count]
        blocks.append((block[0].address - entry, b''.join(i.bytes for i in block)))
        layouts.append(layout)
        bodies.append(image.get_data(entry, end - entry))
    if blocks[0][0] != blocks[1][0] or len(blocks[0][1]) != len(blocks[1][1]):
        raise ValueError('Map-name lookup changes surrounding instruction locations')
    for body, entry, (offset, block) in zip(bodies, (old_entry, new_entry), blocks):
        if any(kind == 'control' and entry + offset < target < entry + offset + len(block)
               for _, _, kind, target in function_references(body, entry)[1]):
            raise ValueError('Control flow enters the interior of the map-name lookup')
    normalized = bytearray(bodies[1])
    offset, block = blocks[0]
    normalized[offset:offset + len(block)] = block
    comparison = verify_function_relocation(bodies[0], old_entry, bytes(normalized), new_entry, {})
    if not comparison['instructions_equivalent'] or comparison['mismatched']:
        raise ValueError('Map selection logic, account/config fields or internal branches changed')
    names = []
    for image, layout in ((old, layouts[0]), (new, layouts[1])):
        def immutable(address, size):
            section = image.get_section_by_rva(address)
            if (section is None or section.Characteristics & (0x20000000 | 0x80000000)
                    or address + size > section.VirtualAddress + section.Misc_VirtualSize):
                raise ValueError('Map-name lookup needs bounded immutable data')
            data = image.get_data(address, size)
            if len(data) != size:
                raise ValueError('Truncated map-name data')
            return data
        values = []
        for index in range(9):
            row = immutable(layout['table'] + index * layout['stride'], layout['stride'])
            pointer, size = struct.unpack_from('<QQ', row, layout['name_pointer'])
            if not 1 <= size <= 32:
                raise ValueError('Map-name length exceeds reviewed bounds')
            values.append(immutable(pointer - image.OPTIONAL_HEADER.ImageBase, size).decode('ascii'))
        names.append(values)
    if names[0] != names[1] or len(set(names[0])) != 9:
        raise ValueError('Map-name identity or order changed')
    return dict(reference=old_entry, candidate=new_entry, lookup_offset=blocks[0][0], lookup_size=len(blocks[0][1]),
                reference_layout=layouts[0],
                candidate_layout=layouts[1], names=names[0], map_name_lookup_verified=True,
                automatic_activation_allowed=False,
                scope='Nine map names and native selection logic only; external dependencies require separate proof')


def discover_menu_contract(reference, binary, structural):
    before_data, after_data = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(before_data).hexdigest() != UPDATED_HASH:
        raise ValueError('Menu contract reference is not reviewed')
    old, new = pefile.PE(data=before_data, fast_load=True), pefile.PE(data=after_data, fast_load=True)
    ends_old, ends_new = dict(unwind_ranges(old)), dict(unwind_ranges(new))
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    old_ui, old_map = [manifest['hooks'][name]['reference_rva'] for name in ('UI_COMMAND', 'MAP_SELECT')]
    map_candidates = []
    for candidate in structural[hex(old_map)]['candidates']:
        try:
            map_candidates.append(map_selection_contract(old, old_map, new, int(candidate['rva'], 16)))
        except (ValueError, UnicodeError):
            continue
    map_proof = unique(map_candidates, 'MAP_SELECT')
    mapped = map_proof['candidate']
    old_dispatch = command_dispatch(old, old_ui, ends_old[old_ui])
    before_enter = enter_map_call(old, old_dispatch, old_map)
    ui = []
    for row in structural[hex(old_ui)]['candidates']:
        address = int(row['rva'], 16)
        try:
            dispatch = command_dispatch(new, address, ends_new[address])
            entry = enter_map_call(new, dispatch, mapped)
        except ValueError:
            continue
        ui.append(dict(dispatch=dispatch, enter=entry))
    menu = unique(ui, 'UI command dispatch and Enter contracts')
    victories = [victory_case_contract(old, old_dispatch, new, menu['dispatch'], tag) for tag in (8, 9)]
    predicates = login_predicates(new)
    predicate = unique(predicates, 'Native unlocked-map predicate')
    caller = unique(login_callers(new, predicate, map_layout=map_proof['candidate_layout']), 'Login map predicate caller')
    if caller['account_server_offset'] != menu['enter']['account_server_offset']:
        raise ValueError('Login and menu use different account structures')
    map_instructions = instructions(old, old_map, ends_old[old_map])
    first_call = next(i for i in map_instructions if i.mnemonic == 'call')
    old_index = first_call.operands[0].imm
    if not equivalent_switch(old, old_index, leaf_bytes(old, old_index), new, predicate['map_index'],
                             leaf_bytes(new, predicate['map_index']), 7):
        raise ValueError('Map-name index switch changed')
    destructor = command_destructor(old, new, 0x546f050)
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(after_data).hexdigest():
        raise ValueError('Game changed while discovering menu contracts')
    return dict(sha256=hashlib.sha256(after_data).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, variant='borrowed_map_predicate',
                ui_command=menu['dispatch']['entry'], command_tags=menu['dispatch']['cases'],
                map_select=mapped, map_selection=map_proof, host_map_return=menu['enter']['return_site'],
                enter_contract=menu['enter'], baseline_enter=before_enter,
                login_predicate=predicate, login=caller, command_destructor=destructor,
                account_config=dict(
                    proof='complete MAP_SELECT logic, typed map-name lookup, unchanged account/config fields and native predicate semantics',
                    account=dict(unlock_pointer=0x20, unlock_count=0x28, unlock_stride=16,
                                 entry_class=0, entry_unlocked_count=8, minimum=1, maximum=9),
                    config=dict(map_pointer=0x20, map_length=0x28, class_id=0x38),
                    arguments=dict(rcx='result', rdx='account', r8='config')),
                victory_cases=victories,
                menu_contract_verified=True,
                map_clamp=dict(site=mapped + 0x39, expected=new.get_data(mapped + 0x39, 19).hex(),
                               allocation_path=mapped + 0xd0),
                unresolved=['Complete candidate adapter proof including native allocator dependency'])


def discover_gear_observation(reference, binary, menu):
    """Observe a native call's scalar result; never authorize calling the helper."""
    after = Path(binary).read_bytes()
    from build_hooks import REVIEWED_RELEASES
    digest = hashlib.sha256(after).hexdigest()
    exact_release = not Path(reference).is_file() and digest in REVIEWED_RELEASES
    # Native item definition resolver per exact release (47e4: 6 aligned callers, coop-lab/port-re).
    item_resolver = {'dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306': 0x53cca10,
                     '47e4ab65c1ad7366e554171a6a28b0272141664010a50795371129b203111bf2': 0x53e0030,
                     # 0.93.1: 47e4 0x53e0030 aligned to 0x53df330 (ratio 0.998, 2 aligned call sites)
                     '0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66': 0x53df330,
                     # 0.95.0: 0931 0x53df330 aligned to 0x53f76a0 (ratio 0.998, coop-lab/port-7264)
                     '7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30': 0x53f76a0}.get(digest, 0x53cca10)
    # Exact-release observation uses current native producers and validates
    # their scalar record/consumer contracts directly. Historical function
    # correspondence remains mandatory for every other executable.
    before = after if exact_release else Path(reference).read_bytes()
    if (not exact_release and hashlib.sha256(before).hexdigest() != UPDATED_HASH) or menu.get('sha256') != hashlib.sha256(after).hexdigest():
        raise ValueError('Gear observation requires the reviewed build and matching menu proof')
    if menu.get('menu_contract_verified') is not True:
        raise ValueError('Gear observation requires proved native menu arguments')
    from native_helper_contracts import HelperProof
    old, new = pefile.PE(data=before, fast_load=True), pefile.PE(data=after, fast_load=True)
    helper = HelperProof(old, new)
    reviewed = 0x539f670
    if exact_release:
        login_start = menu['login']['function']
        stream = instructions(new, login_start, dict(unwind_ranges(new))[login_start])
        calls = [i.operands[0].imm for n, i in enumerate(stream) if n >= 4 and
                 i.mnemonic == 'call' and i.operands[0].type == capstone.x86.X86_OP_IMM and
                 [(p.mnemonic, p.op_str.split(',')[0]) for p in stream[n-3:n]] ==
                 [('mov', 'rdx'), ('mov', 'r8d'), ('mov', 'r9d')] and
                 stream[n-4].mnemonic == 'lea' and stream[n-4].op_str.startswith('rcx, [rbp')]
        reviewed = candidate = unique(calls, 'Exact-release native gear result producer')
    else:
        candidate = unique(helper.candidates(reviewed), 'Native class gear resolver')
    a, b = helper.code(0, reviewed), helper.code(1, candidate)
    paired = compare_function_layout(a, reviewed, b, candidate)
    if not exact_release and (not paired['structure_equivalent'] or paired['field_changes'] or paired['instruction_changes']):
        raise ValueError('Native gear result layout changed')
    decoded = instructions(old, reviewed, reviewed + len(a))
    text = {(i.mnemonic, i.op_str) for i in decoded}
    # These native reads/copies establish the complete scalar record, class
    # discriminator, per-slot appearance Option<u32>, equipped item IDs and
    # nineteen-slot bound. The option span is compared with race/class defaults;
    # the plain-ID span feeds native equipment stat aggregation (see below).
    required = {('mov', 'rax, qword ptr [rdx + 0x50]'),
                ('imul', 'rcx, qword ptr [rdx + 0x58], 0xe8'),
                ('cmp', 'byte ptr [rax + rdx + 0xe4], r8b'),
                ('mov', 'r8d, 0xe8'), ('cmp', 'rdi, 0x13'),
                ('cmp', 'dword ptr [rbp + rdi*8 - 8], 1'),
                ('mov', 'r12d, dword ptr [rbp + rdi*8 - 4]'),
                ('mov', 'edx, dword ptr [rbp + rdi*4 + 0x90]')}
    if not required <= text:
        raise ValueError('Reviewed gear record schema does not match its native resolver')
    default_zeroes = {i.operands[0].mem.disp for i in decoded if i.mnemonic == 'mov'
                      and len(i.operands) == 2 and i.operands[0].type == capstone.x86.X86_OP_MEM
                      and i.operands[0].mem.base == capstone.x86.X86_REG_RBP
                      and i.operands[0].size == 4 and i.operands[1].type == capstone.x86.X86_OP_IMM
                      and i.operands[1].imm == 0}
    if (not {-8 + 8 * slot for slot in range(19)} <= default_zeroes
            or ('xorps', 'xmm0, xmm0') not in text
            or not {('movups', f'xmmword ptr [rbp + {offset:#x}], xmm0')
                    for offset in (0x90, 0xa0, 0xb0, 0xc0, 0xcc)} <= text):
        raise ValueError('Native missing-class gear defaults changed')
    # Native login copies record+98 into constructor input+120. That exact
    # 76-byte span feeds this native stat aggregator, not the appearance span.
    # Both consumer paths are documented in analysis/gear-layout-evidence.txt.
    stats_reference, item_reference = 0x53d2660, 0x53d1840
    if exact_release:
        ranges = unwind_ranges(new)
        starts = [a for a, _ in ranges]
        owners = set()
        for section in new.sections:
            if section.Characteristics & 0x20000000:
                body, offset = section.get_data(), 0
                while (offset := body.find(bytes.fromhex('488d424c'), offset)) >= 0:
                    address = section.VirtualAddress + offset
                    index = bisect.bisect_right(starts, address) - 1
                    if index >= 0 and address < ranges[index][1]:
                        owners.add(ranges[index])
                    offset += 4
        consumers = [start for start, end in owners if
                     {('cmp', 'r15, 0x4c'), ('add', 'r15, 4'), ('call', hex(item_resolver))} <=
                     {(i.mnemonic, i.op_str) for i in instructions(new, start, end)}]
        stats_reference = stats_candidate = unique(consumers, 'Exact-release equipment stat consumer')
        item_reference = item_resolver
    else:
        stats_candidate = unique(helper.candidates(stats_reference), 'Equipment stat consumer')
    release_0843 = exact_release  # exact releases observe their own pinned item resolver
    # This release adds native item definitions. Observe the unchanged 19-slot
    # consumer and gear record; this does not authorize calling the item helper.
    item_candidate = (item_resolver if release_0843 else
                      unique(helper.candidates(item_reference), 'Equipment item definition resolver'))
    consumers = [(stats_reference, stats_candidate)]
    if not release_0843:
        consumers.append((item_reference, item_candidate))
    for source, target in consumers:
        comparison = compare_function_layout(helper.code(0, source), source, helper.code(1, target), target)
        if not comparison['structure_equivalent'] or comparison['field_changes'] or comparison['instruction_changes']:
            raise ValueError('Native equipment stat consumer changed')
    for side, image, address, item in ((0, old, stats_reference, item_reference),
                                      (1, new, stats_candidate, item_candidate)):
        stream = instructions(image, address, address + len(helper.code(side, address)))
        names = {(i.mnemonic, i.op_str) for i in stream}
        if not {('lea', 'rax, [rdx + 0x4c]'), ('cmp', 'r15, 0x4c'), ('add', 'r15, 4'),
                ('mov', 'edx, dword ptr [rdi + r15]'), ('call', hex(item)),
                ('addss', 'xmm1, xmm0')} <= names:
            raise ValueError('Native equipped-item stat iteration changed')
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    old_login = menu['login']['function'] if exact_release else manifest['hooks']['TICK']['reference_rva']
    observations = []
    for image, start, target in ((old, old_login, reviewed), (new, menu['login']['function'], candidate)):
        stream = instructions(image, start, dict(unwind_ranges(image))[start])
        calls = [n for n, i in enumerate(stream) if i.mnemonic == 'call'
                 and i.operands[0].type == capstone.x86.X86_OP_IMM and i.operands[0].imm == target]
        n = unique(calls, 'Native login gear call')
        prefix, following = stream[n-4:n], stream[n+1]
        destination = prefix[0]
        if (destination.mnemonic != 'lea' or destination.reg_name(destination.operands[0].reg) != 'rcx'
                or destination.operands[1].type != capstone.x86.X86_OP_MEM
                or destination.reg_name(destination.operands[1].mem.base) != 'rbp'
                or destination.operands[1].mem.index
                or [(i.mnemonic, i.op_str.split(',')[0]) for i in prefix[1:]] !=
                   [('mov', 'rdx'), ('mov', 'r8d'), ('mov', 'r9d')]
                or following.mnemonic != 'nop' or bytes(following.bytes) != b'\x90'):
            raise ValueError('Native login result is no longer a bounded caller-owned stack record')
        offset = destination.operands[1].mem.disp
        frame = unique([i.operands[1].imm for i in stream[:12]
                        if i.mnemonic == 'mov' and i.op_str.startswith('eax, 0x')], 'Login stack frame')
        if ('lea', 'rbp, [rsp + 0x80]') not in {(i.mnemonic, i.op_str) for i in stream[:20]} or not -0x80 <= offset <= frame - 0x80 - 0xe8:
            raise ValueError('Native gear result escapes its caller frame')
        observations.append(dict(function=start, helper=target, call=stream[n].address,
                                 rva=following.address, expected=bytes(following.bytes).hex(),
                                 output_register='rbp', output_offset=offset, frame_size=frame))
    return dict(sha256=hashlib.sha256(after).hexdigest(), reference_sha256=hashlib.sha256(before).hexdigest(),
                diagnostic_only=True, native_call_allowed=False, layout_verified=True,
                reference=observations[0], login=observations[1],
                equipment_stat_consumer=dict(reference=stats_reference, candidate=stats_candidate,
                                             item_reference=item_reference, item_candidate=item_candidate),
                schema=dict(account_pointer=0x50, account_count=0x58, size=0xe8, class_id=0xe4,
                            slots=19, appearance_stride=8, appearance_tag=0, appearance_id=4, items=0x98),
                runtime_obligations=['Actual native Enter selection', 'Login result equals native selected gear',
                                     'Explicit expected nondefault item selected', 'All native character fields replicated'])


if __name__ == '__main__':
    profile = json.loads((ROOT / 'analysis/structural-hook-candidates.json').read_text())
    report = discover_menu_contract(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
                                    ROOT / 'AzerothSurvivors.exe', profile)
    (ROOT / 'analysis/menu-contract-candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
