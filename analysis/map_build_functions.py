"""Propose function relocations; masked field offsets still require review."""
import ast
import argparse
import bisect
import difflib
from collections import Counter
import json
import hashlib
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tools/python'))
import capstone
import pefile
sys.path.insert(0, str(ROOT / 'reconstruction'))
from build_hooks import UPDATED_HASH, displacement_size, instruction_signature, signature_candidates, write_report


def unwind_ranges(image):
    directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[3]
    data = image.get_data(directory.VirtualAddress, directory.Size)
    if len(data) != directory.Size or len(data) % 12:
        raise ValueError('Truncated native exception directory')
    ranges = sorted((start, end) for start, end, _ in struct.iter_unpack('<III', data))
    if any(not 0 < start < end <= image.OPTIONAL_HEADER.SizeOfImage for start, end in ranges):
        raise ValueError('Invalid native function bounds')
    return ranges


def function_references(code, address):
    """Decode every byte, keeping game-field offsets and all non-address values."""
    if not code:
        raise ValueError('Empty function')
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    pattern, references, consumed = bytearray(code), [], 0
    for ins in md.disasm(code, address):
        start = ins.address - address
        spans = []
        if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
            if ins.imm_size:
                spans.append((ins.imm_offset, ins.imm_size, 'control', ins.operands[0].imm))
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                spans.append((ins.disp_offset, displacement_size(ins), 'rip', ins.address + ins.size + op.mem.disp))
        for offset, size, kind, target in spans:
            pattern[start + offset:start + offset + size] = bytes(size)
            references.append((start + offset, size, kind, target))
        consumed += ins.size
    if consumed != len(code):
        raise ValueError('Function contains undecodable bytes')
    return bytes(pattern), references


def verify_function_relocation(before, old_rva, after, new_rva, address_map):
    """Prove an instruction-preserving move, with explicit external targets.

    This proves this function only. A caller must also validate the referenced
    functions/data and every adapter patch before authorizing the whole build.
    Missing mappings are unresolved dependencies, never assumed unchanged.
    """
    old_pattern, old_refs = function_references(before, old_rva)
    new_pattern, new_refs = function_references(after, new_rva)
    if old_pattern != new_pattern or len(old_refs) != len(new_refs):
        return dict(instructions_equivalent=False, references_verified=False,
                    unresolved=[], mismatched=['instruction or layout change'])
    unresolved, mismatched = [], []
    for old, new in zip(old_refs, new_refs):
        offset, size, kind, target = old
        if old[:3] != new[:3]:
            mismatched.append(dict(offset=offset, reason='operand layout changed'))
            continue
        expected = (new_rva + target - old_rva if old_rva <= target < old_rva + len(before)
                    else address_map.get(target))
        if expected is None:
            unresolved.append(dict(offset=offset, kind=kind, old_target=target, new_target=new[3]))
        elif expected != new[3]:
            mismatched.append(dict(offset=offset, kind=kind, expected=expected, actual=new[3]))
    # A split/cold function may fall through across its unwind range boundary.
    # That implicit edge must move with it too; it has no encoded displacement.
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    last = list(decoder.disasm(before, old_rva))[-1]
    if last.mnemonic not in ('ret', 'retf', 'jmp', 'ud2', 'hlt'):
        expected = address_map.get(old_rva + len(before))
        if expected is None:
            unresolved.append(dict(offset=len(before), kind='fallthrough',
                                   old_target=old_rva + len(before), new_target=new_rva + len(after)))
        elif expected != new_rva + len(after):
            mismatched.append(dict(offset=len(before), kind='fallthrough', expected=expected,
                                   actual=new_rva + len(after)))
    return dict(instructions_equivalent=True, references_verified=not unresolved and not mismatched,
                unresolved=unresolved, mismatched=mismatched)


def dependency_relocations(reference, binary, targets):
    """Map complete native functions, including interior patch destinations."""
    import hashlib
    before_data, after_data = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(before_data).hexdigest() != UPDATED_HASH:
        raise ValueError('Dependency mapping requires the preserved reviewed executable')
    old, new = pefile.PE(data=before_data, fast_load=True), pefile.PE(data=after_data, fast_load=True)
    functions = unwind_ranges(old)
    starts = [start for start, end in functions]
    new_functions = dict(unwind_ranges(new))
    sections = [(s.VirtualAddress, s.get_data()) for s in new.sections if s.Characteristics & 0x20000000]
    grouped, rows = {}, {}
    for target in sorted(set(targets)):
        i = bisect.bisect_right(starts, target) - 1
        if i < 0 or target >= functions[i][1]:
            rows[target] = dict(status='data_or_uncovered_code', candidates=[])
        else:
            grouped.setdefault(functions[i], []).append(target)
    mapped, comparisons = {}, {}
    for (start, end), members in grouped.items():
        before = old.get_data(start, end - start)
        try:
            pattern, mask = instruction_signature(before[:256], start)
            candidates = signature_candidates(sections, pattern, mask)
            candidates = [rva for rva in candidates if new_functions.get(rva, 0) - rva == len(before)
                          and function_references(before, start)[0] ==
                          function_references(new.get_data(rva, len(before)), rva)[0]]
        except ValueError as error:
            candidates = []
            for target in members:
                rows[target] = dict(status='unresolved', candidates=[], reason=str(error))
        if len(candidates) == 1:
            destination = candidates[0]
            mapped[start] = destination
            # Every byte offset is stable because instruction bytes/lengths match.
            comparisons[start] = (before, destination, new.get_data(destination, len(before)))
        for target in members:
            rows.setdefault(target, dict(status='candidate' if len(candidates) == 1 else 'unresolved',
                                         candidates=[rva + target - start for rva in candidates],
                                         function=start))
    # Interior references to another completely matched function are explicit.
    def mapped_target(target):
        i = bisect.bisect_right(starts, target) - 1
        return (mapped[starts[i]] + target - starts[i]
                if i >= 0 and starts[i] in mapped and target < functions[i][1] else None)
    evidence = {}
    for start, (before, destination, after) in comparisons.items():
        refs = function_references(before, start)[1]
        address_map = {target: mapped_target(target) for _, _, _, target in refs
                       if mapped_target(target) is not None}
        evidence[start] = verify_function_relocation(before, start, after, destination, address_map)
    return dict(reference_sha256=UPDATED_HASH, sha256=hashlib.sha256(after_data).hexdigest(),
                automatic_activation_allowed=False,
                reason='Function evidence does not certify data tables, unwind semantics, or full adapter coverage',
                dependencies={hex(k): v for k, v in rows.items()},
                functions={hex(k): v for k, v in evidence.items()})


def instruction_pattern(instructions, *, relocation_only=False, preserve_immediates=False):
    parts = []
    for ins in instructions:
        rip = any(op.type == capstone.x86.X86_OP_MEM and
                  op.mem.base == capstone.x86.X86_REG_RIP for op in ins.operands)
        masked = (set(range(ins.disp_offset, ins.disp_offset + displacement_size(ins)))
                  if not relocation_only or rip else set())
        if (not relocation_only and not preserve_immediates or
                ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL)):
            masked.update(range(ins.imm_offset, ins.imm_offset + ins.imm_size))
        parts.extend(b'.' if i in masked else re.escape(bytes([byte]))
                     for i, byte in enumerate(ins.bytes))
    return re.compile(b''.join(parts), re.DOTALL)


def compare_function_layout(before, old_rva, after, new_rva):
    """Separate field displacement changes from actual instruction changes.

    A matching skeleton is discovery evidence, not proof that two objects have
    the same meaning. In particular, stack slots and different objects can use
    the same register. Callers must never apply these proposals globally.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old, new = list(md.disasm(before, old_rva)), list(md.disasm(after, new_rva))
    if sum(i.size for i in old) != len(before) or sum(i.size for i in new) != len(after):
        return dict(structure_equivalent=False, reason='Undecodable function bytes')
    changes, mismatch = [], []
    if len(old) != len(new):
        return dict(structure_equivalent=False, reason='Instruction count changed',
                    old_instructions=len(old), new_instructions=len(new))
    for a, b in zip(old, new):
        if not instruction_pattern([a], preserve_immediates=True).fullmatch(b.bytes):
            mismatch.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
                                 old=f'{a.mnemonic} {a.op_str}', new=f'{b.mnemonic} {b.op_str}'))
            continue
        for x, y in zip(a.operands, b.operands):
            if (x.type == capstone.x86.X86_OP_MEM and y.type == x.type
                    and x.mem.base != capstone.x86.X86_REG_RIP and x.mem.disp != y.mem.disp):
                changes.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
                    base=a.reg_name(x.mem.base), index=a.reg_name(x.mem.index), scale=x.mem.scale,
                    width=x.size, old_offset=x.mem.disp, new_offset=y.mem.disp,
                    stack=x.mem.base in (capstone.x86.X86_REG_RSP, capstone.x86.X86_REG_RBP)))
    return dict(structure_equivalent=not mismatch, field_changes=changes,
                instruction_changes=mismatch, automatic_activation_allowed=False)


def tick_entry_contract(code, address):
    """Recognize the reviewed server/time entry contract using operand flow."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    aliases = {'rcx': 'server', 'xmm1': 'time'}
    flag, elapsed, stored_time, queue_writes = False, False, False, []
    evidence = []
    for ins in list(md.disasm(code, address))[:90]:
        ops = ins.operands
        def server_memory(op, offset):
            return (op.type == capstone.x86.X86_OP_MEM and not op.mem.index
                    and aliases.get(ins.reg_name(op.mem.base)) == 'server' and op.mem.disp == offset)
        if len(ops) == 2:
            if (ins.mnemonic == 'cmp' and server_memory(ops[0], 0)
                    and ops[1].type == capstone.x86.X86_OP_IMM and ops[1].imm == 1):
                flag = True
                evidence.append(hex(ins.address))
            if ins.mnemonic == 'subsd' and server_memory(ops[1], 8):
                elapsed = True
                evidence.append(hex(ins.address))
            if (ins.mnemonic == 'movsd' and server_memory(ops[0], 8)
                    and ops[1].type == capstone.x86.X86_OP_REG
                    and aliases.get(ins.reg_name(ops[1].reg)) == 'time'):
                stored_time = True
                evidence.append(hex(ins.address))
            if (ins.mnemonic == 'mov' and ops[0].type == capstone.x86.X86_OP_MEM
                    and not ops[0].mem.index and aliases.get(ins.reg_name(ops[0].mem.base)) == 'server'
                    and ops[1].type == capstone.x86.X86_OP_IMM):
                queue_writes.append((ops[0].mem.disp, ops[1].imm, hex(ins.address)))
        copied = None
        if (ins.mnemonic in ('mov', 'movapd', 'movaps') and len(ops) == 2
                and all(op.type == capstone.x86.X86_OP_REG for op in ops)):
            copied = aliases.get(ins.reg_name(ops[1].reg))
        for reg in ins.regs_access()[1]:
            aliases.pop(ins.reg_name(reg), None)
        if copied:
            aliases[ins.reg_name(ops[0].reg)] = copied
    queues = []
    for a, b, c in zip(queue_writes, queue_writes[1:], queue_writes[2:]):
        if (a[1], b[1], c[1]) == (0, 8, 0) and (b[0], c[0]) == (a[0] + 8, a[0] + 16):
            queues.append(dict(offsets=[a[0], b[0], c[0]], sites=[a[2], b[2], c[2]]))
    return dict(server_argument='rcx', time_argument='xmm1', server_flag=flag,
                elapsed_time=elapsed, stored_time=stored_time, queues=queues, sites=evidence,
                verified_header=flag and elapsed and stored_time and len(queues) == 1)


def pointer_offset_candidates(before, old_rva, after, new_rva):
    """Changed full-width pointer arithmetic, conditional on observed ownership."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old, new = list(md.disasm(before, old_rva)), list(md.disasm(after, new_rva))
    if len(old) != len(new):
        return []
    result = []
    for a, b in zip(old, new):
        if not (a.mnemonic in ('add', 'sub') and len(a.operands) == 2
                and a.operands[0].type == capstone.x86.X86_OP_REG and a.operands[0].size == 8
                and a.operands[1].type == capstone.x86.X86_OP_IMM
                and instruction_pattern([a]).fullmatch(b.bytes)
                and a.operands[1].imm != b.operands[1].imm):
            continue
        sign = 1 if a.mnemonic == 'add' else -1
        result.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
            old_offset=a.operands[1].imm * sign, new_offset=b.operands[1].imm * sign,
            register=a.reg_name(a.operands[0].reg), mnemonic=a.mnemonic,
            old_bytes=a.bytes.hex(), expected=b.bytes.hex(), width=1, address_only=True,
            heap_ownership_verified=False, automatic_activation_allowed=False,
            runtime_precondition='register equals captured Game before this instruction'))
    return result


def conditional_game_accesses(before, old_rva, after, new_rva, requested):
    """Pair declared Game member operands without asserting their live owner."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old, new = list(md.disasm(before, old_rva)), list(md.disasm(after, new_rva))
    candidates = {i.address: i for i in old if any(o.type == capstone.x86.X86_OP_MEM
                  and o.mem.disp in requested and not o.mem.index
                  and i.reg_name(o.mem.base) not in ('rbp', 'rsp', 'rip', None) for o in i.operands)}
    new_by_address = {i.address: i for i in new}
    if len(old) == len(new):
        mapped = {a.address: b for a, b in zip(old, new) if a.address in candidates
                  and instruction_pattern([a], preserve_immediates=True).fullmatch(b.bytes)}
    else:
        rows = interior_relocations(before, old_rva, [(new_rva, after)], candidates)
        mapped = {int(site, 16): new_by_address[int(row['candidates'][0]['rva'], 16)]
                  for site, row in rows.items() if len(row['candidates']) == 1
                  and int(row['candidates'][0]['rva'], 16) in new_by_address}
    result = []
    for site, b in mapped.items():
        a = candidates[site]
        for x, y in zip(a.operands, b.operands):
            if not (x.type == y.type == capstone.x86.X86_OP_MEM and x.mem.disp in requested
                    and not x.mem.index and not y.mem.index and x.size == y.size
                    and a.reg_name(x.mem.base) == b.reg_name(y.mem.base)
                    and a.reg_name(x.mem.base) not in ('rbp', 'rsp', 'rip', None)):
                continue
            result.append(dict(old_rva=hex(a.address), new_rva=hex(b.address), register=a.reg_name(x.mem.base),
                old_offset=x.mem.disp, new_offset=y.mem.disp, width=1 if a.mnemonic == 'lea' else x.size,
                address_only=a.mnemonic == 'lea', access=x.access, old_bytes=a.bytes.hex(), expected=b.bytes.hex(),
                heap_ownership_verified=False, automatic_activation_allowed=False,
                runtime_precondition='register equals captured Game before this instruction'))
    return result


def region_instruction_contract(before, old_rva, after, new_rva):
    """Compare only an adapter-controlled region, with exact internal edges."""
    comparison = compare_function_layout(before, old_rva, after, new_rva)
    conditional = pointer_offset_candidates(before, old_rva, after, new_rva)
    changes = comparison.get('instruction_changes', [])
    pointer_only = bool(changes) and {x['old_rva'] for x in changes} == {x['old_rva'] for x in conditional}
    if not comparison['structure_equivalent']:
        if not pointer_only:
            return dict(instruction_roles=False, internal_control_flow=False, comparison=comparison)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old, new = list(md.disasm(before, old_rva)), list(md.disasm(after, new_rva))
    translated = {a.address: b.address for a, b in zip(old, new)}
    translated[old_rva + len(before)] = new_rva + len(after)
    external, valid = [], True
    for a, b in zip(old, new):
        if not (a.group(capstone.CS_GRP_JUMP) or a.group(capstone.CS_GRP_CALL)):
            continue
        if a.operands[0].type != capstone.x86.X86_OP_IMM:
            external.append(dict(kind='indirect', old_rva=hex(a.address), new_rva=hex(b.address),
                                 operands=a.op_str))
            continue
        old_target, new_target = a.operands[0].imm, b.operands[0].imm
        if old_rva <= old_target <= old_rva + len(before):
            valid = valid and translated.get(old_target) == new_target
        elif new_rva <= new_target <= new_rva + len(after):
            valid = False
        else:
            external.append(dict(kind='call' if a.group(capstone.CS_GRP_CALL) else 'branch',
                old_rva=hex(a.address), new_rva=hex(b.address), old_target=hex(old_target), new_target=hex(new_target)))
    return dict(instruction_roles=comparison['structure_equivalent'],
                conditional_instruction_roles=pointer_only, conditional_pointer_immediates=conditional,
                internal_control_flow=valid, instructions=len(old),
                old_start=hex(old_rva), new_start=hex(new_rva), old_end=hex(old_rva + len(before)),
                new_end=hex(new_rva + len(after)), field_changes=comparison['field_changes'],
                stack_field_evidence=stack_field_pairs(before, old_rva, after, new_rva),
                external_edges=external, automatic_activation_allowed=False)


def stack_field_pairs(before, old_rva, after, new_rva):
    """Map fixed frame operands only at paired instructions with exact roles."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old, new = list(md.disasm(before, old_rva)), list(md.disasm(after, new_rva))
    if len(old) != len(new):
        return []
    fields = []
    for a, b in zip(old, new):
        if not instruction_pattern([a], preserve_immediates=True).fullmatch(b.bytes):
            continue
        for x, y in zip(a.operands, b.operands):
            if (x.type == y.type == capstone.x86.X86_OP_MEM and not x.mem.index and not y.mem.index
                    and a.reg_name(x.mem.base) == b.reg_name(y.mem.base) and a.reg_name(x.mem.base) in ('rbp', 'rsp')):
                fields.append(dict(old_rva=hex(a.address), new_rva=hex(b.address), base=a.reg_name(x.mem.base),
                    old_offset=x.mem.disp, new_offset=y.mem.disp, width=1 if a.mnemonic == 'lea' else x.size,
                    address_only=a.mnemonic == 'lea', access=x.access))
    return fields


def anchored_trap_contract(before, old_rva, after, new_rva):
    """Close a paired outgoing branch through simple OOM stubs ending in UD2.

    Duplicate failure stubs need not have unique signatures: the already-paired
    branch names the actual destinations. Callees remain explicit dependencies.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    calls, sites = [], []
    a, b = old_rva, new_rva
    visited = set()
    for _ in range(16):
        if (a, b) in visited:
            return None
        visited.add((a, b))
        x = next(md.disasm(before.get_data(a, 15), a), None)
        y = next(md.disasm(after.get_data(b, 15), b), None)
        if x is None or y is None or not instruction_pattern([x], preserve_immediates=True).fullmatch(y.bytes):
            return None
        if x.mnemonic not in ('mov', 'nop', 'call', 'jmp', 'ud2') or any(o.type == capstone.x86.X86_OP_MEM for o in x.operands):
            return None
        sites.append(dict(old_rva=hex(a), new_rva=hex(b), old_bytes=x.bytes.hex(), new_bytes=y.bytes.hex()))
        if x.mnemonic == 'ud2':
            return dict(terminal_trap=True, instructions=sites, call_dependencies=calls)
        if x.mnemonic in ('jmp', 'call'):
            if x.operands[0].type != capstone.x86.X86_OP_IMM:
                return None
            if x.mnemonic == 'jmp':
                a, b = x.operands[0].imm, y.operands[0].imm
                continue
            calls.append(dict(kind='call', old_rva=hex(a), new_rva=hex(b),
                              old_target=hex(x.operands[0].imm), new_target=hex(y.operands[0].imm)))
        a, b = a + x.size, b + y.size
    return None


def interior_relocations(before, old_start, new_functions, targets):
    """Intersect two instruction windows within discovered candidate functions.

    Returns evidence for changed or split functions, never permission to patch.
    Operand displacement changes remain explicit in each accepted local window.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(before, old_start))
    indices = {ins.address: i for i, ins in enumerate(instructions)}
    def operand_key(ins):
        operands = []
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_REG:
                operands.append(('reg', op.size, ins.reg_name(op.reg)))
            elif op.type == capstone.x86.X86_OP_MEM:
                operands.append(('mem', op.size, ins.reg_name(op.mem.base),
                                 ins.reg_name(op.mem.index), op.mem.scale, ins.reg_name(op.mem.segment)))
            else:
                operands.append(('imm', None if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL) else op.imm))
        return ins.mnemonic, tuple(ins.prefix), tuple(ins.opcode), tuple(operands)
    decoded = [(list(md.disasm(data, start))) for start, data in new_functions]
    decoded_keys = [[operand_key(ins) for ins in stream] for stream in decoded]
    result = {}
    for target in targets:
        index = indices.get(target)
        byte_offset = 0
        if index is None:
            index = bisect.bisect_right(list(indices), target) - 1
            if index < 0 or target >= instructions[index].address + instructions[index].size:
                result[hex(target)] = dict(candidates=[], reason='Outside decoded instructions')
                continue
            byte_offset = target - instructions[index].address
        windows = []
        for first in sorted({max(0, index - 6), index}):
            window = instructions[first:first + 12]
            if len(window) < 8:
                continue
            pattern = instruction_pattern(window, preserve_immediates=True)
            matches = {}
            for start, data in new_functions:
                for match in pattern.finditer(data):
                    candidate = start + match.start() + target - window[0].address
                    comparison = compare_function_layout(b''.join(i.bytes for i in window), window[0].address,
                                                         match.group(), start + match.start())
                    matches[candidate] = comparison
            windows.append(matches)
        shared = set.intersection(*(set(w) for w in windows)) if windows else set()
        semantic_windows = []
        if not shared:
            # ModRM disp8/disp32 size changes alter bytes, but not register roles.
            # Compare decoded operands and retain every stack/object field move.
            for first in sorted({max(0, index - 6), index}):
                window = instructions[first:first + 12]
                if len(window) < 8:
                    continue
                keys = [operand_key(ins) for ins in window]
                matches = {}
                for stream, stream_keys in zip(decoded, decoded_keys):
                    for position in range(len(stream) - len(keys) + 1):
                        if stream_keys[position:position + len(keys)] != keys:
                            continue
                        target_ins = stream[position + index - first]
                        if byte_offset and target_ins.size != instructions[index].size:
                            continue
                        candidate = target_ins.address + byte_offset
                        changes = []
                        for a, b in zip(window, stream[position:position + len(keys)]):
                            for x, y in zip(a.operands, b.operands):
                                if (x.type == capstone.x86.X86_OP_MEM and x.mem.base != capstone.x86.X86_REG_RIP
                                        and x.mem.disp != y.mem.disp):
                                    changes.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
                                        base=a.reg_name(x.mem.base), old_offset=x.mem.disp, new_offset=y.mem.disp,
                                        width=x.size, stack=a.reg_name(x.mem.base) in ('rbp', 'rsp')))
                        matches[candidate] = dict(field_changes=changes, decoded_operands=True)
                semantic_windows.append(matches)
            shared = set.intersection(*(set(w) for w in semantic_windows)) if semantic_windows else set()
            if shared:
                windows = semantic_windows
        result[hex(target)] = dict(candidates=[dict(rva=hex(candidate),
            instruction_byte_offset=byte_offset,
            supporting_windows=len(windows), decoded_operands=windows[0][candidate].get('decoded_operands', False),
            field_changes=list({(change['old_rva'], change['base']): change
                for window in windows for change in window[candidate].get('field_changes', [])}.values()))
            for candidate in sorted(shared)], automatic_activation_allowed=False)
    return result


def private_frame_slots(instructions, *, frame_borrows=None):
    """Find single-writer spills outside separately proved bounded frame borrows.

    frame_borrows maps a MOV frame-pointer copy site to its externally proved
    byte extent. A callee read/escape contract must establish each such extent;
    absent that evidence the original conservative rejection remains.
    """
    frame_borrows = {} if frame_borrows is None else frame_borrows
    copied_frames = {i.address: i for i in instructions
        if i.mnemonic == 'mov' and len(i.operands) == 2
        and i.operands[0].type == capstone.x86.X86_OP_REG and i.operands[0].size == 8
        and i.operands[1].type == capstone.x86.X86_OP_REG
        and i.reg_name(i.operands[1].reg) in ('rbp', 'rsp')}
    if not set(frame_borrows).issubset(copied_frames) or any(
            type(extent) is not int or not 0 < extent <= 65536 for extent in frame_borrows.values()):
        raise ValueError('Invalid bounded native frame-borrow contract')
    setups = [i for i in instructions if i.mnemonic == 'lea' and len(i.operands) == 2
              and i.reg_name(i.operands[0].reg) == 'rbp' and i.operands[1].type == capstone.x86.X86_OP_MEM
              and i.reg_name(i.operands[1].mem.base) == 'rsp' and not i.operands[1].mem.index]
    if len(setups) != 1:
        return set()
    delta = setups[0].operands[1].mem.disp
    first,last=instructions[0].address,instructions[-1].address+instructions[-1].size
    def terminal(ins):
        return ins.mnemonic=='ret' or (ins.mnemonic=='jmp' and ins.operands[0].type==capstone.x86.X86_OP_IMM
                                        and not first<=ins.operands[0].imm<last)
    for index, ins in enumerate(instructions):
        if (ins.address > setups[0].address and not ins.group(capstone.CS_GRP_CALL)
                and 'rsp' in {ins.reg_name(r) for r in ins.regs_access()[1]}):
            tail = instructions[index:]
            if ins.mnemonic == 'add' and len(ins.operands) == 2 and ins.reg_name(ins.operands[0].reg) == 'rsp':
                tail = tail[1:]
            if ins.mnemonic not in ('ret', 'pop', 'add') or not tail:
                return set()
            for following in tail:
                if terminal(following):
                    break
                if following.mnemonic != 'pop':
                    return set()
            else:
                return set()
        if any(ins.reg_name(r) in ('rbp', 'ebp', 'bp', 'bpl') for r in ins.regs_access()[1]) and ins != setups[0]:
            if ins.mnemonic != 'pop' or index + 1 >= len(instructions) or not terminal(instructions[index + 1]):
                return set()
        if (ins.mnemonic == 'mov' and len(ins.operands) == 2 and ins.operands[1].type == capstone.x86.X86_OP_REG
                and ins.reg_name(ins.operands[1].reg) in ('rbp', 'rsp')):
            if ins.address not in frame_borrows:
                return set()  # An unproved copied frame can alias any local.
    slots = {i.operands[0].mem.disp for i in instructions if i.mnemonic == 'mov' and len(i.operands) == 2
             and i.operands[0].type == capstone.x86.X86_OP_MEM and i.operands[0].size == 8
             and i.reg_name(i.operands[0].mem.base) == 'rbp' and not i.operands[0].mem.index
             and i.operands[1].type == capstone.x86.X86_OP_REG and i.operands[1].size == 8}
    result = set()
    for slot in slots:
        # Caller shadow space can be overwritten by a native callee.
        if slot + delta < 32:
            continue
        writes, escaped = 0, False
        for site, extent in frame_borrows.items():
            source = copied_frames[site].reg_name(copied_frames[site].operands[1].reg)
            start = -delta if source == 'rsp' else 0
            if start < slot+8 and start+extent > slot:
                escaped = True
        for ins in instructions:
            for operand_index,op in enumerate(ins.operands):
                if op.type != capstone.x86.X86_OP_MEM or ins.reg_name(op.mem.base) not in ('rbp', 'rsp'):
                    continue
                if op.mem.index:
                    # An indexed read neither modifies a private spill nor
                    # exposes its address. Writes/LEA remain unbounded aliases.
                    if ins.mnemonic == 'lea' or memory_write_operand(ins,operand_index):
                        escaped = True
                        break
                    continue
                offset = op.mem.disp - (delta if ins.reg_name(op.mem.base) == 'rsp' else 0)
                if ins.mnemonic == 'lea' and slot <= offset < slot + 8:
                    escaped = True
                if memory_write_operand(ins,operand_index) and offset < slot + 8 and offset + op.size > slot:
                    writes += 1
        if not escaped and writes == 1:
            result.add(slot)
    return result


def game_field_uses(code, address, *, entry_prefix=False, indirect_edges=None, pointer_immediates=False,
                    entry_register='rcx', call_arguments=None, frame_borrows=None):
    """Conservative RCX-object must-alias flow across direct control-flow edges.

    Join points retain only aliases agreed by every discovered predecessor.
    Calls kill volatile registers. Stack reloads and indirect jump tables are
    deliberately unresolved instead of guessing pointer provenance.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    instructions = {i.address: i for i in md.disasm(code, address)}
    frame_slots = private_frame_slots(list(instructions.values()), frame_borrows=frame_borrows)
    indirect = {i.address for i in instructions.values() if i.mnemonic == 'jmp'
                and i.operands[0].type != capstone.x86.X86_OP_IMM}
    indirect_edges = {} if indirect_edges is None else indirect_edges
    if (not set(indirect_edges).issubset(indirect)
            or any(not targets or any(target not in instructions for target in targets)
                   for targets in indirect_edges.values())):
        raise ValueError('Invalid proved indirect control-flow edges')
    indirect = indirect - set(indirect_edges)
    if indirect and not entry_prefix:
        return {}  # Unknown predecessors require a decoded jump-table proof.
    if entry_register not in ('rcx', 'rdx', 'r8', 'r9'):
        raise ValueError('Unsupported typed Game entry register')
    incoming, pending = {address: {entry_register: 0}}, [address]
    edges = {}
    def full_register(name):
        families = ('rax eax ax al ah', 'rbx ebx bx bl bh', 'rcx ecx cx cl ch',
                    'rdx edx dx dl dh', 'rsi esi si sil', 'rdi edi di dil',
                    'rbp ebp bp bpl', 'rsp esp sp spl')
        for family in families:
            if name in family.split():
                return family.split()[0]
        return name.rstrip('dwb') if re.fullmatch(r'r(?:[89]|1[0-5])[dwb]?', name) else name
    while pending:
        current = pending.pop()
        ins = instructions.get(current)
        if ins is None:
            continue
        state = dict(incoming[current])
        ops, copied = ins.operands, None
        if len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_REG and ops[0].size == 8:
            destination = ins.reg_name(ops[0].reg)
            if ins.mnemonic == 'mov' and ops[1].type == capstone.x86.X86_OP_REG:
                copied = state.get(ins.reg_name(ops[1].reg))
            elif (ins.mnemonic == 'mov' and ops[1].type == capstone.x86.X86_OP_MEM
                    and ins.reg_name(ops[1].mem.base) == 'rbp' and not ops[1].mem.index
                    and ops[1].mem.disp in frame_slots):
                copied = state.get(f'@frame:{ops[1].mem.disp}')
            elif (ins.mnemonic == 'lea' and ops[1].type == capstone.x86.X86_OP_MEM
                    and not ops[1].mem.index and ins.reg_name(ops[1].mem.base) in state):
                copied = state[ins.reg_name(ops[1].mem.base)] + ops[1].mem.disp
            elif (ins.mnemonic in ('add', 'sub') and destination in state
                    and ops[1].type == capstone.x86.X86_OP_IMM):
                copied = state[destination] + ops[1].imm * (1 if ins.mnemonic == 'add' else -1)
        if (ins.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_MEM
                and ins.reg_name(ops[0].mem.base) == 'rbp' and not ops[0].mem.index
                and ops[0].mem.disp in frame_slots and ops[1].type == capstone.x86.X86_OP_REG):
            owned = state.get(ins.reg_name(ops[1].reg))
            state.pop(f'@frame:{ops[0].mem.disp}', None)
            if owned is not None:
                state[f'@frame:{ops[0].mem.disp}'] = owned
        for reg in ins.regs_access()[1]:
            state.pop(full_register(ins.reg_name(reg)), None)
        if copied is not None:
            state[ins.reg_name(ops[0].reg)] = copied
        if ins.group(capstone.CS_GRP_CALL):
            for reg in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                state.pop(reg, None)
        successors = []
        if ins.group(capstone.CS_GRP_JUMP):
            if ops[0].type == capstone.x86.X86_OP_IMM:
                successors.append(ops[0].imm)
            elif current in indirect_edges:
                successors.extend(indirect_edges[current])
            if ins.mnemonic != 'jmp':
                successors.append(ins.address + ins.size)
        elif ins.mnemonic not in ('ret', 'retf', 'ud2', 'hlt'):
            successors.append(ins.address + ins.size)
        edges[current] = [s for s in successors if s in instructions]
        for successor in successors:
            if successor not in instructions:
                continue
            previous = incoming.get(successor)
            merged = dict(state) if previous is None else {k: v for k, v in previous.items() if state.get(k) == v}
            if previous != merged:
                incoming[successor] = merged
                pending.append(successor)
    uses = {}
    for current, aliases in incoming.items():
        ins = instructions[current]
        if call_arguments is not None and (ins.group(capstone.CS_GRP_CALL) or
                ins.mnemonic == 'jmp' and ins.operands[0].type == capstone.x86.X86_OP_IMM
                and ins.operands[0].imm not in instructions):
            call_arguments[current] = {reg: aliases[reg] for reg in ('rcx', 'rdx', 'r8', 'r9') if reg in aliases}
        pointer = (pointer_immediates and ins.mnemonic in ('add', 'sub') and len(ins.operands) == 2
                   and ins.operands[0].type == capstone.x86.X86_OP_REG and ins.operands[0].size == 8
                   and ins.reg_name(ins.operands[0].reg) in aliases
                   and ins.operands[1].type == capstone.x86.X86_OP_IMM)
        if not pointer and not any(op.type == capstone.x86.X86_OP_MEM and not op.mem.index
                                  and ins.reg_name(op.mem.base) in aliases for op in ins.operands):
            continue
        if indirect and entry_prefix:
            # Entry-path evidence only: this site must dominate every reachable
            # indirect exit of the known CFG. No fact is inferred after one.
            pending_nodes, reached = [address], set()
            dominates = True
            while pending_nodes:
                node = pending_nodes.pop()
                if node == current or node in reached:
                    continue
                if node in indirect:
                    dominates = False
                    break
                reached.add(node)
                pending_nodes.extend(edges.get(node, ()))
            if not dominates:
                continue
        if pointer:
            base = ins.reg_name(ins.operands[0].reg)
            uses[(current, 1)] = dict(offset=aliases[base] + ins.operands[1].imm * (1 if ins.mnemonic == 'add' else -1),
                base=base, width=1, address_only=True, access=0, entry_prefix=bool(indirect), pointer_immediate=True)
        for index, op in enumerate(ins.operands):
            if (op.type == capstone.x86.X86_OP_MEM and not op.mem.index
                    and ins.reg_name(op.mem.base) in aliases):
                uses[(current, index)] = dict(offset=aliases[ins.reg_name(op.mem.base)] + op.mem.disp,
                    base=ins.reg_name(op.mem.base), width=1 if ins.mnemonic == 'lea' else op.size,
                    address_only=ins.mnemonic == 'lea', access=op.access,
                    entry_prefix=bool(indirect))
    return uses


def hud_delivery_contracts(code, address):
    """Describe the reviewed indirect receiver/buffer/length call ABI locally.

    The server register must additionally equal the TICK-captured server in an
    observation run: local operand roles alone do not prove heap ownership.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, address))
    result = []
    for index, ins in enumerate(instructions):
        if not (ins.mnemonic == 'call' and len(ins.operands) == 1
                and ins.operands[0].type == capstone.x86.X86_OP_MEM
                and ins.reg_name(ins.operands[0].mem.base) == 'rax'
                and not ins.operands[0].mem.index and ins.operands[0].mem.disp == 0x20):
            continue
        definitions = {}
        for previous in reversed(instructions[max(0, index - 8):index]):
            if previous.group(capstone.CS_GRP_CALL) or previous.group(capstone.CS_GRP_JUMP):
                break
            for reg in previous.regs_access()[1]:
                name = previous.reg_name(reg)
                if name in ('rcx', 'rdx', 'r8', 'rax'):
                    definitions.setdefault(name, previous)
        if definitions.keys() != {'rcx', 'rdx', 'r8', 'rax'}:
            continue
        if not all(i.mnemonic == 'mov' and len(i.operands) == 2
                   and i.operands[0].type == capstone.x86.X86_OP_REG and i.operands[0].size == 8
                   and i.operands[1].type == capstone.x86.X86_OP_MEM and not i.operands[1].mem.index
                   for i in definitions.values()):
            continue
        receiver, vtable = definitions['rcx'].operands[1].mem, definitions['rax'].operands[1].mem
        buffer, length = definitions['rdx'].operands[1].mem, definitions['r8'].operands[1].mem
        if (receiver.base != vtable.base or vtable.disp != receiver.disp + 8
                or buffer.base != length.base or length.disp != buffer.disp + 8
                or ins.reg_name(buffer.base) not in ('rsp', 'rbp')):
            continue
        result.append(dict(rva=hex(ins.address), server_register=ins.reg_name(receiver.base),
            receiver_field=receiver.disp, vtable_field=vtable.disp,
            buffer_register='rdx', length_register='r8', callback_slot=0x20,
            stack_register=ins.reg_name(buffer.base), buffer_stack_offset=buffer.disp,
            length_stack_offset=length.disp, local_abi_roles=True, heap_ownership_verified=False,
            runtime_precondition='server_register equals the captured TICK RCX',
            definitions={reg: dict(rva=hex(i.address), bytes=i.bytes.hex()) for reg, i in definitions.items()}))
    return result


def stable_game_field_uses(code, address):
    """Find never-reassigned callee-saved copies of the entry Game* argument."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    candidates, rcx_intact = {}, True
    for i in ins:
        if i.group(capstone.CS_GRP_CALL):
            break
        if i.group(capstone.CS_GRP_JUMP) and i.operands[0].type != capstone.x86.X86_OP_IMM:
            break
        if (rcx_intact and i.mnemonic == 'mov' and len(i.operands) == 2
                and all(o.type == capstone.x86.X86_OP_REG and o.size == 8 for o in i.operands)
                and i.reg_name(i.operands[1].reg) == 'rcx'
                and i.reg_name(i.operands[0].reg) in ('rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15')):
            candidates[i.reg_name(i.operands[0].reg)] = i.address
        if any(i.reg_name(r) in ('rcx', 'ecx', 'cx', 'cl', 'ch') for r in i.regs_access()[1]):
            rcx_intact = False
    def same_register(name, full):
        aliases = {'rbx': ('rbx', 'ebx', 'bx', 'bl', 'bh'), 'rsi': ('rsi', 'esi', 'si', 'sil'),
                   'rdi': ('rdi', 'edi', 'di', 'dil')}
        return name in aliases.get(full, (full, full + 'd', full + 'w', full + 'b'))
    for reg, initializer in list(candidates.items()):
        valid = True
        for index, i in enumerate(ins):
            if (i.group(capstone.CS_GRP_JUMP) and i.operands[0].type == capstone.x86.X86_OP_IMM
                    and address <= i.operands[0].imm <= initializer):
                valid = False
            if i.address == initializer or not any(same_register(i.reg_name(r), reg) for r in i.regs_access()[1]):
                continue
            tail = ins[index + 1:index + 17]
            terminal = False
            if i.mnemonic == 'pop':
                for following in tail:
                    if following.mnemonic == 'ret':
                        terminal = True
                        break
                    if following.mnemonic != 'pop':
                        break
            if not terminal:
                valid = False
        # An early guard may return before copying RCX. Such paths are safe
        # only when they cannot use this register or reach an unknown jump.
        by_address = {i.address: i for i in ins}
        pending, bypass = [address], set()
        while pending and valid:
            current = pending.pop()
            if current == initializer or current in bypass:
                continue
            bypass.add(current)
            instruction = by_address.get(current)
            if instruction is None:
                continue
            if any(o.type == capstone.x86.X86_OP_MEM and instruction.reg_name(o.mem.base) == reg
                   for o in instruction.operands):
                valid = False
                break
            if instruction.group(capstone.CS_GRP_JUMP):
                if instruction.operands[0].type != capstone.x86.X86_OP_IMM:
                    valid = False
                    break
                pending.append(instruction.operands[0].imm)
                if instruction.mnemonic != 'jmp':
                    pending.append(current + instruction.size)
            elif instruction.mnemonic not in ('ret', 'retf', 'ud2', 'hlt'):
                pending.append(current + instruction.size)
        if not valid:
            del candidates[reg]
    uses = {}
    for i in ins:
        for index, op in enumerate(i.operands):
            base = i.reg_name(op.mem.base) if op.type == capstone.x86.X86_OP_MEM else None
            if base in candidates and not op.mem.index and i.address > candidates[base]:
                uses[(i.address, index)] = dict(offset=op.mem.disp, base=base,
                    width=1 if i.mnemonic == 'lea' else op.size, address_only=i.mnemonic == 'lea',
                    access=op.access, entry_prefix=False, invariant_nonvolatile=True,
                    initializer=hex(candidates[base]))
    return uses


def saved_game_frame_contracts(code, address):
    """Prove the entry Game spill; expose later reloads as conditional roles.

    A reload's following uses are not global aliases: unresolved indirect edges
    may enter after that reload. Their owner register must be checked at runtime.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, address))
    by_address = {i.address: i for i in instructions}
    aliases, copies = {'rcx'}, {}
    def canonical(name):
        for family in ('rax eax ax al ah', 'rcx ecx cx cl ch', 'rdx edx dx dl dh',
                       'rbx ebx bx bl bh', 'rsi esi si sil', 'rdi edi di dil',
                       'rbp ebp bp bpl', 'rsp esp sp spl'):
            if name in family.split():
                return family.split()[0]
        return name.rstrip('dwb') if re.fullmatch(r'r(?:[89]|1[0-5])[dwb]?', name) else name
    # Capture entry aliases only before control flow diverges.
    for ins in instructions:
        if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
            break
        ops = ins.operands
        copy = (len(ops) == 2 and ins.mnemonic == 'mov' and ops[0].type == ops[1].type == capstone.x86.X86_OP_REG
                and ops[0].size == ops[1].size == 8 and ins.reg_name(ops[1].reg) in aliases)
        for reg in ins.regs_access()[1]:
            aliases.discard(canonical(ins.reg_name(reg)))
        if copy:
            name = ins.reg_name(ops[0].reg)
            aliases.add(name)
            if name in ('rbx', 'rsi', 'rdi', 'r12', 'r13', 'r14', 'r15'):
                copies[name] = ins.address
    frame_writes = [i for i in instructions if 'rbp' in {canonical(i.reg_name(r)) for r in i.regs_access()[1]}]
    frame_setups = [i for i in frame_writes if i.mnemonic == 'lea' and len(i.operands) == 2
                    and i.operands[1].type == capstone.x86.X86_OP_MEM
                    and i.reg_name(i.operands[1].mem.base) == 'rsp' and not i.operands[1].mem.index]
    if len(frame_setups) != 1:
        return []
    for write in frame_writes:
        if write == frame_setups[0]:
            continue
        following = instructions[instructions.index(write) + 1:]
        if write.mnemonic != 'pop' or not following or following[0].mnemonic != 'ret':
            return []
    results = []
    for store in instructions:
        ops = store.operands
        if not (store.mnemonic == 'mov' and len(ops) == 2 and ops[0].type == capstone.x86.X86_OP_MEM
                and ops[0].size == 8 and store.reg_name(ops[0].mem.base) == 'rbp' and not ops[0].mem.index
                and ops[1].type == capstone.x86.X86_OP_REG and store.reg_name(ops[1].reg) in copies):
            continue
        owner, slot = store.reg_name(ops[1].reg), ops[0].mem.disp
        initializer = copies[owner]
        if frame_setups[0].address >= store.address or initializer >= store.address or any(initializer < i.address < store.address and
                owner in {canonical(i.reg_name(r)) for r in i.regs_access()[1]} for i in instructions):
            continue
        writers = [i for i in instructions if any(memory_write_operand(i,n)
                   and i.reg_name(o.mem.base) == 'rbp' and not o.mem.index
                   and o.mem.disp < slot + 8 and o.mem.disp + o.size > slot for n,o in enumerate(i.operands))]
        if writers != [store]:
            continue
        # Every reachable entry path must reach this spill before leaving its
        # prefix. Calls preserve the nonvolatile owner under the Windows ABI.
        pending, visited, valid = [address], set(), True
        while pending and valid:
            current = pending.pop()
            if current == store.address or current in visited:
                continue
            visited.add(current)
            ins = by_address.get(current)
            if ins is None or current > store.address or ins.mnemonic in ('ret', 'retf', 'ud2', 'hlt'):
                valid = False
                break
            if ins.group(capstone.CS_GRP_JUMP):
                if ins.operands[0].type != capstone.x86.X86_OP_IMM:
                    valid = False
                    break
                pending.append(ins.operands[0].imm)
                if ins.mnemonic != 'jmp':
                    pending.append(ins.address + ins.size)
            else:
                pending.append(ins.address + ins.size)
        if not valid:
            continue
        reloads = []
        for index, load in enumerate(instructions):
            op = load.operands
            if not (load.address > store.address and load.mnemonic == 'mov' and len(op) == 2
                    and op[0].type == capstone.x86.X86_OP_REG and op[0].size == 8
                    and op[1].type == capstone.x86.X86_OP_MEM and load.reg_name(op[1].mem.base) == 'rbp'
                    and not op[1].mem.index and op[1].mem.disp == slot):
                continue
            register = load.reg_name(op[0].reg)
            uses = []
            for ins in instructions[index + 1:]:
                if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL) or ins.mnemonic.startswith('ret'):
                    break
                for operand in ins.operands:
                    if (operand.type == capstone.x86.X86_OP_MEM and ins.reg_name(operand.mem.base) == register
                            and not operand.mem.index):
                        uses.append(dict(rva=hex(ins.address), offset=operand.mem.disp,
                            width=1 if ins.mnemonic == 'lea' else operand.size, address_only=ins.mnemonic == 'lea'))
                if register in {canonical(ins.reg_name(r)) for r in ins.regs_access()[1]}:
                    break
            reloads.append(dict(rva=hex(load.address), register=register, fields=uses,
                runtime_precondition=f'{register} equals captured Game at each field use'))
        results.append(dict(stack_register='rbp', stack_offset=slot, spill_site=hex(store.address),
            entry_copy=hex(initializer), owner_register=owner, fixed_frame_writes=1,
            entry_spill_dominates=True, reloads=reloads, automatic_activation_allowed=False,
            limitation='Fixed RBP frame accesses checked; indirect stack aliases and unknown jump predecessors require runtime ownership checks'))
    return results


def object_frame_stores(code, address):
    """Native address-of-object-member assignments to fixed local pointers."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    instructions = list(md.disasm(code, address))
    result = {}
    for derive, store in zip(instructions, instructions[1:]):
        a, b = derive.operands, store.operands
        if not (derive.mnemonic == 'lea' and len(a) == 2 and a[0].type == capstone.x86.X86_OP_REG
                and a[0].size == 8 and a[1].type == capstone.x86.X86_OP_MEM and not a[1].mem.index
                and derive.reg_name(a[1].mem.base) not in ('rbp', 'rsp', 'rip', None)
                and store.mnemonic == 'mov' and len(b) == 2 and b[0].type == capstone.x86.X86_OP_MEM
                and b[0].size == 8 and not b[0].mem.index and store.reg_name(b[0].mem.base) in ('rbp', 'rsp')
                and b[1].type == capstone.x86.X86_OP_REG and b[1].reg == a[0].reg):
            continue
        result[hex(derive.address)] = dict(object_register=derive.reg_name(a[1].mem.base),
            field_offset=a[1].mem.disp, stack_register=store.reg_name(b[0].mem.base),
            stack_offset=b[0].mem.disp, store_rva=hex(store.address))
    return result


def paired_frame_stores(before, old_rva, after, new_rva):
    old, new = object_frame_stores(before, old_rva), object_frame_stores(after, new_rva)
    mapped = interior_relocations(before, old_rva, [(new_rva, after)], [int(site, 16) for site in old])
    pairs = []
    for site, mapping in mapped.items():
        if len(mapping['candidates']) != 1:
            continue
        candidate = mapping['candidates'][0]['rva']
        if candidate not in new:
            continue
        a, b = old[site], new[candidate]
        if a['object_register'] != b['object_register'] or a['stack_register'] != b['stack_register']:
            continue
        pairs.append(dict(old_rva=site, new_rva=candidate, old=a, new=b,
            runtime_precondition='object register equals captured Game before deriving the member address',
            automatic_activation_allowed=False))
    return pairs


def restore_game_frame_contract(old_frames, new_frames, stores, requirements=None):
    """Check the reviewed generated restore_game snippet's three local slots.

    These are reviewed adapter dependencies, not hardcoded candidate offsets.
    Pairing maps them to the candidate native instructions and owning frame.
    """
    old = [f for f in old_frames if f['stack_register'] == 'rbp' and f['stack_offset'] == 0x3E0]
    complete = len(old) == len(new_frames) == 1
    vectors = []
    for member, slot in (requirements if requirements is not None else ((0x5E8, 0x3C8), (0x600, 0x80))):
        matches = [p for p in stores if p['old']['field_offset'] == member
                   and p['old']['stack_offset'] == slot and p['old']['stack_register'] == 'rbp']
        choices = {(p['new']['field_offset'], p['new']['stack_offset'], p['new']['stack_register']) for p in matches}
        valid = len(choices) == 1
        complete = complete and valid
        vectors.append(dict(reviewed_field=member, reviewed_slot=slot, unique=valid,
                            candidate=list(next(iter(choices))) if valid else None, evidence=matches))
    return dict(local_dependencies_complete=complete, reviewed_game_slot=0x3E0,
        game_slot=new_frames[0]['stack_offset'] if len(new_frames) == 1 else None,
        stack_register=new_frames[0]['stack_register'] if len(new_frames) == 1 else None,
        vectors=vectors, automatic_activation_allowed=False,
        remaining_preconditions=['captured Game owns the restored pointers',
            'native continuation and skipped-path cleanup contracts remain valid'])


def pursuit_live_contract(before, old_rva, after, new_rva, old_hook, new_hook, game_slot,
                          before_image=None, after_image=None):
    """Match the native two-path interpolation defining the pursuit SIMD input.

    The starting saved-Game reload is discovered in the reviewed code. Runtime
    guards supply heap ownership; the paired slice proves the native arithmetic
    and register roles, including both interpolation and direct endpoint paths.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old = list(md.disasm(before, old_rva))
    index = next((i for i, ins in enumerate(old) if ins.address == old_hook), None)
    if index is None:
        return dict(local_roles_verified=False, reason='Pursuit hook is not an instruction boundary')
    starts = []
    for ins in old[max(0, index - 48):index]:
        op = ins.operands
        if (ins.mnemonic == 'mov' and len(op) == 2 and op[0].type == capstone.x86.X86_OP_REG
                and ins.reg_name(op[0].reg) == 'r13' and op[1].type == capstone.x86.X86_OP_MEM
                and ins.reg_name(op[1].mem.base) == 'rbp' and not op[1].mem.index and op[1].mem.disp == game_slot):
            starts.append(ins.address)
    if not starts:
        return dict(local_roles_verified=False, reason='No bounded saved Game reload before pursuit')
    start = starts[-1]
    mapped = interior_relocations(before, old_rva, [(new_rva, after)], [start])[hex(start)]['candidates']
    if len(mapped) != 1:
        return dict(local_roles_verified=False, reason='Ambiguous interpolation entry')
    target = int(mapped[0]['rva'], 16)
    contract = region_instruction_contract(before[start-old_rva:old_hook-old_rva], start,
        after[target-new_rva:new_hook-new_rva], target)
    valid = (contract.get('instruction_roles') and contract.get('internal_control_flow')
             and not contract.get('external_edges')
             and all(c.get('base') == 'rbp' for c in contract.get('field_changes', ())))
    old_slice = [i for i in old if start <= i.address < old_hook]
    new_slice = list(md.disasm(after[target-new_rva:new_hook-new_rva], target))
    constants = []
    if before_image is not None and after_image is not None and len(old_slice) == len(new_slice):
        for a, b in zip(old_slice, new_slice):
            for x, y in zip(a.operands, b.operands):
                if x.type == y.type == capstone.x86.X86_OP_MEM and a.reg_name(x.mem.base) == b.reg_name(y.mem.base) == 'rip':
                    old_data, new_data = a.address+a.size+x.mem.disp, b.address+b.size+y.mem.disp
                    left, right = before_image.get_data(old_data, x.size), after_image.get_data(new_data, y.size)
                    sections = (before_image.get_section_by_rva(old_data), after_image.get_section_by_rva(new_data))
                    constants.append(dict(old_rva=hex(old_data), new_rva=hex(new_data), width=x.size,
                        equal=left == right and len(left) == x.size,
                        readonly=all(s is not None and not s.Characteristics & 0x80000000 for s in sections),
                        reviewed_bytes=left.hex(), candidate_bytes=right.hex()))
    # These are explicit reviewed adapter roles, not inferred candidate fields.
    endpoints = {(i.reg_name(o.mem.base), o.mem.disp) for i in old_slice for o in i.operands
                 if o.type == capstone.x86.X86_OP_MEM and not o.mem.index}
    valid = bool(valid and {('rsi', x) for x in (0xFC, 0x108, 0x114, 0x118)} <= endpoints
        and any(i.mnemonic == 'mulps' and i.op_str.startswith('xmm15,') for i in old_slice)
        and any(i.mnemonic == 'movsd' and i.op_str.startswith('xmm15,') for i in old_slice))
    return dict(local_roles_verified=valid, native_slice=contract,
        constants=constants, constant_values_verified=bool(constants) and all(c['equal'] and c['readonly'] for c in constants),
        hook_rva=hex(new_hook), enemy_register='rsi', game_register='r13', xy_register='xmm15', z_register='xmm12',
        runtime_guards=[dict(kind='saved_game', stack_register='rbp', reviewed_slot=game_slot),
            dict(kind='enemy_member', register='rsi', reviewed_game_pointer_field=0x578, stride=0x148),
            dict(kind='game_clock', register='xmm7', reviewed_field=0x86C)],
        entry_dependencies=['XMM14 threshold and RIP-relative clamp constant retain reviewed values',
            'native entry reaches the paired interpolation slice; external indirect entry into its middle is not admitted'],
        automatic_activation_allowed=False)


def batch_write_contracts(code, address, serialize, write):
    """Locate the native serialized-batch write and its following UI Vec cleanup."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    result = []
    for index, call in enumerate(ins):
        if not (call.mnemonic == 'call' and call.operands[0].type == capstone.x86.X86_OP_IMM
                and call.operands[0].imm == write and index >= 4):
            continue
        a, b, c, d = ins[index - 4:index]
        if not (a.mnemonic == 'mov' and a.op_str.startswith('rcx, qword ptr [')
                and a.operands[1].type == capstone.x86.X86_OP_MEM and not a.operands[1].mem.index
                and b.mnemonic == 'add' and b.operands[0].type == capstone.x86.X86_OP_REG
                and b.reg_name(b.operands[0].reg) == 'rcx' and b.operands[1].type == capstone.x86.X86_OP_IMM
                and all(i.mnemonic == 'mov' and i.operands[1].type == capstone.x86.X86_OP_MEM
                        and not i.operands[1].mem.index for i in (c, d))
                and c.reg_name(c.operands[0].reg) == 'rdx' and d.reg_name(d.operands[0].reg) == 'r8'
                and c.operands[1].mem.base == d.operands[1].mem.base
                and c.reg_name(c.operands[1].mem.base) in ('rbp', 'rsp')
                and d.operands[1].mem.disp == c.operands[1].mem.disp + 8):
            continue
        serializers = [i for i in ins[max(0, index - 18):index - 4] if i.mnemonic == 'call'
                       and i.operands[0].type == capstone.x86.X86_OP_IMM and i.operands[0].imm == serialize]
        if len(serializers) != 1:
            continue
        vectors = []
        for j in range(index + 1, min(len(ins) - 4, index + 20)):
            loads = ins[j:j + 3]
            if not all(i.mnemonic == 'mov' and len(i.operands) == 2
                       and i.operands[0].type == capstone.x86.X86_OP_REG and i.operands[0].size == 8
                       and i.operands[1].type == capstone.x86.X86_OP_MEM and not i.operands[1].mem.index
                       for i in loads):
                continue
            memory = [i.operands[1].mem for i in loads]
            if (len({m.base for m in memory}) != 1 or loads[0].reg_name(memory[0].base) not in ('rsp', 'rbp')
                    or [m.disp for m in memory] != [memory[0].disp + n * 8 for n in range(3)]):
                continue
            # Vec element extent: count*3 followed by scale8 => 24 bytes.
            count_reg = loads[2].operands[0].reg
            scale, end = ins[j + 3:j + 5]
            if not (scale.mnemonic == 'lea' and scale.operands[1].type == capstone.x86.X86_OP_MEM
                    and scale.operands[1].mem.base == count_reg and scale.operands[1].mem.index == count_reg
                    and scale.operands[1].mem.scale == 2 and end.mnemonic == 'lea'
                    and end.operands[1].type == capstone.x86.X86_OP_MEM
                    and end.operands[1].mem.base == loads[1].operands[0].reg
                    and end.operands[1].mem.index == scale.operands[0].reg
                    and end.operands[1].mem.scale == 8):
                continue
            vectors.append(dict(stack_register=loads[0].reg_name(memory[0].base), capacity=memory[0].disp,
                                pointer=memory[1].disp, count=memory[2].disp, element_size=24))
        if len(vectors) == 1:
            result.append(dict(call_rva=hex(call.address), return_rva=hex(call.address + call.size),
                serializer_rva=hex(serializers[0].address), connection_register=a.reg_name(a.operands[1].mem.base),
                queue_field=a.operands[1].mem.disp, queue_offset=b.operands[1].imm,
                packet_stack_register=c.reg_name(c.operands[1].mem.base),
                packet_buffer_stack_offset=c.operands[1].mem.disp,
                packet_length_stack_offset=d.operands[1].mem.disp,
                ui_vector=vectors[0], local_batch_contract=True))
    return result


def server_vector_contracts(code, address):
    """Recover bounds-checked connection indexing and native Vec header roles."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    result = []
    for index, compare in enumerate(ins[:-7]):
        if not (compare.mnemonic == 'cmp' and len(compare.operands) == 2
                and compare.operands[0].type == capstone.x86.X86_OP_REG
                and compare.operands[1].type == capstone.x86.X86_OP_MEM
                and not compare.operands[1].mem.index and ins[index + 1].mnemonic == 'jae'):
            continue
        counter = compare.operands[0].reg
        member = compare.operands[1].mem
        for j in range(index + 2, index + 4):
            load, multiply, queue, adjust = ins[j:j + 4]
            if not (load.mnemonic == 'mov' and len(load.operands) == 2
                    and load.operands[0].type == capstone.x86.X86_OP_REG
                    and load.operands[1].type == capstone.x86.X86_OP_MEM
                    and load.operands[1].mem.base == member.base and not load.operands[1].mem.index
                    and load.operands[1].mem.disp + 8 == member.disp
                    and multiply.mnemonic == 'imul' and len(multiply.operands) == 3
                    and multiply.operands[1].type == capstone.x86.X86_OP_REG and multiply.operands[1].reg == counter
                    and multiply.operands[2].type == capstone.x86.X86_OP_IMM
                    and queue.mnemonic == 'mov' and len(queue.operands) == 2
                    and queue.reg_name(queue.operands[0].reg) == 'rdx'
                    and queue.operands[1].type == capstone.x86.X86_OP_MEM
                    and queue.operands[1].mem.base == load.operands[0].reg
                    and queue.operands[1].mem.index == multiply.operands[0].reg
                    and queue.operands[1].mem.scale == 1
                    and adjust.mnemonic == 'add' and adjust.reg_name(adjust.operands[0].reg) == 'rdx'
                    and adjust.operands[1].type == capstone.x86.X86_OP_IMM):
                continue
            capacity = member.disp - 16
            # Vec reserve receives the capacity/ptr/len header itself.
            headers = [i for i in ins if i.mnemonic == 'lea' and len(i.operands) == 2
                       and i.operands[1].type == capstone.x86.X86_OP_MEM
                       and i.reg_name(i.operands[1].mem.base) in (compare.reg_name(member.base), 'rcx')
                       and not i.operands[1].mem.index
                       and i.operands[1].mem.disp == capacity]
            if not headers or not 0 <= queue.operands[1].mem.disp < multiply.operands[2].imm:
                continue
            result.append(dict(bounds_site=hex(compare.address), server_register=compare.reg_name(member.base),
                capacity_field=capacity, pointer_field=member.disp - 8, count_field=member.disp,
                element_size=multiply.operands[2].imm, receive_queue_field=queue.operands[1].mem.disp,
                queue_offset=adjust.operands[1].imm, header_sites=[hex(i.address) for i in headers],
                local_vector_contract=True, heap_ownership_verified=False,
                runtime_preconditions=['server_register equals captured TICK RCX',
                    'SERIALIZE RCX equals an aligned element of this vector', '0 <= length <= capacity']))
    return result


def embedded_game_contracts(code, address, update):
    """Trace the Game update argument through its uniquely written frame slot."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    result = []
    for index, call in enumerate(ins):
        if not (call.mnemonic == 'call' and call.operands[0].type == capstone.x86.X86_OP_IMM
                and call.operands[0].imm == update and index >= 2):
            continue
        argument = ins[index - 2]
        if not (argument.mnemonic == 'mov' and len(argument.operands) == 2
                and argument.reg_name(argument.operands[0].reg) == 'rcx'
                and argument.operands[1].type == capstone.x86.X86_OP_REG
                and ins[index - 1].mnemonic == 'movaps' and ins[index - 1].op_str.startswith('xmm1,')):
            continue
        register = argument.operands[1].reg
        writers = [i for i in ins[:index - 2] if register in i.regs_access()[1]]
        if not writers:
            continue
        load = writers[-1]
        if not (load.mnemonic == 'mov' and load.operands[1].type == capstone.x86.X86_OP_MEM
                and load.reg_name(load.operands[1].mem.base) in ('rbp', 'rsp') and not load.operands[1].mem.index):
            continue
        slot = load.operands[1].mem
        stores = [(j, i) for j, i in enumerate(ins) if any(o.type == capstone.x86.X86_OP_MEM
                  and o.access & capstone.CS_AC_WRITE and o.mem.base == slot.base and not o.mem.index
                  and o.mem.disp < slot.disp + 8 and o.mem.disp + o.size > slot.disp for o in i.operands)]
        if len(stores) != 1:
            continue
        j, store = stores[0]
        if not (j > 0 and store.mnemonic == 'mov' and store.operands[1].type == capstone.x86.X86_OP_REG):
            continue
        derive = ins[j - 1]
        if not (derive.mnemonic == 'lea' and derive.operands[0].reg == store.operands[1].reg
                and derive.operands[1].type == capstone.x86.X86_OP_MEM and not derive.operands[1].mem.index):
            continue
        result.append(dict(call_rva=hex(call.address), update_rva=hex(update),
            game_offset=derive.operands[1].mem.disp, server_register=derive.reg_name(derive.operands[1].mem.base),
            derive_site=hex(derive.address), spill_site=hex(store.address), reload_site=hex(load.address),
            stack_register=load.reg_name(slot.base), stack_offset=slot.disp,
            game_register=argument.reg_name(register), argument='rcx', frame_slot_writes=1,
            heap_ownership_verified=False,
            runtime_precondition='Game update RCX equals captured TICK RCX + game_offset'))
    return result


def structural_relocations(reference, binary, targets):
    """Discover moved functions with changed fields, preserving ambiguity.

    Unlike the legacy research command, no hand-selected addresses or masked
    gameplay immediates select a candidate. Full function comparisons decide
    whether a unique prefix match is structurally equivalent.
    """
    old, new = pefile.PE(str(reference), fast_load=True), pefile.PE(str(binary), fast_load=True)
    old_ranges, new_ranges = unwind_ranges(old), unwind_ranges(new)
    starts, new_starts = [s for s, _ in old_ranges], [s for s, _ in new_ranges]
    new_ends = dict(new_ranges)
    sections = [(s.VirtualAddress, s.get_data()) for s in new.sections if s.Characteristics & 0x20000000]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    groups = {}
    for target in targets:
        i = bisect.bisect_right(starts, target) - 1
        if i >= 0 and target < old_ranges[i][1]:
            groups.setdefault(old_ranges[i], []).append(target)
    rows = {}
    for (start, end), members in groups.items():
        code = old.get_data(start, end - start)
        ins = list(md.disasm(code, start))
        votes = Counter()
        # Several independent windows survive insertions or an altered prolog.
        sampled = {0, len(ins) // 4, len(ins) // 2, 3 * len(ins) // 4}
        def collect_windows(indices):
            for index in indices:
                window = ins[index:index + 20]
                if len(window) < 8:
                    continue
                pattern = instruction_pattern(window, preserve_immediates=True)
                matched_functions = set()
                for base, data in sections:
                    for match in pattern.finditer(data):
                        address = base + match.start()
                        i = bisect.bisect_right(new_starts, address) - 1
                        if i >= 0 and address < new_ends[new_starts[i]]:
                            matched_functions.add(new_starts[i])
                # Repeated copies of one window are not independent anchors.
                votes.update(matched_functions)
        collect_windows(sorted(sampled))
        if not any(count >= 2 for count in votes.values()):
            # Changed prologs and insertions can invalidate all four samples.
            # Broader discovery still preserves immediates and proves nothing.
            collect_windows(index for index in range(0, len(ins), 20) if index not in sampled)
        candidates = []
        for candidate, count in votes.most_common():
            if count < 2:
                continue
            comparison = compare_function_layout(code, start,
                new.get_data(candidate, new_ends[candidate] - candidate), candidate)
            candidates.append(dict(rva=hex(candidate), matching_windows=count, **comparison))
        equivalent = [row for row in candidates if row['structure_equivalent']]
        rows[hex(start)] = dict(targets=[hex(t) for t in members], candidates=candidates,
            unique_structure=len(equivalent) == 1, automatic_activation_allowed=False)
    mapped = {int(start, 16): int(next(c for c in row['candidates']
               if c['structure_equivalent'])['rva'], 16)
              for start, row in rows.items() if row['unique_structure']}
    # Changed/split functions can still be located from already matched callees.
    # Decode candidate callers to reject E8 bytes inside data/immediate operands.
    callers, decoded = {}, {}
    destinations = set(mapped.values())
    for base, data in sections:
        cursor = 0
        while (position := data.find(b'\xe8', cursor)) >= 0:
            cursor = position + 1
            if position + 5 > len(data):
                break
            address = base + position
            target = address + 5 + struct.unpack_from('<i', data, position + 1)[0]
            if target not in destinations:
                continue
            i = bisect.bisect_right(new_starts, address) - 1
            if i < 0 or address >= new_ends[new_starts[i]]:
                continue
            caller = new_starts[i]
            if caller not in decoded:
                decoded[caller] = {ins.address: ins for ins in md.disasm(
                    new.get_data(caller, new_ends[caller] - caller), caller)}
            ins = decoded[caller].get(address)
            if ins is not None and ins.mnemonic == 'call' and ins.operands[0].imm == target:
                callers.setdefault(target, []).append((caller, address))
    for (start, end), _ in groups.items():
        row = rows[hex(start)]
        if row['unique_structure']:
            continue
        anchors = {mapped[ins.operands[0].imm] for ins in md.disasm(old.get_data(start, end - start), start)
                   if ins.mnemonic == 'call' and ins.operands[0].type == capstone.x86.X86_OP_IMM
                   and ins.operands[0].imm in mapped}
        evidence = {}
        for target in anchors:
            for caller, address in callers.get(target, ()):
                evidence.setdefault(caller, []).append(dict(site=hex(address), target=hex(target)))
        row['call_graph_candidates'] = [dict(rva=hex(caller), size=new_ends[caller] - caller,
            distinct_anchors=len({hit['target'] for hit in hits}), calls=hits)
            for caller, hits in sorted(evidence.items(), key=lambda item: -len(item[1]))]
    for (start, end), members in groups.items():
        row = rows[hex(start)]
        possible = {int(c['rva'], 16) for c in row['candidates'] + row.get('call_graph_candidates', [])}
        row['interior_candidates'] = interior_relocations(old.get_data(start, end - start), start,
            [(s, new.get_data(s, new_ends[s] - s)) for s in sorted(possible)], members)
    covered = {target for members in groups.values() for target in members}
    for target in sorted(set(targets) - covered):
        rows[hex(target)] = dict(targets=[hex(target)], candidates=[], unique_structure=False,
            automatic_activation_allowed=False, reason='Data or code without native unwind bounds',
            interior_candidates={hex(target): dict(candidates=[], automatic_activation_allowed=False)})
    return rows


def typed_reviewed_references(folder, image):
    """Inventory explicit reviewed-address APIs, excluding legacy literals."""
    rows = []
    def record(path, node, value, contract):
        if type(value) is int and 0x1000 <= value < image.OPTIONAL_HEADER.SizeOfImage:
            rows.append(dict(file=path.name, line=node.lineno, rva=value, contract=contract))
    for path in sorted(Path(folder).glob('*.py')):
        if path.name.startswith(('test_', 'verify_')):
            continue
        tree = ast.parse(path.read_text(encoding='utf-8'))
        constants = {node.targets[0].id: node.value.value for node in tree.body
                     if isinstance(node, ast.Assign) and len(node.targets) == 1
                     and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                count = {'reviewed_rva': 1, 'reviewed_bytes': 1, 'reviewed_branch': 2}.get(node.func.id, 0)
                for argument in node.args[:count]:
                    value = (argument.value if isinstance(argument, ast.Constant)
                             else constants.get(argument.id) if isinstance(argument, ast.Name) else None)
                    record(path, argument, value, node.func.id)
        if path.name == 'boss_rewards.py':
            # This module is updated-only; its named native dependencies are
            # passed through the local reviewed_rva call wrapper. Game fields
            # are below 0x1000 and do not enter the executable-address inventory.
            for node in tree.body:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                    record(path, node, node.value.value, 'updated-only native dependency')
        if path.name == 'visibility_bridge.py':
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'guest_damage_patches')
            updated = next(n for n in function.body if isinstance(n, ast.If)
                           and isinstance(n.test, ast.Name) and n.test.id == 'UPDATED')
            for statement in updated.body:
                for node in ast.walk(statement):
                    if isinstance(node, ast.Constant) and type(node.value) is int and node.value >= 0x5000000:
                        record(path, node, node.value, 'updated guest damage patch')
    return rows


def memory_write_operand(ins, index):
    """Compensate for missing Capstone access flags on SIMD MOV stores."""
    operand=ins.operands[index]
    if operand.type!=capstone.x86.X86_OP_MEM:return False
    if operand.access & capstone.CS_AC_WRITE:return True
    return index==0 and ins.mnemonic in (
        'mov','movabs','movss','movsd','movups','movaps','movupd','movapd',
        'movd','movq','movdqu','movdqa','vmovss','vmovsd','vmovups','vmovaps',
        'vmovupd','vmovapd','vmovd','vmovq','vmovdqu','vmovdqa')


def paired_store_fields(old_code,old_address,new_code,new_address,old_edges,new_edges):
    """Require typed Game ownership for changed displacements in aligned stores."""
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    before,after=list(md.disasm(old_code,old_address)),list(md.disasm(new_code,new_address))
    keys=lambda seq:[instruction_pattern([i],preserve_immediates=True).pattern for i in seq]
    old_uses=game_field_uses(old_code,old_address,indirect_edges=old_edges,pointer_immediates=True)
    new_uses=game_field_uses(new_code,new_address,indirect_edges=new_edges,pointer_immediates=True)
    def frame_bounds(stream):
        if not private_frame_slots(stream):return None
        for n,ins in enumerate(stream[:24]):
            if (ins.mnemonic=='lea' and ins.op_str.startswith('rbp, [rsp') and n
                    and stream[n-1].mnemonic=='sub' and stream[n-1].op_str.startswith('rsp, ')
                    and stream[n-1].operands[1].type==capstone.x86.X86_OP_IMM):
                delta=ins.operands[1].mem.disp
                return 32-delta,stream[n-1].operands[1].imm-delta
        return None
    frames=[frame_bounds(before),frame_bounds(after)]
    changed=[];native_frame=[];unresolved=[];unchanged=0
    for match in difflib.SequenceMatcher(None,keys(before),keys(after),autojunk=False).get_matching_blocks():
        for a,b in zip(before[match.a:match.a+match.size],after[match.b:match.b+match.size]):
            for index,operand in enumerate(a.operands):
                if not memory_write_operand(a,index):continue
                peer=b.operands[index]
                if (operand.type!=peer.type or operand.size!=peer.size or operand.mem.base!=peer.mem.base
                        or operand.mem.index!=peer.mem.index or operand.mem.scale!=peer.mem.scale):
                    unresolved.append(dict(reference=a.address,candidate=b.address,reason='store addressing role changed'));continue
                if operand.mem.disp==peer.mem.disp:
                    unchanged+=1;continue
                aa,bb=old_uses.get((a.address,index)),new_uses.get((b.address,index))
                if aa and bb:
                    changed.append(dict(reference=a.address,candidate=b.address,reference_field=aa['offset'],
                        candidate_field=bb['offset'],width=operand.size,owner='game'))
                elif (a.reg_name(operand.mem.base)==b.reg_name(peer.mem.base)=='rbp'
                      and not operand.mem.index and all(frames)
                      and frames[0][0]<=operand.mem.disp<=frames[0][1]-operand.size
                      and frames[1][0]<=peer.mem.disp<=frames[1][1]-peer.size):
                    native_frame.append(dict(reference=a.address,candidate=b.address,
                        reference_offset=operand.mem.disp,candidate_offset=peer.mem.disp,
                        width=operand.size,owner='native_fixed_frame',runtime_field_mapping=False))
                else:unresolved.append(dict(reference=a.address,candidate=b.address,
                    reason='changed store field lacks paired Game owner',reference_displacement=operand.mem.disp,
                    candidate_displacement=peer.mem.disp))
    return dict(unchanged_store_operands=unchanged,changed_game_stores=changed,
                native_frame_stores=native_frame,unresolved=unresolved,
                conditional_on_installed_dispatch_guards=True,automatic_activation_allowed=False)


def frame_value_reads(code,address,start,slot,width,indirect_edges):
    """Trace remaining bytes of one fixed-frame value until overwritten.

    Partial overwrites retain the untouched bytes. Returned reads/LEAs are
    obligations for the caller, never an implicit escape whitelist.
    """
    if not 0<width<=32:raise ValueError('Frame value width outside bounded analysis')
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    decoded={i.address:i for i in md.disasm(code,address)}
    setups=[i.operands[1].mem.disp for i in decoded.values() if i.mnemonic=='lea'
            and len(i.operands)==2 and i.reg_name(i.operands[0].reg)=='rbp'
            and i.operands[1].type==capstone.x86.X86_OP_MEM
            and i.reg_name(i.operands[1].mem.base)=='rsp' and not i.operands[1].mem.index]
    frame_delta=setups[0] if len(setups)==1 else None
    pending=[(start,(1<<width)-1)];seen=set();reads={};escapes=set();kills=set()
    while pending:
        site,mask=pending.pop()
        if (site,mask) in seen:continue
        if len(seen)>=200000:raise ValueError('Frame byte liveness exceeds bounded analysis')
        seen.add((site,mask));ins=decoded.get(site)
        if ins is None:raise ValueError('Frame liveness leaves decoded native body')
        for index,operand in enumerate(ins.operands):
            if operand.type!=capstone.x86.X86_OP_MEM or ins.reg_name(operand.mem.base) not in ('rbp','rsp'):continue
            if operand.mem.index:raise ValueError('Indexed frame access has unbounded alias')
            offset=operand.mem.disp
            if ins.reg_name(operand.mem.base)=='rsp':
                if frame_delta is None:raise ValueError('Stack pointer access needs a fixed native frame')
                offset-=frame_delta
            bits=sum(1<<j for j in range(width) if offset<=slot+j<offset+operand.size)
            if ins.mnemonic=='lea':
                if slot<=offset<slot+width:escapes.add(site)
            elif bits&mask:
                if memory_write_operand(ins,index):mask&=~bits;kills.add(site)
                else:reads[site]=reads.get(site,0)|(bits&mask)
        if not mask:continue
        if ins.mnemonic=='jmp':
            successors=([ins.operands[0].imm] if ins.operands[0].type==capstone.x86.X86_OP_IMM
                        else indirect_edges.get(site))
            if not successors:raise ValueError('Frame liveness requires proved indirect edges')
        elif ins.group(capstone.CS_GRP_JUMP):successors=[ins.operands[0].imm,site+ins.size]
        elif ins.mnemonic in ('ret','ud2','int3'):successors=[]
        else:successors=[site+ins.size]
        pending.extend((target,mask) for target in successors)
    return dict(reads=[dict(rva=site,byte_mask=mask) for site,mask in sorted(reads.items())],
                address_escapes=sorted(escapes),overwrites=sorted(kills),visited_states=len(seen))


def mutation_footprint(old_code, old_address, new_code, new_address):
    """Inventory every changed native store/call, without guessing heap owners.

    Alignment preserves scalar immediates; address/field relocations are handled
    elsewhere. A nearest lexical register definition is evidence for an owner
    probe, never a must-alias proof across incoming branches.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    old, new = list(md.disasm(old_code, old_address)), list(md.disasm(new_code, new_address))
    keys = lambda seq: [instruction_pattern([i], preserve_immediates=True).pattern for i in seq]
    changed = set()
    for tag, _, _, first, end in difflib.SequenceMatcher(None, keys(old), keys(new), autojunk=False).get_opcodes():
        if tag != 'equal':
            changed.update(range(first, end))
    def definition(index, register):
        for ins in reversed(new[max(0, index - 96):index]):
            if ins.group(capstone.CS_GRP_CALL) and register in ('rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'):
                return dict(rva=hex(ins.address), instruction=ins.mnemonic + ' ' + ins.op_str,
                            kind='call_result' if register == 'rax' else 'call_clobber')
            writes = [ins.reg_name(r) for r in ins.regs_access()[1]]
            aliases = {register, 'e' + register[1:] if register in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp') else register + 'd'}
            if aliases.intersection(writes):
                return dict(rva=hex(ins.address), instruction=ins.mnemonic + ' ' + ins.op_str, kind='lexical_definition')
        return None
    stores, calls = [], []
    for index in sorted(changed):
        ins = new[index]
        if ins.group(capstone.CS_GRP_CALL):
            calls.append(dict(rva=hex(ins.address), instruction=ins.mnemonic + ' ' + ins.op_str,
                target=hex(ins.operands[0].imm) if ins.operands[0].type == capstone.x86.X86_OP_IMM else None,
                arguments={reg: definition(index, reg) for reg in ('rcx', 'rdx', 'r8', 'r9')},
                requires='callee write/escape summary or independently verified native behavior'))
        for operand_index,op in enumerate(ins.operands):
            if not memory_write_operand(ins,operand_index):
                continue
            base, offset = ins.reg_name(op.mem.base), op.mem.disp
            stack = base in ('rbp', 'rsp') and not op.mem.index
            stores.append(dict(rva=hex(ins.address), instruction=ins.mnemonic + ' ' + ins.op_str,
                expected_bytes=ins.bytes.hex(), base=base, index=ins.reg_name(op.mem.index),
                scale=op.mem.scale, offset=offset, width=op.size,
                destination='fixed_frame' if stack else 'unproven_heap_owner',
                source_kind='scalar_simd' if ins.mnemonic in ('movss', 'movsd') else 'integer_or_pointer',
                full_pointer_width=op.size == 8,
                lexical_base_definition=None if stack else definition(index, base)))
    nonstack = [s for s in stores if s['destination'] != 'fixed_frame']
    return dict(changed_instruction_count=len(changed), stores=stores, calls=calls,
        nonstack_store_count=len(nonstack),
        pointer_width_store_count=sum(s['full_pointer_width'] for s in nonstack),
        complete_owner_proof=not nonstack and not calls,
        automatic_activation_allowed=False,
        limitation='Lexical definitions do not prove CFG dominance; heap writes and callee escapes remain explicit obligations. Narrow scalar stores do not establish Enemy ownership.')


def return_tag_values(code, address):
    """Prove finite AL values on every return of a bounded no-call leaf CFG."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    decoded = {i.address: i for i in md.disasm(code, address)}
    incoming, pending, returned = {address: frozenset({None})}, [address], set()
    while pending:
        site = pending.pop()
        ins = decoded.get(site)
        if ins is None or ins.group(capstone.CS_GRP_CALL):
            return None
        values = incoming[site]
        if ins.mnemonic == 'ret':
            if None in values:
                return None
            returned.update(values)
            continue
        op = ins.operands
        if any(ins.reg_name(r) in ('rax', 'eax', 'ax', 'al') for r in ins.regs_access()[1]):
            if (ins.mnemonic == 'mov' and len(op) == 2 and op[0].type == capstone.x86.X86_OP_REG
                    and ins.reg_name(op[0].reg) in ('rax', 'eax', 'ax', 'al') and op[1].type == capstone.x86.X86_OP_IMM):
                values = frozenset({op[1].imm & 255})
            elif (ins.mnemonic == 'xor' and len(op) == 2 and op[0].type == op[1].type == capstone.x86.X86_OP_REG
                  and op[0].reg == op[1].reg):
                values = frozenset({0})
            else:
                values = frozenset({None})
        targets = [site + ins.size]
        if ins.group(capstone.CS_GRP_JUMP):
            if op[0].type != capstone.x86.X86_OP_IMM:
                return None
            targets = [op[0].imm] + ([] if ins.mnemonic == 'jmp' else targets)
        for target in targets:
            joined = incoming.get(target, frozenset()) | values
            if joined != incoming.get(target):
                incoming[target] = joined
                pending.append(target)
    return sorted(returned) if returned else None


def return_tag_switches(image, code, address):
    """Discover typed jump-table edges from a proven finite leaf return tag."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    boundaries = {i.address for i in ins}
    result = []
    for index in range(6, len(ins)):
        jump = ins[index]
        if jump.mnemonic != 'jmp' or jump.op_str != 'rax':
            continue
        call, nop, tag, table, load, add = ins[index-6:index]
        if not (call.mnemonic == 'call' and call.operands[0].type == capstone.x86.X86_OP_IMM
                and nop.mnemonic == 'nop' and tag.mnemonic == 'movzx' and tag.op_str == 'eax, al'
                and table.mnemonic == 'lea' and table.reg_name(table.operands[0].reg) == 'rcx'
                and table.operands[1].type == capstone.x86.X86_OP_MEM
                and table.reg_name(table.operands[1].mem.base) == 'rip'
                and load.mnemonic == 'movsxd' and load.op_str == 'rax, dword ptr [rcx + rax*4]'
                and add.mnemonic == 'add' and add.op_str == 'rax, rcx'):
            continue
        callee = call.operands[0].imm
        tags = return_tag_values(image.get_data(callee, 4096), callee)
        if tags is None or len(tags) > 64:
            continue
        table_rva = table.address + table.size + table.operands[1].mem.disp
        section = image.get_section_by_rva(table_rva)
        if (section is None or section.Characteristics & 0x80000000
                or table_rva + (max(tags) + 1)*4 > section.VirtualAddress + section.Misc_VirtualSize):
            continue
        targets = {tag: table_rva + struct.unpack('<i', image.get_data(table_rva + tag*4, 4))[0] for tag in tags}
        if not all(target in boundaries for target in targets.values()):
            continue
        result.append(dict(jump=hex(jump.address), producer=hex(callee), table=hex(table_rva), tags=tags,
            targets={str(tag): hex(target) for tag, target in targets.items()},
            finite_return_domain_verified=True, readonly_table_verified=True,
            automatic_activation_allowed=False))
    return result


def ability_cast_copies(code, address):
    """Find native 24-byte definition copies into Cast[32] after its Enemy ID.

    This proves tag offset preservation, not the source definition's enum domain;
    immutable definition data and the producer's bounds checks are separate.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    copies = []
    for index in range(5, len(ins)-5):
        pointer, cursor, scale, enemy, store_enemy = ins[index-5:index]
        first, store_first, second, store_second, increment, length = ins[index:index+6]
        if not (pointer.mnemonic == 'mov' and pointer.op_str.startswith('rax, qword ptr [rbp + ')
                and cursor.mnemonic == 'mov' and cursor.op_str.startswith('rcx, ')
                and cursor.operands[1].type == capstone.x86.X86_OP_REG
                and scale.mnemonic == 'shl' and scale.op_str == 'rcx, 5'
                and enemy.mnemonic == 'mov' and enemy.op_str.startswith('rdx, qword ptr [rbp + ')
                and store_enemy.mnemonic == 'mov' and store_enemy.op_str == 'qword ptr [rax + rcx], rdx'
                and first.mnemonic in ('movups', 'movaps') and first.operands[0].type == capstone.x86.X86_OP_REG
                and first.reg_name(first.operands[0].reg) == 'xmm0' and first.operands[1].type == capstone.x86.X86_OP_MEM
                and not first.operands[1].mem.index
                and store_first.mnemonic == 'movups' and store_first.op_str == 'xmmword ptr [rax + rcx + 8], xmm0'
                and second.mnemonic == 'mov' and second.reg_name(second.operands[0].reg) == 'rdx'
                and second.operands[1].type == capstone.x86.X86_OP_MEM
                and second.operands[1].mem.base == first.operands[1].mem.base
                and not second.operands[1].mem.index
                and second.operands[1].mem.disp == first.operands[1].mem.disp + 16
                and store_second.mnemonic == 'mov' and store_second.op_str == 'qword ptr [rax + rcx + 0x18], rdx'
                and increment.mnemonic == 'inc' and increment.operands[0].reg == cursor.operands[1].reg
                and length.mnemonic == 'mov' and length.operands[0].type == capstone.x86.X86_OP_MEM
                and length.reg_name(length.operands[0].mem.base) == 'rbp' and not length.operands[0].mem.index
                and length.operands[1].type == capstone.x86.X86_OP_REG
                and length.operands[1].reg == cursor.operands[1].reg
                and length.operands[0].mem.disp == pointer.operands[1].mem.disp + 8):
            continue
        source = first.operands[1].mem
        row = dict(copy_site=hex(first.address), pointer_slot=pointer.operands[1].mem.disp,
            length_slot=length.operands[0].mem.disp, stack_register='rbp', cast_stride=32,
            source_register=first.reg_name(source.base), source_offset=source.disp,
            source_bytes=24, definition_tag_offset=0, cast_tag_offset=8,
            source_domain_verified=False, automatic_activation_allowed=False)
        if index >= 7:
            base, add = ins[index-7:index-5]
            if (base.mnemonic == 'lea' and base.reg_name(base.operands[0].reg) == 'rax'
                    and base.operands[1].type == capstone.x86.X86_OP_MEM
                    and base.reg_name(base.operands[1].mem.base) == 'rip'
                    and add.mnemonic == 'add' and add.op_str == row['source_register'] + ', rax'):
                row['builtin_table'] = hex(base.address + base.size + base.operands[1].mem.disp)
        copies.append(row)
    return copies


def guarded_update_dispatches(old, new, before, old_rva, after, new_rva):
    """Pair native dispatch edges whose finite bounds are enforced at runtime."""
    specs = [('cast_tag', 0x53f09c4, 0x53f09c6, 0x53f09db, 5, 16),
             ('loot_tag', 0x53f282b, 0x53f23fb, 0x53f2835, 7, 12)]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    decoded = {i.address:i for i in md.disasm(before, old_rva)}
    original_tables = {}
    targets = set()
    for kind, site, lea_site, jump, count, size in specs:
        lea = decoded.get(lea_site)
        if lea is None or lea.mnemonic != 'lea' or lea.reg_name(lea.operands[1].mem.base) != 'rip':
            raise ValueError('Reviewed guarded native table source changed')
        table = lea.address+lea.size+lea.operands[1].mem.disp
        section = old.get_section_by_rva(table)
        if section is None or section.Characteristics & (0x20000000|0x80000000):
            raise ValueError('Reviewed guarded native table is not immutable')
        edges = [table+x[0] for x in struct.iter_unpack('<i',old.get_data(table,count*4))]
        if any(edge not in decoded for edge in edges):
            raise ValueError('Guarded native table has an out-of-function edge')
        original_tables[kind] = (table,edges)
        targets.update([site,lea_site,jump,site+size,*edges])
    mapped = interior_relocations(before,old_rva,[(new_rva,after)],targets)
    translations = {}
    for address in targets:
        candidates = mapped[hex(address)]['candidates']
        if len(candidates) != 1:
            raise ValueError(f'Ambiguous guarded native dispatch anchor {address:x}')
        translations[address] = int(candidates[0]['rva'],16)
    new_decoded = {i.address:i for i in md.disasm(after,new_rva)}
    contracts, old_edges, new_edges = [], {}, {}
    for kind,site,lea_site,jump,count,size in specs:
        paired = translations[site]
        lea = new_decoded[translations[lea_site]]
        table = lea.address+lea.size+lea.operands[1].mem.disp
        section = new.get_section_by_rva(table)
        if (section is None or section.Characteristics & (0x20000000|0x80000000)
                or table+count*4 > section.VirtualAddress+section.Misc_VirtualSize):
            raise ValueError('Candidate guarded native table is not bounded immutable data')
        edges = [table+x[0] for x in struct.iter_unpack('<i',new.get_data(table,count*4))]
        if edges != [translations[x] for x in original_tables[kind][1]]:
            raise ValueError('Candidate guarded native switch targets changed')
        if translations[site+size] != paired+size:
            raise ValueError('Native dispatch patch instruction extent changed')
        expected = new.get_data(paired,size)
        if kind == 'cast_tag':
            if expected[:5] != bytes.fromhex('89d24c8d15') or expected[9:] != bytes.fromhex('496314924c01d2'):
                raise ValueError('Native cast dispatch register roles changed')
        elif expected != bytes.fromhex('89f849634485004c01e8ffe0'):
            raise ValueError('Native loot dispatch register roles changed')
        old_edges[jump] = original_tables[kind][1]
        new_edges[translations[jump]] = edges
        contracts.append(dict(kind=kind,rva=paired,reference_rva=site,
            expected=expected.hex(),table_rva=table,maximum=count-1,
            continuation_rva=paired+size,mandatory_runtime_guard=True,
            guarded_register='edx' if kind=='cast_tag' else 'edi',
            table_register='r10' if kind=='cast_tag' else 'r13',
            native_global_domain_proven=False))
    return dict(contracts=contracts,reference_edges=old_edges,candidate_edges=new_edges,
                conditional_on_installed_guards=True,automatic_activation_allowed=False)


def changed_store_owners(code, address, indirect_edges, stores):
    """Classify changed destinations using all guarded CFG reaching definitions.

    Native vector/allocator contracts remain explicit dependencies. This proves
    which owned container receives a write, not an arbitrary allocator ABI.
    """
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    md.detail=True
    stream=list(md.disasm(code,address)); decoded={i.address:i for i in stream}
    positions={i.address:n for n,i in enumerate(stream)}
    uses=game_field_uses(code,address,indirect_edges=indirect_edges,pointer_immediates=True)
    predecessors={site:set() for site in decoded}
    for ins in stream:
        successors=[]
        if ins.mnemonic=='jmp':
            successors=([ins.operands[0].imm] if ins.operands[0].type==capstone.x86.X86_OP_IMM
                        else indirect_edges.get(ins.address,[]))
            if ins.operands[0].type!=capstone.x86.X86_OP_IMM and not successors:
                raise ValueError('Changed-write owner proof lacks guarded dispatch edges')
        elif ins.group(capstone.CS_GRP_JUMP):
            successors=[ins.operands[0].imm,ins.address+ins.size]
        elif ins.mnemonic not in ('ret','ud2','int3'):
            successors=[ins.address+ins.size]
        for target in successors:
            if target in predecessors:predecessors[target].add(ins.address)
    families=('rax eax ax al ah','rbx ebx bx bl bh','rcx ecx cx cl ch','rdx edx dx dl dh',
              'rsi esi si sil','rdi edi di dil','rbp ebp bp bpl','rsp esp sp spl')
    def root(reg):
        for family in families:
            if reg in family.split():return family.split()[0]
        return reg.rstrip('dwb') if re.fullmatch(r'r(?:[89]|1[0-5])[dwb]?',reg) else reg
    def definitions(site,register):
        pending=list(predecessors[site]); seen=set(); found=set()
        if not pending:return []
        while pending:
            current=pending.pop()
            if current in seen:continue
            seen.add(current); ins=decoded[current]
            writes={root(ins.reg_name(r)) for r in ins.regs_access()[1]}
            if ins.group(capstone.CS_GRP_CALL):writes.update(('rax','rcx','rdx','r8','r9','r10','r11'))
            if register in writes:found.add(current);continue
            if not predecessors[current]:return []
            pending.extend(predecessors[current])
        return [decoded[x] for x in sorted(found)]
    results=[]
    for store in stores:
        if store['destination']!='unproven_heap_owner':continue
        site=int(store['rva'],16); ins=decoded[site]; mem=ins.operands[0].mem
        direct=uses.get((site,0))
        if direct:
            results.append(dict(rva=store['rva'],kind='game',field=direct['offset'],width=store['width']))
            continue
        defs=definitions(site,ins.reg_name(mem.base))
        row=dict(rva=store['rva'],kind='unresolved',reaching_definitions=[hex(d.address) for d in defs])
        if len(defs)==1:
            source=defs[0]; owner=uses.get((source.address,1))
            if (source.mnemonic=='mov' and owner and source.operands[0].size==8
                    and source.operands[1].type==capstone.x86.X86_OP_MEM):
                row.update(kind='game_vector_member',pointer_field=owner['offset'],
                    member_offset=mem.disp,width=store['width'],index_register=ins.reg_name(mem.index),
                    requires_native_vector_contract=True)
                if mem.index:
                    index_defs=definitions(site,ins.reg_name(mem.index))
                    row['index_definitions']=[dict(rva=hex(d.address),instruction=d.mnemonic+' '+d.op_str) for d in index_defs]
                    if len(index_defs)==1 and index_defs[0].mnemonic=='shl' and index_defs[0].operands[1].type==capstone.x86.X86_OP_IMM:
                        shift=index_defs[0]; before_shift=definitions(shift.address,ins.reg_name(mem.index))
                        row['index_scale']=1<<shift.operands[1].imm
                        row['index_source']=[dict(rva=hex(d.address),instruction=d.mnemonic+' '+d.op_str) for d in before_shift]
            elif source.mnemonic=='call' and source.operands[0].type==capstone.x86.X86_OP_IMM and ins.reg_name(mem.base)=='rax' and not mem.index:
                size_defs,align_defs=definitions(source.address,'rcx'),definitions(source.address,'rdx')
                if all(len(items)==1 and items[0].mnemonic=='mov' and items[0].operands[1].type==capstone.x86.X86_OP_IMM for items in (size_defs,align_defs)):
                    size,alignment=size_defs[0].operands[1].imm,align_defs[0].operands[1].imm
                    if 0<=mem.disp and mem.disp+store['width']<=size<=4096:
                        row.update(kind='allocation_body',allocator=source.operands[0].imm,size=size,
                            alignment=alignment,member_offset=mem.disp,width=store['width'],
                            requires_allocator_return_contract=True)
        results.append(row)
    return dict(stores=results,all_destinations_classified=all(r['kind']!='unresolved' for r in results),
                conditional_on_installed_dispatch_guards=True,automatic_activation_allowed=False)


def collect_region_inputs(old, new, regions, required_addresses, required_patches):
    """Materialize exact inputs from independently admitted paired code regions.

    Admission (Game/frame ownership, callees, runtime guards) belongs to the
    caller. This collector never expands an admitted region into an identity
    fallback or authorizes activation. It rechecks instruction pairing and only
    emits requested addresses and exact contiguous patch preconditions.
    """
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    pairs=[]
    for region in regions:
        if region.get('admitted') is not True or not region.get('contract_id'):
            raise ValueError('Exact input collection requires an admitted region contract')
        a,b,c,d=(int(region[k],16) if isinstance(region[k],str) else region[k]
                 for k in ('old_start','old_end','new_start','new_end'))
        before,after=old.get_data(a,b-a),new.get_data(c,d-c)
        compared=region_instruction_contract(before,a,after,c)
        pointer_moves={(r['old_rva'],r['new_rva'],r['old_offset'],r['new_offset'])
                       for r in region.get('verified_pointer_moves',())}
        needed={(r['old_rva'],r['new_rva'],r['old_offset'],r['new_offset'])
                for r in compared.get('conditional_pointer_immediates',())}
        if (not compared['internal_control_flow'] or not (compared['instruction_roles']
                or compared['conditional_instruction_roles'] and needed and needed<=pointer_moves)):
            raise ValueError('Admitted region no longer has the proved instruction roles')
        left,right=list(md.disasm(before,a)),list(md.disasm(after,c))
        if (len(left)!=len(right) or not left or left[-1].address+left[-1].size!=b
                or right[-1].address+right[-1].size!=d):
            raise ValueError('Admitted region has incomplete native instruction boundaries')
        pairs.extend((x,y,region['contract_id']) for x,y in zip(left,right))
    def resolve(point,endpoint=False):
        found=set()
        for a,b,contract in pairs:
            if a.address<=point<a.address+a.size or endpoint and point==a.address+a.size:
                offset=point-a.address
                if offset and a.size!=b.size:continue
                found.add((b.address+offset,contract))
        values={value for value,_ in found}
        return (next(iter(values)),sorted({contract for _,contract in found})) if len(values)==1 else None
    addresses=[];patches=[];unresolved=[]
    for point in sorted(set(required_addresses)):
        result=resolve(point)
        if result is None:unresolved.append(dict(kind='address',reference=point));continue
        destination,contracts=result
        addresses.append(dict(reference=point,candidate=destination,contracts=contracts))
    for point,expected in required_patches:
        expected=bytes.fromhex(expected) if isinstance(expected,str) else expected
        if old.get_data(point,len(expected))!=expected:
            raise ValueError('Requested patch bytes differ from reviewed executable')
        start,end=resolve(point),resolve(point+len(expected),True)
        # Every byte must belong to a declared region; endpoint-only checks
        # could accidentally span an unproved native block between two regions.
        byte_map=[resolve(point+i) for i in range(len(expected))]
        if (not expected or start is None or end is None or end[0]-start[0]!=len(expected)
                or any(item is None or item[0]!=start[0]+i for i,item in enumerate(byte_map))):
            unresolved.append(dict(kind='patch',reference=point,expected=expected.hex()));continue
        candidate=new.get_data(start[0],len(expected))
        if len(candidate)!=len(expected):raise ValueError('Truncated candidate patch bytes')
        patches.append(dict(reference=point,expected=expected.hex(),candidate_bytes=candidate.hex(),
                            contracts=sorted({name for item in byte_map for name in item[1]})))
    return dict(addresses=addresses,patches=patches,unresolved_inputs=unresolved,
                automatic_activation_allowed=False)


def conditional_damage_switch(old, new, before, after):
    """Pair the reviewed DAMAGE dispatch under a mandatory Game tag guard.

    The four-case bound is an adapter input contract, not a claim about every
    native caller. Returned edges must never be consumed without that guard.
    """
    positions = {ins.address: index for index, ins in enumerate(before)}
    load_site, lea_site, jump_site = 0x540cfe8, 0x540d01f, 0x540d02f
    if load_site not in positions:
        return {}, {}, {}, []
    if len(before) != len(after) or any(site not in positions for site in (lea_site, jump_site)):
        raise ValueError('DAMAGE conditional dispatch instruction layout changed')
    loads = [stream[positions[load_site]] for stream in (before, after)]
    leas = [stream[positions[lea_site]] for stream in (before, after)]
    jumps = [stream[positions[jump_site]] for stream in (before, after)]
    for stream, load, lea, jump in zip((before, after), loads, leas, jumps):
        if not (load.mnemonic == 'movzx' and load.op_str.startswith('ebx, byte ptr [rsi + ')
                and load.operands[1].type == capstone.x86.X86_OP_MEM
                and not load.operands[1].mem.index and load.operands[1].size == 1
                and lea.mnemonic == 'lea' and lea.op_str.startswith('rdx, [rip + ')
                and jump.mnemonic == 'jmp' and jump.op_str == 'rcx'):
            raise ValueError('DAMAGE conditional tag source or table registers changed')
        sequence = stream[positions[lea_site]-1:positions[jump_site]+1]
        expected = ['mov ecx, ebx', None, 'movsxd rcx, dword ptr [rdx + rcx*4]',
                    'add rcx, rdx', 'mov edx, eax', 'jmp rcx']
        if len(sequence) != len(expected) or any(want is not None and i.mnemonic+' '+i.op_str != want
                                                 for i, want in zip(sequence, expected)):
            raise ValueError('DAMAGE conditional index computation changed')
        for instruction in stream[positions[load_site]+1:positions[lea_site]-1]:
            if instruction.group(capstone.CS_GRP_CALL) or any(
                    instruction.reg_name(reg) in ('rbx','ebx','bx','bl','bh')
                    for reg in instruction.regs_access()[1]):
                raise ValueError('DAMAGE tag is modified before dispatch')
    if loads[0].operands[1].mem.disp != 0xf8:
        raise ValueError('Reviewed DAMAGE tag field does not match contract')
    tables, targets = [], []
    for image, lea in zip((old, new), leas):
        address = lea.address + lea.size + lea.operands[1].mem.disp
        section = image.get_section_by_rva(address)
        if (section is None or section.Characteristics & (0x20000000 | 0x80000000)
                or address+16 > section.VirtualAddress+section.Misc_VirtualSize):
            raise ValueError('DAMAGE conditional table is not bounded immutable data')
        data = image.get_data(address, 16)
        if len(data) != 16:
            raise ValueError('DAMAGE conditional table is truncated')
        tables.append(address)
        targets.append([address+x[0] for x in struct.iter_unpack('<i', data)])
    if any(target not in positions for target in targets[0]) or [
            after[positions[target]].address for target in targets[0]] != targets[1]:
        raise ValueError('DAMAGE conditional table branches changed')
    condition = dict(kind='game_unsigned_bound', old_offset=0xf8,
        new_offset=loads[1].operands[1].mem.disp, width=1, maximum=3,
        old_rva=hex(loads[0].address), new_rva=hex(loads[1].address), register='rsi',
        mandatory_before_every_adapter_call=True, native_global_domain_proven=False)
    return ({jumps[0].address: targets[0]}, {jumps[1].address: targets[1]},
        {tables[0]: dict(candidate=tables[1], classification='guarded-damage-enum-table', cases=4)},
        [condition])


def ability_source_bounds(code, address):
    """Identify exact native bounded 28-byte definition indexing operations.

    These local contracts deliberately retain the producer-to-copy control-flow
    obligation. Finding a bounds check elsewhere in a function is not dominance.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    ins = list(md.disasm(code, address))
    rows = []
    for index in range(len(ins)-7):
        block = ins[index:index+8]
        texts = [i.mnemonic + ' ' + i.op_str for i in block]
        if (texts[0] == 'cmp rcx, 2' and block[1].mnemonic == 'ja'
                and texts[2:5] == ['lea rdx, [rcx + rcx*8]',
                                    'lea rdi, [rdx + rdx*2]', 'add rdi, rcx']
                and block[5].mnemonic == 'lea' and block[5].op_str.startswith('rcx, [rip + ')
                and texts[6] == 'movss xmm0, dword ptr [rcx + rdi + 0x18]'):
            table = block[5].address + block[5].size + block[5].operands[1].mem.disp
            rows.append(dict(kind='builtin', bounds_site=hex(block[0].address),
                failure_target=hex(block[1].operands[0].imm), count=3,
                stride=28, index_register='rcx', byte_offset_register='rdi',
                definition_table=hex(table), indexed_read=hex(block[6].address),
                producer_control_flow_verified=False))
        # Boss ability tuples are copied through the same private frame that
        # ability_cast_copies consumes. Keep exact payload/source widths.
        if not (texts[0] == 'mov rax, qword ptr [rsi + 0x30]'
                and texts[1] == 'mov rdx, qword ptr [rax + 0x18]'
                and texts[2] == 'cmp rcx, rdx' and block[3].mnemonic == 'jae'
                and texts[4] == 'mov rax, qword ptr [rax + 0x10]'
                and texts[5] == 'mov rcx, qword ptr [rax + r8 + 0x10]'
                and block[6].mnemonic == 'mov' and block[6].op_str.startswith('qword ptr [rbp + ')
                and block[6].operands[1].type == capstone.x86.X86_OP_REG
                and block[6].reg_name(block[6].operands[1].reg) == 'rcx'
                and texts[7] == 'movups xmm0, xmmword ptr [rax + r8]'
                and index+8 < len(ins)):
            continue
        store = ins[index+8]
        if not (store.mnemonic == 'movaps' and store.operands[0].type == capstone.x86.X86_OP_MEM
                and store.reg_name(store.operands[0].mem.base) == 'rbp'
                and not store.operands[0].mem.index and store.op_str.endswith(', xmm0')
                and block[6].operands[0].mem.disp == store.operands[0].mem.disp + 16):
            continue
        # The multiplication must be in the immediately preceding straight
        # path; no call/jump or write to R8/RCX may intervene after it.
        scales = []
        for start in range(max(0, index-16), index-2):
            seq = ins[start:start+3]
            if [i.mnemonic+' '+i.op_str for i in seq] != [
                    'lea r8, [rcx + rcx*8]', 'lea r8, [r8 + r8*2]', 'add r8, rcx']:
                continue
            between = ins[start+3:index]
            if any(i.group(capstone.CS_GRP_JUMP) or i.group(capstone.CS_GRP_CALL)
                   or any(i.reg_name(r) in ('r8','r8d','rcx','ecx') for r in i.regs_access()[1])
                   for i in between):
                continue
            scales.append(seq[0])
        if len(scales) != 1:
            continue
        rows.append(dict(kind='boss', bounds_site=hex(block[2].address),
            failure_target=hex(block[3].operands[0].imm), stride=28,
            enemy_register='rsi', definition_offset=0x30,
            definition_pointer_offset=0x10, definition_count_offset=0x18,
            index_register='rcx', byte_offset_register='r8',
            scale_site=hex(scales[0].address), stack_register='rbp',
            payload_slot=store.operands[0].mem.disp, payload_bytes=24,
            tag_offset=0, producer_control_flow_verified=False))
    return rows


def structural_profile(reference, binary):
    """Complete offline candidate evidence; no profile activation is implied."""
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    targets = [row['reference_rva'] for row in manifest['hooks'].values()]
    from updated_layout import ADDRESSES
    declared = json.loads((ROOT / 'analysis/native-contract-baseline.json').read_text())
    if declared['reference_sha256'] != UPDATED_HASH:
        raise ValueError('Declared native fields do not belong to the reviewed executable')
    requested_game_fields = {int(row[0], 16) for name, row in declared['structures']['game'].items()
                             if isinstance(row, list) and not name.endswith('_size')}
    targets.extend(ADDRESSES.values())
    typed = typed_reviewed_references(ROOT / 'reconstruction', pefile.PE(str(reference), fast_load=True))
    targets.extend(row['rva'] for row in typed)
    report = structural_relocations(reference, binary, targets)
    before, after = pefile.PE(str(reference), fast_load=True), pefile.PE(str(binary), fast_load=True)
    before_ends, after_ends = dict(unwind_ranges(before)), dict(unwind_ranges(after))
    for row in report.values():
        row['target_sources'] = [entry for entry in typed if hex(entry['rva']) in row['targets']]
    tick = manifest['hooks']['TICK']['reference_rva']
    original = tick_entry_contract(before.get_data(tick, before_ends[tick] - tick), tick)
    tick_row = report[hex(tick)]
    tick_row['reference_entry_contract'] = original
    candidates = []
    for row in tick_row.get('call_graph_candidates', []):
        if row['distinct_anchors'] < 2:
            continue
        address = int(row['rva'], 16)
        contract = tick_entry_contract(after.get_data(address, after_ends[address] - address), address)
        candidates.append(dict(rva=row['rva'], **contract))
    tick_row['entry_contract_candidates'] = candidates
    valid = [row for row in candidates if row['verified_header']]
    tick_row['unique_entry_contract'] = original['verified_header'] and len(valid) == 1
    if tick_row['unique_entry_contract']:
        tick_row['queue_moves'] = list(zip(original['queues'][0]['offsets'], valid[0]['queues'][0]['offsets']))
        chosen_tick = int(valid[0]['rva'], 16)
        tick_row['reference_hud_contracts'] = hud_delivery_contracts(before.get_data(tick, before_ends[tick] - tick), tick)
        tick_row['hud_contracts'] = hud_delivery_contracts(
            after.get_data(chosen_tick, after_ends[chosen_tick] - chosen_tick), chosen_tick)
        old_serialize = manifest['hooks']['SERIALIZE']['reference_rva']
        old_write = manifest['hooks']['WRITE']['reference_rva']
        def unique_function(start):
            row = report[hex(start)]
            return int(next(c for c in row['candidates'] if c['structure_equivalent'])['rva'], 16) if row['unique_structure'] else None
        new_serialize, new_write = unique_function(old_serialize), unique_function(old_write)
        tick_row['reference_batch_contracts'] = batch_write_contracts(
            before.get_data(tick, before_ends[tick] - tick), tick, old_serialize, old_write)
        tick_row['batch_contracts'] = batch_write_contracts(
            after.get_data(chosen_tick, after_ends[chosen_tick] - chosen_tick), chosen_tick, new_serialize, new_write)
        tick_row['reference_connection_vectors'] = server_vector_contracts(
            before.get_data(tick, before_ends[tick] - tick), tick)
        tick_row['connection_vectors'] = server_vector_contracts(
            after.get_data(chosen_tick, after_ends[chosen_tick] - chosen_tick), chosen_tick)
        owners = sorted(before_ends)
        update_owner = owners[bisect.bisect_right(owners, manifest['hooks']['ENEMY_AOE']['reference_rva']) - 1]
        update_candidates = report[hex(update_owner)]['candidates']
        if len(update_candidates) == 1:
            new_update = int(update_candidates[0]['rva'], 16)
            update_row = report[hex(update_owner)]
            update_row['reference_return_tag_switches'] = return_tag_switches(before,
                before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner)
            update_row['return_tag_switches'] = return_tag_switches(after,
                after.get_data(new_update, after_ends[new_update] - new_update), new_update)
            update_row['reference_ability_cast_copies'] = ability_cast_copies(
                before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner)
            update_row['ability_cast_copies'] = ability_cast_copies(
                after.get_data(new_update, after_ends[new_update] - new_update), new_update)
            update_row['reference_ability_source_bounds'] = ability_source_bounds(
                before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner)
            update_row['ability_source_bounds'] = ability_source_bounds(
                after.get_data(new_update, after_ends[new_update] - new_update), new_update)
            try:
                update_row['guarded_dispatches'] = guarded_update_dispatches(before,after,
                    before.get_data(update_owner,before_ends[update_owner]-update_owner),update_owner,
                    after.get_data(new_update,after_ends[new_update]-new_update),new_update)
            except ValueError as exc:
                update_row['guarded_dispatches'] = dict(error=str(exc),automatic_activation_allowed=False)
            update_row['changed_mutation_footprint'] = mutation_footprint(
                before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner,
                after.get_data(new_update, after_ends[new_update] - new_update), new_update)
            dispatches = update_row['guarded_dispatches']
            if 'contracts' in dispatches:
                guarded_edges = dict(dispatches['candidate_edges'])
                for switch in update_row['return_tag_switches']:
                    guarded_edges[int(switch['jump'],16)] = [int(t,16) for t in switch['targets'].values()]
                uses = game_field_uses(after.get_data(new_update,after_ends[new_update]-new_update),
                    new_update,indirect_edges=guarded_edges,pointer_immediates=True)
                dispatches['conditional_game_access_count'] = len(uses)
                for store in update_row['changed_mutation_footprint']['stores']:
                    use = uses.get((int(store['rva'],16),0))
                    if use and use['access'] & capstone.CS_AC_WRITE:
                        store['guarded_owner'] = dict(kind='game',offset=use['offset'],width=use['width'],
                            conditional_on_installed_dispatch_guards=True)
                update_row['changed_store_owners'] = changed_store_owners(
                    after.get_data(new_update,after_ends[new_update]-new_update),new_update,
                    guarded_edges,update_row['changed_mutation_footprint']['stores'])
            regions = {}
            # Existing reviewed adapter boundaries: iteration/DOT, enemy AI,
            # world/loot, then the native victory continuation.
            boundaries = [ADDRESSES[a] for a in (0x53E2EB6, 0x53E3381, 0x53E6B22, 0x53EA280)]
            mapped_boundaries = []
            for boundary in boundaries:
                matches = update_row['interior_candidates'].get(hex(boundary), {}).get('candidates', [])
                mapped_boundaries.append(int(matches[0]['rva'], 16) if len(matches) == 1 else None)
            if mapped_boundaries[-1] is not None:
                decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                old_return = next((i for i in decoder.disasm(before.get_data(boundaries[-1], before_ends[update_owner] - boundaries[-1]), boundaries[-1]) if i.mnemonic == 'ret'), None)
                new_return = next((i for i in decoder.disasm(after.get_data(mapped_boundaries[-1], after_ends[new_update] - mapped_boundaries[-1]), mapped_boundaries[-1]) if i.mnemonic == 'ret'), None)
                if old_return is not None and new_return is not None:
                    boundaries.append(old_return.address + old_return.size)
                    mapped_boundaries.append(new_return.address + new_return.size)
            for index, name in enumerate(('enemy_iteration_and_effects', 'enemy_ai_and_cleanup', 'world_and_loot', 'victory_and_final_cleanup')[:len(boundaries) - 1]):
                a, b = boundaries[index:index + 2]
                c, d = mapped_boundaries[index:index + 2]
                if c is None or d is None or not a < b or not c < d:
                    regions[name] = dict(instruction_roles=False, reason='Ambiguous native adapter boundary')
                    continue
                if name == 'world_and_loot':
                    from native_helper_contracts import REVIEWED_START_BUILD
                    if (hashlib.sha256(after.__data__).hexdigest() == REVIEWED_START_BUILD
                            and hashlib.sha256(before.__data__).hexdigest() == UPDATED_HASH
                            and (a,b,c,d) == (0x53f1f62,0x53f56e0,0x53fc242,0x53ff9d0)):
                        # Guests unconditionally bypass this whole range. Host
                        # gold hooks are before the native map-spawn suffix;
                        # retain that release's native logic, not a claimed
                        # instruction-equivalent rewrite. Its hooked calls still
                        # require separate receiver/argument and callee proofs.
                        regions[name] = region_instruction_contract(
                            before.get_data(a,0x53f3e61-a),a,after.get_data(c,0x53fe141-c),c)
                        regions[name]['retained_native_suffix'] = dict(
                            reference_sha256=UPDATED_HASH, sha256=REVIEWED_START_BUILD,
                            old_start=0x53f3e61, old_end=b, new_start=0x53fe141, new_end=d,
                            guest_skip=a, guest_continuation=b, host_code_retained=True,
                            hooked_callees=['SPAWN','SPAWN_BOSS','FIND_SPAWN','SPAWN_LOOT'],
                            scope='Exact-release host-native map/world logic; no adapter input within suffix; '
                                  'guest restoration, all hooked calls and four-player acceptance remain required')
                        continue
                regions[name] = region_instruction_contract(before.get_data(a, b - a), a, after.get_data(c, d - c), c)
            # The adapter also replaces the phase gate and jumps over player
            # actions into native projectile/ground work. Prove these whole
            # paired spans, including the phase flags, clock spill and borrowed
            # container setup; do not admit isolated signature matches alone.
            early = update_row['interior_candidates']
            phase_continuation=ADDRESSES[0x53DCA04]
            projectile_start=ADDRESSES[0x53E1254]
            phase_matches=early.get(hex(phase_continuation),{}).get('candidates',[])
            projectile_matches=early.get(hex(projectile_start),{}).get('candidates',[])
            if len(phase_matches)==1:
                decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
                candidate=int(phase_matches[0]['rva'],16)
                left=list(decoder.disasm(before.get_data(phase_continuation,32),phase_continuation))[:2]
                right=list(decoder.disasm(after.get_data(candidate,32),candidate))[:2]
                if len(left)==len(right)==2:
                    end_old,end_new=left[-1].address+left[-1].size,right[-1].address+right[-1].size
                    regions['phase_clock_entry']=region_instruction_contract(
                        before.get_data(update_owner,end_old-update_owner),update_owner,
                        after.get_data(new_update,end_new-new_update),new_update)
            if len(projectile_matches)==1 and mapped_boundaries[0] is not None:
                candidate=int(projectile_matches[0]['rva'],16)
                regions['projectiles_ground_and_totems']=region_instruction_contract(
                    before.get_data(projectile_start,boundaries[0]-projectile_start),projectile_start,
                    after.get_data(candidate,mapped_boundaries[0]-candidate),candidate)
            external_targets = {int(edge['old_target'], 16) for region in regions.values()
                                for edge in region.get('external_edges', []) if edge['kind'] == 'branch'
                                and update_owner <= int(edge['old_target'], 16) < before_ends[update_owner]}
            external_mapping = interior_relocations(before.get_data(update_owner, before_ends[update_owner] - update_owner),
                update_owner, [(new_update, after.get_data(new_update, after_ends[new_update] - new_update))], external_targets)
            for region in regions.values():
                extra_calls = []
                for edge in region.get('external_edges', []):
                    if edge['kind'] == 'branch':
                        candidates = external_mapping.get(edge['old_target'], {}).get('candidates', [])
                        edge['continuation_verified'] = len(candidates) == 1 and candidates[0]['rva'] == edge['new_target']
                        if not edge['continuation_verified']:
                            failure = anchored_trap_contract(before, int(edge['old_target'], 16), after, int(edge['new_target'], 16))
                            if failure:
                                edge['continuation_verified'] = True
                                edge['anchored_trap'] = failure
                                extra_calls.extend(failure['call_dependencies'])
                region.setdefault('external_edges', []).extend(extra_calls)
                region['outgoing_branches_verified'] = all(e.get('continuation_verified') is True
                    for e in region.get('external_edges', []) if e['kind'] == 'branch')
            update_row['guest_controlled_regions'] = regions
            if 'contracts' in dispatches:
                old_edges=dict(dispatches['reference_edges'])
                for switch in update_row['reference_return_tag_switches']:
                    old_edges[int(switch['jump'],16)]=[int(t,16) for t in switch['targets'].values()]
                old_uses=game_field_uses(before.get_data(update_owner,before_ends[update_owner]-update_owner),
                    update_owner,indirect_edges=old_edges,pointer_immediates=True)
                guarded_fields=[]
                decoder=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
                for name,region in regions.items():
                    if not (region.get('instruction_roles') or region.get('conditional_instruction_roles')):
                        continue
                    a,b,c,d=(int(region[k],16) for k in ('old_start','old_end','new_start','new_end'))
                    left=list(decoder.disasm(before.get_data(a,b-a),a))
                    right=list(decoder.disasm(after.get_data(c,d-c),c))
                    if len(left)!=len(right):continue
                    for x,y in zip(left,right):
                        for operand in range(4):
                            u,v=old_uses.get((x.address,operand)),uses.get((y.address,operand))
                            if not u or not v or (u['width'],u['address_only'],u['access'])!=(v['width'],v['address_only'],v['access']):
                                continue
                            guarded_fields.append(dict(old_rva=hex(x.address),new_rva=hex(y.address),
                                old_offset=u['offset'],new_offset=v['offset'],width=u['width'],
                                address_only=u['address_only'],access=u['access'],alias_proven=True,
                                region=name,conditional_on_installed_dispatch_guards=True))
                update_row['guarded_game_field_evidence']=dict(
                    method='paired controlled-region operands with guarded CFG Game aliases',
                    fields=guarded_fields,mandatory_guards=[c['kind'] for c in dispatches['contracts']],
                    automatic_activation_allowed=False)
            update_row['conditional_pointer_immediates'] = [site for region in regions.values()
                for site in region.get('conditional_pointer_immediates', ())]
            update_row['reference_saved_game_frames'] = saved_game_frame_contracts(
                before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner)
            update_row['saved_game_frames'] = saved_game_frame_contracts(
                after.get_data(new_update, after_ends[new_update] - new_update), new_update)
            old_frames, new_frames = update_row['reference_saved_game_frames'], update_row['saved_game_frames']
            stores = paired_frame_stores(before.get_data(update_owner, before_ends[update_owner] - update_owner),
                update_owner, after.get_data(new_update, after_ends[new_update] - new_update), new_update)
            update_row['object_frame_store_candidates'] = stores
            update_row['generated_restore_game'] = restore_game_frame_contract(old_frames, new_frames, stores)
            update_row['generated_world_containers'] = restore_game_frame_contract(old_frames, new_frames, stores,
                ((0x5E8, 0x3C8), (0x5A0, 0x120), (0x840, 0x188), (0x588, 0x2E8)))
            pursuit = ADDRESSES[0x53E370A]
            pursuit_matches = update_row['interior_candidates'].get(hex(pursuit), {}).get('candidates', [])
            if len(pursuit_matches) == 1 and len(old_frames) == 1:
                update_row['pursuit_live_contract'] = pursuit_live_contract(
                    before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner,
                    after.get_data(new_update, after_ends[new_update] - new_update), new_update,
                    pursuit, int(pursuit_matches[0]['rva'], 16), old_frames[0]['stack_offset'], before, after)
            update_row['conditional_game_accesses'] = conditional_game_accesses(
                before.get_data(update_owner, before_ends[update_owner] - update_owner), update_owner,
                after.get_data(new_update, after_ends[new_update] - new_update), new_update, requested_game_fields)
            if len(old_frames) == len(new_frames) == 1:
                old_fields = {field['rva']: dict(field, base=reload['register'], reload_rva=reload['rva'])
                              for reload in old_frames[0]['reloads'] for field in reload['fields']}
                new_fields = {field['rva']: dict(field, base=reload['register'], reload_rva=reload['rva'])
                              for reload in new_frames[0]['reloads'] for field in reload['fields']}
                mapped = interior_relocations(before.get_data(update_owner, before_ends[update_owner] - update_owner),
                    update_owner, [(new_update, after.get_data(new_update, after_ends[new_update] - new_update))],
                    [int(site, 16) for site in old_fields])
                pairs = []
                for site, match in mapped.items():
                    if len(match['candidates']) != 1:
                        continue
                    candidate = match['candidates'][0]
                    old_field, new_field = old_fields[site], new_fields.get(candidate['rva'])
                    if new_field and all(old_field[k] == new_field[k] for k in ('base', 'width', 'address_only')):
                        pairs.append(dict(old_rva=site, new_rva=candidate['rva'],
                            old_offset=old_field['offset'], new_offset=new_field['offset'],
                            base=old_field['base'], width=old_field['width'], address_only=old_field['address_only'],
                            old_reload=old_field['reload_rva'], new_reload=new_field['reload_rva'],
                            runtime_precondition='base register equals captured Game at field use',
                            automatic_activation_allowed=False))
                update_row['reload_game_field_candidates'] = pairs
            tick_row['reference_game_contracts'] = embedded_game_contracts(
                before.get_data(tick, before_ends[tick] - tick), tick, update_owner)
            tick_row['game_contracts'] = embedded_game_contracts(
                after.get_data(chosen_tick, after_ends[chosen_tick] - chosen_tick), chosen_tick,
                new_update)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    # These reviewed native methods receive Game* in RCX. Do not infer the
    # object type from an arbitrary displacement or from a server hook.
    for name in ('PAUSE', 'RESUME', 'START', 'AWARD_XP', 'CHOOSE', 'MOVE', 'DAMAGE', 'HURT',
                 'SPAWN', 'SPAWN_BOSS', 'FIND_SPAWN', 'SPAWN_LOOT', 'REMOVE_LOOT', 'OFFER_CHOICES', 'DEFEAT_UI'):
        start = manifest['hooks'][name]['reference_rva']
        row = report[hex(start)]
        if not row['unique_structure'] and len(row['candidates']) != 1:
            continue
        selected = next(c for c in row['candidates'] if c['structure_equivalent']) if row['unique_structure'] else row['candidates'][0]
        candidate = int(selected['rva'], 16)
        old_code = before.get_data(start, before_ends[start] - start)
        new_code = after.get_data(candidate, after_ends[candidate] - candidate)
        old_stream, new_stream = list(md.disasm(old_code, start)), list(md.disasm(new_code, candidate))
        if len(old_stream) != len(new_stream):
            continue
        row['conditional_pointer_immediates'] = pointer_offset_candidates(old_code, start, new_code, candidate)
        if not row['unique_structure']:
            row['conditional_game_accesses'] = conditional_game_accesses(
                old_code, start, new_code, candidate, requested_game_fields)
        row['stack_field_evidence'] = stack_field_pairs(old_code, start, new_code, candidate)
        # The reviewed defeat_ui_code wrapper passes its Game argument in RDX;
        # RCX is the output Vec address. All other listed methods receive RCX.
        entry_register = 'rdx' if name == 'DEFEAT_UI' else 'rcx'
        old_uses = game_field_uses(old_code, start, entry_prefix=True, pointer_immediates=True, entry_register=entry_register)
        new_uses = game_field_uses(new_code, candidate, entry_prefix=True, pointer_immediates=True, entry_register=entry_register)
        if entry_register == 'rcx':
            old_uses.update(stable_game_field_uses(old_code, start))
            new_uses.update(stable_game_field_uses(new_code, candidate))
        fields = []
        classified_immediates = []
        for a, b in zip(old_stream, new_stream):
            exact_role = instruction_pattern([a], preserve_immediates=True).fullmatch(b.bytes)
            for index in range(len(a.operands)):
                x, y = old_uses.get((a.address, index)), new_uses.get((b.address, index))
                pointer_pair = (x is not None and y is not None and x.get('pointer_immediate') and y.get('pointer_immediate')
                                and instruction_pattern([a]).fullmatch(b.bytes))
                if x is not None and y is not None and (exact_role or pointer_pair):
                    if pointer_pair and not exact_role:
                        classified_immediates.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
                            old_offset=x['offset'], new_offset=y['offset'], base=x['base']))
                    fields.append(dict(old_offset=x['offset'], new_offset=y['offset'], width=x['width'],
                        address_only=x['address_only'], access=x['access'],
                        entry_prefix=x['entry_prefix'] or y['entry_prefix'],
                        invariant_nonvolatile=x.get('invariant_nonvolatile', False) and y.get('invariant_nonvolatile', False),
                        old_rva=hex(a.address), new_rva=hex(b.address), old_base=x['base'], new_base=y['base']))
        key = 'game_field_evidence' if row['unique_structure'] else 'candidate_game_field_evidence'
        row[key] = dict(method=name, argument=entry_register, fields=fields, classified_pointer_immediates=classified_immediates,
            limitation='Indirect jump tables and stack reload provenance remain unresolved; entry_prefix fields dominate every reachable indirect exit on the initial entry path')
    fields = [f for row in report.values() for f in row.get('game_field_evidence', {}).get('fields', [])]
    for side, prefix, field_key in (('reference', 'reference_', 'old_offset'), ('candidate', '', 'new_offset')):
        games = tick_row.get(prefix + 'game_contracts', [])
        header = original if side == 'reference' else valid[0] if tick_row['unique_entry_contract'] else {}
        if len(games) == 1 and header.get('queues') and fields:
            maximum = max(f[field_key] + f['width'] for f in fields)
            upper = header['queues'][0]['offsets'][0] - games[0]['game_offset']
            games[0]['game_extent'] = dict(observed_field_end=maximum, first_server_member=upper,
                aligned_access_extent=(maximum + 7) & ~7,
                tight_aligned_extent=((maximum + 7) & ~7) == upper)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dependencies', action='store_true', help='Strict current-adapter dependency report')
    parser.add_argument('--structural', action='store_true', help='Compare full functions allowing field displacement changes')
    parser.add_argument('--binary', type=Path, default=ROOT / 'AzerothSurvivors.exe')
    args = parser.parse_args()
    if args.structural:
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        report = structural_profile(reference, args.binary)
        write_report(ROOT / 'analysis/structural-hook-candidates.json', report)
        print(f'{sum(row["unique_structure"] for row in report.values())}/{len(report)} dependency groups have a unique structural match; layout proof still required')
        return
    if args.dependencies:
        from check_build_hooks import embedded_references
        image = pefile.PE(str(args.binary), fast_load=True)
        targets = [int(row['rva'], 16) for row in embedded_references(ROOT / 'reconstruction', image)]
        reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        report = dependency_relocations(reference, args.binary, targets)
        write_report(ROOT / 'analysis/dependency-relocations.json', report)
        print(f"{sum(len(row['candidates']) == 1 for row in report['dependencies'].values())}/"
              f"{len(report['dependencies'])} dependencies mapped; full-build activation remains gated")
        return
    old = pefile.PE(str(ROOT / 'coop-lab/AzerothSurvivors.exe'), fast_load=True)
    new = pefile.PE(str(ROOT / 'AzerothSurvivors.exe'), fast_load=True)
    old.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    new.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    functions = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                       for e in old.DIRECTORY_ENTRY_EXCEPTION)
    starts = [start for start, end in functions]
    new_functions = sorted((e.struct.BeginAddress, e.struct.EndAddress)
                           for e in new.DIRECTORY_ENTRY_EXCEPTION)
    new_starts = [start for start, end in new_functions]
    targets = set()
    for name in ('native_probe', 'visibility_bridge', 'native_guest_combat'):
        tree = ast.parse((ROOT / f'reconstruction/{name}.py').read_text())
        targets.update(node.value for node in ast.walk(tree)
                       if isinstance(node, ast.Constant) and type(node.value) is int
                       and 0x5390000 <= node.value < 0x5480000)
    groups = {}
    for target in sorted(targets):
        i = bisect.bisect_right(starts, target) - 1
        if i >= 0 and target < functions[i][1]:
            groups.setdefault(functions[i], []).append(target)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    sections = [(s.VirtualAddress, s.get_data()) for s in new.sections
                if s.Characteristics & 0x20000000]
    results = []
    for (start, end), targets in groups.items():
        parts = []
        for ins in md.disasm(old.get_data(start, min(end-start, 160)), start):
            masked = set(range(ins.disp_offset, ins.disp_offset + displacement_size(ins)))
            if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
                masked.update(range(ins.imm_offset, ins.imm_offset + ins.imm_size))
            parts.extend(b'.' if i in masked else re.escape(bytes([byte]))
                         for i, byte in enumerate(ins.bytes))
        pattern = re.compile(b''.join(parts), re.DOTALL)
        matches = [rva + m.start() for rva, data in sections for m in pattern.finditer(data)]
        votes = Counter()
        if not matches:
            instructions = list(md.disasm(old.get_data(start, end-start), start))
            for index in sorted({0, len(instructions)//4, len(instructions)//2,
                                 3*len(instructions)//4}):
                parts = []
                for ins in instructions[index:index+20]:
                    masked = set(range(ins.disp_offset, ins.disp_offset + displacement_size(ins)))
                    masked.update(range(ins.imm_offset, ins.imm_offset + ins.imm_size))
                    parts.extend(b'.' if i in masked else re.escape(bytes([byte]))
                                 for i, byte in enumerate(ins.bytes))
                if not parts:
                    continue
                pattern = re.compile(b''.join(parts), re.DOTALL)
                for rva, data in sections:
                    for match in pattern.finditer(data):
                        address = rva + match.start()
                        i = bisect.bisect_right(new_starts, address)-1
                        if i >= 0 and address < new_functions[i][1]:
                            votes[new_starts[i]] += 1
        mapped_targets = {}
        chosen = matches[0] if len(matches) == 1 else None
        reviewed = {0x53F17D0: 0x53FCC80, 0x53F5E70: 0x5401520,
                    0x53FF4B0: 0x540AC40}
        if start in reviewed:
            chosen = reviewed[start]
        if chosen is None and votes:
            ranked = votes.most_common()
            if ranked[0][1] >= 2 and (len(ranked) == 1 or ranked[0][1] > ranked[1][1]):
                chosen = ranked[0][0]
        if chosen in new_starts:
            new_end = new_functions[bisect.bisect_left(new_starts, chosen)][1]
            new_code = new.get_data(chosen, new_end-chosen)
            instructions = list(md.disasm(old.get_data(start, end-start), start))
            addresses = [ins.address for ins in instructions]
            for target in targets:
                if target not in addresses:
                    continue
                index = addresses.index(target)
                evidence = set()
                strict_evidence = set()
                for first in sorted({index, max(0, index-5)}):
                    window = instructions[first:first+12]
                    if len(window) < 4:
                        continue
                    found = list(instruction_pattern(window).finditer(new_code))
                    if len(found) == 1:
                        evidence.add(chosen + found[0].start() + target-instructions[first].address)
                    strict = list(instruction_pattern(window, relocation_only=True).finditer(new_code))
                    if len(strict) == 1:
                        strict_evidence.add(chosen + strict[0].start() + target-instructions[first].address)
                if len(evidence) == 1:
                    address = evidence.pop()
                    mapped_targets[hex(target)] = dict(candidate=hex(address),
                        old_bytes=old.get_data(target,16).hex(), new_bytes=new.get_data(address,16).hex(),
                        fixed_operands_match=strict_evidence == {address},
                        automatic_activation_allowed=False)
        results.append(dict(old_start=hex(start), old_end=hex(end),
                            targets=[hex(t) for t in targets],
                            candidates=[hex(m) for m in matches],
                            fallback_votes={hex(m): count for m, count in votes.most_common(8)},
                            target_candidates=mapped_targets, automatic_activation_allowed=False))
        print(hex(start), '=>', ', '.join(hex(m) for m in matches),
              {hex(m): count for m,count in votes.most_common(3)}, flush=True)
    (ROOT / 'analysis/function-relocation-candidates.json').write_text(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()

