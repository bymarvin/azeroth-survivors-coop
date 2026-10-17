"""Bounded native helper closure proofs; never authorize an adapter by themselves."""
import struct
import hashlib
import json
import math
from pathlib import Path

import capstone
import pefile
from build_hooks import ROOT, UPDATED_HASH, instruction_signature, signature_candidates, displacement_size
from map_build_functions import unwind_ranges, function_references, verify_function_relocation, compare_function_layout, game_field_uses, pointer_offset_candidates, conditional_damage_switch
from menu_contracts import leaf_bytes, instructions, discover_menu_contract, equivalent_switch, map_selection_contract

REVIEWED_FREE = 0x21d0
REVIEWED_DIFFICULTY = 0x53b1dd0
REVIEWED_RESERVE_REWARDS = 0x568de90
REVIEWED_MAP_TABLE = 0x6636f60
REVIEWED_FIND_SPAWN = 0x540a8f0
REVIEWED_BOSS_SCALING_BASE = 0x6662c80
REVIEWED_BOSS_ANNOUNCEMENT = 0x6663868
REVIEWED_BOSS_FINAL_KEY = 0x666387f
REVIEWED_MODEL_SPAWN = 0x5408fb0
REVIEWED_BOSS_HUD_HP = (0x53e4079, 0x53e40eb)
REVIEWED_REMOVE_LOCATION = 0x6663888
REVIEWED_DAMAGE_CLASS_SCALE = 0x6664b8c
REVIEWED_START_COUNT_RANGE = 0x66638d0
REVIEWED_CHOICE_WEIGHT_PAIR = 0x6662d08
REVIEWED_CLASS_NAME_TABLE = 0x6664ae0
REVIEWED_CLASS_NAME_FALLBACK = 0x6637b80
REVIEWED_START_OBJECT = 0x6662eb4
REVIEWED_CHOICE_KIND_LENGTHS = 0x6664b68
REVIEWED_CHOICE_KIND_OFFSETS = 0x6664b80
REVIEWED_LOOT_SCALE_PAIR = 0x6662cf0
REVIEWED_OBJECT_MOVEMENT_PROFILE = 0x66632f4
REVIEWED_RUNE_DURATION_PAIR = 0x6662cf8
REVIEWED_STRING_FORMAT_VTABLE = 0x669d7f0
REVIEWED_DAMAGE_LABELS = {
    0x6662e7f: b'Enemy', 0x6663a50: b'Impossible...', 0x6663a5d: b'bossdown',
    0x6663a65: b'Minions, to me!',
    0x6663208: b'Pets', 0x666320c: b'Ability_Hunter_BeastCall',
    0x6663224: b'Soulstone', 0x666322d: b'Spell_Holy_HolyNova',
    0x6663240: b'Thorns', 0x6663246: b'Spell_Nature_Thorns',
    0x6663259: b'Talents', 0x6663260: b'Ability_Marksmanship',
    0x6663274: b'Melee', 0x6663279: b'INV_Sword_04',
    0x6663285: b'Other', 0x666328a: b'INV_Misc_QuestionMark',
    0x666329f: b'area', 0x66632a3: b'boss spell', 0x66632ad: b'boss melee',
    0x66632b7: b'mob spell', 0x66632c0: b'mob melee', 0x66632c9: b'elite',
    0x6663360: b'defeat',
    0x6662e84: b'|cffff4040You cannot leave the battlefield.|r',
    0x6662ee5: b'Berserking', 0x6662ec0: b'Speed',
    0x6663a74: b'Restoration',
}
REVIEWED_JSON_BOOLEANS = {0x66650f0: b'false', 0x66650f5: b'true'}
REVIEWED_CLOCK_FLOAT = 0x581c4ac
REVIEWED_DEFAULT_MELEE = 0x6638ce0
REVIEWED_CLASS_MELEE_TABLE = 0x6664b18
REVIEWED_DEFEAT_LABEL = 0x6663360
REVIEWED_SCALAR_PAIR_PACKET = 0x544c4f0
REVIEWED_COMPLETE_CHOICE = 0x541a150
# Reviewed CHOOSE enum layouts: five choice variants and five rank-stat tags.
REVIEWED_CHOICE_SWITCHES = ((0x5420b78, 0x5420b8d, 5), (0x5420ed9, 0x5420eee, 5),
                            (0x54213c5, 0x5421482, 5),
                            # Native choice-filter tag and bounded text-length dispatch.
                            (0x5398f05, 0x5398f13, 7), (0x5398f70, 0x5398f7e, 6),
                            (0x53b27ae, 0x53b27bc, 14))
REVIEWED_GEAR_DEFINITIONS = 0x663eb08
REVIEWED_SPELL_DEFINITIONS = 0x6639f58
REVIEWED_CHOICE_FLOATS = {0x59bd210: 2, 0x663dba0: 5, 0x663d980: 2, 0x6640ab0: 5}
REVIEWED_RANK_NAMES = 0x6664990
REVIEWED_RANK_FALLBACK = 0x6664a40
# Reviewed Rust RawVec failure dispatcher: RCX/RDX are allocation-error
# alignment/size scalars, never a Game pointer. Its two paths cannot return.
REVIEWED_ALLOCATION_FAILURE = 0x5817e8b
REVIEWED_BOUNDS_FAILURE = 0x5818223
# Reviewed native packet writers: R8/R9 borrow a UTF-8 key. The string
# writer additionally borrows its value through stack arguments 5/6.
REVIEWED_STRING_WRITER = 0x542ce70
REVIEWED_CHAT_WRITER = 0x5448b30
REVIEWED_KEY_WRITERS = {REVIEWED_STRING_WRITER, 0x542c2d0, 0x542bfd0, 0x542c150}
REVIEWED_FORMAT_WRITER = 0x563ef70
# Manually reviewed native START ABI for the supplied release. This grants only
# entry interception/calling, never function-wide relocation or interior patches.
REVIEWED_START_BUILD = '72b51b222171059029eb762ce800c97614ea94f88de7c14543c5236a6fc34743'
REVIEWED_TERMINAL_ABIS = {
    REVIEWED_BOUNDS_FAILURE: ('r8', 'index_bounds'),
    0x58183e0: ('r8', 'panic_str'),
    0x5818430: ('r9', 'slice_bounds'),
    0x5818180: ('rcx', 'panic_assert'),
    0x5817f5b: ('r8', 'slice_bounds'),
    0x5818400: ('r8', 'panic_format'),
    0x5817e71: (None, 'allocation_error'),
    0x58181a0: (None, 'unwrap_zero_size_error'),
}


def terminal_continuation(stream, start):
    decoded = {ins.address: ins for ins in stream}
    seen = set()
    while start in decoded and start not in seen:
        seen.add(start)
        ins = decoded[start]
        if ins.mnemonic == 'ud2':
            return True
        if ins.mnemonic == 'nop':
            start += ins.size
        elif ins.mnemonic == 'jmp' and ins.operands[0].type == capstone.x86.X86_OP_IMM:
            start = ins.operands[0].imm
        else:
            return False
    return False


def terminal_bounds_call(helper, candidate_stream, call_index):
    """Classify a new native bounds-failure call; caller must prove scalar inputs."""
    if not 0 <= call_index < len(candidate_stream):
        raise ValueError('Native bounds call index is outside its instruction stream')
    call = candidate_stream[call_index]
    if (call.mnemonic != 'call' or len(call.operands) != 1
            or call.operands[0].type != capstone.x86.X86_OP_IMM
            or not terminal_continuation(candidate_stream, call.address + call.size)):
        raise ValueError('Native bounds failure has no direct call and terminal continuation')
    target = call.operands[0].imm
    before, after = helper.code(0, REVIEWED_BOUNDS_FAILURE), helper.code(1, target)
    if function_references(before, REVIEWED_BOUNDS_FAILURE)[0] != function_references(after, target)[0]:
        raise ValueError('Native bounds failure ABI changed')
    for image, entry, code in ((helper.old, REVIEWED_BOUNDS_FAILURE, before), (helper.new, target, after)):
        stream = instructions(image, entry, entry + len(code))
        if any(i.mnemonic in ('ret', 'retf') for i in stream) or not code.endswith(b'\x0f\x0b'):
            raise ValueError('Native bounds failure wrapper is not terminal')
    origin = None
    for ins in reversed(candidate_stream[max(0, call_index - 10):call_index]):
        if ins.group(capstone.CS_GRP_JUMP) or ins.group(capstone.CS_GRP_CALL):
            break
        _, writes = ins.regs_access()
        if any(ins.reg_name(reg) in ('r8', 'r8d', 'r8w', 'r8b') for reg in writes):
            if (ins.mnemonic == 'lea' and len(ins.operands) == 2
                    and ins.reg_name(ins.operands[0].reg) == 'r8'
                    and ins.operands[1].type == capstone.x86.X86_OP_MEM
                    and ins.operands[1].mem.base == capstone.x86.X86_REG_RIP):
                origin = ins
            break
    if origin is None:
        raise ValueError('Native bounds Location provenance is ambiguous or overwritten')
    if any(ins.group(capstone.CS_GRP_JUMP) and ins.operands
           and ins.operands[0].type == capstone.x86.X86_OP_IMM
           and origin.address < ins.operands[0].imm <= call.address for ins in candidate_stream):
        raise ValueError('Native bounds Location producer can be bypassed')
    address = origin.address + origin.size + origin.operands[1].mem.disp
    location = helper.rust_location(1, address)
    return dict(reference=REVIEWED_BOUNDS_FAILURE, candidate=target, call=call.address,
                classification='terminal-native-failure', native_abi='index_bounds',
                no_adapter_success_continuation=True,
                location=dict(rva=address, **location),
                scalar_argument_obligations={'rcx': 'bounds index scalar', 'rdx': 'bounds length scalar'},
                caller_scalar_provenance_verified=False,
                requires_complete_caller_instruction_stream=True,
                scope='Native terminal failure retained; caller scalar provenance required separately')


def choice_switch_edges(old, new, before, after, *, extra_switches=()):
    """Pair reviewed enum tables; target edges must preserve instruction identity."""
    old_by_address = {ins.address: index for index, ins in enumerate(before)}
    switches = REVIEWED_CHOICE_SWITCHES + tuple(extra_switches)
    if any(site in old_by_address for site, _, _ in switches) and len(before) != len(after):
        raise ValueError('Native choice switch owner instruction count changed')
    old_edges, new_edges, tables = {}, {}, {}
    for lea_site, jump_site, count in switches:
        if lea_site not in old_by_address:
            continue
        lea_index, jump_index = old_by_address[lea_site], old_by_address[jump_site]
        a, b = before[lea_index], after[lea_index]
        if (a.mnemonic != 'lea' or b.mnemonic != 'lea'
                or a.operands[1].mem.base != capstone.x86.X86_REG_RIP
                or b.operands[1].mem.base != capstone.x86.X86_REG_RIP):
            raise ValueError('Reviewed choice table producer changed')
        targets = []
        addresses = [ins.address + ins.size + ins.operands[1].mem.disp for ins in (a, b)]
        for image, address in zip((old, new), addresses):
            section = image.get_section_by_rva(address)
            if (section is None or section.Characteristics & (0x20000000 | 0x80000000)
                    or address + count * 4 > section.VirtualAddress + section.Misc_VirtualSize):
                raise ValueError('Native choice table is not immutable')
            data = image.get_data(address, count * 4)
            if len(data) != count * 4:
                raise ValueError('Truncated native choice table')
            targets.append([address + value[0] for value in struct.iter_unpack('<i', data)])
        if any(target not in old_by_address for target in targets[0]):
            raise ValueError('Native choice target outside reviewed function')
        if [after[old_by_address[target]].address for target in targets[0]] != targets[1]:
            raise ValueError('Native choice enum target changed')
        old_edges[jump_site], new_edges[after[jump_index].address] = targets
        tables[addresses[0]] = dict(candidate=addresses[1], classification='native-choice-enum-table', cases=count)
    return old_edges, new_edges, tables


class HelperProof:
    def __init__(self, old, new, *, game_roots=(), switch_roots=None):
        self.old, self.new = old, new
        self.game_roots = dict(game_roots) if isinstance(game_roots, dict) else {root: 'rcx' for root in game_roots}
        self.switch_roots = dict(switch_roots or {})
        self.bounds = [dict(unwind_ranges(image)) for image in (old, new)]
        self.imports = []
        for image in (old, new):
            image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
            self.imports.append({entry.address - image.OPTIONAL_HEADER.ImageBase:
                (dll.dll.lower().decode('ascii'), entry.name.decode('ascii') if entry.name else entry.ordinal)
                for dll in getattr(image, 'DIRECTORY_ENTRY_IMPORT', ()) for entry in dll.imports})
        self.proved, self.pending = {}, set()
        self.format_vtables = {}

    def code(self, side, address):
        image = (self.old, self.new)[side]
        section = image.get_section_by_rva(address)
        if section is None or not section.Characteristics & 0x20000000:
            raise ValueError('Native helper target is not executable')
        end = self.bounds[side].get(address)
        if end:
            code = image.get_data(address, end - address)
        else:
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            first = next(decoder.disasm(image.get_data(address, 16), address), None)
            # Import and allocator thunks can be packed without INT3 padding.
            code = bytes(first.bytes) if first and first.mnemonic in ('jmp', 'ret') else leaf_bytes(image, address)
        if not code or len(code) > 65536:
            raise ValueError('Native helper exceeds bounded proof extent')
        return code

    def candidates(self, old_address):
        before = self.code(0, old_address)
        pattern, mask = instruction_signature(before, old_address)
        sections = [(s.VirtualAddress, s.get_data()) for s in self.new.sections if s.Characteristics & 0x20000000]
        matches = []
        for address in signature_candidates(sections, pattern, mask):
            try:
                after = self.code(1, address)
                if function_references(before, old_address)[0] == function_references(after, address)[0]:
                    matches.append(address)
            except ValueError:
                pass
        return matches

    def pair(self, old_address, new_address, *, candidate_call=False):
        key = (old_address, new_address, 'candidate-call') if candidate_call else (old_address, new_address)
        if key in self.proved:
            return self.proved[key]
        if key in self.pending:
            raise ValueError('Recursive helper closure requires separate proof')
        if len(self.proved) + len(self.pending) >= 128:
            raise ValueError('Native helper closure exceeds bound')
        self.pending.add(key)
        try:
            before, after = self.code(0, old_address), self.code(1, new_address)
            compared_after, game_fields, game_accesses = after, [], []
            old_arguments, new_arguments = {}, {}
            map_layout = None
            if (candidate_call and old_address in (0x53e05d0, 0x5409f40, 0x5408300, 0x540a8f0, 0x542b2e0, 0x542b6d0, 0x5401190)
                    and hashlib.sha256(self.new.__data__).hexdigest() == REVIEWED_START_BUILD):
                from enemy_contracts import reviewed_map_constructor_layout
                map_layout = reviewed_map_constructor_layout(self, old_address, new_address, REVIEWED_START_BUILD)
            if candidate_call and old_address == 0x540ac40 and hashlib.sha256(self.new.__data__).hexdigest() == REVIEWED_START_BUILD:
                from enemy_contracts import reviewed_damage_layout
                map_layout = reviewed_damage_layout(self, new_address)
            if map_layout:
                expected_root = 'rdx' if old_address in (0x540a8f0, 0x5401190) else 'rcx'
                if self.game_roots.get(old_address, expected_root) != expected_root:
                    raise ValueError('Reviewed map helper Game receiver ABI changed')
                self.game_roots[old_address] = expected_root
            old_decoded = instructions(self.old, old_address, old_address + len(before))
            new_decoded = instructions(self.new, new_address, new_address + len(after))
            old_native_decoded, new_native_decoded = old_decoded, new_decoded
            if map_layout:
                left = {i.address: i for i in old_decoded}; right = {i.address: i for i in new_decoded}
                old_decoded = [left[p['reference']] for p in map_layout['instruction_pairs']]
                new_decoded = [right[p['candidate']] for p in map_layout['instruction_pairs']]
            loot_switch = ((0x54101ad, 0x54101bb, 7),) if candidate_call and old_address == 0x5410160 else ()
            old_edges, new_edges, choice_tables = choice_switch_edges(self.old, self.new, old_decoded, new_decoded, extra_switches=loot_switch)
            preconditions, borrow_proofs = [], []
            old_borrows, new_borrows = {}, {}
            if candidate_call:
                old_borrows, new_borrows, borrow_proofs = damage_frame_borrows(self, old_decoded, new_decoded)
                oe, ne, tables, preconditions = conditional_damage_switch(self.old, self.new, old_decoded, new_decoded)
                if loot_switch:
                    index = next(i for i, ins in enumerate(old_decoded) if ins.address == loot_switch[0][0])
                    for stream in (old_decoded, new_decoded):
                        expected = [('mov', 'eax, edx'), None, ('movsxd', 'rax, dword ptr [rcx + rax*4]'),
                                    ('add', 'rax, rcx'), ('jmp', 'rax')]
                        if any(want is not None and (ins.mnemonic, ins.op_str) != want
                               for ins, want in zip(stream[index - 1:index + 4], expected)):
                            raise ValueError('Native loot enum dispatch input changed')
                    preconditions.append(dict(register='edx', minimum=0, maximum=6, width=4,
                                              adapter_allowed_values=[0, 1, 2],
                                              mandatory_before_every_adapter_call=True, native_global_domain_proven=False))
                old_edges.update(oe); new_edges.update(ne); choice_tables.update(tables)
            if old_address in self.game_roots:
                layout = compare_function_layout(before, old_address, after, new_address)
                pointer_changes = pointer_offset_candidates(before, old_address, after, new_address)
                if (not map_layout and not layout['structure_equivalent'] and
                        (not pointer_changes or 'field_changes' not in layout
                         or {x['old_rva'] for x in layout.get('instruction_changes', ())} !=
                         {x['old_rva'] for x in pointer_changes})):
                    raise ValueError('Native Game helper structure changed')
                if map_layout:
                    layout = map_layout
                    pointer_changes = map_layout.get('pointer_changes', [])
                register = self.game_roots[old_address]
                old_uses = game_field_uses(before, old_address, entry_register=register, call_arguments=old_arguments, indirect_edges=old_edges, pointer_immediates=True, frame_borrows=old_borrows)
                new_uses = game_field_uses(after, new_address, entry_register=register, call_arguments=new_arguments, indirect_edges=new_edges, pointer_immediates=True, frame_borrows=new_borrows)
                for condition in preconditions:
                    if condition.get('register') == 'edx':
                        continue  # Caller-provided loot enum, not a Game memory field.
                    for uses, site_key, offset_key in ((old_uses, 'old_rva', 'old_offset'), (new_uses, 'new_rva', 'new_offset')):
                        use = uses.get((int(condition[site_key], 16), 1))
                        if use is None or use['offset'] != condition[offset_key] or use['width'] != condition['width']:
                            raise ValueError('Conditional DAMAGE enum lacks Game ownership proof')
                ordinals = {ins.address: index for index, ins in enumerate(old_decoded)}
                for (site, operand), use in old_uses.items():
                    if site not in ordinals: continue
                    paired_site = new_decoded[ordinals[site]].address
                    paired_use = new_uses.get((paired_site, operand))
                    if paired_use is not None:
                        game_accesses.append(dict(old_offset=use['offset'], new_offset=paired_use['offset'],
                                                  width=use['width'], old_rva=hex(site), new_rva=hex(paired_site)))
                new_instructions = {i.address: i for i in instructions(self.new, new_address, new_address + len(after))}
                normalized = bytearray(after)
                for change in layout['field_changes'] + pointer_changes:
                    a_site, b_site = int(change['old_rva'], 16), int(change['new_rva'], 16)
                    aa = [use for (site, _), use in old_uses.items() if site == a_site]
                    bb = [use for (site, _), use in new_uses.items() if site == b_site]
                    if (len(aa) != 1 or len(bb) != 1 or aa[0]['offset'] != change['old_offset']
                            or bb[0]['offset'] != change['new_offset']):
                        raise ValueError(f'Native helper changed an unproved Game field: {change}')
                    ins = new_instructions[b_site]
                    pointer = change in pointer_changes
                    if pointer and not (aa[0].get('pointer_immediate') and bb[0].get('pointer_immediate')):
                        raise ValueError('Native pointer arithmetic lacks Game alias proof')
                    size = ins.imm_size if pointer else displacement_size(ins)
                    try:
                        encoded = (change['old_offset'] * (-1 if pointer and ins.mnemonic == 'sub' else 1)).to_bytes(size, 'little', signed=True)
                    except OverflowError as error:
                        raise ValueError('Native helper Game field encoding width changed') from error
                    start = b_site - new_address + (ins.imm_offset if pointer else ins.disp_offset)
                    normalized[start:start + size] = encoded
                    game_fields.append(dict(**change, domain='game', alias_proven=True))
                compared_after = bytes(normalized)
            aa, ar = function_references(before, old_address)
            bb, br = function_references(compared_after, new_address)
            if (aa != bb and not map_layout) or len(ar) != len(br):
                raise ValueError('Native helper instruction/layout changed')
            mapping, dependencies = {}, []
            if not map_layout:
                old_decoded = instructions(self.old, old_address, old_address + len(before))
                new_decoded = instructions(self.new, new_address, new_address + len(after))
            terminal_data = {}
            terminal_calls = {}
            string_data = {}
            formatter_data = {}
            for index, ins in enumerate(old_decoded):
                if not (ins.mnemonic == 'lea' and ins.op_str.startswith('rdx, [rip')):
                    continue
                call = next((i for i in old_decoded[index + 1:index + 6] if i.group(capstone.CS_GRP_CALL)), None)
                if call is None or call.operands[0].type != capstone.x86.X86_OP_IMM or call.operands[0].imm != REVIEWED_FORMAT_WRITER:
                    continue
                paired = new_decoded[index]
                a = ins.address + ins.size + ins.operands[1].mem.disp
                b = paired.address + paired.size + paired.operands[1].mem.disp
                programs = self.format_program(0, a), self.format_program(1, b)
                if programs[0] != programs[1]:
                    raise ValueError('Native formatting program changed')
                formatter_data[a] = dict(candidate=b, classification='native-format-program', size=len(programs[0]))
            for index, call in enumerate(old_decoded):
                if (call.mnemonic != 'call' or call.operands[0].type != capstone.x86.X86_OP_IMM
                        or call.operands[0].imm not in REVIEWED_KEY_WRITERS | {REVIEWED_CHAT_WRITER}):
                    continue
                start = index
                while start > 0 and index - start < 14:
                    previous = old_decoded[start - 1]
                    if previous.group(capstone.CS_GRP_CALL) or previous.group(capstone.CS_GRP_JUMP):
                        break
                    start -= 1
                block = old_decoded[start:index]
                spans = []
                keys = [ins for ins in block if ins.mnemonic == 'lea' and ins.op_str.startswith('r8, [rip')]
                lengths = [ins for ins in block if ins.mnemonic == 'mov' and ins.op_str.startswith('r9d, ')
                           and ins.operands[1].type == capstone.x86.X86_OP_IMM]
                if len(keys) == len(lengths) == 1:
                    spans.append((keys[0], lengths[0].operands[1].imm, 'packet-key'))
                if call.operands[0].imm == REVIEWED_CHAT_WRITER:
                    messages = [ins for ins in block if ins.mnemonic == 'lea' and ins.op_str.startswith('r9, [rip')]
                    sizes = [ins.operands[1].imm for ins in block if ins.mnemonic == 'mov'
                             and ins.op_str.startswith('qword ptr [rsp + 0x20], ')
                             and ins.operands[1].type == capstone.x86.X86_OP_IMM]
                    if len(messages) == len(sizes) == 1:
                        spans.append((messages[0], sizes[0], 'native-chat-text'))
                if call.operands[0].imm == REVIEWED_STRING_WRITER:
                    for pos, ins in enumerate(block[:-2]):
                        if (ins.mnemonic == 'lea' and ins.op_str.startswith('rax, [rip')
                                and block[pos + 1].op_str == 'qword ptr [rsp + 0x20], rax'
                                and block[pos + 2].mnemonic == 'mov'
                                and block[pos + 2].op_str.startswith('qword ptr [rsp + 0x28], ')
                                and block[pos + 2].operands[1].type == capstone.x86.X86_OP_IMM):
                            spans.append((ins, block[pos + 2].operands[1].imm, 'packet-string-value'))
                for ins, length, kind in spans:
                    paired = new_decoded[old_decoded.index(ins)]
                    a = ins.address + ins.size + ins.operands[1].mem.disp
                    b = paired.address + paired.size + paired.operands[1].mem.disp
                    before_text, after_text = self.immutable(0, a, length), self.immutable(1, b, length)
                    if before_text != after_text:
                        raise ValueError('Native packet string changed')
                    try:
                        before_text.decode('utf-8')
                    except UnicodeDecodeError as error:
                        raise ValueError('Native packet string is not UTF-8') from error
                    string_data[a] = dict(candidate=b, classification=kind, size=length)
            switch_tables = dict(choice_tables)
            if old_address in self.switch_roots:
                count = self.switch_roots[old_address]
                if not equivalent_switch(self.old, old_address, before, self.new, new_address, after, count):
                    raise ValueError('Reviewed native switch table changed')
                table_a = [r[3] for r in ar if r[2] == 'rip']
                table_b = [r[3] for r in br if r[2] == 'rip']
                self.immutable(0, table_a[0], count * 4)
                self.immutable(1, table_b[0], count * 4)
                switch_tables[table_a[0]] = dict(candidate=table_b[0], classification='complete-native-switch', cases=count)
            for index, call in enumerate(old_decoded):
                if call.mnemonic != 'call' or call.operands[0].type != capstone.x86.X86_OP_IMM:
                    continue
                root = call.operands[0].imm
                if root not in REVIEWED_TERMINAL_ABIS:
                    continue
                new_call = new_decoded[index]
                if (not terminal_continuation(old_native_decoded, call.address + call.size)
                        or not terminal_continuation(new_native_decoded, new_call.address + new_call.size)):
                    raise ValueError('Native panic continuation can resume adapter success')
                target = new_call.operands[0].imm
                aa_code, bb_code = self.code(0, root), self.code(1, target)
                if function_references(aa_code, root)[0] != function_references(bb_code, target)[0]:
                    raise ValueError('Native terminal failure ABI changed')
                for image, entry, code in ((self.old, root, aa_code), (self.new, target, bb_code)):
                    callee = instructions(image, entry, entry + len(code))
                    if any(i.mnemonic in ('ret', 'retf') for i in callee) or not code.endswith(b'\x0f\x0b'):
                        raise ValueError('Native failure wrapper is not terminal')
                location_register, kind = REVIEWED_TERMINAL_ABIS[root]
                location_rows = []
                first = index
                while first > max(0, index - 10):
                    previous = old_decoded[first - 1]
                    if previous.group(capstone.CS_GRP_JUMP) or previous.group(capstone.CS_GRP_CALL):
                        break
                    first -= 1
                window = old_decoded[first:index]
                if kind == 'unwrap_zero_size_error':
                    def origin(register):
                        found = [i for i in window if i.mnemonic == 'lea'
                                 and i.reg_name(i.operands[0].reg) == register
                                 and i.operands[1].type == capstone.x86.X86_OP_MEM
                                 and i.operands[1].mem.base == capstone.x86.X86_REG_RIP]
                        if len(found) != 1:
                            raise ValueError('Native unwrap diagnostic pointer provenance changed')
                        return found[0]
                    if (not any(i.mnemonic == 'mov' and i.op_str == 'qword ptr [rsp + 0x20], rax' for i in window)
                            or not any(i.mnemonic == 'lea' and i.op_str == 'r8, [rbp - 1]' for i in window)):
                        raise ValueError('Native unwrap error is not the reviewed zero-size stack borrow')
                    lengths = [i.operands[1].imm for i in window if i.mnemonic == 'mov' and i.op_str.startswith('edx, ')
                               and i.operands[1].type == capstone.x86.X86_OP_IMM]
                    if len(lengths) != 1 or not 0 < lengths[0] <= 4096:
                        raise ValueError('Native unwrap diagnostic message has no bounded extent')
                    for reg, role in (('rax', 'location'), ('rcx', 'message'), ('r9', 'error-vtable')):
                        ins = origin(reg)
                        paired = new_decoded[old_decoded.index(ins)]
                        addresses = [i.address + i.size + i.operands[1].mem.disp for i in (ins, paired)]
                        evidence = []
                        for side, address in enumerate(addresses):
                            if role == 'location':
                                evidence.append(self.rust_location(side, address))
                            elif role == 'message':
                                evidence.append(self.immutable(side, address, lengths[0]).decode('utf-8'))
                            else:
                                table = struct.unpack('<4Q', self.immutable(side, address, 32))
                                if table[:3] != (0, 0, 1):
                                    raise ValueError('Native unwrap error vtable is not zero-size/no-drop')
                                image = (self.old, self.new)[side]
                                method = table[3] - image.OPTIONAL_HEADER.ImageBase
                                self.code(side, method)  # executable native formatter, only on terminal failure
                                evidence.append(dict(size=0, alignment=1, formatter=method))
                        terminal_data[addresses[0]] = dict(candidate=addresses[1], classification='terminal-unwrap-' + role,
                            evidence=evidence, no_game_arguments=True, no_adapter_success_continuation=True)
                if location_register:
                    origins = [i for i in window if i.mnemonic == 'lea' and len(i.operands) == 2
                               and i.reg_name(i.operands[0].reg) == location_register
                               and i.operands[1].type == capstone.x86.X86_OP_MEM
                               and i.operands[1].mem.base == capstone.x86.X86_REG_RIP]
                    if len(origins) != 1:
                        raise ValueError('Native failure Location provenance is ambiguous')
                    old_ins = origins[0]
                    paired_ins = new_decoded[old_decoded.index(old_ins)]
                    addresses = []
                    for side, ins in enumerate((old_ins, paired_ins)):
                        address = ins.address + ins.size + ins.operands[1].mem.disp
                        addresses.append(address)
                        location_rows.append(self.rust_location(side, address))
                    terminal_data[addresses[0]] = dict(candidate=addresses[1], classification='terminal-failure-location', locations=location_rows)
                if kind in ('panic_str', 'panic_format'):
                    origins = [i for i in window if i.mnemonic == 'lea' and i.reg_name(i.operands[0].reg) == 'rcx'
                               and i.operands[1].type == capstone.x86.X86_OP_MEM
                               and i.operands[1].mem.base == capstone.x86.X86_REG_RIP]
                    lengths = [i for i in window if i.mnemonic == 'mov' and i.reg_name(i.operands[0].reg) == 'edx'
                               and i.operands[1].type == capstone.x86.X86_OP_IMM]
                    if len(origins) != 1 or (kind == 'panic_str' and len(lengths) != 1):
                        raise ValueError('Native panic string has no proved immutable extent')
                    addresses, texts = [], []
                    for side, ins in enumerate((origins[0], new_decoded[old_decoded.index(origins[0])])):
                        address = ins.address + ins.size + ins.operands[1].mem.disp
                        addresses.append(address)
                        texts.append(self.format_program(side, address).hex() if kind == 'panic_format'
                                     else self.immutable(side, address, lengths[0].operands[1].imm).decode('utf-8'))
                    terminal_data[addresses[0]] = dict(candidate=addresses[1], classification='terminal-failure-message', texts=texts)
                terminal_calls[root] = dict(reference=root, candidate=target, classification='terminal-native-failure',
                    native_abi=kind, no_adapter_success_continuation=True, locations=location_rows,
                    scope='Original native failure retained; not a claim of transitive panic-hook equivalence')
            for index, call in enumerate(old_decoded):
                if (call.mnemonic != 'call' or call.operands[0].type != capstone.x86.X86_OP_IMM
                        or call.operands[0].imm != REVIEWED_BOUNDS_FAILURE or index < 3):
                    continue
                if REVIEWED_BOUNDS_FAILURE in terminal_calls:
                    continue
                if index + 1 >= len(old_decoded) or index + 1 >= len(new_decoded):
                    raise ValueError('Native bounds failure has no terminal continuation')
                prefix = old_decoded[index - 3:index]
                paired_prefix = new_decoded[index - 3:index]
                if (prefix[0].mnemonic != 'lea' or prefix[0].reg_name(prefix[0].operands[0].reg) != 'r8'
                        or prefix[0].operands[1].mem.base != capstone.x86.X86_REG_RIP
                        or [i.mnemonic for i in prefix[1:]] != ['mov', 'mov']
                        or prefix[1].reg_name(prefix[1].operands[0].reg) != 'rcx'
                        or prefix[2].reg_name(prefix[2].operands[0].reg) != 'rdx'
                        or old_decoded[index + 1].mnemonic != 'ud2' or new_decoded[index + 1].mnemonic != 'ud2'):
                    raise ValueError('Native bounds failure could resume adapter success')
                target = new_decoded[index].operands[0].imm
                a_code, b_code = self.code(0, REVIEWED_BOUNDS_FAILURE), self.code(1, target)
                if (function_references(a_code, REVIEWED_BOUNDS_FAILURE)[0] != function_references(b_code, target)[0]
                        or not a_code.endswith(b'\x0f\x0b') or not b_code.endswith(b'\x0f\x0b')):
                    raise ValueError('Native bounds panic scalar ABI changed')
                locations = []
                addresses = []
                for side, instruction in enumerate((prefix[0], paired_prefix[0])):
                    location = instruction.address + instruction.size + instruction.operands[1].mem.disp
                    addresses.append(location)
                    locations.append(self.rust_location(side, location))
                terminal_data[addresses[0]] = dict(candidate=addresses[1], classification='native-bounds-panic-location', locations=locations)
                terminal_calls[REVIEWED_BOUNDS_FAILURE] = dict(reference=REVIEWED_BOUNDS_FAILURE, candidate=target,
                    classification='terminal-native-failure', no_adapter_success_continuation=True,
                    arguments='checked index, length, immutable native Location', locations=locations,
                    scope='Original native bounds failure retained; panic hooks/diagnostic text are not gameplay equivalence')
            for a, b in zip(ar, br):
                if map_layout:
                    source_ins = next(i for i in old_decoded if i.address <= old_address+a[0] < i.address+i.size)
                    candidate_ins = new_decoded[old_decoded.index(source_ins)]
                    if (a[1:3] != b[1:3] or not candidate_ins.address <= new_address+b[0] < candidate_ins.address+candidate_ins.size):
                        raise ValueError('Reviewed map helper reference pairing changed')
                elif a[:3] != b[:3]:
                    raise ValueError('Native helper operand layout changed')
                if old_address <= a[3] < old_address + len(before):
                    continue
                mapping[a[3]] = b[3]
                if a[2] == 'control':
                    source_ins = next(i for i in old_decoded if i.address <= old_address + a[0] < i.address + i.size)
                    candidate_ins = new_decoded[old_decoded.index(source_ins)]
                    old_game_arguments = {reg for reg, offset in old_arguments.get(source_ins.address, {}).items() if offset == 0}
                    new_game_arguments = {reg for reg, offset in new_arguments.get(candidate_ins.address, {}).items() if offset == 0}
                    if old_game_arguments != new_game_arguments:
                        raise ValueError('Nested native Game argument provenance changed')
                    if len(old_game_arguments) == 1:
                        register = next(iter(old_game_arguments))
                        # Volatile registers can retain Game across a call to a
                        # no-argument marker. A live value alone is not an ABI.
                        consumed = [bool(game_field_uses(self.code(side, address), address,
                                    entry_prefix=True, entry_register=register))
                                    for side, address in enumerate((a[3], b[3]))]
                        if consumed[0] != consumed[1]:
                            raise ValueError('Nested native Game argument consumption changed')
                        if consumed[0]:
                            if a[3] in self.game_roots and self.game_roots[a[3]] != register:
                                raise ValueError('Nested native Game argument register conflicts')
                            self.game_roots[a[3]] = register
                    if candidate_call:
                        section = self.new.get_section_by_rva(b[3])
                        if section is None or not section.Characteristics & 0x20000000:
                            raise ValueError('Native candidate dependency is not executable')
                        dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-black-box',
                                                 runtime_output_validation_required=True))
                    elif a[3] in terminal_calls:
                        dependencies.append(terminal_calls[a[3]])
                    elif a[3] == REVIEWED_ALLOCATION_FAILURE:
                        call = next(i for i in old_decoded if i.address <= old_address + a[0] < i.address + i.size)
                        if (not terminal_continuation(old_native_decoded, call.address + call.size)
                                or not terminal_continuation(new_native_decoded, new_address + call.address - old_address + call.size)):
                            raise ValueError('Allocation failure could resume a successful adapter path')
                        dependencies.append(self.terminal_allocation_failure(a[3], b[3]))
                    else:
                        dependencies.append(self.pair(a[3], b[3]))
                elif a[3] in self.imports[0]:
                    if self.imports[0][a[3]] != self.imports[1].get(b[3]):
                        raise ValueError(f'Native helper import identity changed: {self.imports[0][a[3]]!r} '
                                         f'!= {self.imports[1].get(b[3])!r} at {old_address:x}/{new_address:x}')
                    dependencies.append(dict(kind='import', identity=self.imports[0][a[3]]))
                else:
                    instruction = next(i for i in old_decoded if i.address <= old_address + a[0] < i.address + i.size)
                    if old_address == 0x5420ad0 and instruction.mnemonic == 'lock xadd':
                        if instruction.op_str != 'dword ptr [rip + 0x1f2fd73], edi':
                            raise ValueError('Reviewed native identity counter instruction changed')
                        index = old_decoded.index(instruction)
                        if (old_decoded[index - 1].op_str != 'edi, 1' or old_decoded[index + 1].op_str != 'edi, 0xdbba0'):
                            raise ValueError('Native identity counter increment/tag changed')
                        for image, target in ((self.old, a[3]), (self.new, b[3])):
                            section = image.get_section_by_rva(target)
                            if section is None or not section.Characteristics & 0x80000000 or section.Characteristics & 0x20000000:
                                raise ValueError('Native identity counter is not writable scalar storage')
                            initial = image.get_data(target, 4)
                            offset = target - section.VirtualAddress
                            if (not initial and section.SizeOfRawData <= offset
                                    and offset + 4 <= section.Misc_VirtualSize):
                                initial = bytes(4)  # PE zero-filled BSS, not a missing arbitrary read.
                            if initial != bytes(4):
                                raise ValueError('Native identity counter initializer changed')
                        dependencies.append(dict(reference=a[3], candidate=b[3], classification='atomic-u32-identity-counter', increment=1, tag=0xdbba0))
                        continue
                    if instruction.mnemonic == 'lea':
                        if candidate_call and a[3] == REVIEWED_DAMAGE_CLASS_SCALE:
                            values = [self.immutable(side, address, 7 * 4) for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1] or not all(math.isfinite(value) and value > 0 for value in struct.unpack('<7f', values[0])):
                                raise ValueError('Native seven-class combat scale changed')
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            for stream in (old_decoded, new_decoded):
                                if ([(ins.mnemonic, ins.op_str) for ins in stream[ordinal - 3:ordinal - 2] + stream[ordinal - 1:ordinal]] !=
                                        [('cmp', 'al, 6'), ('movzx', 'eax, al')]
                                        or stream[ordinal - 2].mnemonic != 'ja'):
                                    raise ValueError('Native seven-class scale bound changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='bounded-combat-float-array', count=7))
                            continue
                        if a[3] == REVIEWED_STRING_FORMAT_VTABLE:
                            dependencies.append(self.string_format_vtable(a[3], b[3]))
                            continue
                        if candidate_call and a[3] == REVIEWED_RUNE_DURATION_PAIR:
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            for stream in (old_decoded, new_decoded):
                                if [(i.mnemonic, i.op_str) for i in stream[ordinal - 3:ordinal]] != [
                                        ('xor', 'eax, eax'), ('cmp', 'edx, 3'), ('sete', 'al')]:
                                    raise ValueError('Native rune duration boolean index changed')
                            values = [self.immutable(side, address, 8) for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1] or not all(math.isfinite(v) and v > 0 for v in struct.unpack('<ff', values[0])):
                                raise ValueError('Native rune duration pair changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-rune-duration-pair', count=2))
                            continue
                        if candidate_call and a[3] == REVIEWED_OBJECT_MOVEMENT_PROFILE:
                            values = [self.immutable(side, address, 24) for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1] or not all(math.isfinite(v) and v > 0 for v in struct.unpack('<6f', values[0])):
                                raise ValueError('Native movement profile changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-object-movement-profile',
                                                     consumed_extent=24, float_count=6,
                                                     consumer='Native packet writer543B3C0 loads six f32 values from argument7'))
                            continue
                        if candidate_call and a[3] == REVIEWED_LOOT_SCALE_PAIR:
                            values = [self.immutable(side, address, 8) for side, address in enumerate((a[3], b[3]))]
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            for stream in (old_decoded, new_decoded):
                                expected = { -9: ('xor', 'ecx, ecx'), -7: ('setae', 'dl'),
                                             -1: ('mov', 'cl, dl'), 1: ('movd', 'xmm8, dword ptr [rdx + rcx*4]') }
                                if any((stream[ordinal + delta].mnemonic, stream[ordinal + delta].op_str) != value
                                       for delta, value in expected.items()):
                                    raise ValueError('Native loot scale boolean index changed')
                            if values[0] != values[1] or not all(math.isfinite(v) and v > 0 for v in struct.unpack('<ff', values[0])):
                                raise ValueError('Native loot scale pair changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-loot-scale-pair', count=2))
                            continue
                        if candidate_call and a[3] in (REVIEWED_CHOICE_KIND_LENGTHS, REVIEWED_CHOICE_KIND_OFFSETS):
                            # OFFER_CHOICES saves zero-extended DL at its private
                            # frame -40 and uses that value in both three-item tables.
                            entry = next((i for i, ins in enumerate(old_decoded) if ins.address == 0x5418ce4), None)
                            if entry is None:
                                raise ValueError('Choice kind tables used outside reviewed input ABI')
                            for stream in (old_decoded, new_decoded):
                                if (stream[entry].mnemonic, stream[entry].op_str) != ('movzx', 'ecx, dl') or (stream[entry + 3].mnemonic, stream[entry + 3].op_str) != ('mov', 'qword ptr [rbp - 0x40], rcx'):
                                    raise ValueError('Choice kind input ownership changed')
                            condition = dict(register='dl', maximum=2, minimum=0, width=1,
                                             mandatory_before_every_adapter_call=True, native_global_domain_proven=False)
                            if condition not in preconditions:
                                preconditions.append(condition)
                            if a[3] == REVIEWED_CHOICE_KIND_LENGTHS:
                                if any(struct.unpack('<QQQ', self.immutable(side, address, 24)) != (7, 5, 8)
                                       for side, address in enumerate((a[3], b[3]))):
                                    raise ValueError('Native choice kind lengths changed')
                            else:
                                for side, address in enumerate((a[3], b[3])):
                                    offsets = struct.unpack('<iii', self.immutable(side, address, 12))
                                    for offset, expected in zip(offsets, (b'levelup', b'cache', b'guardian')):
                                        if self.immutable(side, address + offset, len(expected)) != expected:
                                            raise ValueError('Native choice kind string changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='bounded-choice-kind-table', count=3,
                                                     requires_input_domain=[0, 1, 2]))
                            continue
                        if a[3] == REVIEWED_START_OBJECT:
                            values = [self.immutable(side, address, 12) for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1]:
                                raise ValueError('Native starting object definition changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-object-definition',
                                                     entry_offset=0, display_offset=4, scale_offset=8, consumed_extent=12))
                            continue
                        if a[3] == REVIEWED_START_COUNT_RANGE:
                            values = [struct.unpack('<QQ', self.immutable(side, address, 16))
                                      for side, address in enumerate((a[3], b[3]))]
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            call = old_decoded[ordinal + 1]
                            if values != [(2, 3)] * 2 or call.mnemonic != 'call' or call.operands[0].imm != 0x546dfb0:
                                raise ValueError('Native starting spawn count range or consumer changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-inclusive-u64-range', minimum=2, maximum=3))
                            continue
                        if a[3] == REVIEWED_CHOICE_WEIGHT_PAIR:
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            for stream in (old_decoded, new_decoded):
                                if (stream[ordinal - 1].mnemonic != 'setb' or stream[ordinal - 1].op_str != 'al'
                                        or stream[ordinal + 1].mnemonic != 'movss'
                                        or stream[ordinal + 1].op_str != 'xmm6, dword ptr [rcx + rax*4]'):
                                    raise ValueError('Native choice weight pair index contract changed')
                            values = [self.immutable(side, address, 8) for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1] or not all(math.isfinite(v) and v > 0 for v in struct.unpack('<ff', values[0])):
                                raise ValueError('Native choice weight pair changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-choice-weight-pair', count=2))
                            continue
                        if a[3] in (REVIEWED_CLASS_NAME_TABLE, REVIEWED_CLASS_NAME_FALLBACK):
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            for stream in (old_decoded, new_decoded):
                                if a[3] == REVIEWED_CLASS_NAME_TABLE:
                                    if ([(i.mnemonic, i.op_str) for i in (stream[ordinal - 3], stream[ordinal - 1], stream[ordinal + 1])] !=
                                            [('cmp', 'al, 6'), ('movzx', 'eax, al'), ('mov', 'rax, qword ptr [rcx + rax*8]')]
                                            or stream[ordinal - 2].mnemonic != 'ja'):
                                        raise ValueError('Native class name table index bound changed')
                                elif (stream[ordinal + 1].mnemonic, stream[ordinal + 1].op_str) != ('movups', 'xmm0, xmmword ptr [rax]'):
                                    raise ValueError('Native class fallback string borrow changed')
                            values = []
                            for side, address in enumerate((a[3], b[3])):
                                image = (self.old, self.new)[side]
                                addresses = ([v[0] - image.OPTIONAL_HEADER.ImageBase for v in struct.iter_unpack('<Q', self.immutable(side, address, 56))]
                                             if a[3] == REVIEWED_CLASS_NAME_TABLE else [address])
                                names = []
                                for target in addresses:
                                    pointer, length = struct.unpack('<QQ', self.immutable(side, target, 16))
                                    if not 0 < length <= 4096:
                                        raise ValueError('Native class display name extent is invalid')
                                    names.append(self.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase, length).decode('utf-8'))
                                values.append(names)
                            if values[0] != values[1]:
                                raise ValueError('Native class display names changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-class-display-name-borrows', names=values[0], consumed_extent=16))
                            continue
                        if candidate_call and a[3] == REVIEWED_REMOVE_LOCATION:
                            locations = [self.rust_location(side, address) for side, address in enumerate((a[3], b[3]))]
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            calls = [next(ins for ins in stream[ordinal + 1:] if ins.mnemonic == 'call')
                                     for stream in (old_decoded, new_decoded)]
                            if calls[0].operands[0].imm != 0x5459560:
                                raise ValueError('Native bounds Location consumer changed')
                            target = calls[1].operands[0].imm
                            layout = compare_function_layout(self.code(0, 0x5459560), 0x5459560, self.code(1, target), target)
                            if not layout['structure_equivalent'] or layout['field_changes']:
                                raise ValueError('Native bounds Location passthrough ABI changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-bounds-Location',
                                locations=locations, input_register='r8', consumer=target,
                                scope='Vec remove ignores Location on success; passes it unchanged only to terminal bounds panic',
                                runtime_output_validation_required=True))
                            continue
                        if candidate_call and a[3] in REVIEWED_DAMAGE_LABELS:
                            expected_text = REVIEWED_DAMAGE_LABELS[a[3]]
                            if any(self.immutable(side, address, len(expected_text)) != expected_text
                                   for side, address in enumerate((a[3], b[3]))):
                                raise ValueError('Native combat summary label changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], size=len(expected_text),
                                                     classification='native-combat-summary-label'))
                            continue
                        if candidate_call and a[3] in (REVIEWED_SPELL_DEFINITIONS, REVIEWED_SPELL_DEFINITIONS + 0x78):
                            delta = a[3] - REVIEWED_SPELL_DEFINITIONS
                            values = [self.choice_data(side, address - delta, REVIEWED_SPELL_DEFINITIONS)
                                      for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1]:
                                raise ValueError('Native combat spell definition array changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-choice-data',
                                                     schema=values[0], element_offset=delta // 0x78))
                            continue
                        if candidate_call and a[3] in (REVIEWED_BOSS_ANNOUNCEMENT, REVIEWED_BOSS_FINAL_KEY, *REVIEWED_JSON_BOOLEANS):
                            expected_text = REVIEWED_JSON_BOOLEANS.get(a[3], b'enters the battlefield!' if a[3] == REVIEWED_BOSS_ANNOUNCEMENT else b'final')
                            values = [self.immutable(side, address, len(expected_text)) for side, address in enumerate((a[3], b[3]))]
                            if values != [expected_text] * 2:
                                raise ValueError('Native boss announcement changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-boss-announcement',
                                                     size=len(expected_text), runtime_output_validation_required=True))
                            continue
                        if a[3] == REVIEWED_MAP_TABLE:
                            definitions = map_enemy_contracts(self, a[3], b[3], definitions_only=bool(map_layout),
                                candidate_layout=dict(stride=184, name_pointer=8, name_length=16) if map_layout else None)
                            if map_layout:
                                for change in definitions['map_parameter_changes']:
                                    if change['offset'] != 0x90 or any(not math.isfinite(v) or v <= 0 for v in
                                            (struct.unpack('<f', bytes.fromhex(change[k]))[0] for k in ('before', 'after'))):
                                        raise ValueError('Reviewed map helper scalar changed outside positive native radius')
                                definitions['scope'] = 'Only reviewed map operands; native radius tuning retained; added fields excluded'
                            dependencies.append(definitions)
                            continue
                        if old_address == 0x541e6a0 and a[3] == REVIEWED_GEAR_DEFINITIONS:
                            # The complete paired owner retains its 0x630-byte loop,
                            # 0x48-byte step and record-pointer publication into choices.
                            values = [self.gear_definitions(side, address)
                                      for side, address in enumerate((a[3], b[3]))]
                            if values[0] != values[1]:
                                raise ValueError('Native gear definition contents changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3],
                                classification='native-gear-definitions', stride=0x48,
                                count=22, rows=values[0]))
                            continue
                        if a[3] in (REVIEWED_CLASS_MELEE_TABLE, REVIEWED_DEFAULT_MELEE):
                            profiles = []
                            for side, address in enumerate((a[3], b[3])):
                                image = (self.old, self.new)[side]
                                addresses = ([pointer[0] - image.OPTIONAL_HEADER.ImageBase for pointer in
                                              struct.iter_unpack('<Q', self.immutable(side, address, 80))]
                                             if a[3] == REVIEWED_CLASS_MELEE_TABLE else [address])
                                profiles.append([class_definition(self, side, target) for target in addresses])
                            if profiles[0] != profiles[1]:
                                raise ValueError('Native class definition contents changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-class-definitions',
                                                     count=len(profiles[0]), object_size=0x40, profiles=profiles[0]))
                            continue
                        if old_address == 0x5420ad0 and a[3] in ({REVIEWED_SPELL_DEFINITIONS, REVIEWED_RANK_NAMES, REVIEWED_RANK_FALLBACK} | set(REVIEWED_CHOICE_FLOATS)):
                            values = [self.choice_data(side, target, a[3]) for side, target in enumerate((a[3], b[3]))]
                            if values[0] != values[1]:
                                raise ValueError('Native choice definition data changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-choice-data', schema=values[0]))
                            continue
                        if a[3] in formatter_data and formatter_data[a[3]]['candidate'] == b[3]:
                            dependencies.append(formatter_data[a[3]])
                            continue
                        section_a = self.old.get_section_by_rva(a[3])
                        section_b = self.new.get_section_by_rva(b[3])
                        if candidate_call and section_a and section_b and section_a.Characteristics & section_b.Characteristics & 0x20000000:
                            layout = compare_function_layout(self.code(0, a[3]), a[3], self.code(1, b[3]), b[3])
                            if not layout['structure_equivalent'] or layout['field_changes']:
                                raise ValueError('Native callback body changed')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-callback',
                                                     runtime_output_validation_required=True))
                            continue
                        if a[3] in string_data and string_data[a[3]]['candidate'] == b[3]:
                            dependencies.append(string_data[a[3]])
                            continue
                        if a[3] in switch_tables and switch_tables[a[3]]['candidate'] == b[3]:
                            dependencies.append(switch_tables[a[3]])
                            continue
                        if a[3] in terminal_data and terminal_data[a[3]]['candidate'] == b[3]:
                            dependencies.append(terminal_data[a[3]])
                            continue
                        raise ValueError(f'Address-only data dependency needs typed object extent: {a[3]:x}->{b[3]:x}')
                    if (instruction.mnemonic == 'xor' and len(instruction.operands) == 2
                            and instruction.operands[0].type == capstone.x86.X86_OP_REG
                            and instruction.operands[1].type == capstone.x86.X86_OP_MEM
                            and instruction.operands[1].mem.base == capstone.x86.X86_REG_RIP
                            and instruction.operands[1].size in (1, 2, 4, 8)):
                        width = instruction.operands[1].size
                        if self.immutable(0, a[3], width) != self.immutable(1, b[3], width):
                            raise ValueError('Native fixed-width XOR comparison value changed')
                        dependencies.append(dict(reference=a[3], candidate=b[3], classification='immutable-xor-comparison', size=width))
                        continue
                    if not any(op.type == capstone.x86.X86_OP_REG and instruction.reg_name(op.reg).startswith('xmm')
                               for op in instruction.operands):
                        raise ValueError(f'Non-SIMD data dependency needs pointer/scalar classification: {instruction.mnemonic} {instruction.op_str}')
                    operand = next(op for op in instruction.operands if op.type == capstone.x86.X86_OP_MEM
                                   and op.mem.base == capstone.x86.X86_REG_RIP)
                    width = operand.size
                    for image, target in ((self.old, a[3]), (self.new, b[3])):
                        section = image.get_section_by_rva(target)
                        if section is None or section.Characteristics & (0x20000000 | 0x80000000):
                            raise ValueError('Native helper data is not immutable scalar storage')
                    if self.old.get_data(a[3], width) != self.new.get_data(b[3], width):
                        if candidate_call and a[3] == REVIEWED_BOSS_SCALING_BASE and width == 4:
                            ordinal = next(i for i, ins in enumerate(old_decoded) if ins.address == instruction.address)
                            original = old_decoded[ordinal:ordinal + 4]
                            paired = new_decoded[ordinal:ordinal + 4]
                            call_index = next((i for i, ins in enumerate(original) if ins.mnemonic == 'call'), None)
                            if (instruction.mnemonic not in ('movss', 'movd')
                                    or instruction.reg_name(instruction.operands[0].reg) != 'xmm0'
                                    or call_index not in (1, 2)
                                    or original[call_index].operands[0].imm != 0x5689e4b
                                    or [ins.mnemonic for ins in original] != [ins.mnemonic for ins in paired]):
                                raise ValueError('Native exponential scaling scalar consumer changed')
                            values = [struct.unpack('<f', image.get_data(address, 4))[0]
                                      for image, address in ((self.old, a[3]), (self.new, b[3]))]
                            if not all(math.isfinite(value) and value > 0 for value in values):
                                raise ValueError('Boss scaling base must remain positive finite')
                            dependencies.append(dict(reference=a[3], candidate=b[3], classification='native-boss-scaling-tuning',
                                before=values[0], after=values[1], runtime_output_validation_required=True,
                                policy='Preserve native powf scaling; require finite positive spawned health/damage'))
                            continue
                        raise ValueError(f'Native helper scalar data changed: {a[3]:x}->{b[3]:x} ({width} bytes)')
                    dependencies.append(dict(kind='immutable_scalar', reference=a[3], candidate=b[3], size=width))
            proof = verify_function_relocation(before, old_address, compared_after, new_address, mapping)
            if map_layout:
                # Layout proof checks every non-padding instruction and internal
                # edge; the loop above independently checks every external ref.
                if old_decoded[-1].mnemonic not in ('ret', 'ud2', 'jmp') or new_decoded[-1].mnemonic != old_decoded[-1].mnemonic:
                    raise ValueError('Reviewed map helper has unproved fallthrough')
            elif not proof['instructions_equivalent'] or not proof['references_verified']:
                raise ValueError('Native helper references are incomplete')
            row = dict(reference=old_address, candidate=new_address, size=len(before), dependencies=dependencies,
                       game_fields=game_fields, game_accesses=game_accesses, complete_helper_verified=not candidate_call)
            if map_layout:
                row['reviewed_map_layout'] = map_layout
            if candidate_call:
                row.update(candidate_call_only=True, literals=list(string_data.values()), preconditions=preconditions, frame_borrow_proofs=borrow_proofs)
            self.proved[key] = row
            return row
        except ValueError as error:
            if not hasattr(error, 'native_dependency'):
                error.native_dependency = dict(reference=old_address, candidate=new_address)
            raise
        finally:
            self.pending.remove(key)

    def immutable(self, side, address, size):
        image = (self.old, self.new)[side]
        section = image.get_section_by_rva(address)
        if (not 0 < size <= 4096 or section is None or section.Characteristics & (0x80000000 | 0x20000000)
                or address + size > section.VirtualAddress + section.Misc_VirtualSize):
            raise ValueError('Terminal diagnostic has invalid immutable extent')
        result = image.get_data(address, size)
        if len(result) != size:
            raise ValueError('Truncated terminal diagnostic')
        return result

    def choice_data(self, side, address, reviewed):
        image = (self.old, self.new)[side]
        def span(pair, *, tags=False):
            pointer, length = pair
            if length == 0:
                return ''
            if not 0 < length <= 256:
                raise ValueError('Native choice string/tag extent is invalid')
            data = self.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase, length)
            if tags:
                if any(value > 4 for value in data):
                    raise ValueError('Native rank stat outside five-case enum')
                return data.hex()
            return data.decode('utf-8')
        if reviewed in REVIEWED_CHOICE_FLOATS:
            return dict(kind='bounded-float-array', count=REVIEWED_CHOICE_FLOATS[reviewed],
                        bytes=self.immutable(side, address, REVIEWED_CHOICE_FLOATS[reviewed] * 4).hex())
        if reviewed == REVIEWED_RANK_FALLBACK:
            return dict(kind='rank-fallback', text=self.immutable(side, address, 2).decode('utf-8'))
        if reviewed == REVIEWED_RANK_NAMES:
            return dict(kind='rank-names', rows=[span(pair) for pair in struct.iter_unpack('<QQ', self.immutable(side, address, 11 * 16))])
        if reviewed != REVIEWED_SPELL_DEFINITIONS:
            raise ValueError('Unknown native choice definition contract')
        rows = []
        for index in range(111):
            data = self.immutable(side, address + index * 0x78, 0x78)
            rows.append(dict(strings=[span(struct.unpack_from('<QQ', data, offset)) for offset in (0, 16, 32)],
                             rank_tags=span(struct.unpack_from('<QQ', data, 48), tags=True), scalar_tail=data[64:].hex()))
        return dict(kind='native-spell-definitions', stride=0x78, count=111, rows=rows)

    def gear_definitions(self, side, address):
        """Full immutable records retained by the reviewed native gear-choice loop."""
        image = (self.old, self.new)[side]
        rows = []
        data = self.immutable(side, address, 22 * 0x48)
        for offset in range(0, len(data), 0x48):
            strings = []
            for field in (0, 16, 32, 48):
                pointer, length = struct.unpack_from('<QQ', data, offset + field)
                if not 0 < length <= 4096:
                    raise ValueError('Native gear string extent is invalid')
                strings.append(self.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase,
                                              length).decode('utf-8'))
            rows.append(dict(strings=strings, scalar_tail=data[offset + 64:offset + 72].hex()))
        return rows

    def format_program(self, side, address):
        """Reviewed563EF70 compact literal/format scanner, bounded to4KiB."""
        cursor = 0
        while cursor < 4096:
            tag = self.immutable(side, address + cursor, 1)[0]
            cursor += 1
            if tag == 0:
                return self.immutable(side, address, cursor)
            if tag < 0x80:
                length = tag
            elif tag == 0x80:
                length = struct.unpack('<H', self.immutable(side, address + cursor, 2))[0]
                cursor += 2
            else:
                cursor += ((tag & 1) << 2) + (tag & 2) + ((tag >> 1) & 2) + ((tag >> 2) & 2)
                continue
            self.immutable(side, address + cursor, length).decode('utf-8')
            cursor += length
        raise ValueError('Native format program exceeds bounded extent')

    def string_format_vtable(self, reference, candidate):
        """Close the finite String24 fmt::Write vtable, including its self edge."""
        key = reference, candidate
        if key in self.format_vtables:
            # Only this already shape-checked immutable table can recur. Its
            # surrounding proof must still finish every method successfully.
            return dict(reference=reference, candidate=candidate,
                        classification='native-String24-format-vtable-reference')
        tables = [struct.unpack('<6Q', self.immutable(side, address, 48))
                  for side, address in enumerate(key)]
        if any(table[1:3] != (24, 8) for table in tables):
            raise ValueError('Native String formatting vtable size/alignment changed')
        methods = [(tables[0][i] - self.old.OPTIONAL_HEADER.ImageBase,
                    tables[1][i] - self.new.OPTIONAL_HEADER.ImageBase) for i in (0, 3, 4, 5)]
        for a, b in methods:
            layout = compare_function_layout(self.code(0, a), a, self.code(1, b), b)
            if not layout['structure_equivalent'] or layout.get('field_changes'):
                raise ValueError('Native String formatting vtable method layout changed')
        previous = set(self.proved)
        self.format_vtables[key] = 'checking'
        try:
            proofs = [self.pair(a, b) for a, b in methods]
            row = dict(reference=reference, candidate=candidate,
                       classification='native-String24-format-vtable', object_size=24, alignment=8,
                       table_size=48, methods=proofs, complete_vtable_verified=True)
            self.format_vtables[key] = row
            return row
        except Exception:
            self.format_vtables.pop(key, None)
            # Do not retain a method whose successful proof relied on a table
            # cycle that subsequently failed to close.
            for proof_key in set(self.proved) - previous:
                self.proved.pop(proof_key, None)
            raise

    def rust_location(self, side, address):
        image = (self.old, self.new)[side]
        pointer, size, line, column = struct.unpack('<QQII', self.immutable(side, address, 24))
        filename = self.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase, size).decode('utf-8')
        if not filename.endswith('.rs') or not 0 < line < 1000000 or not 0 < column < 100000:
            raise ValueError('Native panic Location is not a bounded Rust source location')
        return dict(filename=filename, line=line, column=column)

    def terminal_allocation_failure(self, old_address, new_address):
        models = []
        for side, address in enumerate((old_address, new_address)):
            image = (self.old, self.new)[side]
            code = self.code(side, address)
            stream = instructions(image, address, address + len(code))
            names = [(i.mnemonic, i.op_str) for i in stream]
            if (len(stream) != 10 or names[:5] != [('push', 'rbp'), ('sub', 'rsp, 0x20'),
                    ('lea', 'rbp, [rsp + 0x20]'), ('test', 'rcx, rcx'), ('jne', stream[4].op_str)]
                    or stream[4].operands[0].imm != stream[8].address
                    or [i.mnemonic for i in stream[5:]] != ['call', 'ud2', 'nop', 'call', 'ud2']):
                # This build's wrapper has no alignment NOP; accept precisely
                # that form as well, preserving identical old/new structure.
                if (len(stream) != 9 or [i.mnemonic for i in stream] !=
                        ['push', 'sub', 'lea', 'test', 'jne', 'call', 'ud2', 'call', 'ud2']
                        or stream[3].op_str != 'rcx, rcx' or stream[4].operands[0].imm != stream[7].address):
                    raise ValueError('Unknown native allocation failure dispatcher')
            calls = [i for i in stream if i.mnemonic == 'call']
            allocation_error = calls[1].operands[0].imm
            error_code = self.code(side, allocation_error)
            error_stream = instructions(image, allocation_error, allocation_error + len(error_code))
            if (len(error_stream) != 8 or [(i.mnemonic, i.op_str) for i in error_stream[3:6]] !=
                    [('mov', 'rax, rcx'), ('mov', 'rcx, rdx'), ('mov', 'rdx, rax')]
                    or [i.mnemonic for i in error_stream] != ['push', 'sub', 'lea', 'mov', 'mov', 'mov', 'call', 'ud2']):
                raise ValueError('Native allocation failure scalar ABI changed')
            panic = calls[0].operands[0].imm
            panic_code = self.code(side, panic)
            panic_stream = instructions(image, panic, panic + len(panic_code))
            if [i.mnemonic for i in panic_stream] != ['push', 'sub', 'lea', 'lea', 'lea', 'mov', 'call', 'ud2']:
                raise ValueError('Unknown native allocation diagnostic ABI')
            message, location, length = panic_stream[3:6]
            if (message.reg_name(message.operands[0].reg) != 'rcx'
                    or location.reg_name(location.operands[0].reg) != 'r8'
                    or length.reg_name(length.operands[0].reg) != 'edx'
                    or message.operands[1].mem.base != capstone.x86.X86_REG_RIP
                    or location.operands[1].mem.base != capstone.x86.X86_REG_RIP):
                raise ValueError('Native panic message/Location roles changed')
            message_address = message.address + message.size + message.operands[1].mem.disp
            location_address = location.address + location.size + location.operands[1].mem.disp
            # Reviewed panic_const uses the compact single-piece formatting
            # representation: low bit1 denotes a string, upper bits its length.
            # Its downstream native dispatcher tests bit0 then shifts right1.
            tagged_length = length.operands[1].imm
            if tagged_length & 1 != 1:
                raise ValueError('Native panic string representation changed')
            diagnostic = self.immutable(side, message_address, tagged_length >> 1).decode('utf-8')
            pointer, size, line, column = struct.unpack('<QQII', self.immutable(side, location_address, 24))
            filename = self.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase, size).decode('utf-8')
            if not filename.endswith('.rs') or not 0 < line < 1000000 or not 0 < column < 100000:
                raise ValueError('Native panic Location is not a bounded Rust source location')
            models.append(dict(address=address, code=code, panic=panic, panic_code=panic_code,
                               allocation_error=allocation_error, error_code=error_code,
                               calls=[i.operands[0].imm for i in calls], diagnostic=diagnostic,
                               filename=filename, line=line, column=column))
        for key in ('code', 'panic_code', 'error_code'):
            root_key = 'address' if key == 'code' else 'panic' if key == 'panic_code' else 'allocation_error'
            roots = (models[0][root_key], models[1][root_key])
            if function_references(models[0][key], roots[0])[0] != function_references(models[1][key], roots[1])[0]:
                raise ValueError('Native failure wrapper changed behavior')
        return dict(reference=old_address, candidate=new_address, classification='terminal-native-failure',
                    no_adapter_success_continuation=True, arguments='allocation error alignment/size scalars',
                    diagnostics=[{k: row[k] for k in ('diagnostic', 'filename', 'line', 'column')} for row in models],
                    scope='Native panic hooks/text may differ; original game failure path is retained')


def damage_frame_borrows(helper, before, after):
    """Prove three native read-only origin borrows cannot mutate saved Game spills."""
    sites = {0x540d666: (0x5429990, 8), 0x540db46: (0x54554d0, 12),
             0x540dda9: (0x54554d0, 12)}
    positions = {ins.address: index for index, ins in enumerate(before)}
    if not any(site in positions for site in sites):
        return {}, {}, []
    if len(before) != len(after) or any(site not in positions for site in sites):
        raise ValueError('DAMAGE frame-borrow sites changed')
    proofs, old_borrows, new_borrows = [], {}, {}
    def paired_callee(streams, reviewed):
        targets = []
        for a, b in zip(*streams):
            if a.mnemonic == 'call' and a.operands[0].type == capstone.x86.X86_OP_IMM and a.operands[0].imm == reviewed:
                if b.mnemonic != 'call' or b.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError('Borrowed-frame callee form changed')
                targets.append(b.operands[0].imm)
        if not targets or len(set(targets)) != 1:
            raise ValueError('Borrowed-frame callee missing or ambiguous')
        return targets[0]
    def bodies(reviewed, candidate):
        result = [instructions(image, address, address + len(helper.code(side, address)))
                  for side, (image, address) in enumerate(((helper.old, reviewed), (helper.new, candidate)))]
        layout = compare_function_layout(helper.code(0, reviewed), reviewed, helper.code(1, candidate), candidate)
        if not layout['structure_equivalent'] or layout['field_changes']:
            raise ValueError('Borrowed-frame helper layout changed')
        return result
    for site, (callee, extent) in sites.items():
        index = positions[site]
        a, b = before[index], after[index]
        if a.mnemonic != 'mov' or a.op_str not in ('r8, rbp', 'rax, rbp') or (a.mnemonic, a.op_str) != (b.mnemonic, b.op_str):
            raise ValueError('DAMAGE origin frame copy changed')
        following = next((i for i in range(index + 1, len(before)) if before[i].mnemonic == 'call'), None)
        if following is None or before[following].operands[0].imm != callee:
            raise ValueError('DAMAGE borrowed origin escapes to unknown first call')
        target = after[following].operands[0].imm
        if callee == 0x54554d0:
            proof = HelperProof(helper.old, helper.new).pair(callee, target)
            pair = bodies(callee, target)
            for stream in pair:
                loads = [i for i, ins in enumerate(stream) if ins.op_str == 'rax, qword ptr [rbp + 0xb0]']
                if len(loads) != 2:
                    raise ValueError('Native packet origin pointer usage changed')
                expected = [('r12d, dword ptr [rax]',), ('ebx, dword ptr [rax + 4]', 'edi, dword ptr [rax + 8]')]
                for index_load, operands in zip(loads, expected):
                    if tuple(ins.op_str for ins in stream[index_load+1:index_load+1+len(operands)]) != operands:
                        raise ValueError('Native packet origin extent changed')
                # Full paired helper closure preserves the two reviewed pointer kills:
                # native no-argument call then MOV RAX from owned packet storage.
            proof = dict(classification='read-only-native-origin12', dependency=proof)
        else:
            root = HelperProof(helper.old, helper.new, game_roots={callee: 'rdx'}).pair(callee, target, candidate_call=True)
            roots = [instructions(image, address, address + len(helper.code(side, address)))
                     for side, (image, address) in enumerate(((helper.old, callee), (helper.new, target)))]
            for stream in roots:
                stores = [ins for ins in stream if ins.op_str == 'qword ptr [rbp - 0x38], r8']
                if len(stores) != 1:
                    raise ValueError('Native origin iterator field changed')
            collector = paired_callee(roots, 0x545dc80)
            collectors = bodies(0x545dc80, collector)
            leaf = paired_callee(collectors, 0x5472930)
            leaf_proof = HelperProof(helper.old, helper.new).pair(0x5472930, leaf)
            leaves = bodies(0x5472930, leaf)
            for stream in leaves:
                loads = [ins for ins in stream if ins.op_str == 'rbx, qword ptr [rdx + 0x28]']
                reads = [(ins.mnemonic, ins.op_str) for ins in stream if any(
                    op.type == capstone.x86.X86_OP_MEM and ins.reg_name(op.mem.base) == 'rbx' for op in ins.operands)]
                writes = [ins for ins in stream if any(ins.reg_name(reg) == 'rbx' for reg in ins.regs_access()[1])]
                if (len(loads) != 1 or reads != [('movsd', 'xmm3, qword ptr [rbx]')]
                        or any(ins not in loads and ins.mnemonic != 'pop' for ins in writes)
                        or any(ins.mnemonic == 'call' for ins in stream)):
                    raise ValueError('Native origin iterator is not a bounded read-only XY borrow')
            proof = dict(classification='read-only-native-origin8', root=root, collector=collector, leaf=leaf_proof,
                         iterator_field=0x28, retained=False)
        old_borrows[site], new_borrows[b.address] = extent, extent
        proofs.append(dict(reference_site=site, candidate_site=b.address, extent=extent, proof=proof))
    return old_borrows, new_borrows, proofs


def map_radius_contract(helper, old_table, new_table):
    """Native spawn XY is clamped to Map.center + unit(delta) * radius."""
    old_code = helper.code(0, REVIEWED_FIND_SPAWN)
    old_ins = instructions(helper.old, REVIEWED_FIND_SPAWN, REVIEWED_FIND_SPAWN + len(old_code))
    first = next(i for i, ins in enumerate(old_ins) if ins.op_str == 'xmm0, qword ptr [r14 + 0x80]')
    block = old_ins[first:first + 20]
    expected = ['movsd', 'movaps', 'subps', 'movaps', 'mulps', 'movshdup', 'addss', 'sqrtss',
                'movss', 'ucomiss', 'jbe', 'movsldup', 'divps', 'movsldup', 'mulps', 'addps', 'movaps']
    if [ins.mnemonic for ins in block[:17]] != expected or block[8].op_str != 'xmm2, dword ptr [r14 + 0x90]':
        raise ValueError('Reviewed map radial clamp contract changed')
    extent = block[16].address + block[16].size - block[0].address
    pattern, mask = instruction_signature(helper.old.get_data(block[0].address, extent), block[0].address)
    sections = [(s.VirtualAddress, s.get_data()) for s in helper.new.sections if s.Characteristics & 0x20000000]
    accepted = []
    for site in signature_candidates(sections, pattern, mask):
        owners = [start for start, end in helper.bounds[1].items() if start <= site < end]
        if len(owners) != 1:
            continue
        start = owners[0]
        code = helper.code(1, start)
        if not compare_function_layout(old_code, REVIEWED_FIND_SPAWN, code, start)['structure_equivalent']:
            continue
        stream = instructions(helper.new, start, start + len(code))
        for side, decoded, table in ((0, old_ins, old_table), (1, stream, new_table)):
            loads = [i for i, ins in enumerate(decoded) if ins.mnemonic == 'lea' and ins.op_str.startswith('r14, [rip')]
            if len(loads) != 1:
                break
            i = loads[0]
            ins = decoded[i]
            if (ins.address + ins.size + ins.operands[1].mem.disp != table
                    or [(x.mnemonic, x.op_str) for x in decoded[i-2:i]] != [('lea', 'rax, [rax + rax*4]'), ('shl', 'eax, 5')]
                    or decoded[i+1].op_str != 'r14, rax'):
                break
        else:
            accepted.append(dict(reference=REVIEWED_FIND_SPAWN, candidate=start,
                                 offset=0x90, type='positive-finite-f32', meaning='native radial spawn boundary',
                                 center_offset=0x80, radius_consumer=site + block[8].address - block[0].address,
                                 policy='Preserve candidate native tuning; adapter does not overwrite this scalar'))
    if len(accepted) != 1:
        raise ValueError('Native map radial clamp missing or ambiguous')
    return accepted[0]


def builtin_ability_contract(helper, reference_copies, candidate_copies):
    """Borrowed three-element ability data; caller separately proves index<=2."""
    tables = []
    for copies in (reference_copies, candidate_copies):
        found = {int(row['builtin_table'], 16) for row in copies if 'builtin_table' in row}
        if len(found) != 1:
            raise ValueError('Built-in cast producer table missing or ambiguous')
        tables.append(found.pop())
    data = [helper.immutable(side, address, 3 * 28) for side, address in enumerate(tables)]
    if data[0] != data[1]:
        raise ValueError('Built-in ability definitions changed')
    tags = [struct.unpack_from('<I', data[0], index * 28)[0] for index in range(3)]
    if any(tag > 4 for tag in tags):
        raise ValueError('Built-in ability exceeds five-case enum')
    return dict(reference=tables[0], candidate=tables[1], count=3, stride=28,
                tag_offset=0, tags=tags, definition_data_verified=True,
                consumer_obligations=['Native producer index is bounded0..2',
                                      'Definition tag0 copied unchanged to Cast32+8'],
                automatic_activation_allowed=False)


def map_enemy_contracts(helper, old_table, new_table, *, definitions_only=False, candidate_layout=None):
    """Paired immutable map definitions and borrowed Enemy/boss scalar payloads."""
    compared, boss_tags = [], set()
    for side, table in enumerate((old_table, new_table)):
        layout = map_definition_layout(candidate_layout if side else None)
        image = (helper.old, helper.new)[side]
        base = image.OPTIONAL_HEADER.ImageBase
        def string(pair):
            pointer, length = pair
            if length == 0:
                return ''
            if not 0 < length <= 1024:
                raise ValueError('Native map definition string exceeds bound')
            return helper.immutable(side, pointer - base, length).decode('utf-8')
        rows = []
        for index in range(9):
            data = helper.immutable(side, table + index * layout['stride'], layout['stride'])
            names = [string(struct.unpack_from('<QQ', data, offset)) for offset in layout['strings']]
            normal_pointer, normal_count = struct.unpack_from('<QQ', data, layout['normal'])
            boss_pointer, boss_count = struct.unpack_from('<QQ', data, layout['boss'])
            if normal_count != 12 or boss_count != 5:
                raise ValueError('Native map enemy definition array shape changed')
            normals, bosses = [], []
            for position in range(normal_count):
                definition = helper.immutable(side, normal_pointer - base + position * 0x50, 0x50)
                if struct.unpack_from('<I', definition)[0] not in (0, 1):
                    raise ValueError('Normal ranged-attack enum changed')
                normals.append(dict(name=string(struct.unpack_from('<QQ', definition, 0x10)),
                                    ranged=definition[:0x10].hex(), scalar_tail=definition[0x20:].hex()))
            for position in range(boss_count):
                definition = helper.immutable(side, boss_pointer - base + position * 0x58, 0x58)
                pointer, count = struct.unpack_from('<QQ', definition, 0x10)
                if not 0 <= count <= 32:
                    raise ValueError('Boss ability array exceeds bounded definition')
                abilities = helper.immutable(side, pointer - base, count * 28) if count else b''
                tags = [struct.unpack_from('<I', abilities, n * 28)[0] for n in range(count)]
                if any(tag > 4 for tag in tags):
                    raise ValueError('Boss ability tag exceeds five-case enum')
                boss_tags.update(tags)
                bosses.append(dict(name=string(struct.unpack_from('<QQ', definition)),
                                   taunt=string(struct.unpack_from('<QQ', definition, 0x20)),
                                   abilities=abilities.hex(), tags=tags, scalar_tail=definition[0x30:].hex()))
            rows.append(dict(names=names, normal=normals, bosses=bosses, scalar_tail=data[layout['scalars']:].hex()))
        compared.append(rows)
    parameter_changes = []
    for index, (before, after) in enumerate(zip(*compared)):
        if {k: v for k, v in before.items() if k != 'scalar_tail'} != {k: v for k, v in after.items() if k != 'scalar_tail'}:
            raise ValueError('Native map/enemy/boss definition contents changed')
        aa, bb = bytes.fromhex(before['scalar_tail']), bytes.fromhex(after['scalar_tail'])
        for offset in range(0, len(aa), 4):
            if aa[offset:offset + 4] != bb[offset:offset + 4]:
                parameter_changes.append(dict(map_index=index, offset=0x70 + offset,
                    before=aa[offset:offset + 4].hex(), after=bb[offset:offset + 4].hex()))
    radius_proof = None
    layout_changed = map_definition_layout(candidate_layout)['stride'] != 0xa0
    if layout_changed and not definitions_only:
        raise ValueError('Changed map records require separate native consumer and added-field contracts')
    if parameter_changes and not definitions_only:
        if any(change['offset'] != 0x90 for change in parameter_changes):
            raise ValueError(f'Native unclassified map scalar parameters changed: {parameter_changes}')
        radius_proof = map_radius_contract(helper, old_table, new_table)
        for change in parameter_changes:
            for key in ('before', 'after'):
                value = struct.unpack('<f', bytes.fromhex(change[key]))[0]
                if not math.isfinite(value) or value <= 0:
                    raise ValueError('Native map radius must remain finite and positive')
                change[key + '_value'] = value
            change['classification'] = 'native radial boundary tuning preserved'
    return dict(reference=old_table, candidate=new_table, classification='native-map-enemy-definitions',
                map_count=9, map_stride=map_definition_layout(candidate_layout)['stride'],
                name_pointer=map_definition_layout(candidate_layout)['strings'][0],
                name_length=map_definition_layout(candidate_layout)['strings'][0] + 8,
                normal_count=12, normal_stride=0x50, boss_count=5, boss_stride=0x58,
                boss_ability_stride=28, boss_ability_tag_offset=0, boss_ability_tags=sorted(boss_tags),
                definition_arrays_verified=True, map_parameter_changes=parameter_changes, radius_contract=radius_proof,
                candidate_layout=map_definition_layout(candidate_layout),
                entire_map_equivalent=not parameter_changes and not layout_changed,
                pointers='Immutable borrowed string and ability arrays only; native constructors own Enemy allocations',
                rows=compared[0])


def map_definition_layout(selection=None):
    """Known record schemas; callers must separately prove native consumers.

    The newer record's added prefix and slice are deliberately not certified.
    Only the named immutable definition spans are compared by this module.
    """
    if selection is None or (selection['stride'], selection['name_pointer'], selection['name_length']) == (160, 0, 8):
        return dict(stride=160, strings=[0, 16, 32, 80, 96], normal=48, boss=64, scalars=112)
    if (selection['stride'], selection['name_pointer'], selection['name_length']) == (184, 8, 16):
        return dict(stride=184, strings=[8, 24, 40, 104, 120], normal=72, boss=88, scalars=136)
    raise ValueError('Unreviewed native map definition schema')


def map_table_identity(old, new, old_table, new_table, *, candidate_layout=None):
    """Prove only fields consumed by native_map/boss_identity, not all map rules."""
    rows = []
    for index in range(9):
        names, bosses = [], []
        for side, (image, table) in enumerate(((old, old_table), (new, new_table))):
            layout = map_definition_layout(candidate_layout if side else None)
            address = table + index * layout['stride']
            section = image.get_section_by_rva(address)
            if (section is None or section.Characteristics & (0x20000000 | 0x80000000)
                    or address + layout['stride'] > section.VirtualAddress + section.Misc_VirtualSize):
                raise ValueError('Map table is not immutable native data')
            row = image.get_data(address, layout['stride'])
            if len(row) != layout['stride']:
                raise ValueError('Truncated native map row')
            pointer, size = struct.unpack_from('<QQ', row, layout['strings'][0])
            boss_pointer, count = struct.unpack_from('<QQ', row, layout['boss'])
            base = image.OPTIONAL_HEADER.ImageBase
            if not 1 <= size <= 32 or count != 5:
                raise ValueError('Map name or boss array shape changed')
            for pointer_value, extent in ((pointer, size), (boss_pointer, 5 * 0x58)):
                target = pointer_value - base
                storage = image.get_section_by_rva(target)
                if (storage is None or storage.Characteristics & (0x20000000 | 0x80000000)
                        or target + extent > storage.VirtualAddress + storage.Misc_VirtualSize):
                    raise ValueError('Native map reference has invalid immutable extent')
            name = image.get_data(pointer - base, size)
            if len(name) != size or len(image.get_data(boss_pointer - base, 5 * 0x58)) != 5 * 0x58:
                raise ValueError('Truncated native map references')
            names.append(name)
            bosses.append(boss_pointer - base)
        if names[0] != names[1] or names[0] in [r['name'].encode('ascii') for r in rows]:
            raise ValueError('Native map order or name identity changed')
        rows.append(dict(name=names[0].decode('ascii'), reference_bosses=bosses[0], candidate_bosses=bosses[1]))
    layout = map_definition_layout(candidate_layout)
    return dict(reference=old_table, candidate=new_table, row_stride=layout['stride'], boss_stride=0x58,
                map_name_pointer=layout['strings'][0], map_name_length=layout['strings'][0] + 8,
                boss_pointer=layout['boss'], boss_count=layout['boss'] + 8,
                rows=rows, scope='map name/index and boss identity only; boss definition semantics need separate code proof')


def referenced_data_candidate(old, new, structural, reviewed_address):
    """Require coherent RIP target evidence from complete structural functions."""
    bounds_old, bounds_new = dict(unwind_ranges(old)), dict(unwind_ranges(new))
    evidence = []
    for key, row in structural.items():
        source = int(key, 16)
        if source not in bounds_old:
            continue
        before = old.get_data(source, bounds_old[source] - source)
        ar = function_references(before, source)[1]
        if not any(r[2] == 'rip' and r[3] == reviewed_address for r in ar):
            continue
        for candidate in row.get('candidates', ()):
            target = int(candidate['rva'], 16)
            if not candidate.get('structure_equivalent') or target not in bounds_new:
                continue
            after = new.get_data(target, bounds_new[target] - target)
            if not compare_function_layout(before, source, after, target)['structure_equivalent']:
                continue
            aa, bb = instructions(old, source, bounds_old[source]), instructions(new, target, bounds_new[target])
            if len(aa) != len(bb):
                continue
            for a, b in zip(aa, bb):
                for i, operand in enumerate(a.operands):
                    if (operand.type == capstone.x86.X86_OP_MEM and operand.mem.base == capstone.x86.X86_REG_RIP
                            and a.address + a.size + operand.mem.disp == reviewed_address):
                        other = b.operands[i]
                        if other.type != capstone.x86.X86_OP_MEM or other.mem.base != capstone.x86.X86_REG_RIP:
                            raise ValueError('Native data reference addressing changed')
                        evidence.append(dict(function=source, candidate_function=target,
                                             candidate=b.address + b.size + other.mem.disp))
    targets = {row['candidate'] for row in evidence}
    layout = None
    if reviewed_address == REVIEWED_MAP_TABLE:
        # MAP_SELECT's complete bounded name lookup survives the record change.
        # Combine its typed table evidence with any unchanged-function evidence;
        # disagreements remain ambiguous, never silently preferred.
        entry = 0x539a680
        for row in structural.get(hex(entry), {}).get('candidates', ()):
            try:
                proof = map_selection_contract(old, entry, new, int(row['rva'], 16))
            except ValueError:
                continue
            if proof['reference_layout']['table'] != reviewed_address:
                continue
            candidate = proof['candidate_layout']['table']
            targets.add(candidate)
            evidence.append(dict(function=entry, candidate_function=proof['candidate'],
                                 candidate=candidate, map_selection=proof))
            if layout is not None and layout != proof['candidate_layout']:
                raise ValueError('Native map record layout is ambiguous')
            layout = proof['candidate_layout']
    if len(targets) != 1:
        raise ValueError('Native data target is missing or ambiguous')
    result = dict(reference=reviewed_address, candidate=targets.pop(), evidence=evidence)
    if layout is not None:
        result['candidate_layout'] = layout
    return result


def class_definition(helper, side, address):
    """Native START/DEFEAT consumed prefix, distinct from melee's 16 bytes."""
    image = (helper.old, helper.new)[side]
    data = helper.immutable(side, address, 0x40)

    def text(pointer, length):
        if not 0 < length <= 128:
            raise ValueError('Native class string length is invalid')
        try:
            return helper.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase, length).decode('utf-8')
        except UnicodeDecodeError as error:
            raise ValueError('Native class string is not UTF-8') from error

    identifier = text(*struct.unpack_from('<QQ', data, 0x10))
    label = text(*struct.unpack_from('<QQ', data, 0x20))
    pointer, count = struct.unpack_from('<QQ', data, 0x30)
    if not 0 < count <= 128:
        raise ValueError('Native class ability slice length is invalid')
    abilities = helper.immutable(side, pointer - image.OPTIONAL_HEADER.ImageBase, count * 16)
    return dict(consumed_size=0x40, melee=data[:16].hex(), identifier=identifier, label=label,
                ability_names=[text(p, n) for p, n in struct.iter_unpack('<QQ', abilities)])


def adapter_data_contracts(old, new, structural):
    helper = HelperProof(old, new)
    results = {}
    for reviewed, size, kind in ((REVIEWED_CLOCK_FLOAT, 4, 'f32_clock_constant'),
                                 (REVIEWED_DEFAULT_MELEE, 16, 'melee_profile_prefix'),
                                 (REVIEWED_DEFEAT_LABEL, 6, 'result_label')):
        row = referenced_data_candidate(old, new, structural, reviewed)
        aa, bb = helper.immutable(0, reviewed, size), helper.immutable(1, row['candidate'], size)
        if aa != bb:
            raise ValueError(f'Consumed native {kind} data changed')
        if kind == 'f32_clock_constant' and not math.isfinite(struct.unpack('<f', aa)[0]):
            raise ValueError('Native clock constant is not finite')
        if kind == 'result_label' and aa != b'defeat':
            raise ValueError('Native result label does not match the adapter ABI')
        row.update(kind=kind, consumed_size=size, equal_native_bytes=True)
        results[hex(reviewed)] = row
    table = referenced_data_candidate(old, new, structural, REVIEWED_CLASS_MELEE_TABLE)
    selections = []
    for side, image in enumerate((old, new)):
        target = table['reference'] if side == 0 else table['candidate']
        bound_proofs = []
        for evidence in table['evidence']:
            entry = evidence['function'] if side == 0 else evidence['candidate_function']
            stream = instructions(image, entry, helper.bounds[side][entry])
            for index, ins in enumerate(stream):
                if (ins.mnemonic != 'lea' or len(ins.operands) != 2
                        or ins.operands[1].type != capstone.x86.X86_OP_MEM
                        or ins.operands[1].mem.base != capstone.x86.X86_REG_RIP
                        or ins.address + ins.size + ins.operands[1].mem.disp != target):
                    continue
                block = stream[index - 5:index + 2]
                if (len(block) == 7 and block[0].mnemonic == 'movzx'
                        and [(i.mnemonic, i.op_str) for i in block[1:3]] == [('add', 'al, 0xfe'), ('cmp', 'al, 9')]
                        and block[3].mnemonic == 'ja' and (block[4].mnemonic, block[4].op_str) == ('movzx', 'eax, al')
                        and block[6].mnemonic == 'mov' and block[6].op_str in (
                            'rax, qword ptr [rcx + rax*8]', 'rdi, qword ptr [rcx + rax*8]')
                        and ins.reg_name(ins.operands[0].reg) == 'rcx'):
                    bound_proofs.append(ins.address)
        if not bound_proofs:
            raise ValueError('Native melee class table has no proved 2..11 index bound')
        pointers = struct.unpack('<10Q', helper.immutable(side, target, 80))
        profiles = []
        for pointer in pointers:
            address = pointer - image.OPTIONAL_HEADER.ImageBase
            data = helper.immutable(side, address, 16)
            enabled, damage, interval, radius = struct.unpack('<I3f', data)
            if enabled not in (0, 1) or (enabled and not all(math.isfinite(v) and 0 < v <= 1000 for v in (damage, interval, radius))):
                raise ValueError('Native class melee profile prefix violates consumed ABI')
            profiles.append(dict(rva=address, bytes=data.hex(), native_definition=class_definition(helper, side, address)))
        selections.append(dict(index_bound_sites=bound_proofs, profiles=profiles))
    if [p['bytes'] for p in selections[0]['profiles']] != [p['bytes'] for p in selections[1]['profiles']]:
        raise ValueError('Native class melee values changed')
    if [p['native_definition'] for p in selections[0]['profiles']] != [p['native_definition'] for p in selections[1]['profiles']]:
        raise ValueError('Native class identifiers, names or abilities changed')
    default = results[hex(REVIEWED_DEFAULT_MELEE)]
    default_definitions = [class_definition(helper, side, default[key])
                           for side, key in enumerate(('reference', 'candidate'))]
    if default_definitions[0] != default_definitions[1]:
        raise ValueError('Native default class definition changed')
    default['native_definition'] = default_definitions[0]
    table.update(kind='class_profile_pointer_table', consumed_size=80, classes=list(range(2, 12)),
                 reference_profiles=selections[0], candidate_profiles=selections[1],
                 scope='16-byte adapter melee prefix plus distinct64-byte native START/DEFEAT definition contract; no later class fields admitted')
    results[hex(REVIEWED_CLASS_MELEE_TABLE)] = table
    return results


def discover_helper_contracts(reference, binary, structural, menu=None):
    if menu is None:
        menu = discover_menu_contract(reference, binary, structural)
    before, after = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(before).hexdigest() != UPDATED_HASH or menu.get('sha256') != hashlib.sha256(after).hexdigest():
        raise ValueError('Helper contract inputs do not identify the reviewed/candidate builds')
    proof = HelperProof(pefile.PE(data=before, fast_load=True), pefile.PE(data=after, fast_load=True))
    helpers, unresolved = {}, []
    for reviewed in (REVIEWED_FREE, REVIEWED_DIFFICULTY, REVIEWED_RESERVE_REWARDS):
        # The complete menu destructor proof fixes its free-call target.
        candidates = ([reviewed] if reviewed == REVIEWED_FREE and reviewed in
                      menu['command_destructor']['external_dependencies'] else proof.candidates(reviewed))
        accepted = []
        for candidate in candidates:
            try:
                accepted.append(proof.pair(reviewed, candidate))
            except ValueError as error:
                unresolved.append(dict(reference=reviewed, candidate=candidate, reason=str(error)))
        if accepted:
            helpers[hex(reviewed)] = dict(candidate=min(row['candidate'] for row in accepted),
                                        equivalent_aliases=[row['candidate'] for row in accepted], proofs=accepted)
        elif not candidates:
            unresolved.append(dict(reference=reviewed, reason='No complete matching native helper'))
    table = referenced_data_candidate(proof.old, proof.new, structural, REVIEWED_MAP_TABLE)
    table['contract'] = map_table_identity(proof.old, proof.new, table['reference'], table['candidate'],
                                         candidate_layout=table.get('candidate_layout'))
    consumed_data = adapter_data_contracts(proof.old, proof.new, structural)
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(after).hexdigest():
        raise ValueError('Game changed while discovering native helpers')
    return dict(sha256=hashlib.sha256(after).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, helpers=helpers, map_table=table,
                adapter_data=consumed_data, account_config=menu['account_config'], unresolved=unresolved)


def scalar_pair_packet_contract(old, new, candidate):
    """Reviewed packet writer's footprint, only after complete helper closure."""
    proof = HelperProof(old, new).pair(REVIEWED_SCALAR_PAIR_PACKET, candidate)
    return dict(proof=proof, abi={'rcx': 'owned Packet32 output', 'rdx': 'GUID scalar',
                'r8': 'borrowed scalar-pair array', 'r9': 'array element count'},
                source_element_size=8, source_reads=[{'offset': 0, 'size': 4}, {'offset': 4, 'size': 4}],
                writes=['RCX Packet32 output', 'fresh native allocation or its reserved replacement', 'private stack'],
                retains_source_pointer=False, packet_opcode=0x134,
                caller_obligations=['Output is an owned32-byte writable object',
                    'Input points to count valid8-byte scalar pairs for the duration of the call',
                    'GUID is scalar, not a dereferenced pointer', 'Native packet destructor retains allocator ownership'])


def discover_pause_call_contracts(reference, binary, structural):
    """Admission for isolated native calls only; output validation is mandatory."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Pause call reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
    entries = {}
    for name, message, initial, final in [('PAUSE', 'paused', 1, 3), ('RESUME', 'unpaused', 3, 1)]:
        source = hooks[name]['reference_rva']
        accepted = []
        for candidate in structural.get(hex(source), {}).get('candidates', ()):
            target = int(candidate['rva'], 16)
            proof = HelperProof(old, new, game_roots={source: 'rcx'})
            try:
                row = proof.pair(source, target, candidate_call=True)
                strings = {proof.immutable(1, literal['candidate'], literal['size']).decode('utf-8')
                           for literal in row['literals']}
                if strings != {'type', message}:
                    raise ValueError('Native pause output literals changed')
                stream = instructions(new, target, target + row['size'])
                transitions = [ins for ins in stream if ins.mnemonic in ('cmp', 'mov')
                    and len(ins.operands) == 2 and ins.operands[0].type == capstone.x86.X86_OP_MEM
                    and ins.operands[0].mem.base == capstone.x86.X86_REG_RCX
                    and ins.operands[0].size == 1 and ins.operands[1].type == capstone.x86.X86_OP_IMM]
                if (len(transitions) != 2 or [ins.mnemonic for ins in transitions] != ['cmp', 'mov']
                        or [ins.operands[1].imm for ins in transitions] != [initial, final]
                        or transitions[0].operands[0].mem.disp != transitions[1].operands[0].mem.disp):
                    raise ValueError('Native pause phase transition changed')
                row.update(entry=target, expected=new.get_data(target, 16).hex(),
                           game_phase_offset=transitions[0].operands[0].mem.disp,
                           initial_phase=initial, final_phase=final, output_json={'type': message},
                           abi={'rcx': 'owned-live-Game', 'return': 'preserved-native-caller-context'})
                accepted.append(row)
            except ValueError:
                continue
        if len(accepted) != 1:
            raise ValueError(f'{name} isolated call contract missing or ambiguous')
        entries[name] = accepted[0]
    if entries['PAUSE']['game_phase_offset'] != entries['RESUME']['game_phase_offset']:
        raise ValueError('Pause/resume disagree on Game phase field')
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(bb).hexdigest():
        raise ValueError('Game changed while proving isolated pause calls')
    return dict(sha256=hashlib.sha256(bb).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, isolated_candidate_calls_only=True, entries=entries,
                runtime_obligations=['Disposable isolated Game and profile only',
                    'Call from stopped native WRITE with owned Game and preserved caller stack/context',
                    'Observe both 1-to-3 paused and 3-to-1 unpaused phase transitions',
                    'Observe decoded native serializer output containing exact expected type value',
                    'Require both native returns, no crash and clean bounded process exit',
                    'Bind successful evidence to executable and all adapter source hashes; no production activation'])


def boss_hud_health_contract(helper):
    """Pair the native Enemy HP/maximum JSON fields, including their exact keys."""
    start, end = REVIEWED_BOSS_HUD_HP
    raw = helper.old.get_data(start, end - start)
    pattern, mask = instruction_signature(raw, start)
    sections = [(section.VirtualAddress, section.get_data()) for section in helper.new.sections
                if section.Characteristics & 0x20000000]
    accepted = []
    for target in signature_candidates(sections, pattern, mask):
        streams = [instructions(image, address, address + len(raw))
                   for image, address in ((helper.old, start), (helper.new, target))]
        fields = []
        for side, stream in enumerate(streams):
            keys = []
            for index, ins in enumerate(stream):
                if ins.mnemonic != 'lea' or not ins.op_str.startswith('r8, [rip'):
                    continue
                length = next((item.operands[1].imm for item in stream[index + 1:index + 5]
                               if item.mnemonic == 'mov' and item.op_str.startswith('r9d, ')
                               and item.operands[1].type == capstone.x86.X86_OP_IMM), None)
                if length is None:
                    raise ValueError('Native boss HUD key length missing')
                address = ins.address + ins.size + ins.operands[1].mem.disp
                keys.append(helper.immutable(side, address, length).decode('utf-8'))
            reads = [ins.operands[1].mem.disp for ins in stream if ins.mnemonic == 'movss'
                     and ins.op_str.startswith('xmm0, dword ptr [rsi + ')]
            fields.append((keys, reads))
        if fields != [(['hp', 'hpMax'], [0xe0, 0xe4])] * 2:
            continue
        accepted.append(dict(reference=start, candidate=target, extent=end-start,
                             hp='hp', max_hp='hpMax', enemy_hp=0xe0, enemy_max_hp=0xe4))
    if len(accepted) != 1:
        raise ValueError('Native boss HUD HP serialization missing or ambiguous')
    return accepted[0]


def discover_boss_call_contract(reference, binary, structural):
    """One disposable native boss spawn; no production or co-op activation."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Boss reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    source = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['SPAWN_BOSS']['reference_rva']
    accepted, failures = [], []
    for candidate in structural.get(hex(source), {}).get('candidates', ()):
        target = int(candidate['rva'], 16)
        proof = HelperProof(old, new, game_roots={source: 'rcx'})
        try:
            row = proof.pair(source, target, candidate_call=True)
            row.update(entry=target, expected=new.get_data(target, 16).hex(),
                       abi={'rcx': 'owned-live-Game', 'rdx': 'borrowed immutable BossDefinition88 pointer'},
                       initial_phase=1)
            accepted.append(row)
        except ValueError as error:
            failures.append(str(error))
    if len(accepted) != 1:
        raise ValueError(f'Native isolated boss call missing or ambiguous: {failures}')
    row = accepted[0]
    phase = discover_pause_call_contracts(reference, binary, structural)['entries']['PAUSE']['game_phase_offset']
    row['game_phase_offset'] = phase
    fields = {'phase': dict(offset=phase, width=1, reviewed_offset=0x8cf)}
    for name, reviewed in (('map_pointer', 0x2d8), ('map_length', 0x2e0),
                           ('enemies_pointer', 0x578), ('enemies_count', 0x580)):
        offsets = {access['new_offset'] for access in row['game_accesses'] if access['old_offset'] == reviewed and access['width'] == 8}
        if len(offsets) != 1:
            raise ValueError(f'Boss call lacks unique Game {name} field')
        fields[name] = dict(offset=offsets.pop(), width=8, reviewed_offset=reviewed)
    table = next(dep for dep in row['dependencies'] if dep.get('classification') == 'native-map-enemy-definitions')
    model_target = next(dep['candidate'] for dep in row['dependencies'] if dep.get('reference') == REVIEWED_MODEL_SPAWN)
    model = HelperProof(old, new, game_roots={REVIEWED_MODEL_SPAWN: 'rcx'}).pair(REVIEWED_MODEL_SPAWN, model_target, candidate_call=True)
    streams = [instructions(image, address, address + len(HelperProof(old, new).code(side, address)))
               for side, (image, address) in enumerate(((old, REVIEWED_MODEL_SPAWN), (new, model_target)))]
    for stream in streams:
        names = [(ins.mnemonic, ins.op_str) for ins in stream]
        if ('mov', 'r14d, r9d') not in names or ('movss', 'xmm0, dword ptr [rbp + 0xe8]') not in names:
            raise ValueError('Native model/health input roles changed')
        for key, value_register in ((22, 'r12d'), (28, 'r12d'), (131, 'r14d')):
            matched = [index for index, ins in enumerate(stream) if ins.mnemonic == 'mov'
                       and len(ins.operands) == 2 and ins.operands[0].type == capstone.x86.X86_OP_MEM
                       and ins.op_str.startswith('qword ptr [rbp + 0x50], ')
                       and ins.operands[1].type == capstone.x86.X86_OP_IMM and ins.operands[1].imm == key]
            if len(matched) != 1 or stream[matched[0] + 3].op_str != 'r8d, ' + value_register:
                raise ValueError('Native model packet field/value association changed')

    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(bb).hexdigest():
        raise ValueError('Game changed while proving isolated boss call')
    return dict(sha256=hashlib.sha256(bb).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, isolated_candidate_calls_only=True,
                entries={'SPAWN_BOSS': row}, map_table=table, fields=fields,
                world_fields=dict(display_id=131, hp=22, max_hp=28), world_field_proof=model,
                boss_ui=dict(type='boss', name='name'),
                hud_fields=dict(name='name', hp='hp', max_hp='hpMax'), hud_health_proof=boss_hud_health_contract(HelperProof(old,new)),
                enemy=dict(stride=0x148, definition_pointer=0x30, guid=0x78, hp=0xe0, max_hp=0xe4,
                           start_position=0xfc, end_position=0x108, movement_started=0x114, movement_duration=0x118,
                           position_components=3, scalar_width=4,
                           evidence='Paired native constructor copies328 bytes from RBP-38; all non-Game offsets unchanged'),
                boss_definition=dict(stride=0x58, name_pointer=0, name_length=8, entry_id=0x30,
                                     display_id=0x34, scale=0x38, base_hp=0x44,
                                     guid_entry_shift=24, guid_entry_mask=0xffffff,
                                     evidence='Native constructor passes definition+30/R8 entry and+34/R9 display to model spawn'),
                boss_argument=dict(map_stride=table['candidate_layout']['stride'],
                                   array_pointer=table['candidate_layout']['boss'],
                                   array_count=table['candidate_layout']['boss'] + 8, count=5,
                                   stride=0x58, ordinal=0, pointer_ownership='immutable borrowed definition'),
                runtime_obligations=['Disposable isolated running Game and profile; stopped validated WRITE owner',
                    'Resolve map from actual native Game; derive boss0 pointer from verified immutable map table',
                    'Spawn at most one boss; require normal native return and Enemy vector count increment',
                    'Validate new Enemy definition pointer, finite positive HP and scalar combat fields',
                    'Observe native boss UI/announcement and subsequent model/update packets matching spawned GUID',
                    'Preserve native radius and exponential balance changes; do not overwrite native scalar values',
                    'Require unchanged executable and adapter source identity; no production activation'])


def discover_damage_call_contract(reference, binary, structural):
    """Guarded native basic-melee input; actual hit/kill remains a runtime obligation."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Damage reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    source = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['DAMAGE']['reference_rva']
    accepted, failures = [], []
    for candidate in structural.get(hex(source), {}).get('candidates', ()):
        target = int(candidate['rva'], 16)
        try:
            row = HelperProof(old, new, game_roots={source: 'rcx'}).pair(source, target, candidate_call=True)
            row.update(entry=target, expected=new.get_data(target, 16).hex(), initial_phase=1,
                       abi={'rcx': 'owned-live-Game', 'rdx': 'GUID of existing live native Enemy',
                            'xmm2': 'positive finite f32 damage', 'r9': 0},
                       stack_arguments=[0, 0, 1], damage_bounds={'min_exclusive': 0, 'max': 100000})
            accepted.append(row)
        except ValueError as error:
            failures.append(str(error))
    if len(accepted) != 1:
        raise ValueError(f'Native isolated DAMAGE call missing or ambiguous: {failures}')
    row = accepted[0]
    fields = {}
    for name, reviewed, width in (('phase', 0x8cf, 1), ('luck', 0x2d0, 4), ('source_tag', 0xf8, 1),
                                  ('enemies_pointer', 0x578, 8), ('enemies_count', 0x580, 8),
                                  ('xp', 0x4ac, 4), ('boss_kills', 0x6dc, 4),
                                  ('rewards_pointer', 0x650, 8), ('rewards_count', 0x658, 8)):
        targets = {use['new_offset'] for use in row['game_accesses']
                   if use['old_offset'] == reviewed and use['width'] == width}
        if len(targets) != 1:
            raise ValueError(f'DAMAGE lacks unique typed Game {name}')
        fields[name] = dict(offset=targets.pop(), width=width, reviewed_offset=reviewed)
    row['game_phase_offset'] = fields['phase']['offset']
    condition = row['preconditions'][0]
    guard_site = int(condition['new_rva'], 16)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    guard = next(decoder.disasm(new.get_data(guard_site, 15), guard_site))
    if (guard.mnemonic != 'movzx' or guard.operands[0].size != 4
            or guard.operands[1].type != capstone.x86.X86_OP_MEM or guard.operands[1].size != 1
            or guard.reg_name(guard.operands[1].mem.base) != condition['register']
            or guard.operands[1].mem.disp != condition['new_offset']):
        raise ValueError('DAMAGE dispatch guard instruction no longer matches typed load')
    guard_instruction = dict(rva=guard_site, expected=guard.bytes.hex(), base=condition['register'],
        destination=guard.reg_name(guard.operands[0].reg), offset=condition['new_offset'], width=1,
        maximum=3, length=guard.size, zero_extend_to=32, mandatory=True)
    def definition_tables(value):
        if isinstance(value, dict):
            if (value.get('classification') == 'native-choice-data'
                    and value.get('reference') in (REVIEWED_SPELL_DEFINITIONS, REVIEWED_SPELL_DEFINITIONS + 0x78)):
                yield value['candidate'] - (value['reference'] - REVIEWED_SPELL_DEFINITIONS)
            for child in value.values():
                yield from definition_tables(child)
        elif isinstance(value, list):
            for child in value:
                yield from definition_tables(child)
    tables = set(definition_tables(row))
    if len(tables) != 1:
        raise ValueError('DAMAGE trigger lacks unique immutable ability definitions')
    table = tables.pop()
    helper = HelperProof(old, new)
    definitions = helper.choice_data(1, table, REVIEWED_SPELL_DEFINITIONS)
    if definitions != helper.choice_data(0, REVIEWED_SPELL_DEFINITIONS, REVIEWED_SPELL_DEFINITIONS):
        raise ValueError('DAMAGE trigger ability definitions changed')
    # The loop immediately before the guarded load scans Game's Ability80
    # definition pointers and enters only for native tag 11 at definition+75.
    stream = instructions(new, row['entry'], row['entry'] + len(helper.code(1, row['entry'])))
    ordinal = next(i for i, ins in enumerate(stream) if ins.address == guard_site)
    if (stream[ordinal - 2].mnemonic, stream[ordinal - 2].op_str) != ('cmp', 'byte ptr [r8 + 0x75], 0xb') or stream[ordinal - 1].mnemonic != 'jne':
        raise ValueError('DAMAGE guard trigger native ability predicate changed')
    triggers = [dict(index=i, definition=table + i * 120, key=item['strings'][0],
                     title=item['strings'][1], icon=item['strings'][2])
                for i, item in enumerate(definitions['rows'])
                if helper.immutable(1, table + i * 120 + 0x75, 1) == b'\x0b']
    guard_trigger = dict(definition_table=table, definition_stride=120, definition_count=111,
                         ability_stride=80, ability_definition_pointer=0, definition_tag_offset=0x75,
                         tag=11, abilities=triggers,
                         acquisition='Choose an actually offered native ability through CHOOSE; never write the ability vector')
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(bb).hexdigest():
        raise ValueError('Game changed while proving isolated DAMAGE call')
    return dict(sha256=hashlib.sha256(bb).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, isolated_candidate_calls_only=True,
                entries={'DAMAGE': row}, fields=fields, preconditions=row['preconditions'], guard_instruction=guard_instruction,
                guard_trigger=guard_trigger,
                enemy=dict(stride=0x148, dead=0x68, dead_width=4, dead_value=1, guid=0x78, hp=0xe0, max_hp=0xe4),
                kill_ui=dict(type='bossdown'),
                runtime_obligations=['Stopped validated WRITE owning disposable live Game; phase1',
                    'Before each call validate Game source-tag byte0..3 and target GUID exists with finite positive HP',
                    'Retain dispatch tag bound while the native call executes; unknown mutation invalidates this conditional proof',
                    'Use only basic melee spell0 and reviewed stack flags0/0/1; no damage-scaling instruction patches',
                    'Verify actual target HP decrease plus matching native world update/combat packet, not only return',
                    'For kill require native target death/removal and bossdown/XP/reward outputs where applicable',
                    'Observe typed luck field on real boss loot branch; do not change loot chance or RNG',
                    'Require normal return, bounded isolated process and unchanged executable/source identity; no production activation'])


def upgrade_rank_contract(helper, reference, candidate):
    """Interpret the paired CHOOSE upgrade loop: one rank per stat-tag byte."""
    streams = [instructions(image, entry, helper.bounds[side][entry])
               for side, (image, entry) in enumerate(((helper.old, reference), (helper.new, candidate)))]
    if len(streams[0]) != len(streams[1]):
        raise ValueError('Native upgrade instruction pairing changed')
    def paired(pattern):
        positions = []
        for stream in streams:
            matches = [i for i in range(len(stream)-len(pattern)+1)
                       if all(stream[i+j].mnemonic == name and (operand is None or stream[i+j].op_str == operand)
                              for j, (name, operand) in enumerate(pattern))]
            if len(matches) != 1:
                raise ValueError('Native upgrade rank/count producer is missing or ambiguous')
            positions.append(matches[0])
        if positions[0] != positions[1]:
            raise ValueError('Native upgrade producer instruction role moved independently')
        return positions[0]
    capacity = paired([('mov', 'rdx, qword ptr [rax + r9 + 0x48]'),
        ('movabs', 'rsi, 0x8000000000000000'), ('mov', 'r8, rdx'), ('xor', 'r8, rsi'),
        ('test', 'rdx, rdx'), ('mov', 'edx, 1'), ('cmovs', 'rdx, r8')])
    count = paired([('mov', 'rcx, qword ptr [rbx + 0x58]'),
        ('mov', 'qword ptr [rbp + 0x238], rcx'), ('test', 'rcx, rcx'), ('jns', None)])
    index = paired([('mov', 'r12, qword ptr [rbx + 0x60]'), ('je', None),
                    ('mov', 'rdi, qword ptr [rbx + 0x50]')])
    copy = paired([('mov', 'rcx, rax'), ('mov', 'qword ptr [rbp + 0x248], rax'),
        ('mov', 'rdx, rdi'), ('mov', 'r8, r15'), ('call', None), ('mov', 'rdi, r15'), ('jmp', None)])
    length = paired([('mov', 'r15, qword ptr [rbp + 0x238]'), ('mov', 'rcx, r15'), ('call', None)])
    loop = paired([('inc', 'r13'), ('cmp', 'rdi, r13'),
        ('mov', 'rcx, qword ptr [rbp + 0x248]'), ('je', None),
        ('mov', 'r15b, byte ptr [rcx + r13]'), ('mov', 'r14d, dword ptr [rbx + 0x20]'),
        ('inc', 'r14d'), ('mov', 'dword ptr [rbx + 0x20], r14d')])
    zero = paired([('xor', 'r13d, r13d'), ('jmp', None)])
    checked = paired([('test', 'rdi, rdi'), ('je', None), ('lea', 'rbx, [r12 + r12*4]'), ('shl', 'rbx, 4')])
    for stream in streams:
        if (stream[zero+1].operands[0].imm != stream[loop+4].address
                or stream[checked+1].operands[0].imm != stream[loop+3].operands[0].imm
                or not count < index < length < copy < checked < zero < loop):
            raise ValueError('Native upgrade count does not control the rank loop')
        rank_writes = [ins for ins in stream if ins.mnemonic == 'mov' and ins.op_str == 'dword ptr [rbx + 0x20], r14d']
        if len(rank_writes) != 1:
            raise ValueError('Native upgrade has another rank publication')
    return dict(choice_capacity_offset=0x48, choice_pointer_offset=0x50, choice_count_offset=0x58,
        ability_index_offset=0x60, element_size=1, allowed_tags=list(range(5)),
        capacity_max_exclusive=1 << 63, rank_offset=0x20, rank_width=4,
        formula='previous_native_rank + selected_choice_tag_count',
        native_upgrade_loop_verified=True,
        sites=[dict(reference=streams[0][i].address, candidate=streams[1][i].address)
               for i in (capacity, count, index, length, copy, checked, zero, loop)])


def discover_progression_call_contracts(reference, binary, structural):
    """Isolated XP/talent calls with native state/output checks still required."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Progression reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
    entries, field_map = {}, {}
    for name in ('AWARD_XP', 'CHOOSE'):
        source = hooks[name]['reference_rva']
        accepted, failures = [], []
        for candidate in structural.get(hex(source), {}).get('candidates', ()):
            target = int(candidate['rva'], 16)
            proof = HelperProof(old, new, game_roots={source: 'rcx'})
            try:
                row = proof.pair(source, target, candidate_call=True)
                row.update(entry=target, expected=new.get_data(target, 16).hex(),
                           abi={'rcx': 'owned-live-Game', 'rdx': 'u64 XP amount' if name == 'AWARD_XP' else 'u64 native choice index'},
                           second={'min': 1, 'max': 100} if name == 'AWARD_XP' else {'min': 0, 'exclusive_max': 'choices_count'},
                           initial_phase=1 if name == 'AWARD_XP' else 2)
                accepted.append(row)
            except ValueError as error:
                failures.append(str(error))
        if len(accepted) != 1:
            raise ValueError(f'{name} isolated progression call missing or ambiguous: {failures}')
        entries[name] = accepted[0]
        for field in accepted[0]['game_accesses']:
            offset, target = field['old_offset'], field['new_offset']
            if offset in field_map and field_map[offset] != target:
                raise ValueError('Progression calls disagree on typed Game field')
            field_map[offset] = target
    consumption_target = next(dep['candidate'] for dep in entries['CHOOSE']['dependencies']
                              if dep.get('reference') == REVIEWED_COMPLETE_CHOICE)
    consumption = HelperProof(old, new, game_roots={REVIEWED_COMPLETE_CHOICE: 'rcx'}).pair(
        REVIEWED_COMPLETE_CHOICE, consumption_target, candidate_call=True)
    for field in consumption['game_accesses']:
        offset, target = field['old_offset'], field['new_offset']
        if offset in field_map and field_map[offset] != target:
            raise ValueError('Native choice completion disagrees on Game field')
        field_map[offset] = target
    reviewed_fields = {'level': (0x4a8, 4), 'xp': (0x4ac, 4), 'phase': (0x8cf, 1),
                       'choices_pointer': (0x620, 8), 'choices_count': (0x628, 8), 'choice_kind': (0x8ce, 1),
                       'abilities_capacity': (0x358, 8), 'abilities_pointer': (0x360, 8), 'abilities_count': (0x368, 8)}
    reviewed_fields.update(pending_talents=(0x870, 4), pending_chests=(0x874, 4), pending_rewards=(0x878, 4))
    fields = {}
    for name, (offset, width) in reviewed_fields.items():
        if offset not in field_map:
            raise ValueError(f'Missing progression Game field proof: {name}')
        fields[name] = dict(offset=field_map[offset], width=width, reviewed_offset=offset)
    for row in entries.values():
        row['game_phase_offset'] = fields['phase']['offset']
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(bb).hexdigest():
        raise ValueError('Game changed while proving isolated progression calls')
    definitions = next(dep for dep in entries['CHOOSE']['dependencies'] if dep.get('reference') == REVIEWED_SPELL_DEFINITIONS)
    upgrade_rank = upgrade_rank_contract(HelperProof(old, new), hooks['CHOOSE']['reference_rva'], entries['CHOOSE']['entry'])
    return dict(sha256=hashlib.sha256(bb).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, isolated_candidate_calls_only=True, entries=entries,
                fields=fields, choice_stride=0x70,
                choice_title=dict(capacity=0, pointer=8, length=0x10, width=8, max_bytes=1024,
                    ownership='native String24; borrowed read only',
                    runtime_role='Require exact equality with the selected native UI offer title before CHOOSE'),
                choice_consumption=consumption, pending_by_choice_kind={0: 'pending_talents', 1: 'pending_chests', 2: 'pending_rewards'},
                ability_contract=dict(stride=0x50, definition_pointer=0, rank_offset=0x20, rank_width=4,
                    definitions_rva=definitions['candidate'], definitions_count=111, definition_stride=0x78,
                    name_pointer=0x10, name_length=0x18, new_rank=1,
                    offered_ui=dict(type='choices', array='choices', kind='new', title_prefix='New: '),
                    upgrade_ui=dict(kind='upgrade', title_format='{name} rank {rank}', rank_delta=1,
                        rank_delta_source=upgrade_rank,
                        requires='Exact current title equals existing+1; native rank increases by selected stat-tag count; all other abilities unchanged'),
                    consumption_ui={'type': 'resume'}),
                runtime_obligations=['Disposable isolated Game and profile only; stopped validated WRITE owner',
                    'Bound XP amount1..100 and native choice count1..32; index must be below count',
                    'Choose only an existing native-generated choice in phase2 with choice_kind not255',
                    'Record XP/level before and after; prove XP changes and a level increase',
                    'Record offered native choice before call and matching native talent/ability output afterward',
                    'Verify actual choice consumption or replacement and native phase progress, not just function return',
                    'Require native returns, clean exit and unchanged executable plus adapter source identity',
                    'Formatter internals remain native black-box dependencies until these output checks pass; no production activation'])


def native_enum_call_values(stream, call_site, register, width):
    """Prove the native DL/EDX constant or bounded boolean selection at a call."""
    index = next((i for i, ins in enumerate(stream) if ins.address == call_site), None)
    if index is None or stream[index].mnemonic != 'call' or register not in ('dl', 'edx'):
        raise ValueError('Native enum callsite or register is unsupported')
    def checked(values, producer):
        if any(ins.group(capstone.CS_GRP_JUMP) and ins.operands
               and ins.operands[0].type == capstone.x86.X86_OP_IMM
               and producer < ins.operands[0].imm <= call_site for ins in stream):
            raise ValueError('Native enum scalar producer can be bypassed')
        return values
    for i in range(index - 1, max(-1, index - 21), -1):
        ins = stream[i]
        if ins.group(capstone.CS_GRP_CALL) or ins.group(capstone.CS_GRP_JUMP):
            break
        if not any(ins.reg_name(reg) in ('rdx', 'edx', 'dx', 'dl', 'dh') for reg in ins.regs_access()[1]):
            continue
        if (ins.mnemonic == 'mov' and ins.operands[0].type == capstone.x86.X86_OP_REG
                and ins.reg_name(ins.operands[0].reg) in ('rdx', 'edx', 'dx', 'dl')
                and ins.operands[0].size >= width and ins.operands[1].type == capstone.x86.X86_OP_IMM):
            return checked([ins.operands[1].imm & ((1 << (width * 8)) - 1)], ins.address)
        if ins.mnemonic.startswith('cmov') and ins.op_str == 'edx, eax' and width == 4 and i >= 6:
            block = stream[i - 6:i]
            if ([(v.mnemonic, v.op_str) for v in (block[0], block[2])] == [('xor', 'eax, eax'), ('sete', 'al')]
                    and block[1].mnemonic == 'cmp' and block[4].mnemonic == 'test'
                    and block[3].mnemonic == 'xor' and block[3].reg_name(block[3].operands[0].reg) == 'eax'
                    and block[3].operands[1].type == capstone.x86.X86_OP_IMM
                    and block[5].mnemonic == 'mov' and block[5].reg_name(block[5].operands[0].reg) == 'edx'
                    and block[5].operands[1].type == capstone.x86.X86_OP_IMM):
                mask, default = block[3].operands[1].imm, block[5].operands[1].imm
                return checked(sorted({default & 0xffffffff, mask & 0xffffffff, (mask ^ 1) & 0xffffffff}), block[0].address)
        break
    raise ValueError('Native enum input lacks a bounded scalar producer')


def discover_region_call_contracts(reference, binary, dependencies, call_arguments):
    """Pair outgoing native helpers using caller-proved Game receiver aliases."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Region callable reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    verified, unresolved = [], []
    owners = {side: {row['site']: row for row in call_arguments[side]} for side in ('reference', 'candidate')}
    native_streams = {}
    ranges = {'reference': unwind_ranges(old), 'candidate': unwind_ranges(new)}
    for item in dependencies['unresolved']:
        source, target = item['reference'], item['candidate']
        try:
            if source == 0x5399d60:
                proof = HelperProof(old, new, switch_roots={source: 7}).pair(source, target)
                register = None
            elif source == REVIEWED_FORMAT_WRITER:
                proof = HelperProof(old, new).pair(source, target)
                register = None  # Native String output / format program ABI, no Game argument.
            else:
                receivers = set()
                if not item['calls']:
                    raise ValueError('No paired native callsites supplied')
                for call in item['calls']:
                    roots = []
                    for side, entry in (('reference', source), ('candidate', target)):
                        site = int(call[side], 16) if isinstance(call[side], str) else call[side]
                        owner = owners[side].get(site)
                        if owner is None or owner['target'] != entry:
                            raise ValueError('Native callsite has no matching Game receiver evidence')
                        roots.append({reg for reg, offset in owner['args'].items() if offset == 0})
                    if roots[0] != roots[1] or len(roots[0]) != 1:
                        raise ValueError('No unique paired Game receiver at every native callsite')
                    receivers.update(roots[0])
                if len(receivers) != 1:
                    raise ValueError('Native callsites disagree on Game receiver ABI')
                register = next(iter(receivers))
                effect_entry = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']['APPLY_EFFECT']['reference_rva']
                if source == 0x53fce50 and hashlib.sha256(bb).hexdigest() == REVIEWED_START_BUILD:
                    if register != 'rcx': raise ValueError('START caller changed Game receiver ABI')
                    proof = reviewed_start_entry_contract(old, new, REVIEWED_START_BUILD, target)
                elif source == effect_entry:
                    if register != 'rcx':
                        raise ValueError('Native effect has a different Game receiver ABI')
                    from effect_contracts import native_effect_contract
                    proof = native_effect_contract(reference, binary, source, target)
                else:
                    proof = HelperProof(old, new, game_roots={source: register}).pair(source, target, candidate_call=True)
            condition_proofs = []
            for condition in proof.get('preconditions', []):
                if condition.get('register') not in ('dl', 'edx'):
                    condition_proofs.append(dict(condition=condition, statically_discharged=False,
                        required_runtime_guard=('Persistent borrowed Effect12/tag validation at native effect dispatch load'
                            if condition.get('kind') == 'native_effect_enum_bound' else
                            'Persistent owner/tag validation at native DAMAGE dispatch load')))
                    continue
                for call in item['calls']:
                    values = []
                    for side, image in (('reference', old), ('candidate', new)):
                        site = int(call[side], 16) if isinstance(call[side], str) else call[side]
                        owner = next(((a, b) for a, b in ranges[side] if a <= site < b), None)
                        if owner is None:
                            raise ValueError('Native enum caller has no complete function boundary')
                        key = side, owner
                        if key not in native_streams:
                            native_streams[key] = instructions(image, *owner)
                        values.append(native_enum_call_values(native_streams[key], site, condition['register'], condition['width']))
                    if values[0] != values[1] or not all(condition.get('minimum', 0) <= v <= condition['maximum'] for v in values[0]):
                        raise ValueError('Native caller enum changed or exceeds proved callee domain')
                    condition_proofs.append(dict(call=call, condition=condition, values=values[0], statically_discharged=True))
            verified.append(dict(reference=source, candidate=target, game_register=register,
                calls=item['calls'], proof=proof,
                runtime_output_validation_required=bool(proof.get('candidate_call_only') or proof.get('scoped_entry_verified')),
                caller_enum_obligations=proof.get('preconditions', []), caller_condition_proofs=condition_proofs))
        except ValueError as error:
            unresolved.append(dict(item, reason=str(error)))
    digest = hashlib.sha256(bb).hexdigest()
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != digest:
        raise ValueError('Game changed while proving region calls')
    return dict(sha256=digest, reference_sha256=UPDATED_HASH, verified=verified, unresolved=unresolved,
                automatic_activation_allowed=False,
                provenance_requirement='call_arguments must come from paired guarded Game CFG analysis; native caller enum bounds remain mandatory')


def collect_helper_inputs(reference, binary, reports, required_addresses, required_patches):
    """Exact mappings from hash-bound helper reports, retaining scoped obligations."""
    from map_build_functions import collect_region_inputs
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    digest = hashlib.sha256(bb).hexdigest()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Helper input mapping reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    helper = HelperProof(old, new)
    regions, points, obligations = {}, {}, []
    def walk(value, contract):
        if isinstance(value, list):
            for child in value:
                walk(child, contract)
        elif isinstance(value, dict):
            a, b = value.get('reference'), value.get('candidate')
            if isinstance(a, int) and isinstance(b, int):
                if value.get('scoped_entry_verified'):
                    checked = reviewed_start_entry_contract(old, new, digest, b)
                    if a != checked['reference'] or value.get('expected') != checked['expected']:
                        raise ValueError('Scoped START entry contract differs from reviewed build')
                    regions[a, b] = dict(old_start=a, old_end=a + 1, new_start=b, new_end=b + 1,
                                         admitted=True, contract_id=contract + ':reviewed-start-entry')
                    obligations.append(dict(reference=a, candidate=b, contract=contract,
                        runtime_output_validation_required=True,
                        runtime_obligations=value.get('runtime_obligations', [])))
                elif value.get('reviewed_map_layout'):
                    register = 'rdx' if a in (0x540a8f0, 0x5401190) else 'rcx'
                    checked = HelperProof(old, new, game_roots={a: register}).pair(a, b, candidate_call=True)
                    layout = checked['reviewed_map_layout']
                    left_by_site = {i.address: i for i in instructions(old, a, helper.bounds[0][a])}
                    right_by_site = {i.address: i for i in instructions(new, b, helper.bounds[1][b])}
                    for pair in layout['instruction_pairs']:
                        x, y = pair['reference'], pair['candidate']
                        if x == layout['stride_site'] or x in layout.get('excluded_patch_sites', []): continue
                        left, right = left_by_site[x], right_by_site[y]
                        regions[x, y] = dict(old_start=x, old_end=x+left.size, new_start=y, new_end=y+right.size,
                            admitted=True, contract_id=contract+':reviewed-map-operand',
                            verified_pointer_moves=layout.get('pointer_changes', []))
                    obligations.append(dict(reference=a, candidate=b, contract=contract,
                        preconditions=checked.get('preconditions', []), runtime_output_validation_required=True))
                elif value.get('complete_helper_verified') or value.get('candidate_call_only'):
                    before, after = helper.code(0, a), helper.code(1, b)
                    regions[a, b] = dict(old_start=a, old_end=a + len(before), new_start=b, new_end=b + len(after),
                        admitted=True, contract_id=contract,
                        verified_pointer_moves=value.get('game_fields', []))
                    if value.get('candidate_call_only'):
                        obligations.append(dict(reference=a, candidate=b, contract=contract,
                            preconditions=value.get('preconditions', []),
                            runtime_output_validation_required=True))
                elif value.get('classification') or (value.get('kind') in
                        ('f32_clock_constant', 'melee_profile_prefix', 'result_label')
                        and value.get('equal_native_bytes') is True):
                    points.setdefault(a, set()).add((b, contract))
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    walk(child, contract + ':' + key if key == 'entries' else contract)
    for name, report in reports.items():
        if report.get('sha256') != digest or report.get('reference_sha256') != UPDATED_HASH:
            raise ValueError('Helper input report executable identity differs')
        walk(report, name)
        map_row = report.get('map_table')
        if isinstance(map_row, dict) and map_row.get('contract'):
            a, b = map_row['reference'], map_row['candidate']
            if a != REVIEWED_MAP_TABLE:
                raise ValueError('Helper map table is not the reviewed native table')
            identity = map_table_identity(old, new, a, b, candidate_layout=map_row.get('candidate_layout'))
            if identity != map_row['contract']:
                raise ValueError('Helper map identity proof no longer matches executable')
            definitions = map_enemy_contracts(helper, a, b, definitions_only=True,
                                              candidate_layout=map_row.get('candidate_layout'))
            if not definitions['definition_arrays_verified']:
                raise ValueError('Native map boss arrays lack typed definition proof')
            points.setdefault(a, set()).add((b, name + ':typed-map-table'))
            for row in identity['rows']:
                points.setdefault(row['reference_bosses'], set()).add((row['candidate_bosses'], name + ':typed-boss-array'))
        if report.get('unique_called_path_contract'):
            candidates = report.get('candidates', [])
            if (len(candidates) != 1 or not candidates[0].get('scoped_contract_verified')
                    or report.get('unresolved') or set(report.get('forwarded_effects', ())) != {1, 2, 3, 4, 10}):
                raise ValueError('Effect input mapping lacks the complete forwarded-path contract')
            a, b = report['reference'], candidates[0]['candidate']
            decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            first = next(decoder.disasm(old.get_data(a, 15), a), None)
            if first is None or new.get_data(b, first.size) != first.bytes:
                raise ValueError('Scoped native effect entry precondition changed')
            regions[a, b] = dict(old_start=a, old_end=a + first.size, new_start=b, new_end=b + first.size,
                                 admitted=True, contract_id=name + ':scoped-effect-entry')
            obligations.append(dict(reference=a, candidate=b, contract=name,
                preconditions=[dict(effect_pointer_register='r8', effect_size=12, allowed_tags=[1, 2, 3, 4, 10], mandatory_before_every_adapter_call=True)],
                runtime_output_validation_required=True, runtime_obligations=report.get('runtime_obligations', [])))
        if report.get('menu_contract_verified') and report.get('variant') == 'borrowed_map_predicate':
            hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
            old_map, new_map = report['baseline_enter']['map_select'], report['map_select']
            stream = instructions(old, old_map, helper.bounds[0][old_map])
            map_index = next(ins.operands[0].imm for ins in stream if ins.mnemonic == 'call')
            helper.switch_roots[map_index] = 7
            helper.switch_roots[0x546f050] = 15
            selection = map_selection_contract(old, old_map, new, new_map)
            streams = [instructions(image, entry, helper.bounds[side][entry])
                       for side, (image, entry) in enumerate(((old, old_map), (new, new_map)))]
            for side, (image, entry) in enumerate(((old, old_map), (new, new_map))):
                refs = function_references(helper.code(side, entry), entry)[1]
                table = selection['reference_layout' if side == 0 else 'candidate_layout']['table']
                if {target for _, _, kind, target in refs if kind == 'rip'} != {table}:
                    raise ValueError('Map selection has an unproved data dependency')
            calls = [[ins for ins in stream if ins.mnemonic == 'call'] for stream in streams]
            if len(calls[0]) != len(calls[1]):
                raise ValueError('Map selection dependency count changed')
            for x, y in zip(*calls):
                if x.operands[0].type != capstone.x86.X86_OP_IMM or y.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError('Map selection contains unproved indirect call')
                source, target = x.operands[0].imm, y.operands[0].imm
                if source == REVIEWED_ALLOCATION_FAILURE:
                    if not terminal_continuation(streams[0], x.address+x.size) or not terminal_continuation(streams[1], y.address+y.size):
                        raise ValueError('Map selection allocation failure resumes success')
                    helper.terminal_allocation_failure(source, target)
                else:
                    walk(helper.pair(source, target), name + ':map-select-dependency')
            offset, extent = selection['lookup_offset'], selection['lookup_size']
            # The name-lookup block has its own semantic proof. Its entry is a
            # native continuation, but none of its rewritten bytes is patchable.
            points.setdefault(old_map+offset, set()).add((new_map+offset, name+':map-name-lookup'))
            for lo, hi in ((0, offset), (offset+extent, helper.bounds[0][old_map]-old_map)):
                regions[old_map+lo, new_map+lo] = dict(old_start=old_map+lo, old_end=old_map+hi,
                    new_start=new_map+lo, new_end=new_map+hi, admitted=True, contract_id=name+':map-selection')
            destructor = report['command_destructor']
            if destructor.get('variant') == 'trimmed-command-switch':
                from menu_contracts import equivalent_command_drop
                proof = equivalent_command_drop(old, 0x546f050, new, destructor['entry'])
                for address in proof['external_dependencies']:
                    walk(helper.pair(address, address), name + ':command-deallocator')
                points.setdefault(0x546f050, set()).add((destructor['entry'], name + ':command-destructor'))
            else:
                walk(helper.pair(0x546f050, destructor['entry']), name + ':command-destructor')
            a, b = hooks['UI_COMMAND']['reference_rva'], report['ui_command']
            first = next(iter(instructions(old, a, a + 1)), None)
            if first is None or first.mnemonic != 'push' or first.op_str != 'rbp' or new.get_data(b, 1) != first.bytes:
                raise ValueError('Native menu dispatch entry precondition changed')
            regions[a, b] = dict(old_start=a, old_end=a + 1, new_start=b, new_end=b + 1,
                                 admitted=True, contract_id=name + ':proved-dispatch-entry')
            points.setdefault(report['baseline_enter']['return_site'], set()).add((report['host_map_return'], name + ':enter-return'))
    result = collect_region_inputs(old, new, list(regions.values()), required_addresses, required_patches)
    result['fields'] = []
    for report in reports.values():
        table = report.get('map_table', {})
        if table.get('contract'):
            # Identity and definitions were freshly checked above. Record stride
            # is a schema boundary, not an inferred neighboring field offset.
            layout = table['contract']
            result['fields'].extend(dict(domain='map', reference=a, candidate=layout[key])
                for a, key in ((0, 'map_name_pointer'), (8, 'map_name_length'),
                               (0x40, 'boss_pointer'), (0xa0, 'row_stride')))
    unresolved = []
    for row in result['unresolved_inputs']:
        choices = points.get(row['reference'], set()) if row['kind'] == 'address' else set()
        values = {target for target, _ in choices}
        if len(values) == 1:
            result['addresses'].append(dict(reference=row['reference'], candidate=next(iter(values)),
                                            contracts=sorted({name for _, name in choices})))
        else:
            unresolved.append(row)
    result.update(sha256=digest, reference_sha256=UPDATED_HASH, regions=list(regions.values()),
                  unresolved_inputs=unresolved, unresolved_runtime_obligations=obligations,
                  scope='Exact dependency mappings only; scoped native calls still require runtime and guard acceptance')
    if any(report.get('menu_contract_verified') and report.get('variant') == 'borrowed_map_predicate' for report in reports.values()):
        result['superseded_menu_inputs'] = dict(
            required_variant='borrowed_map_predicate',
            source='PartyMenu.__call__: menu_contract branch returns before legacy inline LOGIN patches',
            addresses=[0x53be2ba, 0x53beaa8, 0x53bead1, 0x53beb4a],
            patches=[[0x53be2ba, '4981fcffffff0048898d801f0000488995081f00000f8475080000'], [0x53bead1, '742d']],
            replacement='Validated MENU_LOGIN branch with borrowed host-map equality check; native MAP_SELECT allocation path',
            runtime_requirement='MENU_CONTRACT hash, entries, variant and branch validated by PartyMenu.__init__')
    return result


def reviewed_start_entry_contract(old, new, candidate_hash, target):
    """Exact-build native ownership/lifecycle ABI; gameplay acceptance is separate."""
    if (candidate_hash != REVIEWED_START_BUILD or target != 0x5407340
            or hashlib.sha256(new.__data__).hexdigest() != candidate_hash
            or hashlib.sha256(old.__data__).hexdigest() != UPDATED_HASH):
        raise ValueError('No reviewed changed-build START entry contract')
    if old.get_data(0x53fce50, 1) != b'\x55' or new.get_data(target, 1) != b'\x55':
        raise ValueError('Reviewed START interception instruction changed')
    stream = instructions(new, target, dict(unwind_ranges(new))[target])
    by_address = {ins.address: (ins.mnemonic, ins.op_str) for ins in stream}
    for site, expected in {
        0x54073b4: ('mov', 'r13, rcx'),
        0x54073b7: ('mov', 'byte ptr [rcx + 0x8d7], 1'),
        0x5409645: ('ret', ''),
    }.items():
        if by_address.get(site) != expected:
            raise ValueError('Reviewed START receiver/lifecycle instruction changed')
    for owner, site, mnemonic in ((0x53f1690, 0x53f172f, 'call'), (0x53ea670, 0x53ea9fa, 'jmp')):
        caller = instructions(new, owner, dict(unwind_ranges(new))[owner])
        hits = [ins for ins in caller if ins.address == site]
        if (len(hits) != 1 or hits[0].mnemonic != mnemonic
                or hits[0].operands[0].type != capstone.x86.X86_OP_IMM
                or hits[0].operands[0].imm != target):
            raise ValueError('Reviewed native START caller changed')
    return dict(reference=0x53fce50, candidate=target, scoped_entry_verified=True,
        expected='55', reference_expected='55', game_register='rcx',
        candidate_sha256=candidate_hash, normal_return=0x5409645,
        native_callers=[dict(owner=0x53f1690, site=0x53f172f, kind='call'),
                        dict(owner=0x53ea670, site=0x53ea9fa, kind='tail-jump')],
        phase_offset=0x8d7, embedded_game_extent=0x8d8,
        automatic_activation_allowed=False, runtime_output_validation_required=True,
        scope='Reviewed exact-build RCX Game ABI and entry interception only; native body retained. '
              'Requires embedded-owner guard, independent destructor/structure contracts, '
              'normal return with world output, and four-player start/restart acceptance. '
              'Phase1 is written before initialization and is not completion evidence.')


def discover_state_call_contracts(reference, binary, structural):
    """Scoped native state calls; actual state/output checks remain mandatory."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('State call reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    hooks = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
    abis = {
        'START': {'rcx': 'owned-live-Game'},
        'HURT': {'rcx': 'owned-live-Game', 'xmm1': 'positive finite f32 damage <=100000',
                 'r8': 'source GUID scalar', 'r9': 'melee boolean 0 or 1'},
        'OFFER_CHOICES': {'rcx': 'owned-live-Game', 'dl': 'choice kind 0, 1 or 2', 'r8b': 'pause boolean 0 or 1'},
        'DEFEAT_UI': {'rcx': 'owned writable output String24', 'rdx': 'owned-live-Game',
                      'r8': 'borrowed immutable defeat UTF-8 label', 'r9': 'label length 6'},
        'SPAWN_LOOT': {'rcx': 'owned-live-Game', 'edx': 'kind 0, 1 or 2',
                       'r8d': 'amount 1..100000', 'r9': 'borrowed finite XYZ f32[3]'},
        'MOVE': {'rcx': 'owned-live-Game', 'mode': 'native entry observation; preserve original arguments'},
        'FIND_SPAWN': {'rcx': 'owned writable native position output', 'rdx': 'owned-live-Game',
                       'xmm2': 'native range scalar', 'xmm3': 'native range scalar'},
    }
    obligations = {
        'START': ['Normal native return', 'Native running phase and initial world spawns', 'No second start on an already running Game'],
        'HURT': ['Normal native return', 'Native player HP reduction and matching health output', 'Native death/defeat output when lethal'],
        'OFFER_CHOICES': ['Normal native return', 'Native owned choice vector and UI agree', 'Choice kind equals requested levelup/cache/guardian', 'Native pause flag honored'],
        'DEFEAT_UI': ['Normal native return', 'Output String24 has owned bounded allocation', 'Native defeat JSON contains matching Game summary fields', 'Release output through original native allocator ownership path'],
        'SPAWN_LOOT': ['Normal native return', 'Actual loot vector insertion or merge preserves requested kind and amount',
                       'World CREATE/UPDATE output agrees with native loot GUID and position'],
        'MOVE': ['Observe native owner and typed position fields during actual movement', 'Verify matching world movement output'],
        'FIND_SPAWN': ['Finite output position inside native map boundary', 'Preserve original native RNG and map tuning'],
    }
    entries, unresolved = {}, []
    for name, abi in abis.items():
        entry = hooks[name]['reference_rva']
        matches = structural.get(hex(entry), {}).get('candidates', ())
        try:
            if len(matches) != 1:
                raise ValueError(f'{name} state call candidate is missing or ambiguous')
            target = int(matches[0]['rva'], 16)
            proof = HelperProof(old, new, game_roots={entry: 'rdx' if name in ('DEFEAT_UI', 'FIND_SPAWN') else 'rcx'})
            if name == 'START' and hashlib.sha256(bb).hexdigest() == REVIEWED_START_BUILD:
                row = reviewed_start_entry_contract(old, new, hashlib.sha256(bb).hexdigest(), target)
            else:
                row = proof.pair(entry, target, candidate_call=True)
        except ValueError as error:
            unresolved.append(dict(function=name, reason=str(error)))
            continue
        entries[name] = dict(row, entry=target,
                             expected=row['expected'] if row.get('scoped_entry_verified') else new.get_data(target, 16).hex(), abi=abi,
                             runtime_obligations=obligations[name])
    digest = hashlib.sha256(bb).hexdigest()
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != digest:
        raise ValueError('Game changed while proving state calls')
    return dict(sha256=digest, reference_sha256=UPDATED_HASH, entries=entries, unresolved=unresolved,
                isolated_candidate_calls_only=True, automatic_activation_allowed=False,
                scope='Paired native ABI/body/typed data; state and serialized output require native runtime acceptance')


def discover_callable_contracts(reference, binary, structural):
    """Reuse recursive helper proof for reviewed adapter-callable native entries."""
    aa, bb = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(aa).hexdigest() != UPDATED_HASH:
        raise ValueError('Callable closure reference is not reviewed')
    old, new = pefile.PE(data=aa, fast_load=True), pefile.PE(data=bb, fast_load=True)
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())['hooks']
    game_names = ('PAUSE', 'RESUME', 'START', 'AWARD_XP', 'CHOOSE', 'DAMAGE', 'HURT', 'SPAWN',
                  'SPAWN_BOSS', 'SPAWN_LOOT', 'REMOVE_LOOT', 'OFFER_CHOICES')
    game_roots = {manifest[name]['reference_rva']: 'rcx' for name in game_names}
    game_roots[manifest['DEFEAT_UI']['reference_rva']] = 'rdx'
    map_entry = manifest['MAP_SELECT']['reference_rva']
    map_code = instructions(old, map_entry, dict(unwind_ranges(old))[map_entry])
    map_index = next(ins.operands[0].imm for ins in map_code if ins.mnemonic == 'call')
    proof = HelperProof(old, new, game_roots=game_roots, switch_roots={map_index: 7})
    results = {}
    for name in (*game_names, 'DEFEAT_UI', 'APPLY_DOT', 'UI_COMMAND'):
        entry = manifest[name]['reference_rva']
        candidates = structural.get(hex(entry), {}).get('candidates', ())
        outcomes = []
        for candidate in candidates:
            target = int(candidate['rva'], 16)
            try:
                outcome = dict(candidate=target, verified=True, proof=proof.pair(entry, target))
            except ValueError as error:
                outcome = dict(candidate=target, verified=False, reason=str(error),
                               dependency=getattr(error, 'native_dependency', {}))
            outcomes.append(outcome)
        results[name] = dict(reference=entry, candidates=outcomes,
                             verified_unique=sum(row['verified'] for row in outcomes) == 1)
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(bb).hexdigest():
        raise ValueError('Game changed while proving callable dependencies')
    try:
        progression = discover_progression_call_contracts(reference, binary, structural)
    except ValueError as error:
        progression = dict(isolated_candidate_calls_only=True, automatic_activation_allowed=False, unresolved=str(error))
    return dict(sha256=hashlib.sha256(bb).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, callables=results,
                scoped_progression=progression,
                scope='Exact native helper bodies plus explicitly proven Game fields and terminal failure classifications',
                excluded=dict(APPLY_EFFECT='Use scoped enum contract; whole function intentionally changed'))


if __name__ == '__main__':
    structural = json.loads((ROOT / 'analysis/structural-hook-candidates.json').read_text())
    menu = json.loads((ROOT / 'analysis/menu-contract-candidate.json').read_text())
    report = discover_helper_contracts(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
                                       ROOT / 'AzerothSurvivors.exe', structural, menu)
    (ROOT / 'analysis/native-helper-candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(helpers=list(report['helpers']), unresolved=report['unresolved']), indent=2))
