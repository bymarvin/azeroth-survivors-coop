"""Compare only adapter-forwarded native effect variants by reachable CFG."""
import hashlib
import json
from pathlib import Path
import struct
import re

import capstone
import pefile
from build_hooks import ROOT, UPDATED_HASH
from map_build_functions import unwind_ranges, game_field_uses
from menu_contracts import instructions
from native_helper_contracts import HelperProof

FORWARDED_EFFECTS = (1, 2, 3, 4, 10)
REVIEWED_EFFECT_GAME_HELPER = 0x5411760


def vector_address_adjustment(decoded, address):
    """Recognize capacity check -> Vec* adjustment -> reserve -> restore base."""
    ordered = list(decoded.values())
    index = next(i for i, ins in enumerate(ordered) if ins.address == address)
    if index < 4 or index + 2 >= len(ordered):
        return None
    move, count, capacity, branch, add, call, restore = ordered[index - 4:index + 3]
    if (move.mnemonic != 'mov' or len(move.operands) != 2
            or any(op.type != capstone.x86.X86_OP_REG for op in move.operands)
            or count.mnemonic != 'mov' or capacity.mnemonic != 'cmp' or branch.mnemonic != 'jne'
            or add.mnemonic != 'add' or call.mnemonic != 'call'
            or restore.mnemonic != 'mov' or restore.op_str != move.op_str
            or add.operands[0].type != capstone.x86.X86_OP_REG
            or add.operands[0].reg != move.operands[0].reg
            or add.operands[1].type != capstone.x86.X86_OP_IMM
            or capacity.operands[1].type != capstone.x86.X86_OP_MEM
            or capacity.operands[1].mem.base != move.operands[1].reg
            or capacity.operands[1].mem.disp != add.operands[1].imm
            or branch.operands[0].imm != restore.address + restore.size):
        return None
    return dict(base=move.reg_name(move.operands[1].reg), offset=add.operands[1].imm)


def dispatch(image, entry, tags=FORWARDED_EFFECTS):
    ends = dict(unwind_ranges(image))
    if entry not in ends:
        raise ValueError('Effect entry has no native function bounds')
    decoded = instructions(image, entry, ends[entry])
    matches = []
    for index, ins in enumerate(decoded[:-4]):
        tail = decoded[index + 1:index + 5]
        if ((ins.mnemonic, ins.op_str) == ('mov', 'eax, dword ptr [r8]')
                and tail[0].mnemonic == 'lea' and tail[0].op_str.startswith('r9, [rip + ')
                and [(i.mnemonic, i.op_str) for i in tail[1:]] ==
                [('movsxd', 'rax, dword ptr [r9 + rax*4]'), ('add', 'rax, r9'), ('jmp', 'rax')]):
            table = tail[0].address + tail[0].size + tail[0].operands[1].mem.disp
            section = image.get_section_by_rva(table)
            if section is None or section.Characteristics & (0x20000000 | 0x80000000):
                raise ValueError('Effect dispatch table is not immutable')
            cases = {tag: table + struct.unpack('<i', image.get_data(table + tag * 4, 4))[0]
                     for tag in tags}
            boundaries = {i.address for i in decoded}
            if any(target not in boundaries for target in cases.values()):
                raise ValueError('Effect case target is not an instruction boundary')
            matches.append(dict(entry=entry, end=ends[entry], table=table, jump=tail[-1].address,
                                cases=cases, decoded={i.address: i for i in decoded}))
    if len(matches) != 1:
        raise ValueError('Effect dispatch is missing or ambiguous')
    return matches[0]


def compare_effect_paths(old, new, before, after):
    pending = [(before['entry'], after['entry'])]
    paired, reverse, fields, dependencies = {}, {}, [], []
    while pending:
        a, b = pending.pop()
        if a in paired:
            if paired[a] != b:
                raise ValueError('Effect control-flow target mapping conflicts')
            continue
        if b in reverse and reverse[b] != a:
            raise ValueError('Effect control-flow merges changed')
        if a not in before['decoded'] or b not in after['decoded']:
            raise ValueError('Effect control-flow escapes proved function bounds')
        x, y = before['decoded'][a], after['decoded'][b]
        paired[a], reverse[b] = b, a
        if x.mnemonic != y.mnemonic or tuple(x.prefix) != tuple(y.prefix) or len(x.operands) != len(y.operands):
            raise ValueError(f'Effect reachable instruction changed at {a:x}/{b:x}')
        control = x.group(capstone.CS_GRP_JUMP) or x.group(capstone.CS_GRP_CALL)
        for xo, yo in zip(x.operands, y.operands):
            if xo.type != yo.type or xo.size != yo.size:
                raise ValueError('Effect operand type/width changed')
            if xo.type == capstone.x86.X86_OP_REG:
                if xo.reg != yo.reg:
                    raise ValueError('Effect live register changed')
            elif xo.type == capstone.x86.X86_OP_IMM:
                if not control and xo.imm != yo.imm:
                    old_vector = vector_address_adjustment(before['decoded'], a)
                    new_vector = vector_address_adjustment(after['decoded'], b)
                    if not old_vector or not new_vector or old_vector['base'] != new_vector['base']:
                        raise ValueError(f'Effect scalar constant or enum changed at {a:x}/{b:x}: {xo.imm:x}/{yo.imm:x}')
                    fields.append(dict(reference=a, candidate=b, base=old_vector['base'], width=0,
                                       old_offset=xo.imm, new_offset=yo.imm, kind='corroborated_vector_address'))
            elif xo.type == capstone.x86.X86_OP_MEM:
                xm, ym = xo.mem, yo.mem
                if (xm.segment, xm.base, xm.index, xm.scale) != (ym.segment, ym.base, ym.index, ym.scale):
                    raise ValueError('Effect pointer addressing changed')
                if xm.base == capstone.x86.X86_REG_RIP:
                    old_target, new_target = a + x.size + xm.disp, b + y.size + ym.disp
                    if old_target == before['table']:
                        if new_target != after['table']:
                            raise ValueError('Effect dispatch table reference changed')
                    else:
                        dependencies.append(dict(kind='data', reference=old_target, candidate=new_target,
                                                 width=xo.size, instruction=x.mnemonic))
                elif xm.disp != ym.disp:
                    fields.append(dict(reference=a, candidate=b, base=x.reg_name(xm.base),
                                       index=x.reg_name(xm.index), width=xo.size,
                                       old_offset=xm.disp, new_offset=ym.disp))
        if a == before['jump']:
            if b != after['jump']:
                raise ValueError('Effect dispatch position changed')
            if set(before['cases']) != set(after['cases']):
                raise ValueError('Effect enum domain changed')
            pending.extend((before['cases'][tag], after['cases'][tag]) for tag in before['cases'])
        elif x.mnemonic in ('ret', 'ud2', 'hlt'):
            continue
        elif x.group(capstone.CS_GRP_JUMP):
            if x.operands[0].type != capstone.x86.X86_OP_IMM:
                raise ValueError('Unclassified nested effect dispatch')
            aa, bb = x.operands[0].imm, y.operands[0].imm
            if aa in before['decoded']:
                pending.append((aa, bb))
            else:
                dependencies.append(dict(kind='tail_call', reference=aa, candidate=bb))
            if x.mnemonic != 'jmp':
                pending.append((a + x.size, b + y.size))
        else:
            if x.group(capstone.CS_GRP_CALL):
                if x.operands[0].type != capstone.x86.X86_OP_IMM:
                    raise ValueError('Indirect effect call needs explicit ownership/target proof')
                dependencies.append(dict(kind='call', reference=x.operands[0].imm, candidate=y.operands[0].imm))
            pending.append((a + x.size, b + y.size))
    aliases = []
    for image, model in ((old, before), (new, after)):
        aliases.append(game_field_uses(image.get_data(model['entry'], model['end'] - model['entry']),
            model['entry'], indirect_edges={model['jump']: list(model['cases'].values())}))
    game_fields, untyped_fields = [], []
    for change in fields:
        aa = [u for (site, _), u in aliases[0].items() if site == change['reference']]
        bb = [u for (site, _), u in aliases[1].items() if site == change['candidate']]
        if change.get('kind') == 'corroborated_vector_address':
            # The matched capacity CMP dominates this adjustment; it also proves
            # the owner alias across the branch, which does not write registers.
            old_ins = list(before['decoded'])
            new_ins = list(after['decoded'])
            old_cmp = old_ins[old_ins.index(change['reference']) - 2]
            new_cmp = new_ins[new_ins.index(change['candidate']) - 2]
            aa = [u for (site, _), u in aliases[0].items() if site == old_cmp]
            bb = [u for (site, _), u in aliases[1].items() if site == new_cmp]
        if len(aa) == len(bb) == 1 and aa[0]['offset'] == change['old_offset'] and bb[0]['offset'] == change['new_offset']:
            game_fields.append(dict(**change, domain='game', alias_proven=True))
        else:
            untyped_fields.append(change)
    return dict(called_paths_equivalent=True, reachable_instructions=len(paired),
                field_changes=fields, dependencies=list({json.dumps(d, sort_keys=True): d for d in dependencies}.values()),
                game_fields=game_fields, untyped_fields=untyped_fields,
                instruction_map={hex(a): hex(b) for a, b in sorted(paired.items())})


def dependency_closure(old, new, before, after, dependencies):
    # Reviewed APPLY_EFFECT invokes this helper with its Game argument; the
    # helper's RCX alias analysis must prove every moved field independently.
    helper = HelperProof(old, new, game_roots={REVIEWED_EFFECT_GAME_HELPER})
    results = []
    for dependency in dependencies:
        row = dict(dependency)
        try:
            a, b = row['reference'], row['candidate']
            if row['kind'] in ('call', 'tail_call'):
                row['proof'] = helper.pair(a, b)
            else:
                width = row['width']
                if row['instruction'] == 'lea':
                    # This native lookup has exactly two f32 entries: EAX=0,
                    # SETE AL supplies a boolean index, then MULSS [R8+RAX*4].
                    for model, target in ((before, a), (after, b)):
                        stream = list(model['decoded'].values())
                        matches = []
                        for index, ins in enumerate(stream):
                            if (ins.mnemonic == 'lea' and len(ins.operands) == 2
                                    and ins.operands[1].type == capstone.x86.X86_OP_MEM
                                    and ins.operands[1].mem.base == capstone.x86.X86_REG_RIP
                                    and ins.address + ins.size + ins.operands[1].mem.disp == target):
                                surrounding = stream[index - 3:index + 2]
                                if (len(surrounding) == 5 and surrounding[0].op_str == 'eax, eax'
                                        and surrounding[0].mnemonic == 'xor' and surrounding[1].mnemonic == 'cmp'
                                        and (surrounding[2].mnemonic, surrounding[2].op_str) == ('sete', 'al')
                                        and ins.reg_name(ins.operands[0].reg) == 'r8'
                                        and (surrounding[4].mnemonic, surrounding[4].op_str) ==
                                        ('mulss', 'xmm0, dword ptr [r8 + rax*4]')):
                                    matches.append(ins.address)
                        if len(matches) != 1:
                            raise ValueError('Effect lookup data lacks bounded boolean-index proof')
                    width = 8
                for image, target in ((old, a), (new, b)):
                    section = image.get_section_by_rva(target)
                    if (section is None or section.Characteristics & (0x80000000 | 0x20000000)
                            or target + width > section.VirtualAddress + section.Misc_VirtualSize):
                        raise ValueError('Effect constant has no immutable complete extent')
                if old.get_data(a, width) != new.get_data(b, width):
                    raise ValueError('Effect constant changed')
                row['proof'] = dict(immutable_equal_bytes=width)
            row['verified'] = True
        except ValueError as error:
            row.update(verified=False, reason=str(error))
        results.append(row)
    return results


def shield_stack_branch(image, model, ownership):
    """Recognize the native scalar shield-stack and owned Effect24 append path.

    This intentionally accepts the game's new stacking behavior, not arbitrary
    changed code. Every instruction, branch edge, write and borrowed input is
    accounted for; the native vector allocator/destructor is proved separately.
    """
    values, visited = {}, set()
    def match(start, template):
        stream, address = [], start
        for line in template.strip().splitlines():
            ins = model['decoded'].get(address)
            if ins is None:
                raise ValueError('Shield block escaped native function')
            parts, names, position = [], [], 0
            for token in re.finditer(r'\{(\w+)\}', line):
                parts.append(re.escape(line[position:token.start()]))
                name = token[1]
                parts.append(re.escape(hex(values[name])) if name in values else '(0x[0-9a-f]+)')
                if name not in values:
                    names.append(name)
                position = token.end()
            parts.append(re.escape(line[position:]))
            found = re.fullmatch(''.join(parts), ins.mnemonic + (' ' + ins.op_str if ins.op_str else ''))
            if not found:
                raise ValueError(f'Unclassified shield instruction at {address:x}: {ins.mnemonic} {ins.op_str}')
            values.update(zip(names, (int(v, 16) for v in found.groups())))
            stream.append(ins)
            visited.add(address)
            address += ins.size
        return stream
    first = match(model['cases'][7], '''
movss xmm0, dword ptr [r8 + 4]
mov eax, dword ptr [rcx + {stack_count}]
inc eax
ucomiss xmm6, dword ptr [rcx + {stack_time}]
mov edx, 1
cmovne eax, edx
cmovp eax, edx
mov dword ptr [rcx + {stack_count}], eax
movss dword ptr [rcx + {stack_time}], xmm6
mulss xmm0, dword ptr [rcx + {max_health}]
cmp eax, 5
mov edx, 5
cmovb edx, eax
cvtsi2ss xmm1, edx
mulss xmm1, xmm0
movss xmm0, dword ptr [rcx + {shield_health}]
movaps xmm2, xmm0
maxss xmm2, xmm1
movaps xmm1, xmm2
cmpunordss xmm1, xmm2
movaps xmm3, xmm1
andnps xmm3, xmm2
andps xmm1, xmm0
orps xmm1, xmm3
movss dword ptr [rcx + {shield_health}], xmm1
test esi, esi
je {return}
mov rax, qword ptr [rcx + {vector_pointer}]
mov rdi, qword ptr [rcx + {vector_count}]
lea rdx, [rdi*8]
lea rdx, [rdx + rdx*2]
mov r9, rax
nop word ptr cs:[rax + rax]
test rdx, rdx
je {append}
add rdx, -0x18
cmp dword ptr [r9 + 0xc], esi
lea r9, [r9 + 0x18]
jne {search}
jmp {return}
''')
    second = match(values['append'], '''
cmp rdi, qword ptr [rcx + {vector_capacity}]
jne {write}
lea rax, [rcx + {vector_capacity}]
mov rbx, rcx
mov rcx, rax
mov r14, r8
call {reserve}
mov r8, r14
mov rcx, rbx
mov rax, qword ptr [rbx + {vector_pointer}]
lea rdx, [rdi + rdi*2]
mov r9d, dword ptr [r8 + 8]
mov dword ptr [rax + rdx*8 + 8], r9d
mov r8, qword ptr [r8]
mov qword ptr [rax + rdx*8], r8
mov dword ptr [rax + rdx*8 + 0xc], esi
movss xmm0, dword ptr [rip + {infinity_displacement}]
movlps qword ptr [rax + rdx*8 + 0x10], xmm0
inc rdi
mov qword ptr [rcx + {vector_count}], rdi
movaps xmm6, xmmword ptr [rbp]
movaps xmm7, xmmword ptr [rbp + 0x10]
movaps xmm8, xmmword ptr [rbp + 0x20]
add rsp, 0xb8
pop rbx
pop rdi
pop rsi
pop r14
pop r15
pop rbp
jmp {notify}
''')
    if (values['search'] != first[33].address or values['write'] != second[10].address
            or values['return'] != model['cases'][0]
            or values['stack_count'] != values['stack_time'] + 4):
        raise ValueError('Shield scalar layout or control-flow edge changed')
    for name in ('vector_capacity', 'vector_pointer', 'vector_count'):
        if values[name] != ownership[name]:
            raise ValueError('Shield vector is not the proved native scalar Effect24 owner')
    constant = second[16]
    literal = constant.address + constant.size + constant.operands[1].mem.disp
    section = image.get_section_by_rva(literal)
    if (section is None or section.Characteristics & (0x80000000 | 0x20000000)
            or image.get_data(literal, 4) != struct.pack('<f', float('inf'))):
        raise ValueError('Shield persistent duration is not native immutable positive infinity')
    return dict(**values, instructions=sorted(visited), scalar_vector_stride=24,
                borrowed_effect_bytes=12, native_balance_change='Shield stacks up to five and records spell effect once',
                writes='Two Game scalar fields, shield scalar, owned Effect24 scalars, vector length')


def native_effect_contract(reference, binary, entry, candidate):
    """All native variants, with an explicit guarded enum and new shield schema."""
    from enemy_contracts import effect_vector_contract
    from map_build_functions import structural_relocations
    old_bytes, new_bytes = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(old_bytes).hexdigest() != UPDATED_HASH:
        raise ValueError('Native effect reference is not reviewed')
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    if entry != manifest['hooks']['APPLY_EFFECT']['reference_rva']:
        raise ValueError('Native effect entry is not the reviewed enum contract')
    old = pefile.PE(data=old_bytes, fast_load=True)
    new = pefile.PE(data=new_bytes, fast_load=True)
    before, after = dispatch(old, entry, range(11)), dispatch(new, candidate, range(11))
    unchanged = tuple(tag for tag in range(11) if tag != 7)
    a, b = dict(before), dict(after)
    a['cases'] = {tag: before['cases'][tag] for tag in unchanged}
    b['cases'] = {tag: after['cases'][tag] for tag in unchanged}
    paired = compare_effect_paths(old, new, a, b)
    closure = dependency_closure(old, new, a, b, paired['dependencies'])
    if paired['untyped_fields'] or any(not row['verified'] for row in closure):
        raise ValueError('Native non-shield effect paths or dependencies remain unresolved')
    helper = HelperProof(old, new)
    old_ui = manifest['hooks']['UI_COMMAND']['reference_rva']
    ui = structural_relocations(reference, binary, [old_ui])[hex(old_ui)]
    vectors = []
    for row in ui['candidates']:
        try:
            vectors.append(effect_vector_contract(helper, old_ui, int(row['rva'], 16)))
        except ValueError:
            pass
    if len(vectors) != 1:
        raise ValueError('Native Effect24 ownership link is missing or ambiguous')
    vector = vectors[0]
    ownership = {'vector_' + key: value for key, value in vector['candidate_header'].items()}
    shield = shield_stack_branch(new, after, ownership)
    reverse = HelperProof(new, old)
    reserves = reverse.candidates(shield['reserve'])
    if len(reserves) != 1:
        raise ValueError('Shield native reserve is missing or ambiguous')
    reserve = helper.pair(reserves[0], shield['reserve'])
    reserve_body = instructions(new, shield['reserve'], helper.bounds[1][shield['reserve']])
    reserve_schema = [
        ('mov', 'qword ptr [rsp + 0x28], 0x18'),
        ('mov', 'qword ptr [rsp + 0x20], 4'),
        ('lea', 'rcx, [rsp + 0x30]'), ('mov', 'r9, rdi')]
    if sum(all((reserve_body[i+j].mnemonic, reserve_body[i+j].op_str) == row
                   for j, row in enumerate(reserve_schema))
           for i in range(len(reserve_body)-len(reserve_schema)+1)) != 1:
        raise ValueError('Shield reserve does not allocate Effect24 with alignment four')
    notifications = structural_relocations(binary, reference, [shield['notify']])[hex(shield['notify'])]
    possible = [int(row['rva'], 16) for row in notifications['candidates'] if row.get('structure_equivalent')]
    if len(possible) != 1:
        raise ValueError('Shield notification native method is missing or ambiguous')
    notification = HelperProof(old, new, game_roots={possible[0]: 'rcx'}).pair(
        possible[0], shield['notify'], candidate_call=True)
    fields = paired['game_fields'] + notification['game_fields']
    def mapped(offset):
        values = {row['new_offset'] for row in fields if row['old_offset'] == offset}
        if len(values) != 1:
            raise ValueError('Shield scalar lacks an independent paired native consumer')
        return next(iter(values))
    if shield['max_health'] != mapped(0x508) or shield['shield_health'] != mapped(0x4b4):
        raise ValueError('Shield branch writes a different native scalar field')
    # Every effect variant reads only scalar Effect12 members; the new stored
    # element contains these twelve bytes, spell-ID and scalar duration fields.
    covered = {int(site, 16) for site in paired['instruction_map'].values()} | set(shield['instructions'])
    extra = [ins for site, ins in after['decoded'].items() if site not in covered and ins.mnemonic != 'nop']
    if extra:
        raise ValueError('Native effect has an unclassified instruction outside all guarded cases')
    load = next(ins for ins in after['decoded'].values() if ins.mnemonic == 'mov' and ins.op_str == 'eax, dword ptr [r8]')
    guard = dict(rva=load.address, expected=bytes(load.bytes).hex(), base='r8', destination='eax',
                 offset=0, width=4, maximum=10, length=load.size, zeroextend32=True,
                 borrowed_size=12, mandatory=True, ownership='borrowed-readable-12')
    condition = dict(kind='native_effect_enum_bound', new_rva=hex(load.address),
                     register='r8', width=4, maximum=10, borrowed_size=12)
    digest = hashlib.sha256(new_bytes).hexdigest()
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != digest:
        raise ValueError('Game changed while proving native effects')
    return dict(reference=entry, candidate=candidate, native_effect_contract_verified=True,
                sha256=digest, reference_sha256=UPDATED_HASH,
                native_tags=list(range(11)), unchanged_paths=paired, dependency_closure=closure,
                shield=shield, vector=vector, reserve=reserve, notification=notification,
                game_fields=fields, guard_instruction=guard, preconditions=[condition],
                new_scalar_layout_obligations=[dict(reference_position=0x498,
                    candidate_gap_start=shield['stack_time'], candidate_gap_size=8)],
                automatic_activation_allowed=False)


def discover_effect_contract(reference, binary, structural):
    old_bytes, new_bytes = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(old_bytes).hexdigest() != UPDATED_HASH:
        raise ValueError('Effect reference is not the reviewed build')
    old, new = pefile.PE(data=old_bytes, fast_load=True), pefile.PE(data=new_bytes, fast_load=True)
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    entry = manifest['hooks']['APPLY_EFFECT']['reference_rva']
    before = dispatch(old, entry)
    accepted, failures = [], []
    for candidate in structural[hex(entry)]['candidates']:
        address = int(candidate['rva'], 16)
        try:
            after = dispatch(new, address)
            proof = compare_effect_paths(old, new, before, after)
            proof['dependency_closure'] = dependency_closure(old, new, before, after, proof['dependencies'])
            proof['scoped_contract_verified'] = (not proof['untyped_fields']
                and all(row['verified'] for row in proof['dependency_closure']))
            accepted.append(dict(candidate=address, cases=after['cases'], **proof))
        except ValueError as error:
            failures.append(dict(candidate=address, reason=str(error)))
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(new_bytes).hexdigest():
        raise ValueError('Game changed while discovering effect paths')
    unresolved = []
    for candidate in accepted:
        if candidate['untyped_fields']:
            unresolved.append(dict(candidate=candidate['candidate'], reason='Untyped reachable field changes'))
        unresolved.extend(dict(candidate=row['candidate'], reason=row['reason'])
                          for row in candidate['dependency_closure'] if not row['verified'])
    return dict(sha256=hashlib.sha256(new_bytes).hexdigest(), reference_sha256=UPDATED_HASH,
                reference=entry, forwarded_effects=list(FORWARDED_EFFECTS), candidates=accepted,
                unique_called_path_contract=len(accepted) == 1, failures=failures, automatic_activation_allowed=False,
                abi=dict(rcx='game', rdx='target GUID', r8='borrowed 12-byte effect', stack_argument_5='spell ID'),
                unresolved=unresolved,
                runtime_obligations=['Only forward enums1,2,3,4,10',
                    'Runtime Game field map must match every emitted Game-field contract',
                    'Game mutex/native call stack and borrowed12-byte effect lifetime remain adapter call-site obligations'])


if __name__ == '__main__':
    report = discover_effect_contract(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
        ROOT / 'AzerothSurvivors.exe', json.loads((ROOT / 'analysis/structural-hook-candidates.json').read_text()))
    (ROOT / 'analysis/effect-contract-candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'candidates'}, indent=2))
    for candidate in report['candidates']:
        print(candidate['reachable_instructions'], 'reachable instructions;', len(candidate['field_changes']), 'field changes')
