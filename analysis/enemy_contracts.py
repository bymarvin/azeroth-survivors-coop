"""Native Enemy Vec drop contract and constructor layout evidence."""
import hashlib
import json
from pathlib import Path

import capstone
import pefile
from build_hooks import ROOT, UPDATED_HASH
from map_build_functions import (compare_function_layout, game_field_uses, changed_store_owners,
    memory_write_operand, paired_store_fields, frame_value_reads, region_instruction_contract,
    collect_region_inputs, return_tag_values, instruction_pattern)
from menu_contracts import instructions
from native_helper_contracts import (HelperProof, scalar_pair_packet_contract,
    REVIEWED_SCALAR_PAIR_PACKET, terminal_bounds_call, map_enemy_contracts,
    referenced_data_candidate, REVIEWED_MAP_TABLE, REVIEWED_START_BUILD)

REVIEWED_ENEMY_VECTOR_DROP = 0x53ba0a0


def reviewed_map_constructor_layout(helper, entry, candidate, digest):
    """Exact-release constructor ownership, with explicitly reviewed map reads.

    This compares every non-padding instruction and internal edge. The native
    0..8 map index now multiplies by184; only its reviewed borrowed map operands
    may move independently of Game. Callee/data closure remains a separate proof.
    """
    schemas = {
        0x53e05d0: (0x53ea670, 0x53e069f, 'r14', 'r14d',
                    {0x53e06ba: (0x80, 0x98, 8), 0x53e0709: (0x90, 0xa8, 4)}),
        0x5409f40: (0x5414630, 0x540a119, 'r12', 'r12d',
                    {0x540a13d: (0x30, 0x48, 8), 0x540a1ee: (0x98, 0xb0, 4)}),
        0x5408300: (0x54129f0, 0x5408385, 'rcx', 'ecx',
                    {0x54083e7: (0x98, 0xb0, 4)}),
        0x540a8f0: (0x5414fe0, 0x540a963, 'rax', 'eax',
                    {0x540aa6f: (0x80, 0x98, 8), 0x540aa90: (0x90, 0xa8, 4)}),
        0x542b2e0: (0x5435af0, 0x542b339, 'rbx', 'ebx',
                    {0x542b365: (0x98, 0xb0, 4), 0x542b36f: (0x40, 0x58, 8),
                     0x542b458: (0x30, 0x48, 8)}),
        0x542b6d0: (0x5435ee0, 0x542b715, 'rax', 'eax',
                    {0x542b723: (0x30, 0x48, 8), 0x542b740: (0x98, 0xb0, 4)}),
        0x5401190: (0x540b880, 0x5401444, 'rax', 'eax',
                    {0x5401452: (0x10, 0x18, 16)}),
    }
    if (digest != REVIEWED_START_BUILD or hashlib.sha256(helper.new.__data__).hexdigest() != digest
            or hashlib.sha256(helper.old.__data__).hexdigest() != UPDATED_HASH
            or entry not in schemas or candidate != schemas[entry][0]):
        raise ValueError('No reviewed map constructor layout for this build')
    _, stride_site, register, low_register, map_fields = schemas[entry]
    codes = [helper.code(side, address) for side, address in enumerate((entry, candidate))]
    streams = [instructions(image, address, address + len(code))
               for image, address, code in zip((helper.old, helper.new), (entry, candidate), codes)]
    aliases = [game_field_uses(code, address, entry_register='rdx' if entry in (0x540a8f0, 0x5401190) else 'rcx')
               for code, address in zip(codes, (entry, candidate))]
    left, right = ([i for i in stream if i.mnemonic != 'nop'] for stream in streams)
    pairs, fields, map_reads, accesses = [], [], [], []
    i = j = 0
    while i < len(left) and j < len(right):
        a, b = left[i], right[j]
        if a.address == stride_site:
            if ([(x.mnemonic, x.op_str) for x in left[i:i + 2]] !=
                    [('lea', register + ', [rax + rax*4]'), ('shl', low_register + ', 5')]
                    or (b.mnemonic, b.op_str) != ('imul', register + ', rax, 0xb8')):
                raise ValueError('Reviewed map index multiplication changed')
            # The immediately preceding call is the bounded native map index.
            old_call, new_call = left[i - 1], right[j - 1]
            if old_call.mnemonic != 'call' or new_call.mnemonic != 'call' or old_call.operands[0].imm != 0x5399d60:
                raise ValueError('Constructor map index producer changed')
            helper.switch_roots[0x5399d60] = 7
            helper.pair(0x5399d60, new_call.operands[0].imm)
            pairs.append((a, b))
            i += 2; j += 1
            continue
        move_register_sites = {0x53e0624, 0x53e0638, 0x53e067b, 0x53e06b5, 0x53e06c9,
                               0x53e071c, 0x53e072f, 0x53e074c, 0x53e07a5}
        if entry == 0x53e05d0 and a.address in move_register_sites:
            swapped = a.op_str.replace('rdi', 'SWAP').replace('rbx', 'rdi').replace('SWAP', 'rbx')
            if a.mnemonic != b.mnemonic or swapped != b.op_str:
                raise ValueError('MOVE borrowed-vector register role changed')
        elif not instruction_pattern([a], preserve_immediates=True).fullmatch(b.bytes):
            raise ValueError('Constructor instruction outside map indexing changed')
        for operand, (x, y) in enumerate(zip(a.operands, b.operands)):
            if x.type != capstone.x86.X86_OP_MEM or x.mem.base == capstone.x86.X86_REG_RIP:
                continue
            old_use, new_use = aliases[0].get((a.address, operand)), aliases[1].get((b.address, operand))
            if old_use and new_use and old_use['width'] == new_use['width']:
                accesses.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
                    old_offset=old_use['offset'], new_offset=new_use['offset'], width=old_use['width'],
                    address_only=old_use['address_only'], memory_access=not old_use['address_only']))
            if x.mem.disp == y.mem.disp:
                continue
            row = dict(old_rva=hex(a.address), new_rva=hex(b.address), old_offset=x.mem.disp,
                       new_offset=y.mem.disp, width=x.size)
            if a.address in map_fields and (x.mem.disp, y.mem.disp, x.size) == map_fields[a.address]:
                map_reads.append(row)
            elif (old_use and new_use and old_use['offset'] == x.mem.disp
                  and new_use['offset'] == y.mem.disp):
                fields.append(row)
            else:
                raise ValueError('Constructor changed an unowned member')
        pairs.append((a, b))
        i += 1; j += 1
    if i != len(left) or j != len(right) or len(map_reads) != len(map_fields):
        raise ValueError('Constructor instruction/map-field coverage is incomplete')
    translated = {a.address: b.address for a, b in pairs}
    def skip_padding(stream, target):
        by_address = {ins.address: ins for ins in stream}
        while target in by_address and by_address[target].mnemonic == 'nop':
            target += by_address[target].size
        return target
    for a, b in pairs:
        if a.group(capstone.CS_GRP_JUMP):
            if a.operands[0].type != capstone.x86.X86_OP_IMM or b.operands[0].type != capstone.x86.X86_OP_IMM:
                raise ValueError('Constructor contains an unproved indirect branch')
            old_target, new_target = (skip_padding(stream, ins.operands[0].imm)
                                      for stream, ins in zip(streams, (a, b)))
            if entry == 0x53e05d0 and (old_target, new_target) == (0x53fce50, 0x5407340):
                from native_helper_contracts import reviewed_start_entry_contract
                reviewed_start_entry_contract(helper.old, helper.new, digest, new_target)
            elif translated.get(old_target) != new_target:
                raise ValueError('Constructor internal branch changed or enters the stride block')
    return dict(structure_equivalent=False, reviewed_constructor_layout_verified=True,
                field_changes=fields, map_field_changes=map_reads,
                game_accesses=accesses, stride_site=stride_site,
                excluded_patch_sites=sorted(move_register_sites) if entry == 0x53e05d0 else [],
                instruction_pairs=[dict(reference=a.address, candidate=b.address) for a, b in pairs],
                automatic_activation_allowed=False,
                scope='Constructor layout/owned Enemy writes only; separate typed definitions and callee contracts required')


def reviewed_damage_layout(helper, candidate):
    """Exact-release boss-map register rewrite; Game ownership is checked by pair()."""
    entry = 0x540ac40
    if (candidate != 0x5415330 or hashlib.sha256(helper.old.__data__).hexdigest() != UPDATED_HASH
            or hashlib.sha256(helper.new.__data__).hexdigest() != REVIEWED_START_BUILD):
        raise ValueError('No reviewed DAMAGE map layout for this build')
    streams = [instructions(image, address, helper.bounds[side][address])
               for side, (image, address) in enumerate(((helper.old, entry), (helper.new, candidate)))]
    # The map ordinal is still bounded by the same map-index helper. The
    # candidate retains table/index in RAX/RCX and walks boss definitions in RDX.
    changes = {
        0x540c665: ('lea rax, [rax + rax*4]', 'imul rcx, rax, 0xb8'),
        0x540c66c: ('rdx', 'rax'),  # RIP-relative immutable map-table address.
        0x540c673: ('mov rcx, qword ptr [rax + rdx + 0x40]', 'mov rdx, qword ptr [rcx + rax + 0x58]'),
        0x540c678: ('cmp rcx, r15', 'cmp rdx, r15'),
        0x540c681: ('lea r8, [rcx + 0x58]', 'lea r8, [rdx + 0x58]'),
        0x540c68e: ('lea r8, [rcx + 0xb0]', 'lea r8, [rdx + 0xb0]'),
        0x540c69e: ('lea r8, [rcx + 0x108]', 'lea r8, [rdx + 0x108]'),
        0x540c6ae: ('add rcx, 0x160', 'add rdx, 0x160'),
        0x540c6b5: ('cmp rcx, r15', 'cmp rdx, r15'),
        0x540cb18: ('add rdx, rax', 'add rax, rcx'),
        0x540cb1b: ('mov rcx, qword ptr [rdx]', 'mov rcx, qword ptr [rax + 8]'),
        0x540cb1e: ('mov rdx, qword ptr [rdx + 8]', 'mov rdx, qword ptr [rax + 0x10]'),
    }
    omitted = next(i for i in streams[0] if i.address == 0x540c669)
    if (omitted.mnemonic, omitted.op_str) != ('shl', 'eax, 5'):
        raise ValueError('Reviewed DAMAGE map stride changed')
    left = [i for i in streams[0] if i.mnemonic != 'nop' and i.address != omitted.address]
    right = [i for i in streams[1] if i.mnemonic != 'nop']
    if len(left) != len(right): raise ValueError('Reviewed DAMAGE instruction coverage changed')
    fields, pointers, pairs = [], [], []
    for a, b in zip(left, right):
        if a.address in changes:
            before, after = changes[a.address]
            if a.address == 0x540c66c:
                if any(ins.mnemonic != 'lea' or ins.reg_name(ins.operands[0].reg) != reg
                       or ins.operands[1].mem.base != capstone.x86.X86_REG_RIP
                       for ins, reg in ((a, before), (b, after))):
                    raise ValueError('DAMAGE map table producer changed')
            elif (a.mnemonic+' '+a.op_str, b.mnemonic+' '+b.op_str) != (before, after):
                raise ValueError('DAMAGE reviewed map register roles changed')
        elif a.address in (0x540c340, 0x540ce97):
            reg, offset = ('r14', 0x840) if a.address == 0x540c340 else ('rcx', 0x818)
            if (a.mnemonic+' '+a.op_str, b.mnemonic+' '+b.op_str) != (f'add {reg}, {offset:#x}', f'add {reg}, {offset+8:#x}'):
                raise ValueError('DAMAGE Game pointer arithmetic changed')
            pointers.append(dict(old_rva=hex(a.address), new_rva=hex(b.address), old_offset=offset, new_offset=offset+8))
        else:
            if not instruction_pattern([a], preserve_immediates=True).fullmatch(b.bytes):
                raise ValueError('DAMAGE instruction outside reviewed map operands changed')
            for x, y in zip(a.operands, b.operands):
                if x.type == capstone.x86.X86_OP_MEM and x.mem.base != capstone.x86.X86_REG_RIP and x.mem.disp != y.mem.disp:
                    fields.append(dict(old_rva=hex(a.address), new_rva=hex(b.address),
                        old_offset=x.mem.disp, new_offset=y.mem.disp, width=x.size))
        pairs.append(dict(reference=a.address, candidate=b.address))
    stride_index = next(n for n, ins in enumerate(left) if ins.address == 0x540c665)
    calls = (left[stride_index-1], right[stride_index-1])
    if any(ins.mnemonic != 'call' or ins.operands[0].type != capstone.x86.X86_OP_IMM for ins in calls) or calls[0].operands[0].imm != 0x5399d60:
        raise ValueError('DAMAGE map ordinal producer changed')
    helper.switch_roots[0x5399d60] = 7
    map_index = helper.pair(0x5399d60, calls[1].operands[0].imm)
    translated = {p['reference']: p['candidate'] for p in pairs}
    for a, b in zip(left, right):
        if a.group(capstone.CS_GRP_JUMP) and a.operands[0].type == capstone.x86.X86_OP_IMM:
            targets = []
            for stream, ins in zip(streams, (a, b)):
                by_address = {i.address: i for i in stream}; target = ins.operands[0].imm
                while target in by_address and by_address[target].mnemonic == 'nop':
                    target += by_address[target].size
                targets.append(target)
            if translated.get(targets[0]) != targets[1]:
                raise ValueError('DAMAGE internal continuation changed')
    return dict(structure_equivalent=False, reviewed_damage_layout_verified=True,
        field_changes=fields, pointer_changes=pointers, instruction_pairs=pairs, map_index=map_index,
        excluded_patch_sites=sorted(changes), stride_site=0x540c665,
        automatic_activation_allowed=False,
        scope='Reviewed map register roles and control flow; paired Game aliases, borrowed frame and dependency proofs remain mandatory')


def effect_vector_contract(helper, old_ui, new_ui):
    """Derive the scalar Effect24 vector through the native Game destructor."""
    links = [game_drop_link(image, ui, helper, side)
             for side, (image, ui) in enumerate(((helper.old, old_ui), (helper.new, new_ui)))]
    streams = [instructions(image, link['game_drop'], helper.bounds[side][link['game_drop']])
               for side, (image, link) in enumerate(zip((helper.old, helper.new), links))]
    layout = compare_function_layout(helper.code(0, links[0]['game_drop']), links[0]['game_drop'],
                                     helper.code(1, links[1]['game_drop']), links[1]['game_drop'])
    if not layout['structure_equivalent'] or len(streams[0]) != len(streams[1]):
        raise ValueError('Effect vector Game destructor roles changed')
    sites = [i for i, ins in enumerate(streams[0][:-1])
             if ins.mnemonic == 'lea' and ins.op_str == 'rcx, [rbx + 0x358]'
             and streams[0][i + 1].mnemonic == 'call']
    if len(sites) != 1:
        raise ValueError('Effect vector nested destructor is ambiguous')
    index = sites[0]
    owners = [game_field_uses(helper.code(side, link['game_drop']), link['game_drop'])
              for side, link in enumerate(links)]
    members, entries = [], []
    for side, stream in enumerate(streams):
        derive, call = stream[index:index + 2]
        evidence = owners[side].get((derive.address, 1))
        if (evidence is None or derive.mnemonic != 'lea'
                or derive.reg_name(derive.operands[0].reg) != 'rcx'
                or call.mnemonic != 'call' or call.operands[0].type != capstone.x86.X86_OP_IMM):
            raise ValueError('Effect vector destructor lacks its Game receiver')
        members.append(evidence['offset'])
        entries.append(call.operands[0].imm)
    closure = helper.pair(*entries)
    body = instructions(helper.old, entries[0], helper.bounds[0][entries[0]])
    pattern = [('mov', 'rax, qword ptr [rsi + 0x60]'), ('test', 'rax, rax'),
               ('je', None), ('mov', 'rcx, qword ptr [rsi + 0x68]'),
               ('shl', 'rax, 3'), ('lea', 'rdx, [rax + rax*2]'), ('mov', 'r8d, 4')]
    found = [i for i in range(len(body)-len(pattern)+1)
             if all(body[i+j].mnemonic == name and (operand is None or body[i+j].op_str == operand)
                    for j, (name, operand) in enumerate(pattern))]
    if len(found) != 1:
        raise ValueError('Effect vector scalar deallocation schema changed')
    start = found[0]
    tail = body[start + len(pattern):]
    if (len(tail) < 10 or tail[0].mnemonic != 'add' or tail[0].op_str != 'rsp, 0x28'
            or any(ins.mnemonic != 'pop' for ins in tail[1:9])
            or tail[9].mnemonic != 'jmp' or tail[9].operands[0].imm != 0x21d0):
        raise ValueError('Effect vector destruction is not a scalar free tail')
    return dict(reference=entries[0], candidate=entries[1], scalar_vector_verified=True,
        reference_header=dict(capacity=members[0]+0x60, pointer=members[0]+0x68, count=members[0]+0x70),
        candidate_header=dict(capacity=members[1]+0x60, pointer=members[1]+0x68, count=members[1]+0x70),
        element_size=24, alignment=4, element_destructors=False,
        count_obligation='Native append/iterator must independently prove header count at capacity+16',
        game_drop_links=links, nested_drop=closure, automatic_activation_allowed=False)


def enemy_leaf_contract(old,new,reference,candidate):
    """Prove the reachable Enemy decision leaf, independent of unwind records."""
    md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);md.detail=True
    streams=[];codes=[]
    for image,entry in ((old,reference),(new,candidate)):
        decoded={i.address:i for i in md.disasm(image.get_data(entry,4096),entry)}
        pending=[entry];visited=set()
        while pending:
            site=pending.pop()
            if site in visited:continue
            ins=decoded.get(site)
            if ins is None or ins.group(capstone.CS_GRP_CALL):
                raise ValueError('Enemy decision leaf escapes bounded no-call CFG')
            visited.add(site)
            if ins.mnemonic=='ret':continue
            if ins.group(capstone.CS_GRP_JUMP):
                if ins.operands[0].type!=capstone.x86.X86_OP_IMM:
                    raise ValueError('Enemy decision leaf contains unknown indirect jump')
                pending.append(ins.operands[0].imm)
                if ins.mnemonic=='jmp':continue
            pending.append(site+ins.size)
        end=max(site+decoded[site].size for site in visited)
        stream=[i for i in decoded.values() if i.address<end]
        if {i.address for i in stream}!=visited:
            raise ValueError('Enemy leaf has unclassified unreachable instruction bytes')
        streams.append(stream);codes.append(image.get_data(entry,end-entry))
    roles=region_instruction_contract(codes[0],reference,codes[1],candidate)
    if not roles['instruction_roles'] or not roles['internal_control_flow'] or roles['field_changes']:
        raise ValueError('Enemy leaf instruction/field roles changed')
    literals=[];writes=[]
    for a,b in zip(*streams):
        if any(a.reg_name(r) in ('rcx','ecx','cx','cl','ch') for r in a.regs_access()[1]):
            raise ValueError('Enemy leaf overwrites its typed Enemy receiver')
        for index,operand in enumerate(a.operands):
            if operand.type!=capstone.x86.X86_OP_MEM:continue
            base=a.reg_name(operand.mem.base);peer=b.operands[index]
            if operand.mem.index:raise ValueError('Enemy leaf has unbounded memory indexing')
            if base=='rip':
                points=[a.address+a.size+operand.mem.disp,b.address+b.size+peer.mem.disp]
                values=[]
                for image,point in zip((old,new),points):
                    section=image.get_section_by_rva(point)
                    if (section is None or section.Characteristics&(0x80000000|0x20000000)
                            or point+operand.size>section.VirtualAddress+section.Misc_VirtualSize):
                        raise ValueError('Enemy decision constant is not bounded immutable data')
                    values.append(image.get_data(point,operand.size))
                if values[0]!=values[1] or len(values[0])!=operand.size:
                    raise ValueError('Enemy decision constant changed')
                literals.append(dict(reference=points[0],candidate=points[1],width=operand.size,
                                     bytes=values[0].hex()))
            elif base not in ('rcx','rdx','r8') or not 0<=operand.mem.disp<=({'rcx':0x148,'rdx':8,'r8':8}[base]-operand.size):
                raise ValueError('Enemy leaf reads outside typed Enemy/XY arguments')
            if memory_write_operand(a,index):
                if base!='rcx' or index!=0:raise ValueError('Enemy leaf writes a borrowed input')
                scalar=(a.mnemonic=='mov' and a.operands[1].type==capstone.x86.X86_OP_IMM
                        and a.operands[1].imm in (0,1))
                hp=(a.mnemonic=='movss' and a.op_str=='dword ptr [rcx + 0xe0], xmm1')
                if not scalar and not hp:raise ValueError('Enemy leaf can publish an unclassified value')
                writes.append(dict(offset=operand.mem.disp,width=operand.size,
                    value='native-f32-health' if hp else a.operands[1].imm))
    tags=[return_tag_values(code,entry) for code,entry in zip(codes,(reference,candidate))]
    if tags[0]!=tags[1] or tags[0]!=[0,1,2,3]:raise ValueError('Enemy decision return domain changed')
    return dict(reference=reference,candidate=candidate,classification='typed-enemy-decision-leaf',
        native_leaf_verified=True,old_end=reference+len(codes[0]),new_end=candidate+len(codes[1]),
        paired_roles=roles,readonly_literals=literals,writes=writes,return_tags=tags[0],
        owned_pointer_publication=False,no_calls=True,abi={'rcx':'Enemy148','rdx':'XY8','r8':'XY8','xmm3':'time'},
        automatic_activation_allowed=False)


def added_packet_write_footprint(helper, row, serializer):
    """Inventory an entire added packet-producing branch, including repeated copies.

    Sequence alignment alone can align newly added packet stores with older
    identical stores. Derive this branch from its actual helper call and native
    forward join, then classify every heap write in it using the complete CFG.
    """
    candidates=row.get('candidates',())
    if len(candidates)!=1:raise ValueError('Game update body is ambiguous')
    entry=int(candidates[0]['rva'],16)
    stream=instructions(helper.new,entry,helper.bounds[1][entry])
    added_calls={int(c['rva'],16) for c in row['changed_mutation_footprint']['calls']}
    calls=[n for n,i in enumerate(stream) if i.address in added_calls and i.mnemonic=='call'
           and i.operands[0].type==capstone.x86.X86_OP_IMM and i.operands[0].imm==serializer]
    if len(calls)!=1:raise ValueError('Added packet producer call is ambiguous')
    index=calls[0]; positions={i.address:n for n,i in enumerate(stream)}
    # At least two independent early-outs must share the same forward join.
    joins={}
    for ins in stream[max(0,index-80):index]:
        if (ins.group(capstone.CS_GRP_JUMP) and ins.mnemonic!='jmp'
                and ins.operands[0].type==capstone.x86.X86_OP_IMM):
            target=ins.operands[0].imm
            if target in positions and index<positions[target]<=index+50:
                joins.setdefault(target,[]).append(ins.address)
    joins={target:sites for target,sites in joins.items() if len(sites)>=2}
    if len(joins)!=1:raise ValueError('Added packet branch lacks a unique forward join')
    end,branches=next(iter(joins.items())); start=min(branches)
    block=[i for i in stream if start<=i.address<end]
    stores=[]; stack=[]
    for ins in block:
        for operand_index,operand in enumerate(ins.operands):
            if not memory_write_operand(ins,operand_index):continue
            base=ins.reg_name(operand.mem.base)
            if base in ('rbp','rsp') and not operand.mem.index:
                stack.append(dict(rva=hex(ins.address),base=base,offset=operand.mem.disp,width=operand.size))
            elif operand_index==0 and base not in ('rip',''):
                stores.append(dict(rva=hex(ins.address),width=operand.size,destination='unproven_heap_owner'))
            else:raise ValueError('Added packet branch has an unclassified write operand')
    edges={int(k):v for k,v in row['guarded_dispatches']['candidate_edges'].items()}
    for switch in row['return_tag_switches']:
        edges[int(switch['jump'],16)]=[int(t,16) for t in switch['targets'].values()]
    owners=changed_store_owners(helper.code(1,entry),entry,edges,stores)
    if not stores or not owners['all_destinations_classified']:
        raise ValueError('Added packet branch writes an unknown heap owner')
    allocations=[s for s in owners['stores'] if s['kind']=='allocation_body']
    allocator_sites={int(s['reaching_definitions'][0],16) for s in allocations}
    if len(allocator_sites)!=1:raise ValueError('Added branch allocation provenance is ambiguous')
    allocator_site=next(iter(allocator_sites))
    spills=[i for i in block if i.address>allocator_site and i.mnemonic=='mov'
            and len(i.operands)==2 and i.operands[0].type==capstone.x86.X86_OP_MEM
            and i.reg_name(i.operands[0].mem.base)=='rbp' and not i.operands[0].mem.index
            and i.operands[0].size==8 and i.operands[1].type==capstone.x86.X86_OP_REG
            and i.reg_name(i.operands[1].reg)=='rax']
    if len(spills)!=1:raise ValueError('Fresh Packet allocation spill is ambiguous')
    spill=spills[0]
    liveness=frame_value_reads(helper.code(1,entry),entry,spill.address+spill.size,
        spill.operands[0].mem.disp,8,edges)
    if len(liveness['reads'])!=1 or liveness['address_escapes']:
        raise ValueError('Fresh Packet pointer spill escapes its single publication')
    read=stream[positions[liveness['reads'][0]['rva']]]
    publication=stream[positions[read.address]+1]
    owner=next((s for s in owners['stores'] if int(s['rva'],16)==publication.address),None)
    if (read.mnemonic!='mov' or read.reg_name(read.operands[0].reg)!='rdx'
            or publication.mnemonic!='mov' or publication.reg_name(publication.operands[1].reg)!='rdx'
            or not owner or owner['kind']!='game_vector_member' or owner['member_offset']!=8):
        raise ValueError('Fresh allocation is not published to native Packet.body')
    for first,register,family,allowed in (
            (allocator_site,'rax',{'rax','eax','ax','al','ah'},
             {int(s['rva'],16) for s in allocations}|{spill.address}),
            (read.address,'rdx',{'rdx','edx','dx','dl','dh'},{publication.address})):
        killed=False
        for ins in stream[positions[first]+1:]:
            reads,writes=ins.regs_access()
            if ins.group(capstone.CS_GRP_CALL):killed=True;break
            if family.intersection(ins.reg_name(r) for r in writes):
                # A full MOV/LEA or self-XOR discards the previous pointer.
                if (ins.mnemonic in ('mov','lea') and ins.operands[0].size in (4,8)
                        or ins.mnemonic=='xor' and ins.op_str in (register+', '+register,
                            'e'+register[1:]+', e'+register[1:])):
                    killed=True;break
                raise ValueError('Fresh Packet pointer undergoes unclassified mutation')
            if family.intersection(ins.reg_name(r) for r in reads):
                if ins.address not in allowed and not (ins.mnemonic=='test' and ins.op_str==register+', '+register):
                    raise ValueError('Fresh Packet pointer has an unclassified register use')
        if not killed:raise ValueError('Fresh Packet pointer remains live beyond proven native publication')
    return dict(start=start,end=end,serializer_call=stream[index].address,
                stores=owners['stores'],stack_writes=stack,all_heap_writes_classified=True,
                indirect_edges_guarded=True,pointer_spill=dict(site=spill.address,
                    offset=spill.operands[0].mem.disp,publication=publication.address,liveness=liveness))


def changed_writer_contract(helper, old_link, new_link, structural):
    """Bind guarded destination provenance to native owned-container drops."""
    rows=[row for row in structural.values() if 'changed_store_owners' in row]
    if len(rows)!=1:raise ValueError('Changed Game writer ownership evidence is missing')
    row=rows[0]; owners=row['changed_store_owners']
    if not owners.get('all_destinations_classified') or not row.get('guarded_dispatches',{}).get('contracts'):
        raise ValueError('Changed writer destinations or mandatory dispatch guards unresolved')
    stores=owners['stores']
    unknown=[s for s in stores if s['kind'] not in ('game','game_vector_member','allocation_body')]
    if unknown:raise ValueError('Changed writer publishes an unclassified destination')
    allocations=[s for s in stores if s['kind']=='allocation_body']
    allocation_proofs=[]
    for target in sorted({s['allocator'] for s in allocations}):
        # Reviewed allocator ABI, with the candidate target derived exclusively
        # from the changed store's all-predecessor reaching CALL definition.
        allocation_proofs.append(helper.pair(0x21c0,target))
    if any(s['size']!=32 or s['alignment']!=1 or s['member_offset']+s['width']>12 for s in allocations):
        raise ValueError('New scalar packet allocation layout changed')
    vectors=[s for s in stores if s['kind']=='game_vector_member']
    packet_fields={s['pointer_field'] for s in vectors if s.get('index_scale')==32}
    ability_fields={s['pointer_field'] for s in vectors if s.get('index_scale')==16}
    if len(packet_fields)!=1 or len(ability_fields)!=1:
        raise ValueError('Changed native container types are ambiguous')
    packet_field,ability_field=next(iter(packet_fields)),next(iter(ability_fields))
    for s in vectors:
        if s['pointer_field']==packet_field:
            if s['member_offset'] not in (0,8,16,24) or s['member_offset']+s['width']>32:
                raise ValueError('Packet write exceeds native32-byte member')
        elif (s['pointer_field']!=ability_field or s['width']!=4 or s['member_offset']!=0x24
                or len(s.get('index_source',()))!=1
                or s['index_source'][0]['instruction']!='lea r12, [rbx + rbx*4]'):
            raise ValueError('Changed ability write is not its scalar cooldown')
    entries=[old_link['game_drop'],new_link['game_drop']]
    streams=[instructions(image,entry,helper.bounds[side][entry])
             for side,(image,entry) in enumerate(zip((helper.old,helper.new),entries))]
    aliases=[game_field_uses(helper.code(side,entry),entry) for side,entry in enumerate(entries)]
    packet_drops=[];ability_drops=[]
    for index,ins in enumerate(streams[1]):
        use=aliases[1].get((ins.address,1))
        if not use:continue
        if (ins.mnemonic=='mov' and ins.op_str.startswith('rdi, ') and use['offset']==packet_field):
            # Destructor owns every Packet body at+8, then advances exactly32.
            block=streams[1][index:index+14]
            names=[(i.mnemonic,i.op_str) for i in block]
            required=[('add','rdi, 8'),('add','rdi, 0x20'),('mov','rdx, qword ptr [rdi - 8]'),
                      ('mov','rcx, qword ptr [rdi]'),('mov','r8d, 1')]
            if not all(item in names for item in required):continue
            old_use=aliases[0].get((streams[0][index].address,1))
            if old_use is None:continue
            packet_drops.append(dict(reference_pointer=old_use['offset'],candidate_pointer=packet_field,
                stride=32,body_pointer=8,body_capacity=0,body_alignment=1,
                reference_site=streams[0][index].address,candidate_site=ins.address))
        if (ins.mnemonic=='lea' and ins.op_str.startswith('rcx, ') and use['offset']==ability_field-8
                and index+1<len(streams[1]) and streams[1][index+1].mnemonic=='call'):
            old_call,new_call=streams[0][index+1],streams[1][index+1]
            proof=helper.pair(old_call.operands[0].imm,new_call.operands[0].imm)
            native=instructions(helper.new,new_call.operands[0].imm,helper.bounds[1][new_call.operands[0].imm])
            names=[(i.mnemonic,i.op_str) for i in native[:24]]
            if not all(item in names for item in [('mov','rax, qword ptr [rcx]'),
                    ('mov','rcx, qword ptr [rsi + 8]'),('shl','rax, 4'),('lea','rdx, [rax + rax*4]')]):
                raise ValueError('Ability controller no longer owns80-byte elements')
            ability_drops.append(dict(candidate_pointer=ability_field,stride=80,
                scalar_member=0x24,scalar_width=4,proof=proof))
    if len(packet_drops)!=1 or len(ability_drops)!=1:
        raise ValueError('Changed native owned vectors lack unique paired destructor links')
    called={int(c['target'],16) for c in row['changed_mutation_footprint']['calls'] if c['target']}
    serializers=set(helper.candidates(REVIEWED_SCALAR_PAIR_PACKET))&called
    if len(serializers)!=1:raise ValueError('New scalar packet serializer is ambiguous')
    packet_helper=scalar_pair_packet_contract(helper.old,helper.new,next(iter(serializers)))
    added_branch=added_packet_write_footprint(helper,row,next(iter(serializers)))
    if any(s['kind']=='game_vector_member' and (s['pointer_field']!=packet_field
            or s.get('index_scale')!=32 or not 0<=s['member_offset']
            or s['member_offset']+s['width']>32) for s in added_branch['stores']):
        raise ValueError('Added branch publishes outside the native Packet vector')
    # Derive old/new helper edges from already paired native instruction roles.
    paired_calls={}
    for region in row['guest_controlled_regions'].values():
        if not region.get('instruction_roles') or not region.get('internal_control_flow'):continue
        a,b,c,d=(int(region[k],16) for k in ('old_start','old_end','new_start','new_end'))
        left,right=instructions(helper.old,a,b),instructions(helper.new,c,d)
        if len(left)!=len(right):raise ValueError('Paired region instruction count changed')
        for x,y in zip(left,right):
            if (x.mnemonic==y.mnemonic=='call' and x.operands[0].type==y.operands[0].type==capstone.x86.X86_OP_IMM):
                paired_calls.setdefault(y.operands[0].imm,set()).add(x.operands[0].imm)
    entry=int(row['candidates'][0]['rva'],16)
    stream=instructions(helper.new,entry,helper.bounds[1][entry])
    positions={i.address:n for n,i in enumerate(stream)}
    native_calls=[];unresolved_calls=[]
    for call in row['changed_mutation_footprint']['calls']:
        site=int(call['rva'],16);target=int(call['target'],16) if call['target'] else None
        if target in serializers:
            native_calls.append(dict(site=site,target=target,classification='scalar-packet-helper'));continue
        old_targets=paired_calls.get(target,set())
        if len(old_targets)==1:
            old_target=next(iter(old_targets))
            try:proof=helper.pair(old_target,target)
            except ValueError:
                proof=helper.terminal_allocation_failure(old_target,target)
                if not proof:raise
            native_calls.append(dict(site=site,target=target,proof=proof));continue
        try:terminal=helper.terminal_allocation_failure(0x5817e8b,target) if target in helper.bounds[1] else None
        except ValueError:terminal=None
        if terminal:
            from native_helper_contracts import terminal_continuation
            if not terminal_continuation(stream,site+stream[positions[site]].size):
                raise ValueError('Native allocation failure gained a success continuation')
            native_calls.append(dict(site=site,target=target,proof=terminal));continue
        try:
            proof=terminal_bounds_call(helper,stream,positions[site])
            call_index=positions[site]
            if stream[call_index-1].mnemonic!='mov' or stream[call_index-1].op_str!='rcx, rbx':
                raise ValueError('Bounds index argument no longer comes from native index')
            # The Location LEA begins the sole basic block feeding this CALL.
            block_start=stream[call_index-2].address
            incoming=[n for n,i in enumerate(stream) if i.group(capstone.CS_GRP_JUMP)
                      and i.operands[0].type==capstone.x86.X86_OP_IMM
                      and i.operands[0].imm==block_start]
            if not incoming or any(stream[n].mnemonic!='jae' or n==0
                    or (stream[n-1].mnemonic,stream[n-1].op_str)!=('cmp','rbx, rdx') for n in incoming):
                raise ValueError('Bounds failure does not follow native unsigned index/length comparison')
            proof['caller_scalar_provenance_verified']=True
            proof['scalar_comparisons']=[stream[n-1].address for n in incoming]
            native_calls.append(dict(site=site,target=target,proof=proof))
        except ValueError as error:unresolved_calls.append(dict(site=site,target=target,reason=str(error)))
    old_entry=next(int(k,16) for k,v in structural.items() if v is row)
    all_edges=[]
    for side,key in ((0,'reference'),(1,'candidate')):
        edges={int(k):v for k,v in row['guarded_dispatches'][key+'_edges'].items()}
        for switch in row['reference_return_tag_switches' if side==0 else 'return_tag_switches']:
            edges[int(switch['jump'],16)]=[int(t,16) for t in switch['targets'].values()]
        all_edges.append(edges)
    paired_stores=paired_store_fields(helper.code(0,old_entry),old_entry,helper.code(1,entry),entry,*all_edges)
    return dict(changed_destinations_verified=True,stores=stores,allocation_proofs=allocation_proofs,
        packet_drop=packet_drops[0],ability_drop=ability_drops[0],scalar_packet_helper=packet_helper,
        added_packet_branch=added_branch,
        changed_calls=native_calls,unresolved_calls=unresolved_calls,
        paired_store_fields=paired_stores,
        mandatory_dispatch_guards=row['guarded_dispatches']['contracts'],
        conditional_on_installed_dispatch_guards=True,
        unresolved=(['Bind remaining native changed calls'] if unresolved_calls else [])+
                    (['Unclassified paired native store fields'] if paired_stores['unresolved'] else []),
        automatic_activation_allowed=False)


def drop_fields(image, entry, end):
    stream = instructions(image, entry, end)
    names = [(i.mnemonic, i.op_str) for i in stream]
    for required in [('mov', 'rsi, qword ptr [rcx + 8]'), ('mov', 'rbx, qword ptr [rcx + 0x10]'),
                     ('lea', 'r14, [rsi + 0x48]'), ('add', 'r14, 0x148'),
                     ('imul', 'rdx, rax, 0x148')]:
        if required not in names:
            raise ValueError('Enemy Vec drop layout changed')
    accesses = []
    for ins in stream:
        for operand in ins.operands:
            if operand.type != capstone.x86.X86_OP_MEM or ins.reg_name(operand.mem.base) != 'r14':
                continue
            if operand.mem.index:
                raise ValueError('Enemy drop uses unclassified indexed ownership')
            offset = operand.mem.disp + 0x48
            if not 0 <= offset < 0x68 or offset + operand.size > 0x68:
                raise ValueError('Enemy destructor accesses copied tail')
            accesses.append(dict(offset=offset, width=operand.size, instruction=ins.mnemonic))
    if {a['offset'] for a in accesses} != {0, 8, 0x18, 0x20, 0x40, 0x48}:
        raise ValueError('Enemy destructor owned prefix shape changed')
    return dict(stride=0x148, owned_capacity_offsets=[0, 0x18, 0x40], owned_pointer_offsets=[8, 0x20, 0x48],
                prefix_accesses=accesses, copied_tail=[0x68, 0x148], tail_destructor_references=False)


def game_drop_link(image, ui_entry, helper, side):
    """Identify Game drop immediately before native replacement of Server.Game."""
    stream = instructions(image, ui_entry, helper.bounds[side][ui_entry])
    matches = []
    for index in range(len(stream) - 7):
        block = stream[index:index + 7]
        if ([i.mnemonic for i in block] != ['lea', 'call', 'nop', 'lea', 'mov', 'lea', 'call']
                or block[0].op_str != 'rcx, [rsi + 0x10]' or block[5].op_str != block[0].op_str
                or not block[3].op_str.startswith('rdx, [rbp + ')
                or block[4].reg_name(block[4].operands[0].reg) != 'r8d'
                or block[4].operands[1].type != capstone.x86.X86_OP_IMM):
            continue
        target = block[1].operands[0].imm
        if target not in helper.bounds[side]:
            continue
        drop = instructions(image, target, helper.bounds[side][target])
        aliases = game_field_uses(helper.code(side, target), target)
        loops = []
        for n in range(len(drop) - 6):
            count, test, branch, pointer, adjust, jump = drop[n:n + 6]
            if ([i.mnemonic for i in (count, test, branch, pointer, adjust, jump)] !=
                    ['mov', 'test', 'je', 'mov', 'add', 'jmp']
                    or adjust.op_str != 'rdi, 0x48' or pointer.reg_name(pointer.operands[0].reg) != 'rdi'
                    or count.reg_name(count.operands[0].reg) != 'rsi'
                    or (count.address, 1) not in aliases or (pointer.address, 1) not in aliases):
                continue
            stop = branch.operands[0].imm
            body = [i for i in drop if jump.address < i.address < stop]
            if ('add', 'rdi, 0x148') not in [(i.mnemonic, i.op_str) for i in body]:
                continue
            reads = []
            for ins in body:
                for operand in ins.operands:
                    if operand.type == capstone.x86.X86_OP_MEM and ins.reg_name(operand.mem.base) == 'rdi':
                        if operand.mem.index:
                            raise ValueError('Game Enemy drop has indexed ownership access')
                        reads.append(operand.mem.disp + 0x48)
            if set(reads) != {0, 8, 0x18, 0x20, 0x40, 0x48}:
                raise ValueError('Game Enemy owned field set changed')
            calls = [i.operands[0].imm for i in body if i.mnemonic == 'call']
            if len(calls) != 3 or len(set(calls)) != 1:
                raise ValueError('Game Enemy drop no longer consists of three native frees')
            loops.append(dict(game_pointer=aliases[(pointer.address, 1)]['offset'],
                              game_count=aliases[(count.address, 1)]['offset'],
                              element_stride=0x148, owned_fields=sorted(set(reads)), free=calls[0],
                              start=jump.operands[0].imm, end=stop))
        if len(loops) == 1:
            matches.append(dict(ui_call=block[1].address, game_drop=target, game_size=block[4].operands[1].imm,
                                server_game_offset=0x10, loop=loops[0]))
    if len(matches) != 1:
        raise ValueError('Native Game replacement/drop link is missing or ambiguous')
    return matches[0]


def discover_enemy_contract(reference, binary, structural):
    updates = [row for row in structural.values() if 'changed_store_owners' in row]
    if len(updates) != 1:
        errors = [row['guarded_dispatches']['error'] for row in structural.values()
                  if row.get('guarded_dispatches', {}).get('error')]
        raise ValueError('Native Game.update ownership is missing or ambiguous'
                         + (': ' + '; '.join(errors) if errors else ''))
    update = updates[0]
    before, after = Path(reference).read_bytes(), Path(binary).read_bytes()
    if hashlib.sha256(before).hexdigest() != UPDATED_HASH:
        raise ValueError('Enemy reference is not reviewed')
    old, new = pefile.PE(data=before, fast_load=True), pefile.PE(data=after, fast_load=True)
    helper = HelperProof(old, new)
    baseline = drop_fields(old, REVIEWED_ENEMY_VECTOR_DROP, helper.bounds[0][REVIEWED_ENEMY_VECTOR_DROP])
    drops, failures = [], []
    for candidate in helper.candidates(REVIEWED_ENEMY_VECTOR_DROP):
        try:
            contract = drop_fields(new, candidate, helper.bounds[1][candidate])
            proof = helper.pair(REVIEWED_ENEMY_VECTOR_DROP, candidate)
            drops.append(dict(candidate=candidate, contract=contract, proof=proof))
        except ValueError as error:
            failures.append(dict(candidate=candidate, reason=str(error)))
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    constructors = []
    for name in ('SPAWN', 'SPAWN_BOSS'):
        entry = manifest['hooks'][name]['reference_rva']
        old_code = helper.code(0, entry)
        aliases_old = game_field_uses(old_code, entry)
        for row in structural[hex(entry)]['candidates']:
            candidate = int(row['rva'], 16)
            code = helper.code(1, candidate)
            layout = compare_function_layout(old_code, entry, code, candidate)
            if not layout['structure_equivalent']:
                try:
                    layout = reviewed_map_constructor_layout(helper, entry, candidate, hashlib.sha256(after).hexdigest())
                except ValueError as error:
                    failures.append(dict(function=name, candidate=candidate, reason=str(error)))
                    continue
            aliases_new = game_field_uses(code, candidate)
            untyped = []
            for change in layout['field_changes']:
                aa = [u for (site, _), u in aliases_old.items() if site == int(change['old_rva'], 16)]
                bb = [u for (site, _), u in aliases_new.items() if site == int(change['new_rva'], 16)]
                if (len(aa) != 1 or len(bb) != 1 or aa[0]['offset'] != change['old_offset']
                        or bb[0]['offset'] != change['new_offset']):
                    untyped.append(change)
            constructors.append(dict(function=name, reference=entry, candidate=candidate,
                                     structure=layout, untyped_field_changes=untyped))
    old_ui = manifest['hooks']['UI_COMMAND']['reference_rva']
    old_link = game_drop_link(old, old_ui, helper, 0)
    links = []
    for candidate in structural[hex(old_ui)]['candidates']:
        try:
            new_link = game_drop_link(new, int(candidate['rva'], 16), helper, 1)
            layout = compare_function_layout(helper.code(0, old_link['game_drop']), old_link['game_drop'],
                                             helper.code(1, new_link['game_drop']), new_link['game_drop'])
            if not layout['structure_equivalent']:
                raise ValueError('Native Game destructor structure changed')
            free_proof = helper.pair(old_link['loop']['free'], new_link['loop']['free'])
            links.append(dict(reference=old_link, candidate=new_link, structure=layout, free_proof=free_proof,
                              enemy_owned_prefix_verified=True))
        except ValueError as error:
            failures.append(dict(function='game_drop_link', reason=str(error)))
    changed_writers=None
    if len(links)==1:
        try:
            changed_writers=changed_writer_contract(helper,links[0]['reference'],links[0]['candidate'],structural)
        except ValueError as error:
            failures.append(dict(function='changed_writers',reason=str(error)))
    definitions=None;decision=None
    try:
        table=referenced_data_candidate(old,new,structural,REVIEWED_MAP_TABLE)
        definitions=map_enemy_contracts(helper,REVIEWED_MAP_TABLE,table['candidate'],definitions_only=True,
                                        candidate_layout=table.get('candidate_layout'))
        definitions['table_relocation']=table
    except ValueError as error:failures.append(dict(function='enemy_definitions',reason=str(error)))
    try:
        before_decisions=update['reference_return_tag_switches'];after_decisions=update['return_tag_switches']
        if len(before_decisions)!=1 or len(after_decisions)!=1:
            raise ValueError('Native Enemy decision producer is ambiguous')
        decision=enemy_leaf_contract(old,new,int(before_decisions[0]['producer'],16),
                                    int(after_decisions[0]['producer'],16))
    except ValueError as error:failures.append(dict(function='enemy_decision_leaf',reason=str(error)))
    verified=(len(drops)==1 and len(links)==1 and len(constructors)==2
              and {c['function'] for c in constructors}=={'SPAWN','SPAWN_BOSS'}
              and not any(c['untyped_field_changes'] for c in constructors)
              and changed_writers is not None and not changed_writers['unresolved']
              and decision is not None and decision['native_leaf_verified']
              and definitions is not None and definitions.get('definition_arrays_verified') is True)
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest() != hashlib.sha256(after).hexdigest():
        raise ValueError('Game changed while discovering Enemy contracts')
    return dict(sha256=hashlib.sha256(after).hexdigest(), reference_sha256=UPDATED_HASH,
                automatic_activation_allowed=False, reference_drop=REVIEWED_ENEMY_VECTOR_DROP,
                baseline=baseline, drop_candidates=drops, game_drop_links=links, constructors=constructors, failures=failures,
                changed_writers=changed_writers,
                definitions=definitions,decision_leaf=decision,conditional_enemy_tail_verified=verified,
                mandatory_dispatch_guards=changed_writers['mandatory_dispatch_guards'] if verified else [],
                scope='Reviewed owned-prefix/drop and constructor layout; immutable borrowed definitions; changed Game.update writes/calls and added Packet pointer publication. Requires installed dispatch and live vector ownership guards.',
                unresolved=[] if verified else ['Complete conditional Enemy ownership contracts'])


def conditional_update_regions(reference,binary,structural,required_addresses=(),required_patches=()):
    """Return local region admission with explicit external-callee obligations.

    This is not activation. The compiler must bind outgoing native calls to its
    typed helper reports and install the declared ownership/dispatch guards.
    """
    enemy=discover_enemy_contract(reference,binary,structural)
    if not enemy['conditional_enemy_tail_verified']:
        raise ValueError('Conditional Game.update requires the complete Enemy ownership contract')
    old,new=pefile.PE(str(reference),fast_load=True),pefile.PE(str(binary),fast_load=True)
    helper=HelperProof(old,new)
    old_entry,row=next((int(k,16),v) for k,v in structural.items() if 'changed_store_owners' in v)
    new_entry=int(row['candidates'][0]['rva'],16)
    aliases=[];call_arguments={}
    for side,key,entry in ((0,'reference',old_entry),(1,'candidate',new_entry)):
        edges={int(k):v for k,v in row['guarded_dispatches'][key+'_edges'].items()}
        for switch in row['reference_return_tag_switches' if side==0 else 'return_tag_switches']:
            edges[int(switch['jump'],16)]=[int(t,16) for t in switch['targets'].values()]
        arguments={}
        aliases.append(game_field_uses(helper.code(side,entry),entry,indirect_edges=edges,
            pointer_immediates=True,call_arguments=arguments))
        call_arguments[key]=[dict(site=i.address,target=i.operands[0].imm,args=arguments.get(i.address,{}))
            for i in instructions((old,new)[side],entry,helper.bounds[side][entry])
            if i.mnemonic=='call' and i.operands[0].type==capstone.x86.X86_OP_IMM]
    if (not row['pursuit_live_contract'].get('local_roles_verified')
            or not row['pursuit_live_contract'].get('constant_values_verified')
            or not row['generated_restore_game'].get('local_dependencies_complete')):
        raise ValueError('Generated live-register/frame restoration roles are incomplete')
    regions=[];fields=[];calls=[];readonly={};retained=[]
    for name,region in row['guest_controlled_regions'].items():
        if not all(key in region for key in ('old_start','old_end','new_start','new_end')):
            raise ValueError(f'Controlled native region {name} lacks a complete paired layout: '
                             f"{region.get('comparison', {}).get('reason', region.get('reason', 'unproved roles'))}")
        a,b,c,d=(int(region[k],16) for k in ('old_start','old_end','new_start','new_end'))
        current=region_instruction_contract(old.get_data(a,b-a),a,new.get_data(c,d-c),c)
        if (not current['internal_control_flow'] or not region['outgoing_branches_verified']
                or not (current['instruction_roles'] or current['conditional_instruction_roles'])):
            raise ValueError(f'Controlled native region {name} roles/continuations changed')
        suffix=region.get('retained_native_suffix')
        if suffix:
            if (suffix.get('sha256')!=REVIEWED_START_BUILD or enemy['sha256']!=REVIEWED_START_BUILD
                    or suffix.get('reference_sha256')!=UPDATED_HASH
                    or (suffix['old_start'],suffix['old_end'],suffix['new_start'],suffix['new_end']) !=
                       (0x53f3e61,0x53f56e0,0x53fe141,0x53ff9d0)
                    or a!=0x53f1f62 or c!=0x53fc242 or b!=suffix['old_start'] or d!=suffix['new_start']
                    or suffix.get('guest_skip')!=a or suffix.get('guest_continuation')!=suffix['old_end']):
                raise ValueError('Retained host-native suffix differs from reviewed release/boundaries')
            if (any(suffix['old_start']<=point<suffix['old_end'] for point in required_addresses)
                    or any(point<suffix['old_end'] and point+len(bytes.fromhex(value) if isinstance(value,str) else value)>suffix['old_start']
                           for point,value in required_patches)):
                raise ValueError('Adapter input intersects retained host-native map logic')
            hooks=json.loads((ROOT/'reconstruction/reviewed-hooks.json').read_text())['hooks']
            expected={'SPAWN':4,'SPAWN_BOSS':2,'FIND_SPAWN':3,'SPAWN_LOOT':3}
            if set(suffix.get('hooked_callees',()))!=set(expected):
                raise ValueError('Retained host-native hooked-call inventory changed')
            for callee,count in expected.items():
                source=hooks[callee]['reference_rva']
                candidates=structural[hex(source)]['candidates']
                if len(candidates)!=1:raise ValueError('Retained native callee is ambiguous')
                target=int(candidates[0]['rva'],16)
                paired=[]
                for key,lo,hi,entry in (('reference',suffix['old_start'],suffix['old_end'],source),
                                        ('candidate',suffix['new_start'],suffix['new_end'],target)):
                    found=[call for call in call_arguments[key] if lo<=call['site']<hi and call['target']==entry]
                    receiver='rdx' if callee=='FIND_SPAWN' else 'rcx'
                    if len(found)!=count or any(call['args'].get(receiver)!=0 for call in found):
                        raise ValueError(f'Retained native {callee} calls lack paired Game ownership')
                    paired.append(found)
                calls.extend(dict(kind='call',region='retained-host-world:'+callee,
                    old_rva=hex(x['site']),new_rva=hex(y['site']),old_target=hex(source),new_target=hex(target))
                    for x,y in zip(*paired))
            retained.append(suffix)
        typed=[]
        for x,y in zip(instructions(old,a,b),instructions(new,c,d)):
            for index,operand in enumerate(x.operands):
                if (operand.type!=capstone.x86.X86_OP_MEM or x.mnemonic=='lea'
                        or operand.mem.base!=capstone.x86.X86_REG_RIP
                        or memory_write_operand(x,index)):continue
                reference_data=x.address+x.size+operand.mem.disp
                if reference_data not in required_addresses:continue
                peer=y.operands[index]
                if peer.type!=operand.type or peer.mem.base!=operand.mem.base or peer.size!=operand.size:
                    raise ValueError('Controlled native literal read role changed')
                candidate_data=y.address+y.size+peer.mem.disp
                for image,point in ((old,reference_data),(new,candidate_data)):
                    section=image.get_section_by_rva(point)
                    if section is None or section.Characteristics&(0x20000000|0x80000000):
                        raise ValueError('Controlled literal is not immutable data')
                    if point+operand.size>section.VirtualAddress+section.Misc_VirtualSize:
                        raise ValueError('Controlled literal exceeds its immutable section')
                before_data=old.get_data(reference_data,operand.size)
                if len(before_data)!=operand.size or new.get_data(candidate_data,operand.size)!=before_data:
                    raise ValueError('Adapter consumed native literal changed')
                evidence=dict(reference=reference_data,candidate=candidate_data,width=operand.size,
                    bytes=before_data.hex(),reference_site=x.address,candidate_site=y.address,
                    contracts=['readonly-literal:'+name])
                previous=readonly.get(reference_data)
                if previous and previous['candidate']!=candidate_data:
                    raise ValueError('Controlled native literal relocation is ambiguous')
                readonly[reference_data]=evidence
        for change in current['field_changes']+current['conditional_pointer_immediates']:
            old_site,new_site=int(change['old_rva'],16),int(change['new_rva'],16)
            if change.get('stack'):
                raise ValueError('Adapter-controlled native frame displacement changed')
            aa=[u for (site,_),u in aliases[0].items() if site==old_site and u['offset']==change['old_offset']]
            bb=[u for (site,_),u in aliases[1].items() if site==new_site and u['offset']==change['new_offset']]
            if len(aa)!=1 or len(bb)!=1 or aa[0]['width']!=bb[0]['width']:
                raise ValueError('Controlled region changed field lacks paired typed Game ownership')
            fields.append(dict(domain='game',reference=aa[0]['offset'],candidate=bb[0]['offset'],
                reference_site=old_site,candidate_site=new_site,width=aa[0]['width'],address_only=aa[0]['address_only']))
            if change in current['conditional_pointer_immediates']:typed.append(change)
        regions.append(dict(current,admitted=True,conditionally_admitted=True,
            contract_id='guarded-game-update:'+name,verified_pointer_moves=typed))
        calls.extend(dict(e,region=name) for e in region['external_edges'] if e['kind']=='call')
    exact=collect_region_inputs(old,new,regions,required_addresses,required_patches)
    for point,evidence in readonly.items():
        exact['addresses'].append(evidence)
        exact['unresolved_inputs']=[r for r in exact['unresolved_inputs']
            if not (r['kind']=='address' and r['reference']==point)]
    grouped={}
    for call in calls:
        grouped.setdefault((int(call['old_target'],16),int(call['new_target'],16)),[]).append(
            dict(region=call['region'],reference=call['old_rva'],candidate=call['new_rva']))
    audit=dict(verified=[],unresolved=[])
    for (source,target),sites in grouped.items():
        item=dict(reference=source,candidate=target,calls=sites)
        try:
            leaf=enemy['decision_leaf']
            item['proof']=(leaf if (source,target)==(leaf['reference'],leaf['candidate'])
                           else helper.pair(source,target,candidate_call=True))
            audit['verified'].append(item)
        except ValueError as error:
            item['error']=str(error);audit['unresolved'].append(item)
    if hashlib.sha256(Path(binary).read_bytes()).hexdigest()!=enemy['sha256']:
        raise ValueError('Game changed while collecting conditional native regions')
    return dict(reference_sha256=enemy['reference_sha256'],sha256=enemy['sha256'],static_verified=True,
        conditionally_admitted_regions=regions,fields=fields,exact_inputs=exact,
        frame_fields=[s for r in regions for s in r['stack_field_evidence']],
        mandatory_dispatch_guards=enemy['mandatory_dispatch_guards'],
        mandatory_live_guards=row['pursuit_live_contract'],restore_game=row['generated_restore_game'],
        native_call_dependencies=calls,callee_closure_required=True,enemy=enemy,
        native_call_audit=audit,call_arguments=call_arguments,
        retained_native_regions=retained,
        automatic_activation_allowed=False)


if __name__ == '__main__':
    report = discover_enemy_contract(ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe',
        ROOT / 'AzerothSurvivors.exe', json.loads((ROOT / 'analysis/structural-hook-candidates.json').read_text()))
    (ROOT / 'analysis/enemy-contract-candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(drop_candidates=len(report['drop_candidates']), failures=report['failures'],
                         constructors=[dict(name=r['function'], untyped=len(r['untyped_field_changes']))
                                       for r in report['constructors']]), indent=2))
