"""Manual 0.93.1 (0315cf38) -> 7264d50b decisions with evidence (keys as used by build_7264.py). Values are 7264 numbers.

Entries marked VORSCHLAG are jump destinations whose surrounding hook code changed registers in 7264; the address
itself is the same logical point, but the hook code variant still needs review before activation.
"""

MANUAL = {
    # FREE thunk: 301 aligned calls keep 0x21d0 (jmp to the HeapFree helper, same shape 0x56a4f20 -> 0x56bf490);
    # the single 0x541a050 vote comes from a mis-aligned call inside the reshaped UI-command function.
    'code:0x21d0': (0x21D0, 'Thunk 0x21d0 unverändert (301 ausgerichtete Aufrufe, Ziel 0x56a4f20->0x56bf490 gleiche Form)'),
    # rel32 field of the aligned call 0x549abc3 -> 0x547b963 (+1); helper 0x5488f80 -> 0x5469690 identical up to ret.
    'code:0x549abc4': (0x547B964, 'rel32 des ausgerichteten Aufrufs 0x549abc3->0x547b963 (+1), Ziel 0x5488f80->0x5469690 bis ret gleich'),
    # cast_tag dispatch: 7264 dropped the movaps [rbp+0x210],xmm3 between add rdx,r8 and jmp rdx; the 16 guarded bytes
    # (mov edx,edx / lea r8 / movsxd / add) are unchanged in length, continuation is the jmp rdx itself.
    'code:0x54a3cd8': (0x5484B53, 'Fortsetzung = jmp rdx 0x5484b53 (0931: movaps vor jmp rdx entfallen), 16 Bytes Wächter gleich lang'),
    # VORSCHLAG ENEMY_AOE fall-through after jb 0x54a4777 -> 0x54855e3 (6 bytes): 0x54855e9. 0931 continued with
    # mov rcx,rbx; 7264 keeps the record in rcx and the radius in xmm8 (0931 xmm7) -> code variant needed.
    'code:0x54a477d': (0x54855E9, 'VORSCHLAG: Durchfall nach jb 0x54855e3; Register geändert (rbx->rcx, xmm7->xmm8)'),
    # VORSCHLAG jump destination after the effect/world patch: 0931 mov rsi,[rbp+0x270] -> 7264 mov r15,[rbp+0x290]
    # (same frame slot +0x20, Game pointer now in r15 instead of rsi) -> code variant needed.
    'code:0x54a0bd5': (0x54819D5, 'VORSCHLAG: gleiche Stelle (Game-Zeiger aus [rbp+0x290] jetzt in r15 statt rsi)'),
    # UI-command switch: 7264 inserts a new alternative at tag 10 (default index 10 -> 11, jump table 11 -> 12 entries).
    # 0931 tag 10 block 0x53f370e is instruction-identical to 7264 tag 11 block 0x54307b5 (80 instructions incl. frame
    # slots 0x1bd0..0x1c28); the aligner swapped it with the tag-12 block 0x5430c59 (= 0931 tag 11).
    'code:0x53f3759': (0x5430800, 'Enter-Aufruf im Tag-11-Block 0x54307b5 (+0x4b): call 0x54148c0 (map_select)'),
    'code:0x53f375e': (0x5430805, 'Rücksprung nach Enter-Aufruf 0x5430800 (mov rdx,[rsi+0xb60])'),
    # Native Enter command tag read by party_menu/verify_native_input (0931 and older: 10).
    'menu:enter_tag': (11, 'Enter-Block 0x54307b5 ist Sprungtabellen-Index 9 = Tag 11 (Standardindex 11, Tag 10 neu)'),
    'code:0x53f349f': (0x5430EC6, 'Tag 9 laut Sprungtabelle 0x5430ec6 (leerer Fall, Epilog)'),
    'menu:command_tags': ({'8': 0x5430BBC, '9': 0x5430EC6, '11': 0x54307B5},
                          'Sprungtabelle 7264: Tag 8/9 unverändert, neuer Fall bei Tag 10 (0x5430eaf), 0931-Tag 10 -> Tag 11'),
    # Game layout: 0x918/0x928/0x930 unchanged, everything 0x941..0x95e moved +1 (5/2/1/2/2/11/.../25 votes).
    'field:game:0x920': (0x920, 'Nachbarn 0x918/0x928/0x930 unverändert; Einschub erst hinter 0x930 (0x941->0x942)'),
    # Game ends with the byte 0x94e -> 0x94f; Server-relative twins 0x957/0x95e (= Game+0x947/0x94e, Game at Server+0x10)
    # also move +1, while Server+0x960 (= Game+0x950) .. 0x9a8 stay unchanged -> aligned extent stays 0x950.
    'field:game_extent:0x950': (0x950, 'letztes Game-Byte 0x94e->0x94f; Server+0x957/0x95e +1, Server+0x960..0x9a8 (= Game+0x950..) unverändert'),
    # Map table 0x66d6be0 -> 0x66f07d0 (33 RIP votes): +0x8/+0x10 with stride 0xb8 give the same nine names.
    'field:map:0x8': (0x8, 'Kartentabelle 0x66f07d0: +0x8/+0x10 mit Stride 0xb8 liefern dieselben 9 Namen'),
    # Enemy-function target slot: 7264 frame start 0x5481564 movaps [rbp],xmm0 from Game+0x3e8; pursuit 0x548230c
    # subps xmm9,[rbp] (0931 [rbp-0x20]).
    'frame:0x54a06f0:-0x20': (0x0, 'Rahmenstart 0x5481564 movaps [rbp],xmm0 aus Game+0x3e8; Verfolgung 0x548230c subps xmm9,[rbp]'),
}
