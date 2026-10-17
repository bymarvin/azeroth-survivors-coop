"""Read-only PE string-reference inspection; all addresses are preferred image VAs."""
import argparse
import bisect
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tools/python'))
import capstone
import pefile


def rip_target(code, offset, address):
    return address + offset + 7 + struct.unpack_from('<i', code, offset + 3)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'coop-lab/AzerothSurvivors.exe')
    parser.add_argument('--string', default='spawn the rogue server thread')
    parser.add_argument('--function', type=lambda x: int(x, 0), nargs='+')
    parser.add_argument('--calls-to', type=lambda x: int(x, 0))
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        assert rip_target(bytes.fromhex('488d05f9ffffff'), 0, 0x1000) == 0x1000
        assert rip_target(bytes.fromhex('488d0501000000'), 0, 0x1000) == 0x1008
        print('RIP-relative address checks passed')
        return
    binary = args.binary
    data = binary.read_bytes()
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXCEPTION']])
    base = pe.OPTIONAL_HEADER.ImageBase
    functions = sorted((base + e.struct.BeginAddress, base + e.struct.EndAddress)
                       for e in pe.DIRECTORY_ENTRY_EXCEPTION)
    starts = [a for a, _ in functions]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    targets = set()
    if args.function is not None:
        targets.update(args.function)
    elif args.calls_to is not None:
        for section in pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            code = section.get_data()
            address = base + section.VirtualAddress
            for match in re.finditer(b'\xe8', code):
                offset = match.start()
                if offset + 5 <= len(code):
                    target = address + offset + 5 + struct.unpack_from('<i', code, offset + 1)[0]
                    if target == args.calls_to:
                        targets.add(address + offset)
    else:
        needle = args.string.encode()
        string_vas = {base + pe.get_rva_from_offset(m.start())
                      for m in re.finditer(re.escape(needle), data)}
        print('String addresses:', ', '.join(hex(a) for a in sorted(string_vas)))
        for section in pe.sections:
            if not section.Characteristics & 0x20000000:
                continue
            code = section.get_data()
            address = base + section.VirtualAddress
            for match in re.finditer(rb'[\x48-\x4f][\x8d\x8b][\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', code):
                offset = match.start()
                if offset + 7 <= len(code) and rip_target(code, offset, address) in string_vas:
                    targets.add(address + offset)
    dumped = set()
    for target in sorted(targets):
        i = bisect.bisect_right(starts, target) - 1
        if i < 0 or target >= functions[i][1]:
            print('No unwind function for', hex(target))
            continue
        start, end = functions[i]
        if start in dumped:
            continue
        dumped.add(start)
        print(f'Function {start:#x}..{end:#x}; reference {target:#x}')
        for ins in md.disasm(pe.get_data(start - base, end - start), start):
            print(f'{ins.address:#x}: {ins.mnemonic:8} {ins.op_str}')


if __name__ == '__main__':
    main()
