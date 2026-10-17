"""Refresh read-only relocation candidates, or capture the reviewed reference."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'reconstruction'))
from build_hooks import (UPDATED_HASH, SIGNATURES, discover_manifest,
                         instruction_signature, resolve_updated_hooks, runtime_fingerprint, pefile)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'AzerothSurvivors.exe')
    parser.add_argument('--capture-reviewed', action='store_true')
    args = parser.parse_args()
    path = ROOT / 'reconstruction/reviewed-hooks.json'
    if args.capture_reviewed:
        data = args.binary.read_bytes()
        if hashlib.sha256(data).hexdigest() != UPDATED_HASH:
            raise ValueError('Only the reviewed reference can generate signatures')
        pe = pefile.PE(data=data, fast_load=True)
        entries = resolve_updated_hooks(args.binary)
        tree = ast.parse((ROOT / 'reconstruction/native_probe.py').read_text())
        for block in tree.body:
            if not isinstance(block, ast.If) or ast.unparse(block.test) != "BUILD == 'updated'":
                continue
            for node in block.body:
                if not isinstance(node, ast.Assign):
                    continue
                try:
                    value = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    continue
                target = node.targets[0]
                pairs = zip((x.id for x in target.elts), value) if isinstance(target, ast.Tuple) else [(target.id, value)]
                entries.update((name, rva) for name, rva in pairs if isinstance(rva, int) and rva > 0x5000000)
        hooks = {}
        for name, rva in entries.items():
            pattern, mask = instruction_signature(pe.get_data(rva, 256), rva)
            hooks[name] = dict(reference_rva=rva, pattern=pattern.hex(), mask=mask.hex())
        manifest = dict(reference_sha256=UPDATED_HASH, runtime_fingerprint=runtime_fingerprint(data), hooks=hooks)
        report = discover_manifest(args.binary, manifest)
        assert all(report['hooks'][name]['candidates'] == [entry['reference_rva']]
                   for name, entry in hooks.items()), 'Reference signatures must uniquely resolve'
        path.write_text(json.dumps(manifest, indent=2) + '\n')
    manifest = json.loads(path.read_text())
    report = discover_manifest(args.binary, manifest)
    (ROOT / 'analysis/updated-hook-discovery.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f"{sum(row['unique'] for row in report['hooks'].values())}/{len(report['hooks'])} unique hook candidates; unknown builds remain disabled")


if __name__ == '__main__':
    main()
