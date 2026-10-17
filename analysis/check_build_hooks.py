"""Read-only hook comparison. Byte matches are candidates, never verified ports."""
import ast
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '.tools/python'))
sys.path.insert(0, str(ROOT / 'reconstruction'))
import pefile
from build_hooks import compatibility_report, write_report


def embedded_references(folder, image):
    """Inventory code/data literals too; named hooks alone are not the port."""
    rows = []
    for path in sorted(folder.glob('*.py')):
        if path.name.startswith(('test_', 'verify_')):
            continue
        source = path.read_text(encoding='utf-8')
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Constant) or type(node.value) is not int:
                continue
            # Game code/data reside above this boundary in both reviewed builds.
            # Small object/stack offsets are separately protected by the complete
            # mapped-runtime fingerprint; they cannot be assigned an RVA.
            if 0x5000000 <= node.value < image.OPTIONAL_HEADER.SizeOfImage:
                section = image.get_section_by_rva(node.value)
                rows.append(dict(file=path.name, line=node.lineno, rva=hex(node.value),
                                 section=section.Name.rstrip(b'\x00').decode('ascii', 'replace')
                                 if section else None))
    return rows


def candidate_offsets(data, signature):
    if not signature:
        raise ValueError('Empty hook signature')
    matches, start = [], 0
    while (offset := data.find(signature, start)) >= 0:
        matches.append(offset)
        start = offset + 1
    return matches


def cache_matches(report, identity):
    return (report.get('audit_identity') == identity
            and report.get('automatic_activation_allowed') is False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--if-changed', action='store_true',
                        help='Reuse the report only if binaries and scanner inputs are unchanged')
    args = parser.parse_args()
    old = (ROOT / 'coop-lab/AzerothSurvivors.exe').read_bytes()
    new = (ROOT / 'AzerothSurvivors.exe').read_bytes()
    source = (ROOT / 'reconstruction/native_probe.py').read_bytes()
    identity = dict(old_sha256=hashlib.sha256(old).hexdigest(),
                    new_sha256=hashlib.sha256(new).hexdigest(),
                    adapter_sha256=hashlib.sha256(source).hexdigest(),
                    scanner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    identity['adapter_inputs'] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted((ROOT / 'reconstruction').glob('*'))
        if path.is_file() and (path.suffix == '.py' or path.name == 'reviewed-hooks.json')}
    output = ROOT / 'analysis/update-compatibility.json'
    if args.if_changed:
        try:
            previous = json.loads(output.read_text())
        except (OSError, ValueError):
            previous = {}
        if isinstance(previous, dict) and cache_matches(previous, identity):
            return
    tree = ast.parse(source)
    expected = next(ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node, ast.Assign)
                    and isinstance(node.targets[0], ast.Name)
                    and node.targets[0].id == 'HASH')
    if identity['old_sha256'] != expected:
        raise RuntimeError('Reference EXE is not the supported build; refusing discovery')
    before = pefile.PE(data=old, fast_load=True)
    after = pefile.PE(data=new, fast_load=True)
    rows = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        try:
            value = ast.literal_eval(node.value)
        except (ValueError, TypeError):
            continue
        target = node.targets[0]
        pairs = (zip((x.id for x in target.elts), value)
                 if isinstance(target, ast.Tuple) else [(target.id, value)])
        for name, rva in pairs:
            if not isinstance(rva, int) or rva < 0x5000000:
                continue
            signature = before.get_data(rva, 32)
            matches = [hex(after.get_rva_from_offset(offset))
                       for offset in candidate_offsets(new, signature)]
            rows.append(dict(name=name, old_rva=hex(rva),
                             same_at_old_rva=after.get_data(rva, 32) == signature,
                             exact_32_byte_candidates=matches))
    assert rows, 'No hook constants found; audit cannot establish compatibility'
    report = dict(audit_identity=identity, automatic_activation_allowed=False,
                  status='known_build' if old == new else 'requires_compatibility_port',
                  old_sha256=hashlib.sha256(old).hexdigest(),
                  new_sha256=hashlib.sha256(new).hexdigest(),
                  old_image_size=before.OPTIONAL_HEADER.SizeOfImage,
                  new_image_size=after.OPTIONAL_HEADER.SizeOfImage, hooks=rows)
    manifest = json.loads((ROOT / 'reconstruction/reviewed-hooks.json').read_text())
    report['updated_runtime'] = compatibility_report(ROOT / 'AzerothSurvivors.exe', manifest)
    report['embedded_references'] = embedded_references(ROOT / 'reconstruction', after)
    report['status'] = report['updated_runtime']['status']
    write_report(output, report)
    print(f'{len(rows)} hooks audited; '
          f'{sum(row["same_at_old_rva"] for row in rows)} unchanged prefixes.')
    print('Matching prefixes are unverified candidates, not safe injection targets.')
    print(f"Updated runtime: {report['status']}; "
          f"{len(report['embedded_references'])} embedded code/data references inventoried.")


if __name__ == '__main__':
    main()
