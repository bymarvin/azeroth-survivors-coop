"""Read-only native gear observation rejects changed scalar record layouts."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis'))
from menu_contracts import discover_gear_observation
from native_helper_contracts import HelperProof
from build_hooks import UPDATED_HASH


class GearObservationTests(unittest.TestCase):
    def setUp(self):
        self.reference = ROOT / '.coop-builds' / UPDATED_HASH / 'AzerothSurvivors.exe'
        self.binary = ROOT / 'AzerothSurvivors.exe'
        self.menu = json.loads((ROOT / 'analysis/menu-contract-candidate.json').read_text())
        if self.menu['sha256'] != hashlib.sha256(self.binary.read_bytes()).hexdigest():
            self.skipTest('Current native menu discovery must be regenerated first')

    def test_native_owned_result_is_observation_only(self):
        result = discover_gear_observation(self.reference, self.binary, self.menu)
        self.assertTrue(result['layout_verified'])
        self.assertFalse(result['native_call_allowed'])
        self.assertEqual(result['login']['expected'], '90')
        self.assertEqual(result['schema']['size'], 232)
        self.assertEqual(result['schema']['items'], 0x98)
        self.assertEqual(result['schema']['appearance_stride'], 8)
        self.assertIn('equipment_stat_consumer', result)

    def test_changed_native_record_stride_is_rejected(self):
        original = HelperProof.code
        def changed(helper, side, address):
            code = original(helper, side, address)
            if side == 1:
                code = code.replace(bytes.fromhex('48694a58e8000000'), bytes.fromhex('48694a58e0000000'))
            return code
        with patch.object(HelperProof, 'code', changed), self.assertRaises(ValueError):
            discover_gear_observation(self.reference, self.binary, self.menu)

    def test_changed_equipment_stat_span_is_rejected(self):
        original = HelperProof.code
        def changed(helper, side, address):
            code = original(helper, side, address)
            if side == 1:
                code = code.replace(bytes.fromhex('488d424c'), bytes.fromhex('488d4248'))
            return code
        with patch.object(HelperProof, 'code', changed), self.assertRaises(ValueError):
            discover_gear_observation(self.reference, self.binary, self.menu)


if __name__ == '__main__':
    unittest.main()
