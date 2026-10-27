import tempfile
import unittest
from pathlib import Path
from field_validation20 import prepare, truth, one


class FieldReceiptTest(unittest.TestCase):
    def test_truth_does_not_claim_runtime_or_independent_confirmation(self):
        t=truth()
        self.assertFalse(t['runtimeExploitVerified'])
        self.assertFalse(t['independentReviewer'])
        self.assertFalse(t['upstreamFixedPair'])
        self.assertEqual(t['source']['column'],56)
        self.assertEqual(t['validator']['installed'],'UNKNOWN')

    def test_existing_or_overlapping_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            with self.assertRaises(ValueError):prepare(root,root)
            with self.assertRaises(ValueError):prepare(root,root/'child')

    def test_repeat_receipt_requires_exact_stable_observations(self):
        import json
        with tempfile.TemporaryDirectory() as name:
            p=Path(name)/'receipt.json'
            p.write_text(json.dumps({'projects':[{'runs':[{'finding':0},{'finding':1}]}]}))
            with self.assertRaises(AssertionError):one(p)
