import hashlib
import unittest
from rls_authorization23 import cases, packet


class RlsAuthorization23Test(unittest.TestCase):
    def test_fixed_population_and_source_integrity(self):
        rows = cases()
        self.assertEqual(len(rows), 14)
        self.assertEqual(len({r['id'] for r in rows}), 14)
        self.assertEqual(sum(r['expectedCandidate'] for r in rows), 8)
        for row in rows:
            self.assertEqual(row['sqlSha256'], hashlib.sha256(row['sql'].encode()).hexdigest())
            self.assertEqual(len(row['expectedAuthenticated']), 7)
            self.assertEqual(packet(row)['files'], [])

    def test_column_fix_retains_own_edit_but_blocks_other_and_protected_fields(self):
        row = next(r for r in cases() if r['id'] == 'column-owner-fixed')
        self.assertEqual(row['expectedAuthenticated'], [0, '42501', 1, 0, '42501', '42501', '42501'])
        self.assertFalse(row['expectedCandidate'])

    def test_public_and_restrictive_contracts_are_not_inferred_from_field_names(self):
        rows = {r['id']: r for r in cases()}
        self.assertTrue(rows['public-column']['expectedCandidate'])
        self.assertFalse(rows['restrictive-alone']['expectedCandidate'])
        self.assertEqual(rows['restrictive-alone']['expectedAuthenticated'][3], 0)


if __name__ == '__main__':
    unittest.main()
