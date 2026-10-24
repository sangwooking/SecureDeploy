import unittest
from authorization_matrix import CASES, VALIDATION, PROBES, packet


class AuthorizationMatrixTest(unittest.TestCase):
    def test_truth_has_both_allow_and_deny_and_distinguishes_zero_rows(self):
        self.assertEqual(len({c['id'] for c in CASES+VALIDATION}),15)
        for c in CASES+VALIDATION:
            self.assertEqual(len(c['expect']),len(PROBES))
            self.assertIn(c['truth'],{'REVIEW','NORMAL'})
        owner=next(c for c in CASES if c['id']=='owner-all')
        self.assertEqual(owner['expect'][3],0)
        self.assertEqual(owner['expect'][6],'42501')

    def test_target_operation_matches_the_policy_target(self):
        inserted=packet(next(c for c in CASES if c['id']=='insert-unrestricted'))
        read=packet(next(c for c in CASES if c['id']=='public-read'))
        self.assertIn(".insert({user_id:user.id})",inserted['files'][0]['content'])
        self.assertIn(".select().eq",read['files'][0]['content'])

    def test_omission_is_not_an_explicit_unrestricted_check(self):
        fallback=next(c for c in CASES if c['id']=='update-fallback')
        opened=next(c for c in CASES if c['id']=='update-new-open')
        self.assertNotIn('WITH CHECK(true)',fallback['sql'])
        self.assertIn('WITH CHECK(true)',opened['sql'])
        self.assertEqual(fallback['expect'][4],'42501')
        self.assertEqual(opened['expect'][4],1)
