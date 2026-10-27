import unittest
from audit30 import build


class Audit30Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit=build()

    def test_all_requested_domains_have_explicit_limits_not_full_family_claims(self):
        rows=self.audit['matrix']
        self.assertEqual(23,len(rows))
        self.assertEqual({'P0','P1','P2'},{r['priority'] for r in rows})
        for row in rows:
            self.assertTrue(row['unknownOrUnsupported'])
            self.assertNotEqual('VERIFIED_WITHIN_SCOPE',row['status'])
            for rule in row['rules']:
                self.assertTrue(rule['implementedLiteralFound'],rule['ruleId'])

    def test_intent_and_historical_evidence_are_not_relabelled(self):
        self.assertGreaterEqual(len(self.audit['frozenEvidence']),60)
        self.assertEqual(0,self.audit['newIndependentHoldout'])
        self.assertEqual(0,self.audit['newRealVulnerabilityTP'])
        self.assertTrue(self.audit['originalMetricsNotPooled'])
        row=next(r for r in self.audit['matrix'] if r['area']=='intent-boundary')
        self.assertEqual('REQUIRES_EXTERNAL_CONTEXT',row['status'])
