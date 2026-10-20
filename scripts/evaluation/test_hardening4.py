import unittest
from hardening4 import summary

class NodeEvidenceAccountingTest(unittest.TestCase):
    def test_deferred_receivers_are_not_verified_candidates(self):
        row=dict(filtered=[],securityScore=100,reviewCandidates=[],coverage={'status':'PARTIAL'},
                 risk=dict(prioritizedDeploymentAssessment='REVIEW_REQUIRED',prioritySummary={},policyVersion='unchanged'),
                 java=dict(findings=[],analysis=dict(version='java-sql-v3',status='PARTIAL',files=[],uses=[],limitations=[])),
                 typescript=dict(analyzerVersion='ts-server-v7',status='PARTIAL',files=[],findings=[],validatedFindings=[],
                                 nodeUses=[dict(ruleId='JS_MONGO_WHERE_INPUT_FLOW',kind='RECEIVER_NOT_VERIFIED')]))
        result=summary(row)
        self.assertEqual(result['typescript']['validatedFindings'],{})
        self.assertEqual(result['typescript']['nodeUses']['JS_MONGO_WHERE_INPUT_FLOW:RECEIVER_NOT_VERIFIED'],1)
        del row['typescript']['nodeUses']
        self.assertEqual(summary(row)['typescript']['nodeUses'],{})

if __name__=='__main__':unittest.main()
