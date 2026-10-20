import json
from pathlib import Path
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

    def test_public_evidence_preserves_unknowns_and_policy_boundaries(self):
        report=json.loads(Path(__file__).with_name('hardening4-results.json').read_text())
        self.assertFalse(report['riskPolicyChanged'])
        self.assertFalse(report['scoreFormulaChanged'])
        self.assertFalse(report['userDatabaseUsed'])
        projects=[item for item in report['projects'] if 'before' in item]
        self.assertEqual(len(projects),7)
        for project in projects:
            for field in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
                self.assertEqual(project['before'][field],project['after'][field])
            self.assertTrue(project['comparisonFingerprintChanged'])
        node=next(item for item in projects if item['projectId']=='OWASP--NodeGoat')
        self.assertEqual(node['after']['typescript']['validatedFindings'],{'JS_EVAL_INPUT_FLOW':3})
        uses=node['after']['typescript']['nodeUses']
        self.assertEqual(uses['JS_MONGO_WHERE_INPUT_FLOW:RECEIVER_NOT_VERIFIED'],1)
        self.assertEqual(uses['JS_MONGO_RESOURCE_ACCESS:DATA_QUERY_NOT_AUTHORIZATION_PROOF'],3)
        probes=report['workerProbe']['results']
        for project_id in {item['projectId'] for item in probes}:
            pair=[item for item in probes if item['projectId']==project_id]
            self.assertEqual(len({item['inputSha256'] for item in pair}),1)
        guide=[item for item in probes if item['projectId']=='expressjs--express-scope']
        self.assertTrue(all(item['entrypoints']==0 and not item['findings'] for item in guide))
        self.assertIn('not scored as TN',report['newPublicSource']['interpretation'])
        def check_metadata(value):
            if isinstance(value,dict):
                self.assertFalse(set(value)&{'content','snippet','sql','sourceCode','prompt','responseBody'})
                for child in value.values():check_metadata(child)
            elif isinstance(value,list):
                for child in value:check_metadata(child)
        check_metadata(report)

if __name__=='__main__':unittest.main()
