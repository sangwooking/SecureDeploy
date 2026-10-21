import json
from pathlib import Path
import tempfile
import unittest

from benchmark import digest
from next_flows import report


class NextReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.plan={'projects':[dict(projectId='synthetic',grade='B',evaluationSplit='VALIDATION',groundTruth='TN',
            targetRule='TS_SSRF_INPUT_FLOW',targetFile='app/api/route.ts',repositoryUrl='https://github.com/example/synthetic',commitSha='a'*40,license='MIT')]}
        self.run=dict(typescript=dict(findings=[],authorizationContexts=[],files=[],httpUses=[],exposureUses=[]),
            reviewCandidates=[],filtered=[],securityScore=100,risk=dict(prioritySummary={}),elapsedMs=1,parentHeapUsedBytes=1)

    def write_inputs(self):
        self.path=self.root/'application-plan.json';self.path.write_text(json.dumps(self.plan))
        self.raw=dict(planSha256=digest(self.path.read_bytes()),engineCommit='b'*40,
            projects=[dict(projectId='synthetic',runs=[self.run,self.run])])
        self.rawpath=self.root/'raw.json';self.rawpath.write_text(json.dumps(self.raw));self.output=self.root/'result.json'

    def test_controlled_tn_is_not_a_whole_app_or_independent_truth(self):
        self.write_inputs();report(self.root,self.rawpath,self.output)
        result=json.loads(self.output.read_text())
        self.assertEqual(result['counts']['VALIDATION']['TN'],1)
        self.assertIn('not independent',result['independence'])
        self.assertIsNone(result['baselineStructure'])

    def test_stale_baseline_cannot_be_reported_as_same_source(self):
        self.write_inputs();(self.root/'baseline-structure.json').write_text(json.dumps(dict(planSha256='c'*64)))
        with self.assertRaisesRegex(ValueError,'BASELINE_PLAN_CHANGED'):report(self.root,self.rawpath,self.output)

    def test_missed_target_cannot_be_counted_as_success(self):
        self.plan['projects'][0]['groundTruth']='TP';self.write_inputs()
        with self.assertRaisesRegex(ValueError,'TARGET_EXPECTATION'):report(self.root,self.rawpath,self.output)

    def test_missing_repeat_cannot_be_claimed_as_reproducible(self):
        self.write_inputs();self.raw['projects'][0]['runs'].pop();self.rawpath.write_text(json.dumps(self.raw))
        with self.assertRaisesRegex(ValueError,'NONDETERMINISTIC_OR_INCOMPLETE'):report(self.root,self.rawpath,self.output)
