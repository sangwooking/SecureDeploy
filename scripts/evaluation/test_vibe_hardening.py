import copy
import unittest
from vibe_hardening import compare, summarize


class HardeningReceiptTests(unittest.TestCase):
    def setUp(self):
        self.run = dict(filtered=[], reviewCandidates=[], typescript=dict(files=[], exposureUses=[]),
                        coverage=dict(status='PARTIAL'), securityScore=100,
                        risk=dict(prioritizedDeploymentAssessment='REVIEW_REQUIRED', prioritySummary={}),
                        sca=dict(status='EXTERNAL_LOOKUP_NOT_RUN'), elapsedMs=1, parentHeapUsedBytes=2)
        self.raw = dict(planSha256='same', engineCommit='old', projects=[
            dict(projectId='app', commitSha='pinned', runs=[self.run, copy.deepcopy(self.run)])])
        self.plan = dict(projects=[dict(projectId='app', commitSha='pinned', grade='C')])
        self.review = dict(planSha256='same', engineCommit='old', cases=[])

    def test_summary_is_metadata_only_and_partial_is_not_safe(self):
        self.run['secretPrompt'] = 'must not export'
        self.raw['projects'][0]['runs'][1]['secretPrompt'] = 'must not export'
        result = compare(self.plan, self.raw, self.raw, self.review)
        self.assertNotIn('must not export', str(result))
        self.assertEqual(result['projects'][0]['after']['coverage']['status'], 'PARTIAL')
        self.assertNotIn('TP', summarize(self.run))

    def test_mismatched_plan_or_nonrepeated_results_fail_closed(self):
        changed = copy.deepcopy(self.raw); changed['planSha256'] = 'other'
        with self.assertRaisesRegex(ValueError, 'PLAN_MISMATCH'):
            compare(self.plan, self.raw, changed, self.review)
        changed = copy.deepcopy(self.raw); changed['projects'][0]['runs'][1]['securityScore'] = 0
        with self.assertRaisesRegex(ValueError, 'REPEAT_MISMATCH'):
            compare(self.plan, self.raw, changed, self.review)

    def test_absence_alone_is_not_a_fixed_false_positive(self):
        self.review['cases'] = [dict(caseId='case', projectId='app', outcome='FP',
                                    targetRules=['RULE'], sites=[dict(filePath='a.ts', line=3)])]
        result = compare(self.plan, self.raw, self.raw, self.review)
        self.assertEqual(result['failurePacks'][0]['status'], 'UNRESOLVED')
