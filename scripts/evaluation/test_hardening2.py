"""Freeze observed improvements without converting unsupported code into safety."""
import unittest
from pathlib import Path
from benchmark import read

class Hardening2ResultsTest(unittest.TestCase):
    def setUp(self):
        self.data=read(Path(__file__).with_name('hardening2-results.json'))
        self.projects={p['projectId']:p for p in self.data['projects']}
    def test_exact_false_observations_removed_without_new_signal_locations(self):
        removed=self.data['removedWarningObservations']
        self.assertEqual(len(removed),7)
        self.assertEqual(sum(f['ruleId']=='INSECURE_API_URL'for f in removed),6)
        self.assertEqual(sum(f['ruleId']=='HARDCODED_FRONTEND_SECRET'for f in removed),1)
        self.assertEqual(self.data['newWarningObservations'],[])
        netbox=self.projects['netbox-community--netbox']['stages']
        self.assertEqual((netbox['baseline']['securityScore'],netbox['baseline']['deploymentAssessment']),(86,'BLOCKED'))
        self.assertEqual((netbox['afterB']['securityScore'],netbox['afterB']['deploymentAssessment']),(100,'REVIEW_REQUIRED'))
    def test_same_java_input_and_memory_limits_with_actual_parse_coverage(self):
        memory=self.data['memory']
        self.assertEqual(memory['before']['heapLimitMiB'],192)
        self.assertEqual(memory['after']['heapLimitMiB'],192)
        self.assertEqual(memory['after']['metaspaceLimitMiB'],96)
        for before,after in zip(memory['before']['results'],memory['after']['results']):
            self.assertEqual(before['inputSha256'],after['inputSha256'])
            self.assertIn('Java heap space',before['oomCategories'])
            self.assertEqual(after['exitCode'],0)
            self.assertLess(after['workerMaximumRssBytes'],before['workerMaximumRssBytes'])
            stages=self.projects[after['projectId']]['stages']
            self.assertEqual(stages['baseline']['java']['status'],'UNAVAILABLE')
            self.assertEqual(stages['afterB']['java']['files'],{'PARSED':after['inputFiles']})
            self.assertEqual(stages['afterB']['java']['status'],'PARTIAL')
            self.assertEqual(stages['afterB']['java']['tracedSqlCalls'],0)
    def test_risk_policy_and_old_failure_data_are_not_rewritten(self):
        self.assertFalse(self.data['riskPolicyChanged']);self.assertFalse(self.data['scoreFormulaChanged'])
        self.assertFalse(self.data['oldReviewsRecomputed']);self.assertFalse(self.data['userDatabaseUsed'])
        for project in self.data['projects']:
            if 'stages'not in project:continue
            self.assertTrue(project['comparisonFingerprintChanged'])
            self.assertEqual(len({v['riskPolicyVersion']for v in project['stages'].values()}),1)
            self.assertEqual(project['stages']['afterA']['prioritySummary'],project['stages']['afterB']['prioritySummary'])
        self.assertEqual(self.projects['sahat--hackathon-starter']['status'],'COLLECTION_FAILED_NOT_ANALYZED')
        self.assertEqual(self.data['cveRegression']['afterCounts'],{'NOT_SUPPORTED':38,'RESOURCE_LIMIT':2})
        self.assertTrue(self.data['cveRegression']['allRepeatsConsistent'])
    def test_five_followups_link_original_packs_and_committed_engines(self):
        original=read(Path(__file__).with_name('application-review.json'))
        ids={case['caseId']for case in original['pathReviews']}
        self.assertEqual(len(self.data['failureCaseHistory']),5)
        for pack in self.data['failureCaseHistory']:
            self.assertIn(pack['originalPackCaseId'],ids)
            self.assertEqual(pack['sourcePlanSha256'],self.data['sourcePlanSha256'])
            self.assertEqual(pack['engineCommits'],self.data['engineCommits'])
            self.assertTrue(pack['remainingLimitations'])
            self.assertEqual(len(pack['commitSha']),40)

if __name__=='__main__':unittest.main()
