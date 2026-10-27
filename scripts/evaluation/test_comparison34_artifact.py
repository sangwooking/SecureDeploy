import json
from pathlib import Path
import re
import unittest
from application_track import CREDENTIAL
from comparison34 import ENGINES

ROOT=Path(__file__).resolve().parents[2]
class Comparison34ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.content=(ROOT/'docs/evaluation/analysis-comparison-v40-v41-v42.json').read_bytes()
        cls.result=json.loads(cls.content)
    def test_published_metadata_does_not_claim_truth_or_include_local_sources(self):
        r=self.result;self.assertEqual(r['newVerifiedRealVulnerabilityTP'],0)
        self.assertEqual(r['independentHoldout'],0)
        self.assertFalse(r['workerChanges']);self.assertFalse(r['productApiDbUiRiskChanges'])
        self.assertIsNone(CREDENTIAL.search(self.content))
        self.assertNotIn(b'/Users/',self.content);self.assertNotIn(b'/private/tmp/',self.content)
        self.assertEqual({v:tuple(p)for v,p in r['engines'].items()},ENGINES)
    def test_counts_preserve_limits_and_missing_metrics_are_not_fabricated(self):
        for p in self.result['projects']:
            for row in p['versions'].values():
                self.assertLessEqual(row['parsedFiles'],100)
                self.assertEqual(row['sourceCandidates']-row['workerSelectedFiles'],row['notSubmittedSources'])
                self.assertEqual(row['budgetUsage']['STEPS_LIMIT'],100000)
                self.assertLessEqual(row['budgetUsage']['STEPS_USED'],100000)
                self.assertEqual(len(row['elapsedMs']),2)
                for key in ['connectedModules','functionArgumentTransfers','functionReturnConnections','wholeProjectTP','wholeProjectFP','wholeProjectFN','wholeProjectTN','workerPeakRssBytes']:
                    self.assertIsNone(row[key])
    def test_flow_locations_link_to_pinned_retained_hashes_and_no_code_contents(self):
        projects={p['projectId']:p for p in self.result['projects']}
        for case in self.result['codeFlowReviews']['cases']:
            p=projects[case['projectId']];index={f['path']:f for f in p['retainedFileManifest']}
            for site in case['sites']:
                self.assertEqual(site['sha256'],index[site['filePath']]['sha256'])
                self.assertIn('/blob/'+p['commitSha']+'/',site['sourceUrl'])
                self.assertTrue(re.fullmatch('[a-f0-9]{64}',site['sha256']))
        for p in projects.values():
            self.assertEqual(len(p['retainedFileManifest']),p['retainedFiles'])
            self.assertTrue(all(set(f)=={'path','sha256','bytes'} for f in p['retainedFileManifest']))
    def test_regression_and_new_unlabelled_projects_are_separate(self):
        self.assertEqual(len(self.result['existingRealAppRegression']['entries']),15)
        self.assertEqual(len(self.result['projects']),3)
        self.assertEqual(set(self.result['developmentGradeB']),set(ENGINES))
        self.assertTrue(all(p['groundTruth']=='GRADE_C_UNVERIFIED_NOT_SAFE_OR_VULNERABLE'for p in self.result['projects']))

if __name__=='__main__':unittest.main()
