"""Offline integrity checks for committed public metadata, not execution of upstream code."""
import json
from pathlib import Path
import unittest
import benchmark as b

ROOT=Path(__file__).parent


class PublicPilotMetadataTest(unittest.TestCase):
    def test_catalog_has_pinned_truth_pairs_and_no_original_source(self):
        catalog=b.read(ROOT/'pilot-catalog.json')
        self.assertEqual(b.validate(catalog),{'cases':38,'labels':{'DANGEROUS':19,'SAFE':19},'splits':{'REGRESSION':24,'VALIDATION':10,'HOLDOUT':4},'pairs':7})
        for c in catalog['cases']:
            for f in c['files']:
                self.assertEqual(set(f),{'path','url','sha256'})
                self.assertNotIn('/Users/',f['path'])

    def test_baseline_identifies_exact_frozen_manifest(self):
        baseline=b.read(ROOT/'pilot-baseline.json')
        self.assertEqual(baseline['manifestSha256'],b.digest((ROOT/'pilot-catalog.json').read_bytes()))
        self.assertEqual(len(baseline['results']),38)
        self.assertTrue(baseline['allRepeatsConsistent'])
        self.assertEqual(baseline['summary']['finalUser']['counts'],{'TP':12,'FP':6,'TN':2,'UNKNOWN':3,'NOT_INSPECTED':1,'RESOURCE_LIMIT':4,'NOT_SUPPORTED':10})
        self.assertEqual(baseline['targetRiskCaseCounts']['BLOCKING'],0)

    def test_reviewed_causes_and_failure_index_share_dataset_version(self):
        review=b.read(ROOT/'pilot-cause-review.json');baseline=b.read(ROOT/'pilot-baseline.json');index=b.read(ROOT/'pilot-failure-index.json')
        self.assertEqual(len(review['cases']),26);self.assertEqual(len(index['packs']),33)
        self.assertEqual(review['manifestSha256'],baseline['manifestSha256'])
        self.assertEqual(review['runnerVersion'],baseline['runnerVersion'])
        self.assertTrue(set(review['cases']).issubset({r['caseId']for r in baseline['results']}))
        self.assertTrue(all(p['group']in b.CAUSES for p in index['packs']))


if __name__=='__main__':unittest.main()
