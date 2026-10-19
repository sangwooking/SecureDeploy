"""Offline assertions on real frozen results; original code stays outside Git."""
from pathlib import Path
import unittest
import benchmark as b

ROOT=Path(__file__).parent


class RealWorldMetadataTests(unittest.TestCase):
    def test_twenty_real_fix_pairs_and_project_split_isolation(self):
        catalog=b.read(ROOT/'realworld-catalog.json')
        self.assertEqual(b.validate(catalog),dict(cases=40,labels={'DANGEROUS':20,'SAFE':20},
            splits={'REGRESSION':16,'VALIDATION':14,'HOLDOUT':10},pairs=20))
        self.assertEqual(len({c['cve']for c in catalog['cases']}),20)
        self.assertEqual(len({c['repositoryUrl']for c in catalog['cases']}),20)
        self.assertEqual({c['language']for c in catalog['cases']},{'JAVA','PYTHON','JAVASCRIPT','TYPESCRIPT'})
        self.assertEqual(len({c['cwe']for c in catalog['cases']}),15)
        self.assertFalse(any('BenchmarkJava'in c['repositoryUrl']for c in catalog['cases']))
        for c in catalog['cases']:
            self.assertIn('only',c['unknownFacts'][1])
            self.assertNotIn('UNCLASSIFIED',c['license'])
            for f in c['files']:
                self.assertEqual(set(f),{'path','url','sha256'})
                self.assertNotIn('/Users/',f['path'])

    def test_partial_archive_provenance_is_not_full_database_verification(self):
        receipt=b.read(ROOT/'realworld-catalog.json')['collectionMetadata']
        self.assertEqual(receipt['rangeBytes'],2097152)
        self.assertEqual(receipt['githubFixRows'],12864)
        self.assertEqual(receipt['otherRowsNotSelected'],59)
        self.assertFalse(receipt['sqlExecuted'])
        self.assertEqual(receipt['integrity'],'PARTIAL_ARCHIVE_FULL_CHECKSUM_NOT_VERIFIED')

    def test_baseline_preserves_unsupported_and_resource_limits_not_safe(self):
        baseline=b.read(ROOT/'realworld-baseline.json')
        self.assertEqual(baseline['manifestSha256'],b.digest((ROOT/'realworld-catalog.json').read_bytes()))
        self.assertTrue(baseline['allRepeatsConsistent'])
        self.assertEqual(baseline['summary']['finalUser']['counts'],{'NOT_SUPPORTED':38,'RESOURCE_LIMIT':2})
        self.assertIsNone(baseline['summary']['finalUser']['precision'])
        self.assertIsNone(baseline['summary']['finalUser']['recallWithinScoredScope'])
        self.assertEqual(baseline['summary']['finalUser']['scoredCoverage'],0)

    def test_reviewed_scope_packs_are_not_fabricated_false_negatives(self):
        baseline=b.read(ROOT/'realworld-baseline.json');review=b.read(ROOT/'realworld-cause-review.json')
        index=b.read(ROOT/'realworld-failure-index.json')
        self.assertEqual(review['manifestSha256'],baseline['manifestSha256'])
        self.assertEqual(review['runnerVersion'],baseline['runnerVersion'])
        self.assertEqual(len(review['cases']),40)
        self.assertEqual(len(index['packs']),40)
        self.assertTrue(all(p['confirmed']for p in index['packs']))
        self.assertTrue(all(p['verdict']not in {'FP','FN'}for p in index['packs']))

    def test_secondary_false_alerts_do_not_change_cve_target_metrics(self):
        review=b.read(ROOT/'realworld-secondary-review.json');baseline=b.read(ROOT/'realworld-baseline.json')
        self.assertEqual(review['manifestSha256'],baseline['manifestSha256'])
        self.assertEqual(review['counts'],{'CONFIRMED_FALSE_POSITIVE':12,'REQUIRES_CONTEXT':2})
        self.assertEqual(len(review['observations']),14)
        for r in review['observations']:
            self.assertEqual(r['scope'],'SECONDARY_ALERT_NOT_CVE_TARGET')
            self.assertIn('Excluded from CVE-target',r['countingPolicy'])
            self.assertEqual(r['ruleId'],'INSECURE_API_URL')
            self.assertNotIn('sourceCode',r)


if __name__=='__main__':unittest.main()
