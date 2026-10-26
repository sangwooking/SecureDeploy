import unittest
from authorization_truth11 import freeze, packet, probes, POLICIES, PROBE_NAMES, A, B, metrics
from paired_worker_profile11 import percentile


class AuthorizationTruthTest(unittest.TestCase):
    def test_frozen_cases_have_explicit_requirements_unique_ids_and_no_fake_commits(self):
        p=freeze();self.assertEqual(36,len(p['cases']));self.assertEqual(36,len({c['caseId'] for c in p['cases']}))
        self.assertTrue(all(c['requirement'] and len(c['sourceSha256'])==64 for c in p['cases']))
        self.assertEqual({'RISK','NORMAL','UNKNOWN'},{c['truth'] for c in p['cases']})

    def test_role_expectations_and_subject_queries_are_complete(self):
        for p in POLICIES:self.assertEqual(len(PROBE_NAMES),len(p['expect']))
        self.assertEqual(14,len(probes(A)));self.assertEqual(14,len(probes(B)))
        self.assertNotEqual(probes(A)[3],probes(B)[3])
        self.assertTrue(any('role=' in q for q in probes(A)))

    def test_metrics_reject_unverified_database_or_changed_source(self):
        with self.assertRaises(ValueError):metrics(freeze(),{'rows':[]},{'matched':0,'total':1})

    def test_privacy_and_shared_intent_do_not_depend_on_field_names(self):
        p=freeze();private=next(c for c in p['cases'] if c['caseId']=='route-private-read');shared=next(c for c in p['cases'] if c['caseId']=='route-intentional-share')
        self.assertEqual('RISK',private['truth']);self.assertEqual('NORMAL',shared['truth'])
        self.assertIn('explicitly shared',shared['requirement'])

    def test_unsupported_risks_are_not_removed_from_all_target_false_negatives(self):
        p=freeze();rows=[];checks={}
        for c in p['cases']:
            rows.append(dict(caseId=c['caseId'],sourceSha256=c['sourceSha256'],findings=[],access=None))
            if c['truth']!='UNKNOWN':
                checks[(c['policy'],c['oracleProbe'])]=c['truth']
        oracle=dict(matched=1,total=1,policyHashes={c['id']:c['sqlSha256'] for c in p['policies']},rows=[dict(policy=policy,probe=probe,role='authenticated',subject=subject,actual=1) for policy,probe in checks for subject in ['A','B']])
        r=metrics(p,dict(rows=rows),oracle)
        self.assertEqual(18,r['counts']['FN']);self.assertEqual(8,r['counts']['UNKNOWN']);self.assertEqual(0,r['knownRiskDetection'])
        self.assertIsNone(r['reviewCandidatePrecision'])

    def test_profile_percentiles_use_nearest_rank_not_best_sample(self):
        self.assertEqual(10,percentile(list(range(1,21)),.5));self.assertEqual(19,percentile(list(range(1,21)),.95))
