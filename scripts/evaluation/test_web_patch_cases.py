import json
from pathlib import Path
import tempfile
import unittest
from web_patch_cases import SPECS, verify_patch
from web_patch_report import preserve_pack


class WebPatchEvaluationTest(unittest.TestCase):
    def test_evidence_keeps_grade_support_and_independence_separate(self):
        data=json.loads(Path(__file__).with_name('hardening7-results.json').read_text())
        self.assertEqual(data['survey']['screenedCandidates'],32)
        self.assertEqual(len({c['ghsa'] for c in data['survey']['candidates']}),32)
        self.assertEqual(data['gradeA']['pairs'],3)
        self.assertEqual(data['gradeA']['supportedEndToEndPairs'],0)
        self.assertEqual(sum(c.get('truthGrade')=='A' for c in data['survey']['candidates']),3)
        self.assertFalse(data['gradeA']['independentCuratorOrBlind'])
        self.assertFalse(data['engineChanged']);self.assertFalse(data['riskPolicyChanged'])
        self.assertTrue(data['repeatConsistent'])
        self.assertEqual(data['targetResults']['finalUser']['counts'],{'NOT_SUPPORTED':6})
        self.assertIsNone(data['targetResults']['finalUser']['precision'])
        self.assertIsNone(data['targetResults']['finalUser']['recallWithinScoredScope'])
        self.assertEqual(len(data['failureCasePacks']),3)
        self.assertTrue(all(p['patchFacts']['status']=='STATIC_PATCH_FACTS_MATCH' for p in data['failureCasePacks']))

    def test_non_target_alerts_cannot_be_counted_as_cve_detection(self):
        data=json.loads(Path(__file__).with_name('hardening7-results.json').read_text())
        for pair in data['pairs']:
            for row in pair['results']:
                self.assertEqual(row['layers']['finalUser']['matches'],0)
                self.assertEqual(row['recognizedEntries'],0)
                self.assertTrue(all(a['ruleId']=='PACKAGE_JSON_RISK' for a in row['nonTargetRuleAlerts']))
        self.assertEqual(sum(len(r['nonTargetRuleAlerts']) for p in data['pairs'] for r in p['results']),4)

    def test_no_original_source_or_advisory_body_in_public_metadata(self):
        data=json.loads(Path(__file__).with_name('hardening7-results.json').read_text())
        def inspect(value):
            if isinstance(value,dict):
                self.assertFalse(set(value)&{'content','snippet','sourceCode','prompt','description','responseBody','patch'})
                for child in value.values():inspect(child)
            elif isinstance(value,list):
                for child in value:inspect(child)
        inspect(data)
        self.assertNotIn('Authorization: Bearer',json.dumps(data))

    def test_patch_fact_gate_rejects_missing_or_reverted_defense(self):
        spec=SPECS[0];name=spec['targets'][0]
        original='tokens.reduce(); const uid=tokens[token];'
        fixed='tokens.find(t => t.token === token);new BearerStrategy({}, Auth.verifyToken);'
        self.assertEqual(verify_patch(spec,{('parent',name):original,('fixed',name):fixed})['checks'],4)
        with self.assertRaisesRegex(ValueError,'REVIEWED_PATCH_FACT_MISMATCH'):
            verify_patch(spec,{('parent',name):original,('fixed',name):original})

    def test_identical_failure_pack_replay_preserves_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'pack.json';pack={'caseId':'synthetic','grade':'A'}
            preserve_pack(path,pack);before=path.read_bytes();preserve_pack(path,pack)
            self.assertEqual(path.read_bytes(),before)
            with self.assertRaisesRegex(ValueError,'EXISTING_PACK_MUST_NOT_CHANGE'):
                preserve_pack(path,{'caseId':'changed'})
            link=Path(directory)/'link';link.symlink_to(path)
            with self.assertRaisesRegex(ValueError,'PACK_SYMLINK'):preserve_pack(link,pack)

    def test_reserved_candidates_are_not_claimed_as_validated_holdout(self):
        data=json.loads(Path(__file__).with_name('hardening7-results.json').read_text())
        reserved=[c for c in data['survey']['candidates'] if c.get('reservation')]
        self.assertTrue(reserved)
        self.assertTrue(all('NOT_VALIDATED_HOLDOUT' in c['reservation'] or 'no validated' in c['reservation'] for c in reserved))


if __name__=='__main__':unittest.main()
