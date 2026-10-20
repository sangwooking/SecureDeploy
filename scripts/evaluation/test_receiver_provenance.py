import json
from pathlib import Path
import tempfile
import unittest
from receiver_provenance import external_packets
from application_track import digest

class FrozenExternalPacketTest(unittest.TestCase):
    def fixture(self,root):
        path=root/'fixture--server'/'before';path.mkdir(parents=True)
        data=b'const value=1;'
        (path/'server.js').write_bytes(data)
        project={'repository':'fixture/server','stages':[{'stage':'before','commitSha':'a'*40,'files':[{'path':'server.js','sha256':digest(data)}]}]}
        (root/'receipt.json').write_text(json.dumps([project]))
        return project,path

    def test_preserves_exact_source_and_pinned_sha_without_running_it(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);self.fixture(root)
            ident,sha,data=external_packets(root)[0]
            self.assertEqual(ident,'fixture/server:before');self.assertEqual(sha,'a'*40)
            self.assertEqual(json.loads(data)['files'][0]['content'],'const value=1;')

    def test_changed_source_is_not_silently_reused(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);_,path=self.fixture(root);(path/'server.js').write_text('changed')
            with self.assertRaisesRegex(ValueError,'SOURCE_HASH'):external_packets(root)

    def test_symlinks_and_repository_escape_are_rejected(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);project,path=self.fixture(root)
            (path/'server.js').unlink();(path/'server.js').symlink_to(root/'receipt.json')
            with self.assertRaisesRegex(ValueError,'SOURCE_PATH'):external_packets(root)
            project['repository']='../../escape'
            (root/'receipt.json').write_text(json.dumps([project]))
            with self.assertRaisesRegex(ValueError,'REPOSITORY_IDENTITY'):external_packets(root)

    def test_public_results_do_not_promote_unknown_or_rejected_truth(self):
        report=json.loads(Path(__file__).with_name('hardening5-results.json').read_text())
        self.assertEqual(report['failureCaseFollowup']['status'],'UNKNOWN_CALL_DEPTH_BOUNDARY_REMAINS')
        self.assertFalse(report['policy']['riskChanged']);self.assertFalse(report['policy']['resourceLimitsChanged'])
        self.assertFalse(report['safety']['userDatabaseEvaluationWrites'])
        self.assertEqual(len([p for p in report['projects']if 'after'in p]),7)
        for p in report['projects']:
            if 'after'not in p:continue
            for key in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
                self.assertEqual(p['before'][key],p['after'][key])
            self.assertTrue(p['comparisonFingerprintChanged'])
        self.assertEqual(report['externalGroundTruth'][1]['truth'],'CANDIDATE_PAIR_EXCLUDED_FROM_GROUND_TRUTH')
        self.assertIn('NOT_SUPPORTED',report['externalGroundTruth'][0]['result'])
        for p in report['probe']:self.assertEqual(p['before']['inputSha256'],p['after']['inputSha256'])
        def inspect(value):
            if isinstance(value,dict):
                self.assertFalse(set(value)&{'content','snippet','sourceCode','prompt','responseBody','sql'})
                for child in value.values():inspect(child)
            elif isinstance(value,list):
                for child in value:inspect(child)
        inspect(report)

if __name__=='__main__':unittest.main()
