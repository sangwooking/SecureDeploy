import json
from pathlib import Path
import tempfile
import unittest
from application_track import digest
from constructor_effects import classify,control_packet

class ConstructorEvaluationTest(unittest.TestCase):
    def test_final_isolation_evidence_does_not_relabel_consumed_holdout(self):
        report=json.loads(Path(__file__).with_name('hardening6-isolation-results.json').read_text())
        self.assertEqual(report['stage'],'FINAL_AFTER_ENTRY_ISOLATION')
        self.assertEqual(report['protocol'],'ts-server-v10')
        self.assertEqual(report['gradeB']['split'],'REGRESSION')
        self.assertTrue(report['gradeB']['previousHoldoutObserved'])
        self.assertFalse(report['gradeB']['independentOrBlind'])
        self.assertEqual(report['gradeA']['newSupportedPatchPairs'],0)
        self.assertFalse(report['gradeC']['scored'])
        self.assertFalse(report['limitsChanged']);self.assertFalse(report['riskChanged'])
        self.assertEqual(report['nodeUseKinds']['DATA_QUERY_NOT_AUTHORIZATION_PROOF'],8)
        self.assertEqual(report['nodeUseKinds']['INPUT_TO_EXECUTION'],4)
        self.assertEqual(sum(c['after'] in {'TP','TN'} for c in report['gradeB']['casesSummary']),5)
        for project in report['projects']:
            if 'after' not in project:continue
            self.assertTrue(project['repeatConsistent']);self.assertTrue(project['fingerprintChanged'])
            for key in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
                self.assertEqual(project['before'][key],project['after'][key])
        self.assertFalse(report['safety']['targetExecution'])
        self.assertEqual(report['safety']['paidAiCalls'],0)

    def test_public_summary_preserves_grade_boundaries_and_unknowns(self):
        report=json.loads(Path(__file__).with_name('hardening6-results.json').read_text())
        self.assertEqual(report['gradeA']['newSupportedPatchPairs'],0)
        self.assertFalse(report['gradeC']['scored']);self.assertFalse(report['riskChanged'])
        self.assertFalse(report['constructorContract']['resourceLimitsChanged'])
        self.assertEqual(report['failureCaseFollowup']['status'],'STATIC_INPUT_TO_WHERE_AND_CURSOR_CONSUMPTION_CONFIRMED')
        validation=report['gradeBValidation'];holdout=report['gradeBHoldout']
        self.assertEqual(validation['engineCommit'],holdout['engineCommit'])
        self.assertEqual(validation['workingTreeDiffSha256'],digest(b''))
        self.assertEqual(holdout['workingTreeDiffSha256'],digest(b''))
        self.assertEqual(len(validation['cases'])+len(holdout['cases']),17)
        for group in report['gradeBTopologyResults'].values():
            self.assertNotIn('FP',group['after']);self.assertNotIn('FN',group['after'])
        self.assertEqual(sum(g['after'].get('UNKNOWN',0)+g['after'].get('NOT_INSPECTED',0)for g in report['gradeBTopologyResults'].values()),12)
        for p in report['projects']:
            if 'after'not in p:continue
            for key in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
                self.assertEqual(p['before'][key],p['after'][key])
            self.assertTrue(p['fingerprintChanged'])
        def inspect(value):
            if isinstance(value,dict):
                self.assertFalse(set(value)&{'content','snippet','sourceCode','prompt','responseBody','sql'})
                for child in value.values():inspect(child)
            elif isinstance(value,list):
                for child in value:inspect(child)
        inspect(report)

    def test_cursor_creation_alone_is_not_a_true_negative(self):
        result={'findings':[],'nodeUses':[{'ruleId':'JS_MONGO_WHERE_INPUT_FLOW','kind':'CURSOR_CREATED_EXECUTION_NOT_OBSERVED','location':{'filePath':'repository.cjs'}}]}
        self.assertEqual(classify(result,'NORMAL'),'NOT_INSPECTED')
        result['nodeUses'][0]['kind']='RECEIVER_NOT_VERIFIED'
        self.assertEqual(classify(result,'RISK'),'UNKNOWN')

    def test_only_target_flow_is_scored_and_unknown_never_becomes_safe(self):
        result={'findings':[{'ruleId':'JS_MONGO_WHERE_INPUT_FLOW','confidence':'HIGH','sink':{'filePath':'repository.cjs'}}],'nodeUses':[]}
        self.assertEqual(classify(result,'RISK'),'TP');self.assertEqual(classify(result,'NORMAL'),'FP')
        result['findings'][0]['confidence']='MEDIUM';self.assertEqual(classify(result,'NORMAL'),'UNKNOWN')

    def test_control_source_is_frozen_and_never_loaded(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);folder=root/'example';folder.mkdir();path=folder/'entry.cjs'
            payload=b'throw new Error("must not execute");';path.write_bytes(payload)
            case={'caseId':'example','files':[{'path':'entry.cjs','sha256':digest(payload)}]}
            self.assertEqual(json.loads(control_packet(root,case))['files'][0]['content'],payload.decode())
            path.write_text('changed')
            with self.assertRaisesRegex(ValueError,'SOURCE_HASH'):control_packet(root,case)

if __name__=='__main__':unittest.main()
