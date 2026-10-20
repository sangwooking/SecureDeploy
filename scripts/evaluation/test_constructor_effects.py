import json
from pathlib import Path
import tempfile
import unittest
from application_track import digest
from constructor_effects import classify,control_packet

class ConstructorEvaluationTest(unittest.TestCase):
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
