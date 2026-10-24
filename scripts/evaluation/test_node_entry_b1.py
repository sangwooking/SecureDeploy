import unittest
from node_entry_b1 import identities

class NodeEntryReceiptTests(unittest.TestCase):
    def test_structural_identity_preserves_sink_and_rule_not_version_dependent_finding_id(self):
        def row(rule='JS_EVAL_INPUT_FLOW',file='service.js',line=8,version='v21'):
            return {'typescript':{'validatedFindings':[{'findingId':version,'ruleId':rule,'location':{'filePath':file,'line':line,'column':3}}]}}
        self.assertEqual(identities(row()),identities(row(version='v22')))
        self.assertNotEqual(identities(row()),identities(row(file='different.js')))
        self.assertNotEqual(identities(row()),identities(row(line=9)))
        self.assertNotEqual(identities(row()),identities(row(rule='JS_SHELL_COMMAND_INPUT_FLOW')))
    def test_no_structural_finding_is_not_a_normal_truth_label(self):
        self.assertEqual(identities({'typescript':{'validatedFindings':[]}}),[])

if __name__=='__main__':unittest.main()
