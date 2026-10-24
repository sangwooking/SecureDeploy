import unittest
from validation5 import target_status,controlled_outcome,target_findings

class Validation5Contracts(unittest.TestCase):
    def test_missing_file_is_not_supported_flow_or_tn(self):
        self.assertEqual(target_status(None),'NOT_INSPECTED')
    def test_limits_and_failures_remain_separate(self):
        self.assertEqual(target_status({'parseStatus':'LIMIT_EXCEEDED'}),'RESOURCE_LIMIT')
        self.assertEqual(target_status({'parseStatus':'PARSE_FAILED'}),'ANALYSIS_FAILED')
    def test_parsing_is_not_security_flow_success(self):
        self.assertEqual(target_status({'parseStatus':'PARSED'}),'NOT_SUPPORTED')
    def test_absent_warning_without_positive_defense_is_unknown(self):
        self.assertEqual(controlled_outcome([],[]),'UNKNOWN')
        self.assertEqual(controlled_outcome([],[{'kind':'FLOW_UNRESOLVED'}]),'UNKNOWN')
    def test_only_target_filtered_findings_and_positive_native_contracts_are_scored(self):
        self.assertEqual(controlled_outcome([{'ruleId':'JS_SHELL_COMMAND_INPUT_FLOW'}],[]),'TP')
        self.assertEqual(controlled_outcome([],[{'kind':'ARGV_WITHOUT_SHELL_DECLARED'}]),'TN_TARGET_ONLY')
    def test_unrelated_rules_files_and_locations_never_count_as_target_success(self):
        findings=[{'ruleId':'OTHER','location':{'filePath':'index.js','line':4}},
                  {'ruleId':'JS_SHELL_COMMAND_INPUT_FLOW','location':{'filePath':'other.js','line':4}},
                  {'ruleId':'JS_SHELL_COMMAND_INPUT_FLOW','location':{'filePath':'index.js','line':12}}]
        self.assertEqual(target_findings(findings,'index.js',4,'JS_SHELL_COMMAND_INPUT_FLOW'),[])

if __name__=='__main__':unittest.main()
