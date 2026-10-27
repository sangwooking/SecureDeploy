import unittest
from mongoose18 import classify


class MongooseContractMetrics(unittest.TestCase):
    def test_removed_callback_api_is_not_a_valid_query_candidate(self):
        self.assertEqual(classify(dict(findings=[],files=[],nodeUses=[dict(ruleId='JS_MONGOOSE_SELECTOR_INPUT_FLOW',kind='CALLBACK_VERSION_UNSUPPORTED')])), 'CALLBACK_VERSION_UNSUPPORTED')
    def test_absence_without_contract_is_not_a_normal_result(self):
        self.assertEqual(classify(dict(findings=[], nodeUses=[], files=[])), 'NOT_SUPPORTED_OR_NOT_APPLICABLE')

    def test_unknown_and_unconsumed_do_not_become_successes(self):
        for state in ['UNKNOWN', 'QUERY_CREATED_EXECUTION_NOT_OBSERVED', 'SANITIZE_FILTER_DECLARED']:
            self.assertEqual(classify(dict(findings=[], files=[], nodeUses=[dict(ruleId='JS_MONGOOSE_SELECTOR_INPUT_FLOW', kind=state)])), state)

    def test_unrelated_findings_are_not_target_success(self):
        self.assertEqual(classify(dict(findings=[dict(ruleId='JS_EVAL_INPUT_FLOW')], files=[], nodeUses=[])), 'NOT_SUPPORTED_OR_NOT_APPLICABLE')

    def test_later_unknown_chain_is_not_hidden_by_creation_observation(self):
        self.assertEqual(classify(dict(findings=[], files=[dict(limitations=['MONGOOSE_QUERY_CHAIN_UNKNOWN'])],
            nodeUses=[dict(ruleId='JS_MONGOOSE_SELECTOR_INPUT_FLOW',kind='QUERY_CREATED_EXECUTION_NOT_OBSERVED')])), 'UNKNOWN')
