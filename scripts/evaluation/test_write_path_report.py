import copy
import unittest
from write_path_report import controls


class WritePathReportTest(unittest.TestCase):
    def fixture(self):
        side=dict(rows=[dict(caseId='one',truth='UNKNOWN',operation='UPDATE',runtimeAuthorization='UNKNOWN')],counts=dict(finalPolicyWarnings={'TP':0}))
        return dict(before=copy.deepcopy(side),after=copy.deepcopy(side))

    def test_unknown_is_not_automatically_runtime_protection(self):
        result=self.fixture();self.assertIs(controls(result),result)
        result['after']['rows'][0]['runtimeAuthorization']='PROTECTED'
        with self.assertRaisesRegex(ValueError,'OVERCLAIM'):controls(result)

    def test_changed_truth_or_policy_warning_cannot_be_hidden_as_link_improvement(self):
        result=self.fixture();result['after']['rows'][0]['truth']='NORMAL'
        with self.assertRaisesRegex(ValueError,'TRUTH_CHANGED'):controls(result)
        result=self.fixture();result['after']['counts']['finalPolicyWarnings']['TP']=1
        with self.assertRaisesRegex(ValueError,'WARNING_REGRESSION'):controls(result)
