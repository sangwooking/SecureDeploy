import unittest
from freeze_closeout_audit import freeze_checks


class FreezeCloseoutTest(unittest.TestCase):
    def result(self):
        return dict(counts={'TP':20,'TN':18,'UNKNOWN':10,'NOT_INSPECTED':10,'NOT_SUPPORTED':2},
            acceptanceChecks=dict(everySupportedCoreRiskDetected=True,allUncertaintyChecksPassed=True,
                repeatConsistencyPassed=True,independentExternalReview=False))

    def test_scope_freeze_is_not_a_general_accuracy_or_external_review_claim(self):
        self.assertTrue(all(freeze_checks(self.result()).values()))

    def test_any_scored_error_or_failed_uncertainty_check_prevents_go(self):
        for outcome in ['FP','FN']:
            r=self.result();r['counts'][outcome]=1
            self.assertFalse(all(freeze_checks(r).values()))
        for check in ['everySupportedCoreRiskDetected','allUncertaintyChecksPassed','repeatConsistencyPassed']:
            r=self.result();r['acceptanceChecks'][check]=False
            self.assertFalse(all(freeze_checks(r).values()))
