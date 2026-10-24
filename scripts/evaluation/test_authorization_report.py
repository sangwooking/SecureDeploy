import copy
import unittest
from authorization_report import metrics


class AuthorizationReportTest(unittest.TestCase):
    def row(self):
        return dict(caseId='one',truth='REVIEW',sqlSha256='hash',findings=[],policyOperations=[],
                    access=dict(table='public.items',operation='UPDATE',authorizationEvidence=dict(state='UNKNOWN')))

    def oracle(self):
        return dict(matched=1,total=1,rows=[dict(match=True)],policyHashes={'one':'hash'})

    def test_unrelated_operation_warning_does_not_count_as_detection(self):
        row=self.row();row['findings']=[dict(table='public.items',operations=['INSERT'],priority='REVIEW_REQUIRED',comparisonPolicy='NOT_COMPARED')]
        r=metrics(dict(rows=[row]),dict(rows=[row]),self.oracle())
        self.assertEqual(r['counts']['after']['FN'],1)

    def test_changed_truth_or_target_cannot_improve_metrics(self):
        row=self.row();changed=copy.deepcopy(row);changed['access']['operation']='INSERT'
        with self.assertRaisesRegex(ValueError,'TRUTH_OR_SQL_CHANGED'):
            metrics(dict(rows=[row]),dict(rows=[changed]),self.oracle())

    def test_oracle_mismatch_and_duplicate_ids_are_rejected(self):
        row=self.row();oracle=self.oracle();oracle['rows'][0]['match']=False
        with self.assertRaisesRegex(ValueError,'ORACLE_TRUTH_NOT_VERIFIED'):
            metrics(dict(rows=[row]),dict(rows=[row]),oracle)
        with self.assertRaisesRegex(ValueError,'DUPLICATE_CASE'):
            metrics(dict(rows=[row,row]),dict(rows=[row]),self.oracle())
