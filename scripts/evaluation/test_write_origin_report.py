import unittest
from write_origin_report import compare_origins


class OriginReportTest(unittest.TestCase):
    def packet(self):
        return {'rows':[{'caseId':'same','expected':'REQUEST_CONTROLLED','operation':'INSERT','runtimeAuthorization':'UNKNOWN','policyWarnings':1}]}

    def test_keeps_origin_metric_separate(self):
        r=compare_origins(self.packet(),self.packet())
        self.assertEqual(r['metric'],'LOCAL_ORIGIN_CLASSIFICATION_NOT_VULNERABILITY_DETECTION')

    def test_changed_truth_or_runtime_claim_is_rejected(self):
        for field,value in [('expected','SERVER_CONTROLLED'),('runtimeAuthorization','VERIFIED'),('policyWarnings',0)]:
            a,b=self.packet(),self.packet();b['rows'][0][field]=value
            with self.assertRaises(ValueError):compare_origins(a,b)
