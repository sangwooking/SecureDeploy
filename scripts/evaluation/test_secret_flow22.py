import unittest
from secret_flow22 import decision


class SecretDecisionTest(unittest.TestCase):
    def packet(self):
        return {'findings':[],'exposureUses':[],'files':[{'parseStatus':'PARSED','entrypoints':1,'limitations':[]}]}

    def case(self,truth):
        return {'truth':truth,'input':{'files':[{'filePath':'route.ts'}]}}

    def test_normal_parse_or_flow_failure_cannot_be_counted_as_tn(self):
        r=self.packet();r['files'][0]['parseStatus']='PARSE_FAILED'
        self.assertEqual(decision(self.case('NORMAL'),r),'NORMAL_DEFERRED_NOT_TN')
        r=self.packet();r['files'][0]['limitations']=['PROPERTY_WRITE_UNRESOLVED']
        self.assertEqual(decision(self.case('NORMAL'),r),'NORMAL_DEFERRED_NOT_TN')

    def test_unrelated_finding_does_not_detect_the_http_target(self):
        r=self.packet();r['findings']=[{'ruleId':'TS_SENSITIVE_DATA_EXPOSURE','sink':{'filePath':'route.ts','kind':'LOG_ARGUMENT'}}]
        self.assertEqual(decision(self.case('RISK'),r),'FN_INCLUDING_DEFERRED')

    def test_unknown_candidate_is_not_a_known_normal_false_positive(self):
        r=self.packet();r['findings']=[{'ruleId':'TS_SENSITIVE_DATA_EXPOSURE','sink':{'filePath':'route.ts','kind':'HTTP_RESPONSE'}}]
        self.assertEqual(decision(self.case('UNKNOWN'),r),'UNEXPECTED_CANDIDATE')
