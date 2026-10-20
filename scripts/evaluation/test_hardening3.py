import unittest
from hardening3 import summary

class DataAccessMetadataTest(unittest.TestCase):
    def test_contracts_are_not_executions_or_findings(self):
        row=dict(filtered=[],securityScore=100,reviewCandidates=[],coverage={'status':'PARTIAL'},
                 risk=dict(prioritizedDeploymentAssessment='REVIEW_REQUIRED',prioritySummary={},policyVersion='unchanged'),
                 java=dict(findings=[],analysis=dict(version='java-sql-v3',status='PARTIAL',files=[],uses=[],limitations=[],
                     dataAccess=[dict(framework='SPRING_DATA_JPA',status='DECLARED_QUERY_CONTRACT'),dict(framework='MYBATIS_PLUS',status='UNKNOWN') ])))
        result=summary(row)
        self.assertEqual(result['java']['tracedSqlCalls'],0)
        self.assertEqual(result['java']['independentCandidates'],0)
        self.assertEqual(result['java']['dataAccess']['MYBATIS_PLUS:UNKNOWN'],1)
        del row['java']['analysis']['dataAccess']
        self.assertEqual(summary(row)['java']['dataAccess'],{})

if __name__=='__main__':unittest.main()
