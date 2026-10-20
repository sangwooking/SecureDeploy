import unittest
import json
from pathlib import Path
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

    def test_frozen_evidence_preserves_risk_and_scope_cautions(self):
        report=json.loads(Path(__file__).with_name('hardening3-results.json').read_text())
        self.assertEqual(len(report['failureCaseHistory']),2)
        self.assertFalse(report['riskPolicyChanged'])
        self.assertFalse(report['userDatabaseUsed'])
        self.assertEqual(report['benchmarkRegression']['owaspJavaBefore'],report['benchmarkRegression']['owaspJavaAfter'])
        for project in report['projects']:
            if 'before'not in project:continue
            for key in ['rules','securityScore','deploymentAssessment','prioritySummary']:
                self.assertEqual(project['before'][key],project['after'][key])
        mall=next(p for p in report['projects']if p['projectId']=='macrozheng--mall-tiny')
        self.assertIn('DATA_ACCESS_RESULT_LIMIT',mall['after']['java']['limitations'])
        self.assertEqual(mall['after']['java']['independentCandidates'],0)
        self.assertEqual(report['runtime']['workerVersion'],'java-sql-v3')
        def no_source(value):
            if isinstance(value,dict):
                self.assertFalse({'content','snippet','sql','sourceCode','prompt','responseBody'}&value.keys())
                for child in value.values():no_source(child)
            elif isinstance(value,list):
                for child in value:no_source(child)
        no_source(report)

if __name__=='__main__':unittest.main()
