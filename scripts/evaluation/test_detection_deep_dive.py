import unittest
from detection_deep_dive import outcome

class PathJudgmentTests(unittest.TestCase):
    def case(self, **change):
        return dict(dict(caseId='shell',filePath='api.cjs',line=4,cwe='CWE-78',truth='RISK'),**change)
    def row(self, findings=None, uses=None, files=None, version='ts-server-v18'):
        return {'typescript':dict(analyzerVersion=version,validatedFindings=findings or [],nodeUses=uses or [],
            files=files if files is not None else [dict(filePath='api.cjs',parseStatus='PARSED',entrypoints=1)])}
    def finding(self, **change):
        return dict(dict(ruleId='JS_SHELL_COMMAND_INPUT_FLOW',location=dict(filePath='api.cjs',line=4)),**change)
    def test_only_the_target_mechanism_and_location_count(self):
        self.assertEqual(outcome(self.case(),self.row([self.finding()])),'TP')
        self.assertEqual(outcome(self.case(),self.row([self.finding(ruleId='TS_SQL_INPUT_FLOW')])),'FN')
        self.assertEqual(outcome(self.case(),self.row([self.finding(location=dict(filePath='other.cjs',line=4))])),'FN')
        self.assertEqual(outcome(self.case(),self.row([self.finding(location=dict(filePath='api.cjs',line=5))])),'FN')
    def test_uninspected_and_unsupported_are_not_scored_success_or_false_negative(self):
        self.assertEqual(outcome(self.case(),self.row(files=[])),'NOT_INSPECTED')
        self.assertEqual(outcome(self.case(),self.row(version='ts-server-v17')),'NOT_SUPPORTED')
        self.assertEqual(outcome(self.case(cwe='CWE-502'),self.row()),'NOT_SUPPORTED')
    def test_normal_requires_positive_narrow_evidence_not_absence_of_findings(self):
        case=self.case(caseId='dvna-execfile-counterpart',truth='NORMAL_FOR_TARGET')
        self.assertEqual(outcome(case,self.row()),'UNKNOWN')
        use=dict(kind='ARGV_WITHOUT_SHELL_DECLARED',location=dict(filePath='api.cjs',line=4))
        self.assertEqual(outcome(case,self.row(uses=[use])),'TN')
        self.assertEqual(outcome(case,self.row([self.finding()],uses=[use])),'FP')

if __name__=='__main__':unittest.main()
