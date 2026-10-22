import copy
import json
from pathlib import Path
import tempfile
import unittest
from freeze_audit import audit


class FreezeAuditTest(unittest.TestCase):
    def fixture(self,root):
        rows=[];cases=[]
        for kind,state,outcome in [('EDGE','UID_COLUMN_EQUALITY','UNKNOWN'),('NEXT','UNKNOWN','UNCERTAINTY_CHECK_FAILED')]:
            project=kind.lower();table='public.'+project
            file='supabase/functions/freeze-policy-links/index.ts'if kind=='EDGE'else'app/api/freeze/policy-links/route.ts'
            snapshot=dict(tables=[dict(table=table,operations=[dict(role='authenticated',operation='SELECT',state=state)])],
                accesses=[dict(table=table,location=dict(filePath=file),authorizationEvidence=dict(authStatus='SESSION_READ_UNVERIFIED',effectiveRole='UNKNOWN'))])
            rows.append(dict(projectId=project,runs=[dict(typescript=dict(supabaseAnalysis=snapshot))]))
            cases.append(dict(caseId=project+'-session',framework=kind,projectId=project,table=table,
                uncertaintyDimension='AUTH_SESSION',role='authenticated',operation='SELECT',observedDimensions={},outcome=outcome,
                structuralCandidates=[],ruleSignals=[]))
        primary=dict(engineCommit='a'*40,planSha256='b'*64,counts={'UNKNOWN':1,'UNCERTAINTY_CHECK_FAILED':1},caseResults=cases)
        for name,data in [('report.json',primary),('results.json',dict(engineCommit='a'*40,planSha256='b'*64,projects=rows)),('pre-run-receipt.json',{})]:
            (root/name).write_text(json.dumps(data))
        return primary

    def test_next_path_fact_is_corrected_without_changing_frozen_outcome(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);original=self.fixture(root);result=audit(root)
            self.assertEqual(result['counts'],original['counts'])
            self.assertEqual([r['outcome']for r in result['caseResults']],[r['outcome']for r in original['caseResults']])
            self.assertTrue(all(s['sessionCorrectlyUnverified']for s in result['sessionEvidenceAudit']))
            self.assertEqual(result['sessionEvidenceAudit'][1]['auditedObservedDimensions']['policyState'],'UNKNOWN')
            self.assertTrue(result['noAutomaticFreezeOrPolicyChange'])

    def test_mismatched_results_cannot_be_attached_to_another_study(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);self.fixture(root);p=root/'results.json';raw=json.loads(p.read_text());raw['planSha256']='c'*64;p.write_text(json.dumps(raw))
            with self.assertRaisesRegex(ValueError,'PRIMARY_MISMATCH'):audit(root)
