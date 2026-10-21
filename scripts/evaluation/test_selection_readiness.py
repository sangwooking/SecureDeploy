import copy
import json
from pathlib import Path
import tempfile
import unittest

from selection_readiness import report, summarize, next_summary


class SelectionReadinessTest(unittest.TestCase):
    def next_fixture(self):
        from next_flows import CASES
        projects=[]
        for name,(file,_,truth,rule,_)in CASES.items():
            finding=dict(ruleId=rule,location=dict(filePath=file),priority='REVIEW_REQUIRED',comparisonPolicy='NOT_COMPARED')
            typed=[finding]if truth=='TP'else[]
            final=[{k:v for k,v in f.items()if k!='comparisonPolicy'}for f in typed]
            run=dict(typescript=dict(validatedFindings=typed),reviewCandidates=final)
            projects.append(dict(projectId='next-boundary-'+name,runs=[run,copy.deepcopy(run)]))
        projects.append(dict(projectId='next-boundary-original',runs=[{},{}]))
        return dict(projects=projects)

    def test_next_uses_typed_policy_evidence_not_the_compact_candidate_projection(self):
        result=next_summary(self.next_fixture())
        self.assertEqual(result['counts']['REGRESSION']['TP'],2)
        self.assertEqual(result['counts']['VALIDATION']['UNKNOWN'],1)

    def test_next_missing_comparison_evidence_is_not_invented(self):
        raw=self.next_fixture()
        for run in raw['projects'][0]['runs']:
            del run['typescript']['validatedFindings'][0]['comparisonPolicy']
        with self.assertRaisesRegex(ValueError,'NEXT_PRIORITY_CHANGED'):next_summary(raw)

    def row(self):
        sql=dict(files=[],tables=[],clients=[],accesses=[],limitations=[])
        run=dict(typescript=dict(status='PARTIAL',files=[],authorizationContexts=[],supabaseAnalysis=sql,limitations=[]),
            coverage=dict(discoveredFiles=0,selectedFiles=0,unsupportedFiles=0,excludedFiles=0,failedFiles=0),
            reviewCandidates=[],filtered=[],securityScore=100,risk=dict(prioritySummary={}),elapsedMs=1,parentHeapUsedBytes=1)
        return dict(projectId='synthetic',commitSha='a'*40,runs=[run,copy.deepcopy(run)])

    def test_repeat_checks_semantics_not_timing_samples(self):
        p=self.row();p['runs'][1]['elapsedMs']=99
        self.assertTrue(summarize(p)['repeatConsistent'])
        p['runs'][1]['securityScore']=1
        with self.assertRaisesRegex(ValueError,'REPEAT_OR_COMPLETENESS'):summarize(p)

    def test_partial_metadata_cannot_relabel_an_unavailable_worker_as_success(self):
        p=self.row()
        for r in p['runs']:r['typescript']['status']='TIMEOUT'
        with self.assertRaisesRegex(ValueError,'WORKER_NOT_COMPLETED'):summarize(p)

    def test_source_and_rule_changes_cannot_be_silently_counted_as_selection_improvement(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);b=dict(planSha256='a'*64,engineCommit='a'*40,projects=[self.row()]);a=copy.deepcopy(b)
            a['planSha256']='b'*64
            before=root/'before.json';after=root/'after.json';output=root/'report.json'
            before.write_text(json.dumps(b));after.write_text(json.dumps(a))
            with self.assertRaisesRegex(ValueError,'DIFFERENT_SOURCE_PLAN'):report(before,after,output)
            a['planSha256']=b['planSha256']
            for r in a['projects'][0]['runs']:r['securityScore']=86
            after.write_text(json.dumps(a))
            with self.assertRaisesRegex(ValueError,'RULE_SCORE_RISK_DIFFERENCE'):report(before,after,output)
