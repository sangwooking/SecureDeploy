import unittest
import json
import re
from pathlib import Path
from differential35 import inspect,pair_status

class Differential35Test(unittest.TestCase):
    def test_public_catalog_keeps_source_truth_and_patch_readiness_separate(self):
        text=Path(__file__).with_name('detection35-catalog.json').read_text();catalog=json.loads(text)
        self.assertEqual(7,len(catalog['cases']));self.assertEqual(5,len({c['group'] for c in catalog['cases']}))
        self.assertEqual(72,catalog['rules']['count'])
        self.assertEqual([],catalog['remediationContract']['automaticEligibleRules'])
        self.assertFalse(any(r['status']=='REMEDIATION_READY' for r in catalog['readinessMatrix']))
        self.assertTrue(all(set('ABCDEFG').issubset(r) for r in catalog['readinessMatrix']))
        self.assertTrue(all(re.fullmatch('[a-f0-9]{40}',p['sourceSha'])for p in catalog['projects'].values()))
        self.assertNotIn('/Users/',text);self.assertNotIn('/private/tmp/',text)
        summary=json.loads(Path(__file__).with_name('detection35-summary.json').read_text())
        self.assertEqual(catalog['baseline'],summary['baseline'])
        for worker in ('v40','v44'):
            self.assertEqual({'TP':4,'NOT_SUPPORTED_REQUEST_CONNECTION':3},summary['counts'][worker]['before'])
            self.assertEqual(4,summary['counts'][worker]['targetContrasts'])
        self.assertEqual(0,summary['newRealVulnerabilityTP'])
        self.assertFalse(summary['engineChanged'])
    def fixture(self):
        source=dict(filePath='route.js',line=2);sink=dict(filePath='service.js',line=9)
        target=dict(ruleId='KNOWN',source=dict(filePath='route.js',lines=[2]),sink=dict(filePath='service.js',lines=[9]),
            normalProof=dict(field='nodeUses',kind='STATIC_OR_DATA_ONLY',filePath='service.js',lines=[9]))
        finding=dict(ruleId='KNOWN',location=sink,evidence=[dict(source=source,sink=sink)])
        run=dict(raw=[],filtered=[],typescript=dict(files=[dict(filePath='service.js',parseStatus='PARSED',entrypoints=1,functionsAnalyzed=1,limitations=[])],
            validatedFindings=[finding],nodeUses=[],authorizationContexts=[]))
        return run,target
    def test_exact_source_and_sink_not_unrelated_warning(self):
        r,t=self.fixture();self.assertEqual('TP',inspect(r,t)['status'])
        r['typescript']['validatedFindings'][0]['evidence'][0]['source']['line']=3
        self.assertNotEqual('TP',inspect(r,t)['status'])
    def test_absence_without_proof_is_never_normal_success(self):
        r,t=self.fixture();r['typescript']['validatedFindings']=[]
        self.assertTrue(inspect(r,t,True)['status'].startswith('UNKNOWN'))
    def test_normal_requires_executed_path_and_specific_proof(self):
        r,t=self.fixture();r['typescript']['validatedFindings']=[]
        r['typescript']['nodeUses']=[dict(kind='STATIC_OR_DATA_ONLY',location=dict(filePath='service.js',line=9))]
        self.assertEqual('TN_TARGET_ONLY',inspect(r,t,True)['status'])
        r['typescript']['files'][0]['functionsAnalyzed']=0
        self.assertNotEqual('TN_TARGET_ONLY',inspect(r,t,True)['status'])
    def test_uninspected_resource_and_no_entry_are_distinct(self):
        r,t=self.fixture();r['typescript']['validatedFindings']=[]
        r['typescript']['files'][0]['entrypoints']=0
        self.assertEqual('NOT_SUPPORTED_REQUEST_CONNECTION',inspect(r,t)['status'])
        r['typescript']['files'][0]['limitations']=['ANALYSIS_STEP_BUDGET_EXCEEDED']
        self.assertEqual('RESOURCE_LIMIT',inspect(r,t)['status'])
        r['typescript']['files']=[];self.assertEqual('NOT_INSPECTED',inspect(r,t)['status'])
    def test_normal_warning_is_fp_and_failed_pair_never_resolved(self):
        r,t=self.fixture();self.assertEqual('FP',inspect(r,t,True)['status'])
        self.assertEqual('NOT_VERIFIED_AS_SUCCESSFUL_REPAIR',pair_status({'status':'NOT_INSPECTED'},{'status':'TN_TARGET_ONLY'}))
    def test_medium_candidate_cannot_be_hidden_by_absence_of_validated_finding(self):
        r,t=self.fixture();r['typescript']['validatedFindings']=[]
        r['typescript']['findings']=[dict(ruleId='KNOWN',confidence='MEDIUM',source=dict(filePath='route.js',line=2),sink=dict(filePath='service.js',line=9))]
        self.assertEqual('FP_REVIEW_CANDIDATE',inspect(r,t,True)['status'])
        self.assertNotEqual('TP',inspect(r,t)['status'])
