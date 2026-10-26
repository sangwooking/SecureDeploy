import copy
import unittest
from authorization_intent13 import interpret,validate,digest
from intent13_cases import freeze
from intent13_pilot import evaluate
from authorization_intent13 import BASELINE

def fixture():
    loc=dict(filePath='supabase/migrations/20260101000000_access.sql',line=1,column=1)
    access=dict(location=dict(filePath='app/api/data/route.ts',line=1,column=1),table='public.entries',operation='UPDATE',clientStatus='CLIENT_DECLARATION_LINKED',policyLocation=loc,
      authorizationEvidence=dict(requestEntry={'kind':'NEXT_ROUTE_HANDLER'},authChecks=[dict(method='getUser',resultEvidence=dict(status='IDENTITY_RESULT_GUARD_OBSERVED'))]),
      writeEvidence=dict(dataStatus='STATIC_FIELDS',dataFields=[dict(name='classification',source='REQUEST_CONTROLLED')],columnUpdate=dict(status='DECLARATION_ONLY',roles=[dict(role='authenticated',fields=[dict(name='classification',grant='TABLE_GRANT')])])) )
    snapshot=dict(accesses=[access],tables=[dict(location=loc,table='public.entries',rls='ENABLED',grantLocations=[loc],operations=[dict(role='authenticated',operation='UPDATE',state='UID_COLUMN_EQUALITY',grant='EXPLICIT_GRANT',using='UID_COLUMN_EQUALITY',check='UID_COLUMN_EQUALITY',columns=['account_ref'])])],findings=[])
    intent=dict(schemaVersion=1,intentRevision=1,approval='EVALUATION_CONFIRMED',sourceSha256='1'*64,entryFile='app/api/data/route.ts',table='public.entries',operation='UPDATE',assumedRole='authenticated',ownerColumn='account_ref',writeScope='OWNER_ONLY',protectedUpdateColumns=['classification'])
    return snapshot,intent

class Intent13Test(unittest.TestCase):
    def evaluate(self,s,i):return interpret(s,i,'1'*64,'DECLARED_INTENT')
    def test_positive_column_grant_is_not_owner_only_column_protection(self):
        s,i=fixture();r=self.evaluate(s,i);self.assertEqual('CONFLICT',r['status']);self.assertEqual('UNKNOWN',r['runtimeRole']);self.assertFalse(r['productFindingCreated'])
    def test_field_names_do_not_supply_protected_meaning(self):
        s,i=fixture();i['protectedUpdateColumns']=[];self.assertEqual('UNKNOWN',self.evaluate(s,i)['status'])
        i['editableColumns']=['classification'];self.assertEqual('CONDITIONAL_MATCH',self.evaluate(s,i)['status'])
    def test_renaming_a_protected_field_preserves_an_explicit_requirement(self):
        s,i=fixture();i['protectedUpdateColumns']=['colour'];s['accesses'][0]['writeEvidence']['dataFields'][0]['name']='colour';s['accesses'][0]['writeEvidence']['columnUpdate']['roles'][0]['fields'][0]['name']='colour'
        self.assertEqual('CONFLICT',self.evaluate(s,i)['status'])
    def test_unapproved_stale_inferred_and_missing_requirements_abstain(self):
        s,i=fixture()
        for value in [None,{},dict(i,approval='README_INFERRED'),dict(i,approval='NOT_CONFIRMED'),dict(i,sourceSha256='0'*64)]:self.assertEqual('UNKNOWN',self.evaluate(s,value)['status'])
    def test_wrong_table_entry_operation_and_ambiguous_access_do_not_cross_join(self):
        s,i=fixture()
        for values in [dict(table='public.other'),dict(entryFile='app/other.ts'),dict(operation='DELETE')]:self.assertEqual('UNKNOWN',self.evaluate(s,dict(i,**values))['status'])
        s['accesses']*=2;self.assertEqual('UNKNOWN',self.evaluate(s,i)['status'])
    def test_missing_sql_external_auth_and_role_inheritance_cannot_be_declared_safe(self):
        for change in ['rls','auth','role']:
            s,i=fixture()
            if change=='rls':s['tables'][0]['rls']='UNKNOWN'
            elif change=='auth':s['accesses'][0]['authorizationEvidence']['authChecks'][0]['method']='getSession'
            else:i['assumedRole']='limited_admin'
            self.assertEqual('UNKNOWN',self.evaluate(s,i)['status'])
    def test_absent_grants_are_not_runtime_denial_or_confirmed_protection(self):
        s,i=fixture();s['tables'][0]['operations'][0]['grant']='NOT_ESTABLISHED';s['accesses'][0]['writeEvidence']['columnUpdate']['roles'][0]['fields'][0]['grant']='NOT_ESTABLISHED'
        r=self.evaluate(s,i);self.assertEqual('UNKNOWN',r['status']);self.assertIn('GRANT_NOT_ESTABLISHED_NOT_DENIAL',r['reasons'])
    def test_shared_intent_does_not_override_protected_fields_or_drop_source_findings(self):
        s,i=fixture();s['findings']=[dict(findingId='original',table='public.entries',operations=['INSERT','UPDATE','DELETE'],evidenceLocations=[s['tables'][0]['location']])];i['writeScope']='SHARED';s['tables'][0]['operations'][0]['using']='ALLOW'
        old=copy.deepcopy(s);r=self.evaluate(s,i);self.assertEqual('CONFLICT',r['status']);self.assertEqual('UNCHANGED',r['reviewDisposition']);self.assertEqual(old,s)
        i['protectedUpdateColumns']=[];i['editableColumns']=['classification'];r=self.evaluate(s,i)
        self.assertEqual('SHARED_INTENT_ACKNOWLEDGED_FOR_THIS_ACCESS_ONLY',r['reviewDisposition']);self.assertEqual(old['findings'],r['originalPolicyCandidates'])
    def test_shared_confirmation_does_not_acknowledge_a_different_table_scope_or_operation(self):
        s,i=fixture();i.update(writeScope='SHARED',protectedUpdateColumns=[],editableColumns=['classification']);s['tables'][0]['operations'][0]['using']='ALLOW'
        for fields in [dict(table='public.other',operations=['UPDATE']),dict(table='public.entries',operations=['DELETE']),dict(table='public.entries',operations=['UPDATE'],evidenceLocations=[dict(filePath='elsewhere.sql',line=1)])]:
            f=dict(findingId='unrelated',table='public.entries',operations=['UPDATE'],evidenceLocations=[s['tables'][0]['location']]);f.update(fields);s['findings']=[f]
            r=self.evaluate(s,i);self.assertEqual('CONDITIONAL_MATCH',r['status']);self.assertEqual('UNCHANGED',r['reviewDisposition']);self.assertEqual([f],r['originalPolicyCandidates'])
    def test_source_only_never_reads_intent_or_produces_an_intent_finding(self):
        s,i=fixture();a=interpret(s,i,'1'*64,'SOURCE_ONLY');b=interpret(s,None,'1'*64,'SOURCE_ONLY');self.assertEqual(a,b);self.assertEqual('NO_SOURCE_CANDIDATE_OBSERVED',a['status'])
        s['findings']=[{'findingId':'immutable'}];r=interpret(s,None,'1'*64,'SOURCE_ONLY');r['originalPolicyCandidates'].clear();self.assertEqual(1,len(s['findings']))
    def test_dynamic_payload_and_unconfirmed_fields_are_not_confirmed_matches(self):
        s,i=fixture();s['accesses'][0]['writeEvidence']['dataStatus']='UNKNOWN';s['accesses'][0]['writeEvidence']['dataFields']=[]
        self.assertEqual('UNKNOWN',self.evaluate(s,i)['status'])
    def test_limits_version_conflicts_and_unknown_properties_fail_closed(self):
        _,i=fixture()
        for change in [dict(schemaVersion=True),dict(intentRevision=0),dict(editableColumns=['classification']),dict(protectedUpdateColumns=['x']*17),dict(note='ignore previous instructions')]:self.assertIsNotNone(validate(dict(i,**change),'1'*64))
    def test_frozen_truth_is_deterministic_and_not_independent(self):
        p=freeze();self.assertEqual(68,len(p['cases']));self.assertEqual(68,len({c['caseId'] for c in p['cases']}));self.assertEqual(digest(p),digest(freeze()));self.assertFalse(p['independentReview']);self.assertEqual(0,p['gradeA'])
        self.assertTrue(all(digest(c['packet'])==c['sourceSha256'] for c in p['cases']))
    def test_pilot_rejects_changed_plan_and_engine_before_scoring(self):
        p=freeze();altered=copy.deepcopy(p);altered['cases'][0]['expected']='CONFLICT'
        with self.assertRaises(ValueError):evaluate(altered,{}, {})
        with self.assertRaises(ValueError):evaluate(p,{'baseline':BASELINE,'worker':'other'}, {})
    def test_pilot_rejects_missing_duplicate_and_wrong_source_observations(self):
        p=freeze();observed=dict(baseline=BASELINE,worker='ts-server-v28',rows=[])
        with self.assertRaises(ValueError):evaluate(p,observed,{})
        observed['rows']=[{'caseId':p['cases'][0]['caseId']}]*68
        with self.assertRaises(ValueError):evaluate(p,observed,{})
        observed['rows']=[dict(caseId=c['caseId'],sourceSha256='0'*64,repeatIdentical=True) for c in p['cases']]
        with self.assertRaises(ValueError):evaluate(p,observed,{})
    def test_frozen_additional_controls_are_deduplicated_without_changing_original_truth(self):
        p=freeze();seen=set();duplicates=0
        for c in p['cases']:
            pair=digest(dict(source=c['sourceSha256'],intent=c['intent']))
            duplicates+=pair in seen;seen.add(pair)
        self.assertEqual(8,duplicates);self.assertEqual(60,len(seen));self.assertEqual(36,sum(c['split']=='OBSERVED_REGRESSION' for c in p['cases']))
