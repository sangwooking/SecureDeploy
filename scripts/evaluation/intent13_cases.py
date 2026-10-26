"""Frozen authored intent controls, separate from the interpreter and engine output."""
import argparse
import copy
from pathlib import Path
from application_track import write
from authorization_truth11 import freeze as original
from authorization_intent13 import digest,BASELINE

def contract(case):
    return dict(schemaVersion=1,intentRevision=1,approval='EVALUATION_CONFIRMED',sourceSha256=case['sourceSha256'],
      entryFile=case['packet']['files'][0]['filePath'],table='public.items',operation=case['operation'],assumedRole='authenticated',ownerColumn='user_id',
      readScope='OWNER_ONLY' if case['operation']=='SELECT' else 'UNKNOWN',writeScope='OWNER_ONLY',editableColumns=['payload'],protectedUpdateColumns=[],ownershipTransfer='UNKNOWN')

def freeze():
    cases=[]
    for c in original()['cases']:
        intent=contract(c);scenario=c['scenario']
        if scenario in ['role-field','column-denial']:intent['protectedUpdateColumns']=['role']
        if scenario=='admin-field':intent['protectedUpdateColumns']=['is_admin']
        if scenario=='transfer-owner':intent['ownershipTransfer']='FORBIDDEN'
        if scenario=='claim-other':intent['editableColumns']=['user_id']
        if scenario=='intentional-share':intent['writeScope']='SHARED';intent.pop('ownerColumn')
        expected='CONFLICT' if c['truth']=='RISK' else 'CONDITIONAL_MATCH' if scenario in ['own-title','constant-own','intentional-share'] else 'UNKNOWN'
        cases.append(dict(caseId=c['caseId'],split='OBSERVED_REGRESSION',sourceSha256=c['sourceSha256'],packet=c['packet'],intent=intent,
          originalTruth=c['truth'],originalRequirement=c['requirement'],expected=expected,oraclePolicy=c['policy'],oracleProbe=c['oracleProbe']))
    for layout in ['route','action']:
        def variant(scenario,name,expected):
            c=copy.deepcopy(next(c for c in cases if c['caseId']==layout+'-'+scenario));c.update(caseId=layout+'-validation-'+name,split='VALIDATION_SAME_AUTHOR_NOT_BLIND',expected=expected,originalTruth='COUNTERFACTUAL_INTENT_NOT_ORIGINAL_LABEL');return c
        variants=[]
        c=variant('private-read','public-read','CONDITIONAL_MATCH');c['intent']['readScope']='PUBLIC';variants.append(c)
        c=variant('intentional-share','private-bulletin','CONFLICT');c['intent'].update(writeScope='OWNER_ONLY',ownerColumn='user_id');variants.append(c)
        c=variant('role-field','unconfirmed','UNKNOWN');c['intent']['approval']='NOT_CONFIRMED';variants.append(c)
        c=variant('private-read','stale','UNKNOWN');c['intent']['sourceSha256']='0'*64;variants.append(c)
        c=variant('intentional-share','shared-but-protected','CONFLICT');c['intent']['protectedUpdateColumns']=['payload'];c['intent']['editableColumns']=[];variants.append(c)
        c=variant('role-field','wrong-table','UNKNOWN');c['intent']['table']='public.unrelated';variants.append(c)
        c=variant('role-field','admin-role','UNKNOWN');c['intent']['assumedRole']='limited_admin';variants.append(c)
        c=variant('private-read','no-intent','UNKNOWN');c['intent']=None;variants.append(c)
        c=variant('partial-sql','missing-migration','UNKNOWN');variants.append(c)
        c=variant('external-auth','external-auth','UNKNOWN');variants.append(c)
        c=variant('role-field','comment-not-consent','UNKNOWN');c['intent']['approval']='README_INFERRED';variants.append(c)
        c=variant('column-denial','admin-only-requirement','UNKNOWN');variants.append(c)
        c=variant('role-field','renamed-protected-column','CONFLICT')
        for f in c['packet']['files']:f['content']=f['content'].replace('role','accent').replace("'items'","'documents'")
        for f in c['packet']['policyFiles']:
            if 'content' in f:f['content']=f['content'].replace('role','accent').replace('public.items','public.documents')
        c['sourceSha256']=digest(c['packet']);c['intent'].update(sourceSha256=c['sourceSha256'],table='public.documents',protectedUpdateColumns=['accent']);variants.append(c)
        c=variant('own-title','wrong-owner-mapping','UNKNOWN');c['intent']['ownerColumn']='tenant_id';variants.append(c)
        c=variant('role-field','contradictory-requirement','UNKNOWN');c['intent']['editableColumns']=['role'];variants.append(c)
        c=variant('own-title','invalid-revision','UNKNOWN');c['intent']['intentRevision']=0;variants.append(c)
        cases.extend(variants)
    return dict(schemaVersion=1,baseline=BASELINE,source='AUTHOR_ORIGINAL_CONTROLLED_REQUIREMENTS_NOT_EXTERNAL_PROJECT_APPROVAL',gradeA=0,independentReview=False,
      protocol='Freeze before first interpreter run. Original 36 already observed; 32 new contract/counterfactual controls, same author and source families, not blind or independent apps.',
      cases=cases)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);a=p.parse_args();r=freeze();write(a.output,r);print(dict(cases=len(r['cases']),gradeA=0,independentReview=False))
