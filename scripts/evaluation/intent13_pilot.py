"""Replay frozen sources through the unchanged Worker, then compare two modes."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from application_track import read,write
from authorization_intent13 import BASELINE,digest,interpret
from intent13_cases import freeze
from authorization_truth11 import freeze as original,metrics

def replay(plan,root):
    if plan!=freeze():raise ValueError('FROZEN_PLAN_CHANGED')
    root=root.resolve()
    subprocess.run(['git','merge-base','--is-ancestor',BASELINE,'HEAD'],cwd=root,check=True,capture_output=True)
    if subprocess.check_output(['git','diff',BASELINE,'--name-only','--','analyzers','src/main','frontend/src'],cwd=root,text=True).strip():raise ValueError('PRODUCT_ENGINE_CHANGED')
    if subprocess.check_output(['git','ls-files','--others','--exclude-standard','--','analyzers','src/main'],cwd=root,text=True).strip():raise ValueError('UNTRACKED_ENGINE_CODE')
    worker=root/'analyzers/typescript';files=subprocess.check_output(['git','ls-files','analyzers/typescript'],cwd=root,text=True).splitlines()
    fingerprint=digest({f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files})
    rows=[];node=shutil.which('node')
    env={k:v for k,v in os.environ.items() if k in ['LANG','LC_ALL']}
    for c in plan['cases']:
        if digest(c['packet'])!=c['sourceSha256']:raise ValueError('SOURCE_HASH_CHANGED')
        packet=json.dumps(c['packet']).encode();runs=[];elapsed=[]
        for repeat in range(2):
            start=time.monotonic()
            p=subprocess.run([node,'--permission','--no-addons','--max-old-space-size=192','--allow-fs-read='+str(worker),str(worker/'worker.mjs')],input=packet,capture_output=True,timeout=8,env=env,check=True)
            if len(p.stdout)>2000000:raise ValueError('OUTPUT_LIMIT')
            r=json.loads(p.stdout)
            if r['analyzerVersion']!='ts-server-v28' or r['parserVersion']!='6.0.3' or r['supabaseAnalysis']['analyzerVersion']!='supabase-rls-v3':raise ValueError('VERSION_CHANGED')
            runs.append(r);elapsed.append(round((time.monotonic()-start)*1000,2))
        if runs[0]!=runs[1]:raise ValueError('WORKER_NONDETERMINISM')
        r=runs[0];rows.append(dict(caseId=c['caseId'],sourceSha256=c['sourceSha256'],snapshot=r['supabaseAnalysis'],files=r['files'],elapsedMs=elapsed,repeatIdentical=True))
    return dict(baseline=BASELINE,worker='ts-server-v28',runtimeFingerprint=fingerprint,rows=rows,targetExecuted=False,paidAiCalls=0)

def evaluate(plan,observed,oracle):
    if plan!=freeze() or observed['baseline']!=BASELINE or observed['worker']!='ts-server-v28':raise ValueError('PINNED_INPUTS_REQUIRED')
    original_plan=original();expected_ids={c['caseId'] for c in plan['cases']};by_id={r['caseId']:r for r in observed['rows']}
    if len(by_id)!=len(observed['rows']) or set(by_id)!=expected_ids:raise ValueError('OBSERVATION_CASE_SET')
    rows=[];old_engine=[];seen_pairs={};facts_by_hash={}
    for c in plan['cases']:
        r=by_id[c['caseId']]
        if r['sourceSha256']!=c['sourceSha256'] or not r['repeatIdentical']:raise ValueError('SOURCE_OR_REPEAT_CHANGED')
        sb=r['snapshot'];source=interpret(sb,None,c['sourceSha256'],'SOURCE_ONLY');declared=interpret(sb,c['intent'],c['sourceSha256'],'DECLARED_INTENT')
        if source['originalPolicyCandidates']!=declared['originalPolicyCandidates']:raise ValueError('SOURCE_FACTS_MUTATED')
        pair=digest(dict(source=c['sourceSha256'],intent=c['intent']));duplicate=seen_pairs.get(pair);seen_pairs.setdefault(pair,c['caseId'])
        facts=dict(accesses=[dict(location=a['location'],table=a['table'],operation=a['operation'],clientStatus=a['clientStatus'],authorizationEvidence=a.get('authorizationEvidence'),writeEvidence=a.get('writeEvidence')) for a in sb['accesses']],
          sqlFiles=sb['files'],rowOperations=[dict(table=t['table'],location=t['location'],rls=t['rls'],operations=t['operations']) for t in sb['tables']])
        if c['sourceSha256'] in facts_by_hash and facts_by_hash[c['sourceSha256']]!=facts:raise ValueError('IDENTICAL_SOURCE_OBSERVATION_DIFFER')
        facts_by_hash[c['sourceSha256']]=facts
        rows.append(dict(caseId=c['caseId'],split=c['split'],sourceSha256=c['sourceSha256'],intentSha256=digest(c['intent']),
          duplicateOf=duplicate,evaluationRole='DUPLICATE_REPLAY_NOT_NEW_VALIDATION' if duplicate else c['split'],
          requirement=c['intent'],expected=c['expected'],sourceOnly=source,declaredIntent=declared,match=declared['status']==c['expected'],
          sourceFactsRef=c['sourceSha256'],
          policyInputSha256=digest(c['packet']['policyFiles']),elapsedMs=r['elapsedMs'],originalTruth=c['originalTruth']))
        if c['split']=='OBSERVED_REGRESSION':
            access=sb['accesses'][0] if sb['accesses'] else None
            old_engine.append(dict(caseId=c['caseId'],sourceSha256=c['sourceSha256'],access=access,findings=sb['findings']))
    old_metrics=metrics(original_plan,{'rows':old_engine},oracle)
    counts=Counter();normal_abstentions=0
    for row in rows[:36]:
        truth=row['originalTruth'];state=row['declaredIntent']['status']
        if truth=='UNKNOWN' or state=='UNKNOWN':counts['UNKNOWN']+=1;normal_abstentions+=truth=='NORMAL' and state=='UNKNOWN';continue
        counts[('TP' if state=='CONFLICT' else 'FN') if truth=='RISK' else ('FP' if state=='CONFLICT' else 'TN')]+=1
    source_hashes={c['id']:c['sqlSha256'] for c in original_plan['policies']}
    if oracle['matched']!=oracle['total'] or oracle['policyHashes']!=source_hashes:raise ValueError('SQL_ORACLE_NOT_VERIFIED')
    return dict(schemaVersion=1,baseline=BASELINE,worker='ts-server-v28',engineChanged=False,productDatabaseChanged=False,
      planSha256=digest(plan),runtimeFingerprint=observed['runtimeFingerprint'],gradeA=0,newActualVulnerabilityTP=0,independentReview=False,
      originalSourceOnlyMetrics=old_metrics,declaredIntentRequirementMetrics=dict(counts={k:counts[k] for k in ['TP','FP','FN','TN','UNKNOWN']},
        metric='APPROVED_FIXTURE_REQUIREMENT_VS_REPOSITORY_DECLARATION_NOT_AUTOMATIC_VULNERABILITY_DETECTION',knownNormalAbstentions=normal_abstentions),
      regressionStates=dict(Counter(r['declaredIntent']['status'] for r in rows[:36])),validationStates=dict(Counter(r['declaredIntent']['status'] for r in rows[36:] if not r['duplicateOf'])),
      uniqueValidationCases=sum(not r['duplicateOf'] for r in rows[36:]),duplicateReplayCases=sum(bool(r['duplicateOf']) for r in rows),
      uniqueSourcePackets=len({r['sourceSha256'] for r in rows}),uniqueSourceIntentContexts=len(seen_pairs),
      expectationMatches=sum(r['match'] for r in rows),cases=len(rows),sharedReviewBurdenAcknowledged=sum(r['declaredIntent']['reviewDisposition']!='UNCHANGED' for r in rows[:36]),
      conditionalConflictReviewContexts=sum(r['declaredIntent']['status']=='CONFLICT' for r in rows[:36]),
      productFindingsPromoted=0,realProjectOwnerApprovals=0,operatingAuthorizationUnknown=len(rows),rows=rows,sourceFacts=facts_by_hash,
      oracle=dict(postgres=oracle['postgres'],matched=oracle['matched'],total=oracle['total'],policyHashes=oracle['policyHashes'],
        receiptSha256=digest(oracle),authUid=oracle['authUid'],scope='AUTHORED_SQL_A_B_ANON_LIMITED_ADMIN_NOT_HTTP_OR_DEPLOYED_SUPABASE'),
      targetExecuted=False,userDatabaseAccessed=False,paidAiCalls=0,
      limitations=['Original 36 labels and first reported metrics are unchanged; normal UNKNOWN cases are not converted to verified safe TN.',
        'Intent requirements were already known for regression; additional control deduplication uses the source-plus-intent digest. Duplicate replays are retained, not counted as new Validation. All cases share source families and author, not independent apps or blind holdout.',
        'EVALUATION_CONFIRMED is synthetic fixture-author confirmation, not real project-owner approval or authentication.',
        'Every result leaves runtime role, deployment and invocation UNKNOWN. A declaration conflict is not a reproduced production exploit.',
        'Shared intent acknowledges review burden only for the exact access/operation. Original policy observations and other operations remain intact.',
        'SELECT has request/Client/operation declarations but no UPDATE-style argument provenance. Private-read conflicts describe policy-scope mismatch, not proven end-to-end HTTP selector control.',
        'Admin-only protected-column denial, absent grants, role inheritance, dynamic/external protection and incomplete SQL cannot be certified here.',
        'No product API, persistent requirement, UI, Rule, Risk, score, snapshot, patch or automatic Finding behavior changed.'])

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['replay','evaluate']);p.add_argument('output',type=Path);p.add_argument('--plan',type=Path,required=True);p.add_argument('--root',type=Path);p.add_argument('--observed',type=Path);p.add_argument('--oracle',type=Path);p.add_argument('--verification',type=Path);a=p.parse_args()
    r=replay(read(a.plan),a.root) if a.mode=='replay' else evaluate(read(a.plan),read(a.observed),read(a.oracle))
    if a.verification:
        if a.mode!='evaluate' or a.verification.stat().st_size>256000:raise ValueError('VERIFICATION_METADATA_LIMIT')
        r['verification']=read(a.verification)
    write(a.output,r)
    print(dict(mode=a.mode,cases=r.get('cases',len(r.get('rows',[]))),matches=r.get('expectationMatches'),source=(r.get('originalSourceOnlyMetrics')or{}).get('counts'),intent=r.get('declaredIntentRequirementMetrics')))
    if a.mode=='evaluate' and r['expectationMatches']!=r['cases']:raise SystemExit(2)
