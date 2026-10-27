"""Frozen-worker comparison of local identity-filter evidence, not IDOR truth."""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
import time
from application_track import outside, write
from mongoose18 import run, digest


def facts(r):
    accesses=r['supabaseAnalysis']['accesses']
    return dict(worker=r['analyzerVersion'],findings=len(r['findings']),
        policyFindings=r['supabaseAnalysis']['findings'],
        identityFilters=sum(len((c.get('resultEvidence') or {}).get('userIdFilters',[]))
            for a in accesses for c in (a.get('authorizationEvidence') or {}).get('authChecks',[])),
        states=[(a.get('authorizationEvidence') or {}).get('state') for a in accesses],
        roles=[(a.get('authorizationEvidence') or {}).get('effectiveRole') for a in accesses],
        requestAssociations=sum(bool((a.get('authorizationEvidence') or {}).get('requestEntry')) for a in accesses),
        budget=r['supabaseAnalysis']['budgetUsage'])


def evaluate(repo,baseline,output):
    node=shutil.which('node');fixture=repo/'analyzers/typescript/test/access-control-cases.mjs'
    cases=run(node,['--allow-fs-read='+str(fixture),'--input-type=module','-e',
        'import {accessCases} from '+json.dumps(fixture.as_uri())+';console.log(JSON.stringify(accessCases));'])
    rows=[]
    for c in cases:
        observations={};raw={}
        for label,source in [('before',baseline),('after',repo)]:
            worker=source/'analyzers/typescript';started=time.monotonic()
            a,b=[run(node,['--allow-fs-read='+str(worker),str(worker/'worker.mjs')],json.dumps(c['input']).encode()) for _ in range(2)]
            if a!=b:raise ValueError('NONDETERMINISM')
            raw[label]=a;observations[label]=dict(facts(a),averageWallMs=round((time.monotonic()-started)*500,2))
        a,b=raw['before'],raw['after']
        if a['findings']!=b['findings'] or a['supabaseAnalysis']['findings']!=b['supabaseAnalysis']['findings'] or a['supabaseAnalysis']['tables']!=b['supabaseAnalysis']['tables']:
            raise ValueError('UNRELATED_SECURITY_JUDGMENT_CHANGED')
        after=observations['after']
        if after['identityFilters']!=c.get('observedExpected',c['expected']):raise ValueError('EVIDENCE_CONTRACT_FAILED')
        if any(r!='UNKNOWN' for r in after['roles']):raise ValueError('RUNTIME_ROLE_INFERRED')
        rows.append(dict(caseId=c['id'],desiredIdentityFilters=c['expected'],knownGap=c.get('knownGap'),inputSha256=digest(c['input']),**observations))
    result=dict(schemaVersion=1,baseline='8c35a52b409b61d424c82e1c48170b755bbc43ce',grade='B_AUTHORED_NOT_INDEPENDENT',cases=len(rows),rows=rows,
        beforeComplete=sum(r['before']['identityFilters']==r['desiredIdentityFilters'] for r in rows),
        afterComplete=sum(r['after']['identityFilters']==r['desiredIdentityFilters'] for r in rows),
        repeatIdentical=True,newRealIdorTP=0,runtimeAuthorizationTests=0,
        limitations=['Counts measure filter provenance only, not TP/TN or authorization success.',
            'No column name is an ownership schema assertion; intent, deployment, role and middleware remain unknown.',
            'An earlier argument escape still prevents proof of the second filter in one control.'])
    write(outside(output),result)
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();evaluate(a.repo.resolve(),a.baseline.resolve(),a.output)
