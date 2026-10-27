"""Authored static exposure controls; no target execution or credential validation."""
import argparse
from collections import Counter
import json
from pathlib import Path
import shutil
from application_track import outside, write
from mongoose18 import run, digest


def decision(c,r):
    found=[f for f in r['findings'] if f['ruleId']=='TS_SENSITIVE_DATA_EXPOSURE'
        and f['sink']['filePath']==c['input']['files'][0]['filePath']
        and f['sink']['kind'] in ('HTTP_RESPONSE','EXPRESS_HTTP_RESPONSE')]
    if c['truth']=='UNKNOWN':return 'UNEXPECTED_CANDIDATE' if found else 'UNKNOWN'
    if c['truth']=='RISK':return 'TP_STATIC_CONTRACT' if found else 'FN_INCLUDING_DEFERRED'
    if found:return 'FP_STATIC_CONTRACT'
    unresolved=any(u['status']=='FLOW_UNRESOLVED' for u in r['exposureUses']) or any(
        any(reason in f['limitations'] for reason in ['OBJECT_MEMBER_UNRESOLVED','OBJECT_SPREAD_UNRESOLVED','PROPERTY_WRITE_UNRESOLVED','OBJECT_DELETE_UNRESOLVED','EXPRESSION_UNSUPPORTED']) for f in r['files'])
    # Negative counts require the reviewed constant/field-selection control AND inspected scope.
    inspected=all(f['parseStatus']=='PARSED' for f in r['files']) and sum(f['entrypoints'] for f in r['files'])==1
    return 'NORMAL_DEFERRED_NOT_TN' if unresolved or not inspected else 'TN_REVIEWED_STATIC_CONTROL'


def evaluate(repo,baseline,output,prepare=None):
    node=shutil.which('node');fixture=repo/'analyzers/typescript/test/secret-flow-cases.mjs'
    cases=run(node,['--allow-fs-read='+str(fixture),'--input-type=module','-e',
        'import {secretCases} from '+json.dumps(fixture.as_uri())+';console.log(JSON.stringify(secretCases));'])
    rows=[]
    for c in cases:
        observations={}
        for label,source in [('before',baseline),('after',repo)]:
            worker=source/'analyzers/typescript';packet=json.dumps(c['input']).encode()
            a,b=[run(node,['--allow-fs-read='+str(worker),str(worker/'worker.mjs')],packet) for _ in range(2)]
            if a!=b:raise ValueError('NONDETERMINISM')
            observations[label]=dict(worker=a['analyzerVersion'],decision=decision(c,a),
                findings=[f for f in a['findings'] if f['ruleId']=='TS_SENSITIVE_DATA_EXPOSURE'],
                observations=a['exposureUses'],budget=a['supabaseAnalysis']['budgetUsage'])
        rows.append(dict(caseId=c['id'],framework=c['framework'],truth=c['truth'],inputSha256=digest(c['input']),**observations))
    result=dict(schemaVersion=1,grade='B_AUTHORED_NOT_INDEPENDENT',cases=len(rows),rows=rows,
        before=dict(Counter(r['before']['decision'] for r in rows)),after=dict(Counter(r['after']['decision'] for r in rows)),
        repeatIdentical=True,newRealApplicationTP=0,externalSourceExecuted=False,paidAiCalls=0,
        limitations=['Static source-name/format contracts are not actual credential validity or real service exploits.',
            'Normal deferred cases are not TN; unknown unexpected candidates are separate from known FP.',
            'Express request.url remains outside the environment-selector source contract.'])
    write(outside(output),result)
    if prepare:
        prepare=outside(prepare);projects=[]
        # Only authored literal canaries. No .env files from any retained project are read.
        for name in ['before','after']:
            content=(repo/'analyzers/typescript/evaluation/secret-lab'/(name+'.mjs')).read_text()
            projects.append((name,{'package.json':json.dumps({'dependencies':{'next':'15.3.0'}}),'app/api/check/route.js':content}))
        public='sb_publishable_'+'Ab2Cd3Ef4Gh5Jk6Lm7Np8Qr9St0Uv1Wx'
        private='sb_secret_'+'A'*32
        for name,key in [('publishable',public),('private',private)]:
            projects.append((name,{'package.json':json.dumps({'dependencies':{'vite':'5.4.0'}}),
                'src/main.ts':'export const token='+json.dumps(key)+';'}))
        plan=[]
        for name,files in projects:
            inventory=[]
            for path,content in files.items():
                data=content.encode();dest=prepare/'sources'/name/path;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);dest.chmod(0o600)
                inventory.append(dict(path=path,bytes=len(data),sha256=__import__('hashlib').sha256(data).hexdigest()))
            plan.append(dict(projectId=name,commitSha='AUTHORED_CONTROL_NOT_GIT_SHA_'+digest(inventory),files=inventory,collectionStatus='COLLECTED_GRADE_B_CONTROL',omitted=[]))
        write(prepare/'application-plan.json',dict(schemaVersion=1,projects=plan))
    print(json.dumps({k:v for k,v in result.items() if k!='rows'}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--repo',type=Path,required=True);p.add_argument('--baseline',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--prepare',type=Path)
    a=p.parse_args();evaluate(a.repo.resolve(),a.baseline.resolve(),a.output,a.prepare)
