"""Grade-separated constructor/cursor replay. Target modules are never loaded."""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import tempfile
from application_track import read,write,outside,digest,relative
from receiver_provenance import execute,REPO
from node_worker_probe import packet,public_packet

BASELINE='b59bc764d872629112b7075ecc86bc6b71a201e7'

def control_packet(root,case):
    files=[];manifests=[];base=root/relative(case['caseId'])
    for item in case['files']:
        path=base/relative(item['path'])
        if path.is_symlink()or not path.resolve().is_relative_to(base.resolve()):raise ValueError('SOURCE_PATH')
        data=path.read_bytes()
        if digest(data)!=item['sha256']:raise ValueError('SOURCE_HASH')
        if path.suffix=='.cjs':files.append(dict(filePath=item['path'],content=data.decode()))
        elif item['path']=='package.json':
            deps=json.loads(data)['dependencies'];manifests=[dict(filePath='package.json',mongodb=deps['mongodb'],express=deps['express'])]
    data=json.dumps(dict(files=files,nodeManifests=manifests),separators=(',',':')).encode()
    if len(data)>1200000:raise ValueError('PACKET_LIMIT')
    return data

def classify(result,label):
    findings=[f for f in result['findings']if f['ruleId']=='JS_MONGO_WHERE_INPUT_FLOW'and f['sink']['filePath']=='repository.cjs']
    if any(f['confidence']=='HIGH'for f in findings):return 'TP'if label=='RISK'else 'FP'
    uses=[u for u in result['nodeUses']if u['ruleId']=='JS_MONGO_WHERE_INPUT_FLOW'and u['location']['filePath']=='repository.cjs']
    if findings or any(u['kind']in {'RECEIVER_NOT_VERIFIED','FLOW_UNRESOLVED','UNKNOWN'}for u in uses):return 'UNKNOWN'
    data_use=any(u['kind']=='DATA_QUERY_NOT_AUTHORIZATION_PROOF'and u['location']['filePath']=='repository.cjs'for u in result['nodeUses'])
    bounded=any(u['kind']=='STATIC_OR_DATA_ONLY'for u in uses)or data_use
    if not bounded:return 'NOT_INSPECTED'
    return 'FN'if label=='RISK'else 'TN'if label=='NORMAL'else 'UNKNOWN'

def evaluate(root,application_root,output,split,release_holdout=False,official_root=None):
    root=outside(root);output=outside(output);manifest=read(root/'manifest.json')
    if any(c.get('grade')!='B'or c.get('label')not in {'RISK','NORMAL','UNKNOWN'}for c in manifest['cases']):raise ValueError('GRADE_OR_LABEL')
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    if split=='HOLDOUT'and not release_holdout:raise ValueError('HOLDOUT_RELEASE_REQUIRED')
    if split=='HOLDOUT':
        if subprocess.check_output(['git','diff','HEAD','--','src/main','analyzers'],cwd=REPO).strip():raise ValueError('COMMITTED_ENGINE_REQUIRED')
        if subprocess.check_output(['git','ls-files','--others','--exclude-standard','--','src/main','analyzers'],cwd=REPO).strip():raise ValueError('COMMITTED_ENGINE_REQUIRED')
        event=root/'holdout-observed.json'
        if event.exists():raise ValueError('HOLDOUT_ALREADY_OBSERVED')
        write(event,dict(event='RESULTS_WILL_BE_OBSERVED',reuse='Regression material after this execution; not a blind independent corpus.'))
    rows=[]
    with tempfile.TemporaryDirectory(prefix='securedeploy-constructor-baseline-')as directory:
        base=Path(directory)
        for name in ['analyzer.mjs','node-server.mjs','destination.mjs','exposure.mjs']:
            (base/name).write_bytes(subprocess.check_output(['git','show',BASELINE+':analyzers/typescript/'+name],cwd=REPO))
        (base/'node_modules').symlink_to(REPO/'analyzers/typescript/node_modules',target_is_directory=True)
        for case in manifest['cases']:
            if case['split']!=split:continue
            data=control_packet(root,case)
            before=execute(base/'analyzer.mjs',data);after=execute(REPO/'analyzers/typescript/analyzer.mjs',data)
            rows.append(dict(caseId=case['caseId'],grade='B',label=case['label'],topology=case.get('topology','UNRECORDED'),before=before,after=after,
                beforeOutcome=classify(before,case['label']),afterOutcome=classify(after,case['label'])))
        node=None
        if split=='VALIDATION':
            sha,data=packet(outside(application_root))
            node=dict(sourceCommit=sha,before=execute(base/'analyzer.mjs',data),after=execute(REPO/'analyzers/typescript/analyzer.mjs',data))
        scope=None
        if official_root and split=='VALIDATION':
            sha,data=public_packet(outside(official_root))
            scope=dict(grade='C',sourceCommit=sha,before=execute(base/'analyzer.mjs',data),after=execute(REPO/'analyzers/typescript/analyzer.mjs',data),scored=False)
    result=dict(schemaVersion=1,baseline=BASELINE,engineCommit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
        workingTreeDiffSha256=digest(subprocess.check_output(['git','diff','HEAD','--','src/main','analyzers'],cwd=REPO)),
        manifestSha256=digest((root/'manifest.json').read_bytes()),baseRepository=manifest['baseRepository'],baseCommit=manifest['baseCommit'],
        grade='B',split=split,cases=rows,nodegoatRegression=node,gradeCScope=scope,
        beforeCounts=dict(Counter(c['beforeOutcome']for c in rows)),afterCounts=dict(Counter(c['afterOutcome']for c in rows)),
        interpretation=manifest['independence'],gradeANewSupportedPairs=0,sourceExecution=False,userDatabaseUsed=False,
        note='TN applies only to the labeled controlled execution path, not the original Express example or whole application.')
    write(output,result);print(json.dumps(dict(split=split,cases=len(rows),before=result['beforeCounts'],after=result['afterCounts'])))

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ['root','application_root','output']:p.add_argument(name)
    p.add_argument('--split',choices=['VALIDATION','HOLDOUT'],default='VALIDATION');p.add_argument('--release-holdout',action='store_true')
    p.add_argument('--official-root')
    evaluate(**vars(p.parse_args()))
