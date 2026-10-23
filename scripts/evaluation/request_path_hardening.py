"""Frozen-source request-path audit; no target execution or whole-project safety labels."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
from application_track import outside, relative, write
from benchmark import stable
from detection_deep_dive import PINS, outcome

def read(path):
    return json.loads(path.read_text())

def load(root, name, phase):
    suffix='release' if phase=='after' else phase
    result=read(root/(name+'-hardening2-'+suffix+'.json'))
    if len(result['projects'])!=1:raise ValueError('PROJECT_IDENTITY')
    project=result['projects'][0]
    if len(project.get('runs',[]))!=2 or stable(project['runs'][0])!=stable(project['runs'][1]):raise ValueError('REPEAT_MISMATCH')
    return result,project

def profile(root, worker, phase):
    root=outside(root);worker=worker.resolve();reports=[]
    if phase not in {'before','after'}:raise ValueError('PHASE')
    for name in ['juice-shop','goof-validation','dvna-vulnerable','dvna-remediated','next-supabase']:
        _,project=load(root,name,phase);row=project['runs'][0];plan=read(root/name/'application-plan.json')['projects'][0]
        source=root/name/'sources'/plan['projectId'];inventory={f['path']:f for f in plan['files']}
        def content(path):
            path=str(relative(path));file=source/path
            if file.is_symlink() or not file.resolve().is_relative_to(source.resolve()):raise ValueError('SOURCE_PATH')
            data=file.read_bytes()
            if hashlib.sha256(data).hexdigest()!=inventory[path]['sha256']:raise ValueError('SOURCE_HASH')
            return '\n'.join(data.decode().splitlines())
        submitted=row['typescript']['selectionCoverage']['submittedFiles']
        # These selected application trees contain no Supabase policy SQL inputs.
        if row['typescript']['supabaseAnalysis']['files']:raise ValueError('PROFILE_SCOPE_REQUIRES_JS_ONLY_SELECTION')
        files=[dict(filePath=f['filePath'],content=content(f['filePath'])) for f in row['typescript']['files'][:submitted]]
        manifests=[]
        for path in sorted(inventory):
            if not path.endswith('package.json'):continue
            try:deps=json.loads(content(path)).get('dependencies',{})
            except ValueError:continue
            manifests.append(dict(filePath=path,**{k:v for k,v in deps.items() if k in {'express','mongodb','next'}
                and isinstance(v,str) and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v)}))
        packet=json.dumps(dict(files=files,nodeManifests=manifests),ensure_ascii=False).encode()
        if len(packet)>1_200_000:raise ValueError('PACKET_LIMIT')
        measurements=[]
        for _ in range(2):
            start=time.monotonic();child=subprocess.Popen(['/usr/bin/time','-l','node','--max-old-space-size=192',
                str(Path(__file__).with_name('node_probe_worker.mjs')),str(worker/'analyzer.mjs')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}})
            try:stdout,stderr=child.communicate(packet,timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid,signal.SIGKILL);child.wait();raise ValueError('PROFILE_TIMEOUT')
            if child.returncode or len(stdout)>2_000_000:raise ValueError('PROFILE_FAILED')
            result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
            measurements.append(dict(wallMs=round((time.monotonic()-start)*1000),maxRssBytes=int(rss[1]) if rss else None,
                version=result['analyzerVersion'],entries=sum(f['entrypoints'] for f in result['files']),
                candidateCount=len(result['findings']),budgetUsage=result['supabaseAnalysis']['budgetUsage']))
        reports.append(dict(project=name,submittedFiles=len(files),inputSha256=hashlib.sha256(packet).hexdigest(),measurements=measurements))
    suffix='release' if phase=='after' else phase
    write(root/('request-path-resource-'+suffix+'.json'),dict(scope='FULL_SELECTED_JS_INCLUDING_PARSE_FAILURES; NOT_LIVE_BACKEND_REQUEST',
        workerHashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(worker.glob('*.mjs'))},projects=reports))
    print(json.dumps([dict(project=p['project'],rss=[m['maxRssBytes'] for m in p['measurements']]) for p in reports]))

def audit(root):
    root=outside(root);truth=read(root/'ground-truth-v2.json');pairs={};checks=[]
    for name in list(PINS)+['goof-validation','new-rest']:
        before,a=load(root,name,'before');after,b=load(root,name,'after')
        if before['planSha256']!=after['planSha256'] or a['commitSha']!=b['commitSha']:raise ValueError('INPUT_CHANGED')
        x,y=a['runs'][0],b['runs'][0];pairs[name]=(x,y)
        unchanged={k:stable(x[k])==stable(y[k]) for k in ['raw','filtered','securityScore','risk','sca']}
        if not all(unchanged.values()):raise ValueError('LEGACY_REGRESSION')
        checks.append(dict(project=name,sha=a['commitSha'],legacyUnchanged=unchanged,
            selection=[r['typescript']['selectionCoverage'] for r in [x,y]],
            parseStates=[dict(Counter(f['parseStatus'] for f in r['typescript']['files'])) for r in [x,y]],
            entries=[sum(f['entrypoints'] for f in r['typescript']['files']) for r in [x,y]],
            structuralCandidates=[len(r['typescript']['validatedFindings']) for r in [x,y]],
            coverage=[r['coverage']['status'] for r in [x,y]],
            elapsedMsBefore=[r['elapsedMs'] for r in a['runs']],elapsedMsAfter=[r['elapsedMs'] for r in b['runs']]))
    cases=[]
    for c in truth['cases']:
        x,y=pairs[c['project']]
        cases.append(dict(caseId=c['caseId'],truth=c['truth'],cwe=c['cwe'],filePath=c['filePath'],line=c['line'],
            fileSha256=c['fileSha256'],before=outcome(c,x),after=outcome(c,y)))
    original=read(root/'source-free-summary.json')
    if Counter(c['before'] for c in cases)!=Counter(original['counts']['after']):raise ValueError('PREVIOUS_BASELINE_CHANGED')
    before=read(root/'four-app-hardening2-before.json');after=read(root/'four-app-hardening2-release.json')
    if before['planSha256']!=after['planSha256']:raise ValueError('REGRESSION_PLAN_CHANGED')
    old={p['projectId']:p for p in before['projects']};regressions=[]
    for p in after['projects']:
        a=old[p['projectId']];x,y=a['runs'][0],p['runs'][0]
        if a['commitSha']!=p['commitSha'] or stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('REGRESSION_IDENTITY_OR_REPEAT')
        same={k:stable(x[k])==stable(y[k]) for k in ['raw','filtered','securityScore','risk','sca']}
        regressions.append(dict(project=p['projectId'],sha=p['commitSha'],legacyUnchanged=same,
            entries=[sum(f['entrypoints'] for f in r['typescript']['files']) for r in [x,y]],
            flowCounts=[len(r['typescript']['validatedFindings']) for r in [x,y]],
            clients=[len(r['typescript']['supabaseAnalysis']['clients']) for r in [x,y]],
            accesses=[len(r['typescript']['supabaseAnalysis']['accesses']) for r in [x,y]]))
        if not all(same.values()) or regressions[-1]['flowCounts'][0]!=regressions[-1]['flowCounts'][1]:raise ValueError('APPLICATION_REGRESSION')
    fragments=read(root/'juice-fragment-classification-v3.json')
    targets=['server.ts','routes/login.ts','routes/search.ts','routes/profileImageUrlUpload.ts']
    targetStates={phase:[f for f in pairs['juice-shop'][i]['typescript']['files'] if f['filePath'] in targets] for i,phase in enumerate(['before','after'])}
    result=dict(schemaVersion=1,baseline='315c7dfdc06811f5edf3bf9dd5a919e45f87af52',
        engineCommit=read(root/'juice-shop-hardening2-release.json')['engineCommit'],truthSha256=hashlib.sha256((root/'ground-truth-v2.json').read_bytes()).hexdigest(),
        counts={phase:dict(Counter(c[phase] for c in cases)) for phase in ['before','after']},cases=cases,
        projects=checks,regressionApps=regressions,juiceTargetStates=targetStates,fragmentAudit=fragments,
        newValidation=dict(repository='hagopj13/node-express-boilerplate',sha=checks[-1]['sha'],grade='C_CONTEXT_ONLY',
            wholeProjectTruth='UNKNOWN_NEVER_TN',limitation='Conditional initialization and array/forEach route registration remain outside proven request dispatch.'),
        conclusion='SERVER_FILE_AND_REQUEST_OPPORTUNITY_IMPROVED; NO_NEW_REAL_WORLD_TARGET_TP',
        policyChanges=False,userPostgresModified=False,originalCodeIncluded=False,externalIndependentReview=False)
    write(root/'request-path-release-summary.json',result)
    print(json.dumps(dict(counts=result['counts'],projects=len(checks),regressionApps=len(regressions))))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--worker',type=Path);p.add_argument('--phase',choices=['before','after']);a=p.parse_args()
    if a.worker:profile(a.root,a.worker,a.phase)
    else:audit(a.root)
