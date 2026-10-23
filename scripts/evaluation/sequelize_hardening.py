"""Source-free comparison of pinned observations; never executes collected applications."""
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
from application_track import outside, write
from benchmark import stable
from detection_deep_dive import PINS, outcome

def read(path):
    return json.loads(path.read_text())

def audit(root, output, suffix='after', validation=None):
    root=outside(root)
    truth_path=root/'ground-truth-v2.json';truth=read(truth_path)
    pairs={};projects=[]
    for name in [*PINS,'goof-validation']:
        before=read(root/(name+'-hardening2-release.json'))
        after=read(root/(name+'-hardening3-'+suffix+'.json'))
        assert before['planSha256']==after['planSha256'], 'SOURCE_PLAN_CHANGED'
        a,b=before['projects'][0],after['projects'][0]
        assert a['commitSha']==b['commitSha'], 'SOURCE_SHA_CHANGED'
        assert len(b['runs'])==2 and stable(b['runs'][0])==stable(b['runs'][1]), 'REPEAT_MISMATCH'
        x,y=a['runs'][0],b['runs'][0];pairs[name]=(x,y)
        legacy={key:stable(x[key])==stable(y[key]) for key in ['raw','filtered','securityScore','risk','sca']}
        assert all(legacy.values()), 'LEGACY_REGRESSION'
        projects.append(dict(project=name,sha=b['commitSha'],engine=after['engineCommit'],legacyUnchanged=legacy,
            securityScore=[r['securityScore'] for r in [x,y]],legacyFindingCount=[len(r['filtered']) for r in [x,y]],
            candidates=[len(r['typescript']['validatedFindings']) for r in [x,y]],
            entries=[sum(f['entrypoints'] for f in r['typescript']['files']) for r in [x,y]],
            coverage=[r['coverage']['status'] for r in [x,y]],elapsedMs=[r['elapsedMs'] for r in b['runs']]))
    cases=[dict(caseId=c['caseId'],project=c['project'],sha=c['sha'],cwe=c['cwe'],truth=c['truth'],
        filePath=c['filePath'],line=c['line'],fileSha256=c['fileSha256'],
        before=outcome(c,pairs[c['project']][0]),after=outcome(c,pairs[c['project']][1])) for c in truth['cases']]
    before_count=dict(Counter(c['before'] for c in cases));after_count=dict(Counter(c['after'] for c in cases))
    assert before_count=={'NOT_SUPPORTED':7,'TP':2,'TN':1}, 'BASELINE_CHANGED'
    regression=[]
    before=read(root/'four-app-hardening2-release.json');after=read(root/('four-app-hardening3-'+suffix+'.json'))
    assert before['planSha256']==after['planSha256'], 'APP_PLAN_CHANGED'
    old={p['projectId']:p for p in before['projects']}
    for p in after['projects']:
        a=old[p['projectId']];assert a['commitSha']==p['commitSha']
        assert len(p['runs'])==2 and stable(p['runs'][0])==stable(p['runs'][1])
        x,y=a['runs'][0],p['runs'][0]
        same={k:stable(x[k])==stable(y[k]) for k in ['raw','filtered','securityScore','risk','sca']}
        assert all(same.values()), 'VIBE_LEGACY_REGRESSION'
        flows=[len(r['typescript']['validatedFindings']) for r in [x,y]]
        clients=[len(r['typescript']['supabaseAnalysis']['clients']) for r in [x,y]]
        accesses=[len(r['typescript']['supabaseAnalysis']['accesses']) for r in [x,y]]
        assert flows[0]==flows[1] and clients[0]==clients[1] and accesses[0]==accesses[1], 'VIBE_FLOW_REGRESSION'
        regression.append(dict(project=p['projectId'],sha=p['commitSha'],legacyUnchanged=same,flows=flows,clients=clients,accesses=accesses))
    failures=[]
    for c in cases:
        if c['caseId'] not in {'dvna-sql','dvna-2017-sql-still-present'}:continue
        failures.append(dict(c,rootCause='Missing declared Sequelize constructor/query contract plus branch-created registry initialization provenance.',
            commonImprovement='Closed initialization grammar over complete supplied inventory; define-only model summaries; versioned native query receiver.',
            normalCounterpart='dvna-model-query-counterpart remains NOT_SUPPORTED: removed raw query is documented, Model.find origin is not proven.',
            patch='https://github.com/appsecco/dvna/commit/dc1f9c54685eb04f55e444370d6d622834e4cc00',
            routeEvidence=['server.js:38 /app mount','routes/app.js:50 POST /usersearch','core/appHandler.js:8 userSearch'],
            flowEvidence=[f['evidence'][0]['flow'] for f in pairs[c['project']][1]['typescript']['validatedFindings']
                if f['ruleId']=='JS_SEQUELIZE_SQL_INPUT_FLOW' and f['location']['filePath']==c['filePath'] and f['location']['line']==c['line']],
            remainingHypotheses=['Middleware validation and runtime DB execution are not proven.','Installed dependency versions and deployed model directory may differ.'],
            regressionTest='analyzers/typescript/test/sequelize.test.mjs',
            limitation='Same DVNA project and vulnerability family, not independent project successes.'))
    result=dict(schemaVersion=1,baseline='2835484429802cffe847914c4bf83b10de5ffe4b',
        baselineReceipt='hardening2-release: production bytes identical; no new baseline API execution claimed',
        truthSha256=hashlib.sha256(truth_path.read_bytes()).hexdigest(),counts=dict(before=before_count,after=after_count),
        originalRiskDenominator=8,cases=cases,projects=projects,regressionApps=regression,failureCasePack=failures,
        interpretation='New TP through support expansion, not a pre-existing supported-contract FN repair; normal ORM counterpart is not TN.',
        independentExternalReview=False,policyChanged=False,userDatabaseModified=False,targetExecuted=False,originalCodeIncluded=False)
    if validation:
        validation=outside(validation);a=read(validation/'baseline.json');b=read(validation/(suffix+'.json'))
        assert a['planSha256']==b['planSha256']
        x,y=a['projects'][0],b['projects'][0]
        assert x['commitSha']==y['commitSha'] and len(y['runs'])==2 and stable(y['runs'][0])==stable(y['runs'][1])
        legacy={k:stable(x['runs'][0][k])==stable(y['runs'][0][k]) for k in ['raw','filtered','securityScore','risk','sca']}
        assert all(legacy.values())
        plan=read(validation/'application-plan.json')['projects'][0]
        result['newValidation']=dict(repository=plan['full_name'],sha=y['commitSha'],license=plan['license'],licenseFiles=plan['licenseFiles'],
            grade='C_CONTEXT_ONLY_NOT_TN',engine=b['engineCommit'],repeatIdentical=True,legacyUnchanged=legacy,
            entries=[sum(f['entrypoints'] for f in r['typescript']['files']) for r in [x['runs'][0],y['runs'][0]]],
            flows=[len(r['typescript']['validatedFindings']) for r in [x['runs'][0],y['runs'][0]]],
            limits=['Array-based model setup, custom associations and dynamic route loops remain unsupported.',
                    'No independent risk/fixed pair or external reviewer. No Grade C negative is scored TN.'])
    resource=root/('sequelize-resource-'+suffix+'.json')
    if resource.exists():result['workerResourceProfile']=read(resource)
    write(Path(output),result)
    print(json.dumps(result['counts']))

def profile(root, worker, label):
    root=outside(root);worker=worker.resolve();reports=[]
    if label not in {'before','release','verified','complete'}:raise ValueError('PROFILE_LABEL')
    for name in ['dvna-vulnerable','dvna-remediated','juice-shop','goof-validation']:
        plan=read(root/name/'application-plan.json')['projects'][0]
        suffix='hardening2-release' if label=='before' else 'hardening3-'+label
        row=read(root/(name+'-'+suffix+'.json'))['projects'][0]['runs'][0]
        source=root/name/'sources'/plan['projectId'];inventory={f['path']:f for f in plan['files']}
        def content(file):
            if file not in inventory:raise ValueError('SOURCE_INVENTORY')
            target=source/file
            if target.is_symlink() or not target.resolve().is_relative_to(source.resolve()):raise ValueError('SOURCE_PATH')
            data=target.read_bytes()
            if hashlib.sha256(data).hexdigest()!=inventory[file]['sha256']:raise ValueError('SOURCE_HASH')
            return '\n'.join(data.decode().splitlines())
        ts=row['typescript'];files=[dict(filePath=f['filePath'],content=content(f['filePath'])) for f in ts['files'][:ts['selectionCoverage']['submittedFiles']]]
        manifests=[]
        for file in sorted(inventory):
            if not file.endswith('package.json'):continue
            try:deps=json.loads(content(file)).get('dependencies',{})
            except ValueError:continue
            keys={'express','mongodb','next'}|({'sequelize'} if label!='before' else set())
            manifests.append(dict(filePath=file,**{k:v for k,v in deps.items() if k in keys and isinstance(v,str)
                and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v)}))
        packet=dict(files=files,nodeManifests=manifests)
        if label!='before':
            coverage=row['coverage'];directories={'.'}
            for file in inventory:
                directories.update(str(p) for p in Path(file).parents)
            names=sorted((set(e['filePath'] for e in coverage['entries'])|directories)-{'.'})
            complete=not coverage['omittedEntries'] and len(names)<=1000 and '[redacted-path]' not in names
            packet.update(nodeSourceInventory=names[:1000],nodeSourceInventoryComplete=coverage['inventoryComplete'] and complete,
                nodeEnumeratedDirectories=sorted(directories) if complete and len(directories)<=1000 else [])
        data=json.dumps(packet).encode()
        if len(data)>1_200_000:raise ValueError('PROFILE_INPUT_LIMIT')
        runs=[]
        for _ in range(2):
            start=time.monotonic();process=subprocess.Popen(['/usr/bin/time','-l','node','--max-old-space-size=192',str(Path(__file__).with_name('node_probe_worker.mjs')),str(worker/'analyzer.mjs')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}})
            try:stdout,stderr=process.communicate(data,timeout=10)
            except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait();raise ValueError('PROFILE_TIMEOUT')
            if process.returncode or len(stdout)>2_000_000:raise ValueError('PROFILE_FAILURE')
            result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
            runs.append(dict(wallMs=round((time.monotonic()-start)*1000),maxRssBytes=int(rss[1]) if rss else None,
                version=result['analyzerVersion'],budget=result['supabaseAnalysis']['budgetUsage'],candidates=len(result['findings'])))
        reports.append(dict(project=name,inputSha256=hashlib.sha256(data).hexdigest(),runs=runs))
    write(root/('sequelize-resource-'+label+'.json'),dict(scope='FULL_SELECTED_SOURCE_STATIC_WORKER_PROFILE_NOT_LIVE_BACKEND_RSS',
        workerHashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in worker.glob('*.mjs')},projects=reports))
    print(json.dumps(reports))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('output',type=Path,nargs='?')
    parser.add_argument('--suffix',default='after');parser.add_argument('--worker',type=Path);parser.add_argument('--profile',choices=['before','release','verified','complete'])
    parser.add_argument('--validation',type=Path)
    args=parser.parse_args()
    if args.worker:profile(args.root,args.worker,args.profile)
    elif args.output:audit(args.root,args.output,args.suffix,args.validation)
    else:parser.error('output or --worker/--profile required')
