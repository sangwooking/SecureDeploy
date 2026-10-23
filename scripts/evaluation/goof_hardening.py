"""Pinned source-free regression receipt; never loads target modules or executes regexes."""
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

def audit(root, output, suffix='verified'):
    root=outside(root);pairs={};projects=[]
    for name in [*PINS,'goof-validation']:
        a=read(root/(name+'-hardening3-complete.json'))
        b=read(root/(name+'-hardening4-'+suffix+'.json'))
        assert a['planSha256']==b['planSha256']
        x,y=a['projects'][0],b['projects'][0]
        assert x['commitSha']==y['commitSha']
        assert len(y['runs'])==2 and stable(y['runs'][0])==stable(y['runs'][1])
        before,after=x['runs'][0],y['runs'][0];pairs[name]=(before,after)
        unchanged={k:stable(before[k])==stable(after[k]) for k in ['raw','filtered','securityScore','risk','sca']}
        assert all(unchanged.values()),'LEGACY_REGRESSION'
        projects.append(dict(project=name,sha=y['commitSha'],engine=b['engineCommit'],legacyUnchanged=unchanged,
            candidates=[len(r['typescript']['validatedFindings']) for r in [before,after]],
            entries=[sum(f['entrypoints'] for f in r['typescript']['files']) for r in [before,after]],
            elapsedMs=[r['elapsedMs'] for r in y['runs']],repeatIdentical=True))
    truth=read(root/'ground-truth-v2.json')
    cases=[dict(caseId=c['caseId'],before=outcome(c,pairs[c['project']][0]),after=outcome(c,pairs[c['project']][1])) for c in truth['cases']]
    counts={key:dict(Counter(c[key] for c in cases)) for key in ['before','after']}
    assert counts['before']==counts['after']=={'TP':4,'TN':1,'NOT_SUPPORTED':5}
    before,after=pairs['goof-validation']
    def target(row):
        return [f for f in row['typescript']['validatedFindings'] if f['ruleId']=='JS_SHELL_COMMAND_INPUT_FLOW'
            and f['location']['filePath']=='routes/index.js' and f['location']['line']==174]
    assert not target(before) and len(target(after))==1
    finding=target(after)[0];evidence=finding['evidence'][0]
    assert evidence['source']['line']==168 and any(p['kind']=='REGEX_CAPTURE' and p['line']==171 for p in evidence['flow'])
    assert finding['priority']=='REVIEW_REQUIRED' and finding['comparisonPolicy']=='NOT_COMPARED'
    apps=[]
    a=read(root/'four-app-hardening3-complete.json');b=read(root/('four-app-hardening4-'+suffix+'.json'))
    assert a['planSha256']==b['planSha256'];old={p['projectId']:p for p in a['projects']}
    for p in b['projects']:
        x,y=old[p['projectId']],p
        assert x['commitSha']==y['commitSha'] and stable(y['runs'][0])==stable(y['runs'][1])
        unchanged={k:stable(x['runs'][0][k])==stable(y['runs'][0][k]) for k in ['raw','filtered','securityScore','risk','sca']}
        assert all(unchanged.values())
        measures=lambda r:[len(r['typescript']['validatedFindings']),len(r['typescript']['supabaseAnalysis']['clients']),len(r['typescript']['supabaseAnalysis']['accesses'])]
        assert measures(x['runs'][0])==measures(y['runs'][0])
        apps.append(dict(project=p['projectId'],sha=p['commitSha'],legacyUnchanged=unchanged,flowClientAccess=measures(y['runs'][0]),repeatIdentical=True))
    plan=read(root/'goof-validation/application-plan.json')['projects'][0]
    selected=[p for p in plan['files'] if p['path'] in ['app.js','routes/index.js','exploits/shell-injection.md','LICENSE']]
    result=dict(schemaVersion=1,baseline='3ceb6de3b7e2bdb0b82564937d18df1986ffe853',engine=b['engineCommit'],
        originalRiskDenominator=8,originalPathCount=10,counts=counts,cases=cases,projects=projects,regressionApps=apps,
        goof=dict(grade='DOCUMENTED_VULNERABLE_APPLICATION_NO_VERIFIED_FIX_PAIR',split='REGRESSION_NOT_BLIND',
            repository='https://github.com/snyk-labs/nodejs-goof',sha=plan['commitSha'],license=plan['license'],sourceHashes=selected,
            before='NOT_SUPPORTED',after='TP',finding=finding,
            reference='https://github.com/snyk-labs/nodejs-goof/blob/'+plan['commitSha']+'/exploits/shell-injection.md',
            failureCasePack=dict(confirmedCauses=['Unsupported regex literal and typeof; unknown extraction result without capture/null semantics.',
                'Logical condition heap merge erased unrelated native command API identity.',
                'Unrelated unknown external data-property write marked all subsequent request paths uncertain.'],
                improvement='Bounded regex syntax/capture summaries, state-local successful match refinement, pure-match condition evaluation, scoped external data-write uncertainty.',
                evidence=evidence,normalCounterparts='Synthetic overwrite, fixed input, ASCII token after fixed executable, execFile argv, user-defined function.',
                remaining=['No target or regex execution; middleware, runtime shell and setter behavior not proven.',
                    'No real fixed-pair or independent external reviewer; Goof observed during development.',
                    'NoSQL login, dynamic regex, global/sticky captures, lookaround/backreferences, dynamic slots and external sanitizers not added.'],
                regression='analyzers/typescript/test/regex-flow.test.mjs')),
        independentNewApplicationSuccess=False,externalIndependentReview=False,policyChanged=False,userDatabaseModified=False,
        targetExecuted=False,paidAiCalls=0,originalCodeIncluded=False)
    write(Path(output),result)
    print(json.dumps(dict(counts=counts,goof=result['goof']['after'],projects=len(projects),apps=len(apps))))

def profile(root,worker,output,suffix='verified'):
    root=outside(root);worker=worker.resolve();reports=[]
    for name in ['goof-validation','dvna-vulnerable','dvna-remediated','juice-shop']:
        plan=read(root/name/'application-plan.json')['projects'][0]
        row=read(root/(name+'-hardening4-'+suffix+'.json'))['projects'][0]['runs'][0]
        source=root/name/'sources'/plan['projectId'];inventory={f['path']:f for f in plan['files']}
        def content(name):
            target=source/name
            assert name in inventory and not target.is_symlink() and target.resolve().is_relative_to(source.resolve())
            data=target.read_bytes();assert hashlib.sha256(data).hexdigest()==inventory[name]['sha256']
            return '\n'.join(data.decode().splitlines())
        ts=row['typescript'];files=[dict(filePath=f['filePath'],content=content(f['filePath'])) for f in ts['files'][:ts['selectionCoverage']['submittedFiles']]]
        manifests=[]
        for file in sorted(inventory):
            if not file.endswith('package.json'):continue
            try:deps=json.loads(content(file)).get('dependencies',{})
            except ValueError:continue
            manifests.append(dict(filePath=file,**{k:v for k,v in deps.items() if k in {'express','mongodb','next','sequelize'}
                and isinstance(v,str) and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v)}))
        coverage=row['coverage'];directories={'.'}
        for file in inventory:directories.update(str(p) for p in Path(file).parents)
        names=sorted((set(e['filePath'] for e in coverage['entries'])|directories)-{'.'})
        complete=not coverage['omittedEntries'] and len(names)<=1000 and '[redacted-path]' not in names
        packet=dict(files=files,nodeManifests=manifests,nodeSourceInventory=names[:1000],
            nodeSourceInventoryComplete=coverage['inventoryComplete'] and complete,
            nodeEnumeratedDirectories=sorted(directories) if complete and len(directories)<=1000 else [])
        data=json.dumps(packet).encode();assert len(data)<=1_200_000
        runs=[]
        for _ in range(2):
            start=time.monotonic()
            p=subprocess.Popen(['/usr/bin/time','-l','node','--max-old-space-size=192',str(Path(__file__).with_name('node_probe_worker.mjs')),str(worker/'analyzer.mjs')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}})
            try:stdout,stderr=p.communicate(data,timeout=10)
            except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait();raise ValueError('PROFILE_TIMEOUT')
            assert p.returncode==0 and len(stdout)<=2_000_000
            result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
            runs.append(dict(wallMs=round((time.monotonic()-start)*1000),maxRssBytes=int(rss[1]) if rss else None,
                version=result['analyzerVersion'],budget=result['supabaseAnalysis']['budgetUsage'],candidates=len(result['findings'])))
        reports.append(dict(project=name,inputSha256=hashlib.sha256(data).hexdigest(),runs=runs))
    write(Path(output),dict(scope='SELECTED_STATIC_WORKER_NOT_BACKEND_RSS',projects=reports))
    print(json.dumps(reports))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('output',type=Path)
    parser.add_argument('--worker',type=Path);parser.add_argument('--suffix',default='verified')
    args=parser.parse_args()
    if args.worker:profile(args.root,args.worker,args.output,args.suffix)
    else:audit(args.root,args.output,args.suffix)
