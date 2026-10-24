"""Source-free comparison and resource receipts for Node entry/module contracts."""
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
from application_track import read, write, outside
from benchmark import stable

def identities(row):
    return sorted((f['ruleId'],f['location']['filePath'],f['location']['line'],f['location']['column'])
                  for f in row['typescript']['validatedFindings'])

def summary(row):
    ts=row['typescript'];sb=ts['supabaseAnalysis']
    return dict(entries=sum(f['entrypoints'] for f in ts['files']),findings=identities(row),
        selected=ts['selectionCoverage']['submittedFiles'],parsed=sum(f['parseStatus']=='PARSED' for f in ts['files']),
        selectedCharacters=ts['selectionCoverage']['submittedCharacters'],
        clients=len(sb['clients']),accesses=len(sb['accesses']),budget=sb['budgetUsage'],
        limits=dict(Counter(l for f in ts['files'] for l in f['limitations'])),
        manifestSelected=[f['filePath'] for f in ts['files'] if f.get('selectionReason')=='TS_NODE_MANIFEST_ENTRY_HINT' and f['parseStatus']=='PARSED'],
        score=row['securityScore'],coverage=row['coverage']['status'],risk=row['risk']['prioritizedDeploymentAssessment'])

def compare(spec,output):
    reports=[]
    for item in read(spec)['receipts']:
        before,after=read(Path(item['before'])),read(Path(item['after']))
        if before['planSha256']!=after['planSha256']:raise ValueError('PLAN_CHANGED')
        old={p['projectId']:p for p in before['projects']}
        if set(old)!={p['projectId'] for p in after['projects']}:raise ValueError('PROJECT_SET_CHANGED')
        for p in after['projects']:
            a=old[p['projectId']]
            if a['commitSha']!=p['commitSha'] or len(p['runs'])!=2:raise ValueError('SOURCE_OR_REPEAT_CHANGED')
            x,y=a['runs'][0],p['runs'][0]
            repeat=stable(p['runs'][0])==stable(p['runs'][1])
            unchanged={k:stable(x[k])==stable(y[k]) for k in ['raw','filtered','securityScore','risk','sca']}
            if not repeat or not all(unchanged.values()):raise ValueError('REPEAT_OR_LEGACY_REGRESSION')
            if not set(identities(x)).issubset(identities(y)):raise ValueError('STRUCTURAL_FINDING_REGRESSION')
            reports.append(dict(project=p['projectId'],sha=p['commitSha'],engine=after['engineCommit'],
                planSha256=after['planSha256'],before=summary(x),after=summary(y),
                legacyUnchanged=unchanged,repeatIdentical=repeat,elapsedMs=[r['elapsedMs'] for r in p['runs']],
                sampledParentHeapBytes=[r['parentHeapUsedBytes'] for r in p['runs']],
                targetTruth='REGRESSION_PREVIOUSLY_OBSERVED_NOT_NEW_HOLDOUT'))
    write(outside(output),dict(schemaVersion=1,baseline='effdc2d88f292628417df34c63b59290fff4767b',
        worker='ts-server-v22',projects=reports,targetExecuted=False,paidAiCalls=0,userDatabaseModified=False,
        limits='100 combined files, 100k chars/file, 1M source chars, 200k AST nodes, 100k steps, depth 3, 5s, Node old-space 192MiB unchanged',
        limitsOfEvidence=['Selection is not request execution. Module source linking is not runtime proof.',
            'FlintCMS class initialization, DB events and Mongoose query contracts remain unsupported.',
            'No new independent real-application or external-review accuracy claim.']))
    print(json.dumps(dict(projects=len(reports),legacyPreserved=True,repeatIdentical=True)))

def profile(root,receipt,output):
    root=outside(root);raw=read(receipt);plan=read(root/'application-plan.json')
    if raw['planSha256']!=hashlib.sha256((root/'application-plan.json').read_bytes()).hexdigest():raise ValueError('PLAN_HASH')
    reports=[];repo=Path(__file__).resolve().parents[2]
    for p in raw['projects']:
        original=next(x for x in plan['projects'] if x['projectId']==p['projectId'])
        inventory={f['path']:f for f in original['files']};source=root/'sources'/p['projectId']
        def content(name):
            target=source/name
            if target.is_symlink() or not target.resolve().is_relative_to(source.resolve()):raise ValueError('SOURCE_PATH')
            data=target.read_bytes()
            if hashlib.sha256(data).hexdigest()!=inventory[name]['sha256']:raise ValueError('SOURCE_HASH')
            return '\n'.join(data.decode().splitlines())
        row=p['runs'][0];ts=row['typescript'];manifests=[]
        for name in sorted(inventory):
            if name!='package.json' and not name.endswith('/package.json'):continue
            if len(manifests)>=100:break
            try:
                doc=json.loads(content(name));main=doc.get('main')
                m=dict(filePath=name,resolutionStatus='PARSED',moduleType=doc.get('type','commonjs'),
                       mainStatus='ABSENT' if not main else 'STATIC' if isinstance(main,str) else 'UNKNOWN')
                if m['mainStatus']=='STATIC':m['main']=main
                m.update({k:v for k,v in doc.get('dependencies',{}).items() if k in {'express','mongodb','next','sequelize'}
                    and isinstance(v,str) and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v)})
            except (ValueError,TypeError,AttributeError):m=dict(filePath=name,resolutionStatus='MALFORMED',mainStatus='UNKNOWN')
            manifests.append(m)
        directories={'.'}
        for name in inventory:directories.update(str(x) for x in Path(name).parents)
        coverage=row['coverage'];names=sorted((set(e['filePath'] for e in coverage['entries'])|directories)-{'.'})
        complete=not coverage['omittedEntries'] and len(names)<=1000 and '[redacted-path]' not in names
        packet=dict(files=[dict(filePath=f['filePath'],content=content(f['filePath'])) for f in ts['files'][:ts['selectionCoverage']['submittedFiles']]],
            nodeManifests=manifests,nodeSourceInventory=names[:1000],nodeSourceInventoryComplete=complete and coverage['inventoryComplete'],
            nodeEnumeratedDirectories=sorted(directories) if complete else [])
        data=json.dumps(packet).encode()
        if len(data)>1_200_000:raise ValueError('PROFILE_INPUT_LIMIT')
        runs=[]
        for _ in range(2):
            started=time.monotonic()
            child=subprocess.Popen(['/usr/bin/time','-l','node','--max-old-space-size=192',str(repo/'scripts/evaluation/node_probe_worker.mjs'),str(repo/'analyzers/typescript/analyzer.mjs')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}})
            try:stdout,stderr=child.communicate(data,timeout=10)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait();raise ValueError('PROFILE_TIMEOUT')
            if child.returncode or len(stdout)>2_000_000:raise ValueError('PROFILE_WORKER_FAILURE')
            result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
            if result['analyzerVersion']!='ts-server-v22':raise ValueError('WORKER_VERSION')
            runs.append(dict(wallMs=round((time.monotonic()-started)*1000),maxRssBytes=int(rss[1]) if rss else None,
                budget=result['supabaseAnalysis']['budgetUsage'],findings=len(result['findings'])))
        reports.append(dict(project=p['projectId'],sha=p['commitSha'],inputSha256=hashlib.sha256(data).hexdigest(),runs=runs))
    write(outside(output),dict(scope='STATIC_SELECTED_WORKER_ONLY_NOT_WHOLE_BACKEND_RSS',projects=reports,targetExecuted=False))
    print(json.dumps(dict(profiledProjects=len(reports))))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['compare','profile']);p.add_argument('input',type=Path);p.add_argument('output',type=Path);p.add_argument('--receipt',type=Path)
    a=p.parse_args()
    if a.command=='compare':compare(a.input,a.output)
    else:profile(a.input,a.receipt,a.output)
