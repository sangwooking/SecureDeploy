"""Pinned Next template with isolated, explicitly Grade B boundary controls.

Never runs the template. Modified copies are not upstream revisions or CVEs.
"""
import argparse
import copy
from pathlib import Path
import shutil
import subprocess
import json

import application_track as app
from benchmark import read, outside, digest, stable

TEMPLATE='vercel--nextjs-postgres-nextauth-tailwindcss-template'
CASES={
    'route-secret':('app/api/seed/route.ts',"export async function GET(){return Response.json({value:process.env.SERVER_SECRET});}", 'TP','TS_SENSITIVE_DATA_EXPOSURE','REGRESSION'),
    'route-destination':('app/api/seed/route.ts',"export async function POST(req:Request){const body=await req.json();await fetch(body.target);return Response.json({ok:true});}", 'TP','TS_SSRF_INPUT_FLOW','REGRESSION'),
    'route-fixed':('app/api/seed/route.ts',"export async function POST(req:Request){const body=await req.json();await fetch('https://service.example/?q='+encodeURIComponent(body.query));return Response.json({ok:true});}", 'TN','TS_SSRF_INPUT_FLOW','REGRESSION'),
    'action-secret':('app/(dashboard)/actions.ts',"'use server';export async function inspect(form:FormData){return {result:process.env.PRIVATE_KEY};}", 'TP','TS_SENSITIVE_DATA_EXPOSURE','VALIDATION'),
    'action-public':('app/(dashboard)/actions.ts',"'use server';export async function inspect(form:FormData){return {result:process.env.NEXT_PUBLIC_SITE_URL};}", 'TN','TS_SENSITIVE_DATA_EXPOSURE','VALIDATION'),
    'action-destination':('app/(dashboard)/actions.ts',"'use server';export async function inspect(form:FormData){await fetch(form.get('target'));return {ok:true};}", 'TP','TS_SSRF_INPUT_FLOW','VALIDATION'),
    'action-unknown':('app/(dashboard)/actions.ts',"'use server';export async function inspect(form:FormData){await fetch(transform(form.get('target')));return {ok:true};}", 'UNKNOWN','TS_SSRF_INPUT_FLOW','VALIDATION'),
}


def prepare(root,destination):
    root=outside(root);destination=outside(destination)
    plan=read(root/'application-plan.json')
    base=next(p for p in plan['projects']if p['projectId']==TEMPLATE)
    source=root/'sources'/TEMPLATE
    for f in base['files']:
        path=source/f['path']
        if path.is_symlink()or digest(path.read_bytes())!=f['sha256']:raise ValueError('SOURCE_HASH')
    destination.mkdir(mode=0o700);(destination/'sources').mkdir(mode=0o700)
    projects=[]
    for name,case in [('original',None),*CASES.items()]:
        p=copy.deepcopy(base);p['projectId']='next-boundary-'+name
        target=destination/'sources'/p['projectId'];shutil.copytree(source,target)
        if case:
            file,content,truth,rule,split=case
            path=target/file;path.write_text(content+'\n');path.chmod(0o600)
            f=next(f for f in p['files']if f['path']==file)
            f.update(sha256=digest(path.read_bytes()),bytes=path.stat().st_size)
            p.update(grade='B',evaluationSplit=split,groundTruth=truth,targetRule=rule,targetFile=file,
                     provenanceKind='CONTROLLED_VARIANT',sourceCommitMeaning='Pinned upstream base; modified copy identified by file hashes, not an upstream commit')
        else:p.update(grade='C',evaluationSplit='REGRESSION',groundTruth='UNVERIFIED_PROJECT_NOT_SAFE_OR_VULNERABLE_LABEL')
        projects.append(p)
    controlled=copy.deepcopy(plan);controlled['projects']=projects
    controlled['knownTruthPolicy']='Controlled target path only; no whole-app SAFE truth or real CVE claim'
    controlled['splits']='Same upstream project and curator; validation variants are not independent external or blind evaluation'
    app.write(destination/'application-plan.json',controlled)


def report(root,raw_file,output):
    root=outside(root);plan=read(root/'application-plan.json');raw=read(raw_file)
    if raw['planSha256']!=digest((root/'application-plan.json').read_bytes()):raise ValueError('PLAN_CHANGED')
    rows=[];counts={}
    for p in plan['projects']:
        actual=next(r for r in raw['projects']if r['projectId']==p['projectId']);runs=actual.get('runs',[])
        if len(runs)!=2 or stable(runs[0])!=stable(runs[1]):raise ValueError('NONDETERMINISTIC_OR_INCOMPLETE')
        r=runs[0];ts=r['typescript'];target=p.get('targetFile');rule=p.get('targetRule')
        structural=[f for f in ts.get('findings',[])if f['ruleId']==rule and f['sink']['filePath']==target]
        final=[f for f in r['reviewCandidates']if f['ruleId']==rule and f['location']['filePath']==target]
        expected=p['groundTruth']
        if p['grade']=='B':
            found=bool(final)
            if expected in {'TP','TN'} and found!=(expected=='TP'):raise ValueError('TARGET_EXPECTATION_'+p['projectId'])
            if expected=='UNKNOWN' and found:raise ValueError('UNKNOWN_PROMOTED')
            split=p['evaluationSplit'];counts.setdefault(split,dict(TP=0,TN=0,FP=0,FN=0,UNKNOWN=0))[expected]+=1
        rows.append(dict(projectId=p['projectId'],grade=p['grade'],split=p['evaluationSplit'],truth=expected,
            targetRule=rule,structuralTargetFindings=len(structural),validatedTargetFindings=len(final),
            entries=ts['authorizationContexts'],files=ts['files'],httpUses=ts.get('httpUses'),exposureUses=ts.get('exposureUses'),
            ruleCount=len(r['filtered']),score=r['securityScore'],risk=r['risk']['prioritySummary'],
            elapsedMs=[v['elapsedMs']for v in runs],sampledParentHeapBytes=[v['parentHeapUsedBytes']for v in runs],repeatConsistent=True))
    app.write(output,dict(schemaVersion=1,engineCommit=raw['engineCommit'],planSha256=raw['planSha256'],
        repositoryUrl=plan['projects'][0]['repositoryUrl'],baseCommit=plan['projects'][0]['commitSha'],
        license=plan['projects'][0]['license'],counts=counts,projects=rows,
        independence='One previously observed public MIT template; controlled validation not independent/blind; no real CVE detection claim',
        safety='No target code execution/build/install/network/AI; isolated H2 evaluation; no user PostgreSQL changes',
        limitations=['Auth.js reexports and @ imports not resolved','No actual Next build, client bundle, Server Action invocation or middleware verification',
                     'Parent heap samples are not peak worker RSS','Supabase factory/context aliases remain unverified']))


def probe(root,analyzer,output):
    root=outside(root);plan=read(root/'application-plan.json');rows=[]
    # Only this trusted analyzer runs; target source is JSON, never imported.
    program="""import {pathToFileURL} from 'node:url';
    const {analyze,VERSION}=await import(pathToFileURL(process.argv[1]).href);
    let text='';for await(const chunk of process.stdin)text+=chunk;
    const result=analyze(JSON.parse(text));
    console.log(JSON.stringify({version:VERSION,status:result.status,findings:result.findings,
      entries:result.authorizationContexts}));"""
    for p in plan['projects']:
        source=root/'sources'/p['projectId'];files=[];manifests=[]
        for f in p['files']:
            path=source/f['path'];content=path.read_bytes()
            if path.is_symlink()or digest(content)!=f['sha256']:raise ValueError('SOURCE_HASH')
            if path.name=='package.json':
                document=json.loads(content);manifests.append(dict(filePath=f['path'],next=document.get('dependencies',{}).get('next')))
            if path.suffix in {'.js','.jsx','.ts','.tsx','.mjs','.cjs'}:files.append(dict(filePath=f['path'],content=content.decode()))
        completed=subprocess.run(['node','--input-type=module','-e',program,str(analyzer.resolve())],
            input=json.dumps(dict(files=sorted(files,key=lambda f:f['filePath']),nodeManifests=manifests)),
            text=True,capture_output=True,timeout=15,check=True)
        result=json.loads(completed.stdout)
        rows.append(dict(projectId=p['projectId'],version=result['version'],status=result['status'],
            targetFindings=sum(f['ruleId']==p.get('targetRule') and f['sink']['filePath']==p.get('targetFile')for f in result['findings']),
            entries=len(result['entries'])))
    app.write(output,dict(schemaVersion=1,planSha256=digest((root/'application-plan.json').read_bytes()),
        scope='Structure-only probe; not full Rule/FPR/Risk evaluation',projects=rows))


if __name__=='__main__':
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('prepare');p.add_argument('root',type=Path);p.add_argument('destination',type=Path)
    p=sub.add_parser('report');p.add_argument('root',type=Path);p.add_argument('raw_file',type=Path);p.add_argument('output',type=Path)
    p=sub.add_parser('probe');p.add_argument('root',type=Path);p.add_argument('analyzer',type=Path);p.add_argument('output',type=Path)
    args=vars(parser.parse_args());command=args.pop('cmd');dict(prepare=prepare,report=report,probe=probe)[command](**args)
