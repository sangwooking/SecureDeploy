"""Grade B policy-link controls on two pinned, licensed app trees. Never execute sources."""
import argparse
import copy
import json
from collections import Counter
from pathlib import Path
import shutil

from application_track import read,write,outside,digest
from benchmark import stable
from selection_readiness import summarize,next_summary,express_summary

CASES={
    'next-owner':('NEXT','CONFIRMED_POLICY_EVIDENCE','REGRESSION'),
    'next-broad':('NEXT','BROAD_ACCESS_REVIEW','REGRESSION'),
    'next-session':('NEXT','CONFIRMED_POLICY_EVIDENCE','REGRESSION'),
    'next-unknown':('NEXT','UNKNOWN','REGRESSION'),
    'edge-owner':('EDGE','CONFIRMED_POLICY_EVIDENCE','VALIDATION'),
    'edge-broad':('EDGE','BROAD_ACCESS_REVIEW','VALIDATION'),
    'edge-admin':('EDGE','ADMIN_ACCESS_REVIEW','VALIDATION'),
    'edge-unknown':('EDGE','UNKNOWN','VALIDATION'),
}

def prepare(vibe_root,next_root,destination):
    vibe_root=outside(vibe_root);next_root=outside(next_root);destination=outside(destination)
    if destination.exists():raise ValueError('NEW_DESTINATION_REQUIRED')
    plans={k:read(r/'application-plan.json')for k,r in [('EDGE',vibe_root),('NEXT',next_root)]}
    roots={'EDGE':vibe_root,'NEXT':next_root};ids={'EDGE':'nglguarino--echoverse-11labs','NEXT':'next-boundary-original'}
    destination.mkdir(mode=0o700);(destination/'sources').mkdir(mode=0o700);projects=[]
    for name,(kind,expected,split)in CASES.items():
        original=next(p for p in plans[kind]['projects']if p['projectId']==ids[kind]);source=roots[kind]/'sources'/ids[kind]
        if original.get('license')!='MIT':raise ValueError('VERIFIED_LICENSE_REQUIRED')
        for f in original['files']:
            p=source/f['path']
            if p.is_symlink()or not p.resolve().is_relative_to(source.resolve())or digest(p.read_bytes())!=f['sha256']:raise ValueError('SOURCE_HASH_OR_PATH')
        p=copy.deepcopy(original);p['projectId']='supabase-auth-'+name;target=destination/'sources'/p['projectId'];shutil.copytree(source,target)
        route='app/api/seed/route.ts'if kind=='NEXT'else'supabase/functions/policy-probe/index.ts'
        helper='lib/security-client.ts'if kind=='NEXT'else'supabase/functions/policy-probe/client.ts'
        sql='supabase/migrations/20261022000000_controlled_notes.sql'
        factory="import {createServerClient} from '@supabase/ssr';import {cookies} from 'next/headers';export async function make(){const jar=await cookies();return createServerClient(process.env.SUPABASE_URL,process.env.ANON_KEY,{cookies:{getAll(){return jar.getAll()},setAll(values){values.forEach(({name,value,options})=>jar.set(name,value,options))}}});}"if kind=='NEXT'else"import {createClient} from '@supabase/supabase-js';export function make(){return createClient(Deno.env.get('SUPABASE_URL'),Deno.env.get('ANON_KEY'));}"
        constructor='externalFactory()'if name.endswith('unknown')else'await make()'if kind=='NEXT'else'make()'
        session="await db.auth.getSession();"if name=='next-session'else''
        if kind=='NEXT':
            code=f"import {{make}} from '../../../lib/security-client';export async function POST(req:Request){{const db={constructor};{session}const services={{db}};return Response.json(await services.db.from('notes').update({{label:'synthetic'}}));}}"
        elif name=='edge-owner':
            code="import {withSupabase} from 'npm:@supabase/server@1';export default {fetch:withSupabase({auth:'user'},async(req,ctx)=>Response.json(await ctx.supabase.from('notes').update({label:'synthetic'})))};"
        elif name=='edge-admin':
            code="import {withSupabase} from 'npm:@supabase/server@1';export default {fetch:withSupabase({auth:'user'},async(req,ctx)=>Response.json(await ctx.supabaseAdmin.from('notes').update({label:'synthetic'})))};"
        else:
            code=f"import {{make}} from './client';Deno.serve(async(req)=>{{const db={constructor};return Response.json(await rows(db));}});function rows(client){{return client.from('notes').update({{label:'synthetic'}});}}"
        condition='true'if name.endswith('broad')else'auth.uid()=user_id'
        policy=f"CREATE TABLE public.notes(user_id uuid,label text);ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;GRANT SELECT,INSERT,UPDATE,DELETE ON public.notes TO authenticated;CREATE POLICY controlled_owner ON public.notes FOR ALL TO authenticated USING({condition}) WITH CHECK({condition});"
        by_path={f['path']:f for f in p['files']}
        manifest_path=target/'package.json'
        manifest=json.loads(manifest_path.read_text())if manifest_path.exists()else dict(private=True)
        deps=manifest.setdefault('dependencies',{});deps.setdefault('@supabase/supabase-js','*')
        if kind=='NEXT':deps.setdefault('@supabase/ssr','*')
        for file,text in [(route,code),(helper,factory),(sql,policy),('package.json',json.dumps(manifest,indent=2))]:
            path=target/file;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text+'\n');path.chmod(0o600)
            by_path[file]=dict(path=file,sha256=digest(path.read_bytes()),bytes=path.stat().st_size)
        p.update(files=list(by_path.values()),grade='B',evaluationSplit=split,targetFile=route,targetState=expected,
            provenanceKind='CONTROLLED_VARIANT',groundTruth='NAMED_CLIENT_OPERATION_AND_REPOSITORY_POLICY_ONLY',
            sourceCommitMeaning='Pinned licensed upstream base; modified files identified by hashes, not an upstream commit')
        projects.append(p)
    plan=copy.deepcopy(plans['NEXT']);plan['projects']=projects
    plan['knownTruthPolicy']='No real CVE or whole-app safety labels; identity API observations are not authentication success'
    plan['splits']='Two upstream structures, same curator; validation is not independent authorship or blind evaluation'
    write(destination/'application-plan.json',plan)

def report(root,raw_file,before_file,after_file,output,next_file=None,express_file=None):
    root=outside(root);plan=read(root/'application-plan.json');raw=read(raw_file)
    if raw['planSha256']!=digest((root/'application-plan.json').read_bytes()):raise ValueError('PLAN_HASH')
    expected={'supabase-auth-'+n for n in CASES}
    if {p['projectId']for p in plan['projects']}!=expected or {p['projectId']for p in raw['projects']}!=expected:raise ValueError('CONTROL_CASE_SET')
    for p in plan['projects']:
        if p['grade']!='B'or p['targetState']!=CASES[p['projectId'].removeprefix('supabase-auth-')][1]:raise ValueError('CONTROL_TRUTH_CHANGED')
    rows=[];counts={}
    for p in plan['projects']:
        actual=next(x for x in raw['projects']if x['projectId']==p['projectId']);runs=actual.get('runs',[])
        if len(runs)!=2 or stable(runs[0])!=stable(runs[1]):raise ValueError('REPEAT_OR_COMPLETENESS')
        s=runs[0]['typescript']['supabaseAnalysis'];access=[a for a in s['accesses']if a['location']['filePath']==p['targetFile']and a['table']=='public.notes']
        if len(access)!=1:raise ValueError('TARGET_OPERATION_MISSING')
        e=access[0].get('authorizationEvidence');observed=e['state']if e else'NOT_INSPECTED'
        if observed!=p['targetState']:raise ValueError('POLICY_LINK_MISMATCH:'+p['projectId'])
        if e['effectiveRole']!='UNKNOWN':raise ValueError('RUNTIME_ROLE_OVERCLAIM')
        if p['projectId'].endswith('next-session')and e['authStatus']!='SESSION_READ_UNVERIFIED':raise ValueError('SESSION_IS_NOT_IDENTITY')
        counts.setdefault(p['evaluationSplit'],Counter())[observed]+=1
        rows.append(dict(caseId=p['projectId'],baseSha=p['commitSha'],targetFile=p['targetFile'],expected=p['targetState'],observed=observed,
            clientStatus=access[0]['clientStatus'],authStatus=e['authStatus'],policyStates=e['policyStates'],clientTrace=e['clientTrace'],policyLocations=e['policyLocations'],
            elapsedMs=[r['elapsedMs']for r in runs],budget=s.get('budgetUsage')))
    before=read(before_file);after=read(after_file)
    if before['planSha256']!=after['planSha256']or raw['engineCommit']!=after['engineCommit']:raise ValueError('ENGINE_OR_ORIGINAL_PLAN')
    original=[]
    for old in before['projects']:
        new=next(p for p in after['projects']if p['projectId']==old['projectId']);b=summarize(old);a=summarize(new)
        if old['commitSha']!=new['commitSha']or any(b[k]!=a[k]for k in ('ruleSignals','score','risk','structural')):raise ValueError('LEGACY_REGRESSION')
        s=new['runs'][0]['typescript']['supabaseAnalysis'];states=Counter(a.get('authorizationEvidence',{}).get('state','NOT_INSPECTED')for a in s['accesses'])
        original.append(dict(projectId=old['projectId'],sourceCommit=new['commitSha'],before=b,after=a,
            authorizationStates=dict(states),authCheckReferences=sum(len(a.get('authorizationEvidence',{}).get('authChecks',[]))for a in s['accesses']),
            uniqueAuthApiCalls=len({(c['method'],c['location']['filePath'],c['location']['line'],c['location']['column'])for a in s['accesses']for c in a.get('authorizationEvidence',{}).get('authChecks',[])}),
            limitations=s['limitations']))
    next_result=None
    if next_file:
        data=read(next_file)
        if data['engineCommit']!=raw['engineCommit']:raise ValueError('NEXT_ENGINE_MISMATCH')
        next_result=next_summary(data)
    express_result=express_summary(read(express_file),raw['engineCommit'])if express_file else None
    write(output,dict(schemaVersion=1,engineCommit=raw['engineCommit'],baselineEngine=before['engineCommit'],nextRegression=next_result,expressRegression=express_result,
        planSha256=raw['planSha256'],evaluatorSha256=digest(Path(__file__).read_bytes()),cases=rows,counts={k:dict(v)for k,v in counts.items()},original=original,
        remainingGaps=['Proxy/path aliases/reexports/TanStack middleware contexts are not resolved',
          'CopyMonster has 62 selected SQL files not run at the existing policy work cap; effective policy remains UNKNOWN',
          'Identity API calls do not prove successful guards or JWT application; operational project, DB roles and deployment remain unverified'],
        interpretation='Grade B named declaration links, not real CVEs or whole-app TP/TN; UNKNOWN is not safe. Same curator, no blind independent validation.',
        safety='Sources never executed/imported/installed; isolated H2, no operational Supabase/user DB/AI calls',
        limits='Existing 100000 shared steps and 15000 client steps; linking adds at most 5000 charged steps inside that client share. Prior declarations survive link truncation.'))

if __name__=='__main__':
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True)
    q=sub.add_parser('prepare')
    for n in ('vibe_root','next_root','destination'):q.add_argument(n,type=Path)
    q=sub.add_parser('report')
    for n in ('root','raw_file','before_file','after_file','output'):q.add_argument(n,type=Path)
    q.add_argument('--next-file',type=Path);q.add_argument('--express-file',type=Path)
    a=vars(p.parse_args());globals()[a.pop('cmd')](**a)
