"""Pre-labelled v1 freeze controls on licensed app trees; target code is never run."""
import argparse
import subprocess
from collections import Counter, defaultdict
import copy
import hashlib
import json
import re
from pathlib import Path
import shutil

from benchmark import outside, read, write, digest, stable

ENGINE = 'fb6bb350a8097601f8e5b5a0fd862dfba7c5cae4'
EXPOSURE = 'TS_SENSITIVE_DATA_EXPOSURE'
SSRF = 'TS_SSRF_INPUT_FLOW'
HTML = 'REACT_DANGEROUS_HTML'
RLS = 'SUPABASE_BROAD_WRITE_DECLARATION'


def controls(kind):
    records = []
    files = {}
    env = lambda name: f'Deno.env.get("{name}")' if kind == 'EDGE' else f'process.env.{name}'

    def add(name, area, truth, rule, path, content, needle, support='SUPPORTED', rationale='', **extra):
        if path in files:
            raise ValueError('DUPLICATE_CONTROL_FILE')
        files[path] = content + '\n'
        line = next(i+1 for i, text in enumerate(content.splitlines()) if needle in text)
        records.append(dict(caseId=kind.lower()+'-'+name, framework=kind, area=area, truth=truth,
            targetRule=rule, targetFile=path, targetLine=line, support=support,
            grade='B', rationale=rationale, **extra))

    def server(name, area, truth, rule, body, needle, prefix='', **extra):
        path = f'supabase/functions/freeze-{name}/index.ts' if kind == 'EDGE' else f'app/api/freeze/{name}/route.ts'
        opening = 'Deno.serve(async (req) => {' if kind == 'EDGE' else 'export async function POST(req: Request) {'
        closing = '});' if kind == 'EDGE' else '}'
        add(name, area, truth, rule, path, prefix+'\n'+opening+'\n'+body+'\n'+closing, needle, **extra)

    secret = env('BILLING_SECRET')
    public = env('SUPABASE_ANON_KEY' if kind == 'EDGE' else 'NEXT_PUBLIC_SUPABASE_ANON_KEY')
    server('secret-envelope','EXPOSURE','RISK',EXPOSURE,
        f'const credential={secret};\nreturn Response.json({{settings:{{credential}}}});','return Response.json',
        rationale='Private server configuration returned inside a nested response object.')
    server('secret-helper','EXPOSURE','RISK',EXPOSURE,
        f'return packageReply({secret});','return packageReply',
        prefix='function packageReply(value){return new Response(JSON.stringify({payload:value}));}',
        sinkFileLine=1,rationale='Local function parameter reaches a serialized HTTP response.')
    server('auth-log','EXPOSURE','RISK',EXPOSURE,
        'const supplied=req.headers.get("Authorization");\nconsole.warn("request credential",supplied);\nreturn new Response("done");','console.warn',
        rationale='Authorization header value is logged; actual log access is not proved.')
    server('public-key','EXPOSURE','NORMAL',EXPOSURE,
        f'return Response.json({{publishable:{public}}});','return Response.json',
        rationale='Explicitly public/anonymous configuration is not a private-server-secret leak.')
    server('private-internal','EXPOSURE','NORMAL',EXPOSURE,
        f'const credential={secret};\nawait fetch("https://billing.example.invalid/check",{{headers:{{Authorization:credential}}}});\nreturn Response.json({{ok:true}});','return Response.json',
        rationale='Private value stays in a fixed outbound service header, not the returned response.')
    server('presence-only','EXPOSURE','NORMAL',EXPOSURE,
        f'const configured={secret}!==undefined;\nreturn Response.json({{configured}});','return Response.json',
        rationale='Boolean presence information does not reveal the secret value.')
    server('opaque-mask','EXPOSURE','UNKNOWN',EXPOSURE,
        f'return Response.json(unknownRedactor({secret}));','return Response.json',
        rationale='Unprovided transform may remove or retain sensitive information.')

    server('body-relay','SSRF','RISK',SSRF,
        'const packet=await req.json();\nconst address=packet.destination;\nreturn relay(address);','return relay',
        prefix='function relay(destination){return fetch(destination);}',
        sinkFileLine=1, rationale='Request body controls a URL passed through a local function to fetch.')
    server('request-wrapper','SSRF','RISK',SSRF,
        'const address=new URL(req.url).searchParams.get("remote");\nreturn fetch(new Request(address));','return fetch',
        rationale='Query parameter controls the Request destination passed to fetch.')
    server('header-relay','SSRF','RISK',SSRF,
        'const destination=req.headers.get("X-Upstream");\nreturn fetch(destination);','return fetch',
        rationale='Caller-controlled request header determines the outbound destination.')
    server('fixed-query','SSRF','NORMAL',SSRF,
        'const body=await req.json();\nreturn fetch("https://catalog.example.invalid/search?q="+encodeURIComponent(body.term));','return fetch',
        rationale='Request data changes query data only, not the fixed authority.')
    server('url-query','SSRF','NORMAL',SSRF,
        'const endpoint=new URL("https://catalog.example.invalid/search");\nendpoint.searchParams.set("q",new URL(req.url).searchParams.get("q"));\nreturn fetch(endpoint);','return fetch',
        rationale='Parsed fixed URL is modified only through searchParams.')
    server('fixed-choice','SSRF','NORMAL',SSRF,
        'const body=await req.json();\nconst endpoint=body.region==="west"?"https://west.example.invalid/data":"https://east.example.invalid/data";\nreturn fetch(endpoint);','return fetch',
        rationale='Either branch selects a fixed server-owned destination.')
    server('opaque-address','SSRF','UNKNOWN',SSRF,
        'const body=await req.json();\nreturn fetch(unknownAddressPolicy(body.remote));','return fetch',
        rationale='Unprovided transform could validate or retain an arbitrary destination.')

    # Each React case has its own line; DOM contracts are explicitly unsupported.
    html_path='src/freeze-evaluation/HtmlCases.tsx' if kind=='EDGE' else 'app/freeze-evaluation/page.tsx'
    html_lines=["'use client';",'function RawQuery(){return <div dangerouslySetInnerHTML={{__html:new URL(location.href).searchParams.get("html")??""}}/>;}',
        'function DomInsert(){document.body.innerHTML=new URL(location.href).searchParams.get("html")??"";return null;}',
        'function Plain({value}:{value:string|null}){return <div>{value}</div>;}',
        'function FixedLink(){return <div dangerouslySetInnerHTML={{__html:\'<a href="https://example.invalid/policy">Policy</a>\'}}/>;}',
        'function Filtered({value}:{value:string|null}){const clean=(window as Window & {runtimeHtmlFilter?:(x:string|null)=>string}).runtimeHtmlFilter;if(!clean)return <p>Filter unavailable</p>;return <div dangerouslySetInnerHTML={{__html:clean(value)}}/>;}',
        ('export function EvaluationPanel'if kind=='EDGE'else'export default function EvaluationPanel')+'(){if(typeof window==="undefined")return null;const query=new URL(location.href).searchParams;const choice=query.get("case");if(choice==="raw")return <RawQuery/>;if(choice==="dom")return <DomInsert/>;if(choice==="link")return <FixedLink/>;if(choice==="unknown")return <Filtered value={query.get("html")}/>;return <Plain value={query.get("html")}/>;}']
    files[html_path]='\n'.join(html_lines)+'\n'
    for name,truth,line,support,rationale in [
        ('react-raw-query','RISK',2,'SUPPORTED','Decoded URL query value enters the React raw-HTML property directly on a rendered panel route.'),
        ('dom-insert','RISK',3,'NOT_SUPPORTED','Raw DOM innerHTML input; current React rule is not general DOM taint support.'),
        ('react-escaped','NORMAL',4,'SUPPORTED','React ordinary string child, not raw HTML insertion.'),
        ('react-link','NORMAL',5,'SUPPORTED','Known fixed HTTPS link with no active attributes; do not relabel normal as UNKNOWN.'),
        ('react-opaque','UNKNOWN',6,'SUPPORTED','Sanitizer contract is absent; sink review is not confirmed XSS.')]:
        records.append(dict(caseId=kind.lower()+'-'+name,framework=kind,area='HTML',truth=truth,grade='B',targetRule=HTML,
            targetFile=html_path,targetLine=line,support=support,rationale=rationale))

    sql_path='supabase/migrations/20261022000000_freeze_controls.sql'
    sql=[]
    client_body=[]
    for name,truth,operation,condition,role in [
        ('wide-update','RISK','UPDATE','true','authenticated'),
        ('wide-insert','RISK','INSERT','true','authenticated'),
        ('owner-update','NORMAL','UPDATE','auth.uid()=owner_id','authenticated'),
        ('public-read','NORMAL','SELECT','true','anon'),
        ('custom-owner','UNKNOWN','UPDATE','can_edit(owner_id)','authenticated'),
        ('session-only','UNKNOWN','SELECT','auth.uid()=owner_id','authenticated')]:
        table='freeze_'+kind.lower()+'_'+name.replace('-','_')
        sql += [f'CREATE TABLE public.{table}(owner_id uuid, label text);',f'ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY;',
            f'GRANT {operation} ON public.{table} TO {role};']
        clause=f'WITH CHECK({condition})' if operation=='INSERT' else f'USING({condition})'+(f' WITH CHECK({condition})' if operation=='UPDATE' else '')
        sql.append(f'CREATE POLICY declared_scope ON public.{table} FOR {operation} TO {role} {clause};')
        records.append(dict(caseId=kind.lower()+'-'+name,framework=kind,area='RLS',truth=truth,grade='B',
            targetRule=RLS,targetFile=sql_path,targetLine=len(sql),table='public.'+table,role=role,operation=operation,support='SUPPORTED',
            uncertaintyDimension='AUTH_SESSION'if name=='session-only'else'POLICY_FUNCTION'if name=='custom-owner'else None,
            rationale='Repository policy declaration only; private-row intent for write controls, deliberately public SELECT for public-read.' if truth!='UNKNOWN' else
                ('Custom policy function unavailable.' if name=='custom-owner' else 'Session read does not prove authentication success or object permission.')))
        op="update({label:'synthetic'})" if operation=='UPDATE' else "insert({label:'synthetic'})" if operation=='INSERT' else "select('*')"
        if name=='session-only':client_body.append('await db.auth.getSession();')
        client_body.append(f"await db.from('{table}').{op};")
    files[sql_path]='\n'.join(sql)+'\n'
    route='supabase/functions/freeze-policy-links/index.ts' if kind=='EDGE' else 'app/api/freeze/policy-links/route.ts'
    prefix="import {createClient} from '@supabase/supabase-js';\n"
    source_url=env('SUPABASE_URL' if kind=='EDGE' else 'NEXT_PUBLIC_SUPABASE_URL')
    source_key=public
    opening='Deno.serve(async(req)=>{' if kind=='EDGE' else 'export async function POST(req:Request){'
    files[route]=prefix+opening+'\n'+f'const db=createClient({source_url},{source_key});\n'+'\n'.join(client_body)+'\nreturn Response.json({ok:true});\n'+('});'if kind=='EDGE'else'}')+'\n'

    for name,truth,user in [('runtime-root','RISK','root'),('runtime-user','NORMAL','10001')]:
        add(name,'DEPLOYMENT',truth,'DOCKER_ROOT_USER',f'freeze-config/{name}/Dockerfile',
            f'FROM alpine:3.20 AS runtime\nUSER {user}\n',f'USER {user}',rationale='Explicit default final-stage USER declaration; no image or deployment execution.')
    for name,truth,version in [('sca-affected','RISK','4.17.20'),('sca-fixed','NORMAL','4.17.21'),('sca-range','UNKNOWN','^4.17.20')]:
        add(name,'SCA',truth,'VULNERABLE_NPM_DEPENDENCY',f'freeze-packages/{name}/package.json',
            json.dumps(dict(private=True,dependencies=dict(lodash=version)),indent=2),'"lodash"',support='LOOKUP_REQUIRED',
            advisory='GHSA-35jh-r3h4-6jhm',rationale='Declared package version against this advisory only; not installed-version, reachability or all-advisory safety.')
    assert Counter(r['truth']for r in records)=={'RISK':12,'NORMAL':12,'UNKNOWN':6}
    return records,files


def prepare(original_root,destination):
    original_root=outside(original_root);destination=outside(destination)
    plan=read(original_root/'application-plan.json')
    if len(plan['projects'])!=2:raise ValueError('TWO_NEW_BASE_FAMILIES')
    destination.mkdir(mode=0o700);(destination/'sources').mkdir(mode=0o700)
    projects=[];cases=[]
    for index,base in enumerate(plan['projects']):
        kind='EDGE'if index==0 else'NEXT'
        source=original_root/'sources'/base['projectId']
        if base['license']!='MIT':raise ValueError('LICENSE')
        for f in base['files']:
            path=source/f['path']
            if path.is_symlink()or not path.resolve().is_relative_to(source.resolve())or digest(path.read_bytes())!=f['sha256']:raise ValueError('SOURCE_HASH')
        if 'Permission is hereby granted' not in (source/'LICENSE').read_text():raise ValueError('LICENSE_TEXT')
        original=copy.deepcopy(base);original['projectId']='freeze-original-'+kind.lower()
        shutil.copytree(source,destination/'sources'/original['projectId']);projects.append(original)
        controlled=copy.deepcopy(base);controlled['projectId']='freeze-controls-'+kind.lower()
        target=destination/'sources'/controlled['projectId'];shutil.copytree(source,target)
        records,changes=controls(kind)
        # Preserve original route trees. Import only the synthetic React declaration
        # module to make its static relation visible; no source module is executed.
        anchors=['src/App.tsx','src/App.jsx']if kind=='EDGE'else['app/layout.tsx']
        for anchor in anchors:
            if (target/anchor).exists():
                original_text=(target/anchor).read_text()
                if kind=='EDGE':
                    if original_text.count('<Routes>')!=1:raise ValueError('STATIC_ROUTER_ANCHOR_REQUIRED')
                    relation="import {EvaluationPanel} from './freeze-evaluation/HtmlCases';\n"
                    original_text=original_text.replace('<Routes>','<Routes>\n<Route path="/engine-evaluation" element={<EvaluationPanel/>}/>')
                    changes[anchor]=relation+original_text
                break
        by_path={f['path']:f for f in controlled['files']}
        for file,content in changes.items():
            path=target/file;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(content);path.chmod(0o600)
            by_path[file]=dict(path=file,sha256=digest(path.read_bytes()),bytes=path.stat().st_size)
        controlled.update(files=list(by_path.values()),upstreamRetainedFiles=base['retainedFiles'],retainedFiles=len(by_path),grade='B',provenanceKind='CONTROLLED_VARIANT',
            groundTruth='NAMED_PATH_ONLY_NOT_REAL_CVE_OR_WHOLE_APP_SAFE',sourceCommitMeaning='Upstream base SHA; modified files identified by frozen SHA256')
        projects.append(controlled)
        for record in records:
            record.update(projectId=controlled['projectId'],baseRepository=base['repositoryUrl'],baseCommit=base['commitSha'],
                fileSha256=by_path[record['targetFile']]['sha256'],linePolicy='EXACT_TARGET_SINK_OR_POLICY_NOT_UNRELATED_FINDINGS')
            if record.get('sinkFileLine'):record['targetLine']=record.pop('sinkFileLine')
            record['pairedTemplateId']=record['caseId'].removeprefix(kind.lower()+'-')
            cases.append(record)
    assert len({c['caseId']for c in cases})==60
    assert len({(c['projectId'],c['targetRule'],c['targetFile'],c['targetLine'])for c in cases})==60
    frozen=dict(schemaVersion=1,engineCommit=ENGINE,cases=cases,
        caseGradeCounts={'A':0,'B':60},applicationContextGradeCounts={'C':2},pairedSemanticTemplates=30,
        truthCounts=dict(Counter(c['truth']for c in cases)),
        evaluatorSha256=digest(Path(__file__).read_bytes()),
        runnerSourceSha256=digest((Path(__file__).resolve().parents[2]/'src/test/java/com/securedeploy/evaluation/ApplicationEvaluationRunner.java').read_bytes()),
        acceptance={'precisionTarget':0.90,'recallTarget':0.85,'noSilentSupportedExposureOrSsrfMiss':True,
            'repeatConsistencyRequired':True,'independentExternalReviewRequiredForGeneralAccuracyClaim':True},
        scoring='Named-target REVIEW SIGNAL precision, not confirmed-vulnerability precision. Exact rule/path/line and flow trace or policy evidence. Unsupported/uninspected risks never TP. Grade C excluded.',
        independence='60 instances of 30 paired semantic templates on two new source repositories; same curator, not external independent/blind. No AI-generation provenance assumed.',
        scaScope='Live OSV/TI disabled consistently with application runner; SCA controls count NOT_INSPECTED, never TN/TP.',
        engineChanges='FORBIDDEN_DURING_STUDY')
    write(destination/'frozen-ground-truth.json',frozen)
    result=copy.deepcopy(plan);result['projects']=projects;result['frozenGroundTruthSha256']=digest((destination/'frozen-ground-truth.json').read_bytes())
    result['knownTruthPolicy']=frozen['scoring'];write(destination/'application-plan.json',result)
    print(json.dumps({'projects':4,'gradeBCases':60,'truth':frozen['truthCounts'],'groundTruthSha256':result['frozenGroundTruthSha256']}))


def report(root,raw_file,output,comparison_engine=None):
    root=outside(root);plan=read(root/'application-plan.json');truth=read(root/'frozen-ground-truth.json');raw=read(raw_file)
    if truth['engineCommit']!=ENGINE or raw['engineCommit']!=(comparison_engine or ENGINE):raise ValueError('ENGINE_CHANGED')
    if comparison_engine:
        if not re.fullmatch('[0-9a-f]{40}',comparison_engine):raise ValueError('EXACT_COMPARISON_ENGINE_REQUIRED')
        original=subprocess.check_output(['git','show','c492568b501473acf1eef31f53e0879c2a7bd462:scripts/evaluation/freeze_evaluation.py'],cwd=Path(__file__).resolve().parents[2])
        if digest(original)!=truth['evaluatorSha256']:raise ValueError('BASELINE_EVALUATOR_MISMATCH')
    elif truth['evaluatorSha256']!=digest(Path(__file__).read_bytes()):raise ValueError('EVALUATOR_CHANGED_AFTER_FREEZE')
    if truth['runnerSourceSha256']!=digest((Path(__file__).resolve().parents[2]/'src/test/java/com/securedeploy/evaluation/ApplicationEvaluationRunner.java').read_bytes()):raise ValueError('RUNNER_CHANGED_AFTER_FREEZE')
    if digest((root/'application-plan.json').read_bytes())!=raw['planSha256']or digest((root/'frozen-ground-truth.json').read_bytes())!=plan['frozenGroundTruthSha256']:raise ValueError('FROZEN_INPUT_CHANGED')
    by_project={p['projectId']:p for p in raw['projects']};rows=[];counts=Counter();areas=defaultdict(Counter);frameworks=defaultdict(Counter)
    if set(by_project)!={p['projectId']for p in plan['projects']}:raise ValueError('PROJECT_SET')
    for p in raw['projects']:
        runs=p.get('runs',[])
        if len(runs)!=2 or stable(runs[0])!=stable(runs[1]):raise ValueError('REPEATS_OR_SEMANTICS')
    for c in truth['cases']:
        r=by_project[c['projectId']]['runs'][0];ts=r['typescript'];path=c['targetFile'];line=c['targetLine'];rule=c['targetRule']
        matches=lambda signals:[s for s in signals if s.get('ruleId')==rule and s.get('filePath',s.get('location',{}).get('filePath'))==path and s.get('line',s.get('location',{}).get('line'))==line]
        rule_signals=matches(r['filtered']);structural=matches(r['reviewCandidates'])
        # A same-ID unrelated warning is not flow proof. Exposure/SSRF positives
        # require a structural trace at the pre-labelled sink.
        found=bool(structural and any(s.get('trace')for s in structural))if c['area']in {'EXPOSURE','SSRF'}else bool(rule_signals or structural)
        tf=next((f for f in ts.get('files',[])if f['filePath']==path),None)
        uses=[u for u in ts.get('exposureUses'if c['area']=='EXPOSURE'else'httpUses',[])if u['location']['filePath']==path and u['location']['line']==line]
        table=next((t for t in ts.get('supabaseAnalysis',{}).get('tables',[])if t['table']==c.get('table')),None)
        operation=next((o for o in (table or {}).get('operations',[])if o['role']==c.get('role')and o['operation']==c.get('operation')),None)
        exact_policy=operation is not None and any(p['filePath']==path and p['line']==line for p in operation.get('policyLocations',[]))
        rule_input=next((f for f in r.get('ruleInputs',[])if f['filePath']==path and f['lineCount']>=line),None)
        dimensions={};uncertainty_ok=None
        inspected=True;why=[]
        if c['support']=='NOT_SUPPORTED':outcome='NOT_SUPPORTED';inspected=False;why=['GENERAL_DOM_FLOW_NOT_SUPPORTED']
        elif c['area']=='SCA'and r['sca']['status']=='EXTERNAL_LOOKUP_NOT_RUN':outcome='NOT_INSPECTED';inspected=False;why=['LIVE_ADVISORY_LOOKUP_NOT_RUN']
        elif c['area']in {'EXPOSURE','SSRF'}and tf and tf['parseStatus']=='LIMIT_EXCEEDED':
            outcome='RESOURCE_LIMIT';inspected=False;why=['TARGET_FILE_RESOURCE_LIMIT']
        elif c['area']in {'EXPOSURE','SSRF'}and tf and tf['parseStatus']=='PARSE_FAILED':
            outcome='ANALYSIS_FAILED';inspected=False;why=['TARGET_FILE_PARSE_FAILED']
        elif c['area']in {'EXPOSURE','SSRF'}and(not tf or tf['parseStatus']!='PARSED'or tf.get('entrypoints',0)==0 or tf.get('functionsAnalyzed',0)==0):
            outcome='NOT_INSPECTED';inspected=False;why=['REQUEST_FLOW_NOT_INSPECTED']
        elif c['area']=='RLS'and(not ts.get('supabaseAnalysis')or not any(t.get('table')==c['table']for t in ts['supabaseAnalysis'].get('tables',[]))):
            outcome='NOT_INSPECTED';inspected=False;why=['TARGET_TABLE_NOT_INSPECTED']
        elif c['area']in {'EXPOSURE','SSRF'}and not found and not uses:
            outcome='NOT_INSPECTED';inspected=False;why=['NO_EXACT_SINK_NEGATIVE_OR_UNCERTAIN_EVIDENCE']
        elif c['truth']=='NORMAL'and c['area']=='SSRF'and not found and not any(u.get('kind')=='FIXED_DESTINATION'for u in uses):
            outcome='INDETERMINATE';inspected=False;why=['NO_FIXED_DESTINATION_PROOF']
        elif c['truth']=='NORMAL'and c['area']=='EXPOSURE'and not found and not any(u.get('status')=='SENSITIVITY_UNVERIFIED'and u.get('trace')and all(t.get('kind')=='DECLARED_PUBLIC_ENVIRONMENT_VALUE'for t in u['trace'])for u in uses):
            outcome='INDETERMINATE';inspected=False;why=['NO_EXACT_NORMAL_EXPOSURE_PROOF']
        elif c['area']in {'HTML','DEPLOYMENT'}and not rule_input:
            outcome='NOT_INSPECTED';inspected=False;why=['FULL_TARGET_RULE_INPUT_NOT_RECORDED']
        elif c['truth']=='UNKNOWN':
            if c['area']=='EXPOSURE':uncertainty_ok=any(u.get('status')=='FLOW_UNRESOLVED'for u in uses)and not found
            elif c['area']=='SSRF':uncertainty_ok=any(u.get('kind')=='UNRESOLVED_DESTINATION'for u in uses)and not found
            elif c['area']=='HTML':uncertainty_ok=any(e['filePath']==path and e['line']==line and 'HTML_CONTEXT=UNRESOLVED_HTML' in e['analysisNote']for e in r.get('htmlContextEvidence',[]))
            elif c.get('uncertaintyDimension')=='AUTH_SESSION':
                session_path='supabase/functions/freeze-policy-links/index.ts'if c['framework']=='EDGE'else'app/api/freeze/policy-links/route.ts'
                access=next((a for a in ts['supabaseAnalysis'].get('accesses',[])if a.get('table')==c['table']and a['location']['filePath']==session_path),{})
                e=access.get('authorizationEvidence')or{}
                dimensions={'policyState':(operation or {}).get('state'),'authStatus':e.get('authStatus'),'effectiveRole':e.get('effectiveRole')}
                uncertainty_ok=exact_policy and dimensions=={'policyState':'UID_COLUMN_EQUALITY','authStatus':'SESSION_READ_UNVERIFIED','effectiveRole':'UNKNOWN'}
            else:uncertainty_ok=exact_policy and operation.get('state')=='UNKNOWN'and not found
            outcome='UNKNOWN'if uncertainty_ok else'UNCERTAINTY_CHECK_FAILED'
        elif c['truth']=='NORMAL'and c['area']=='RLS'and(not exact_policy or operation.get('state')not in {'UID_COLUMN_EQUALITY','ALLOW'}):
            outcome='NOT_INSPECTED';inspected=False;why=['NO_EXACT_POLICY_DEFENSE_EVIDENCE']
        elif c['truth']=='RISK':outcome='TP'if found else'FN'
        else:outcome='FP'if found else'TN'
        counts[outcome]+=1;areas[c['area']][outcome]+=1;frameworks[c['framework']][outcome]+=1
        rows.append({**c,'outcome':outcome,'inspectionConfirmed':inspected,'ruleSignals':rule_signals,
            'structuralCandidates':structural,'limitations':why,'observedDimensions':dimensions,'uncertaintyCheckPassed':uncertainty_ok,
            'uncertainReviewSignal':c['truth']=='UNKNOWN'and found})
    denominator=sum(counts[k]for k in ['TP','FP','FN','TN'])
    risk_count=sum(c['truth']=='RISK'for c in truth['cases'])
    result=dict(schemaVersion=1,engineCommit=raw['engineCommit'],baselineEngineCommit=ENGINE,comparisonPhase=bool(comparison_engine),planSha256=raw['planSha256'],groundTruthSha256=plan['frozenGroundTruthSha256'],
        evaluatorSha256=digest(Path(__file__).read_bytes()),counts=dict(counts),byArea={k:dict(v)for k,v in areas.items()},
        precision=counts['TP']/(counts['TP']+counts['FP'])if counts['TP']+counts['FP']else None,
        supportedInspectedRecall=counts['TP']/(counts['TP']+counts['FN'])if counts['TP']+counts['FN']else None,
        allRiskDetectionFraction=counts['TP']/risk_count,
        binaryInspectionFraction=denominator/sum(c['truth']!='UNKNOWN'for c in truth['cases']),
        allCaseInspectionFraction=sum(r['inspectionConfirmed']for r in rows)/len(rows),
        caseResults=rows,caseGradeCounts=truth['caseGradeCounts'],applicationContextGradeCounts=truth['applicationContextGradeCounts'],
        pairedSemanticTemplates=truth['pairedSemanticTemplates'],byFramework={k:dict(v)for k,v in frameworks.items()},acceptance=truth['acceptance'],
        applicationRuns=[dict(projectId=p['projectId'],commitSha=p['commitSha'],status=p['status'],
            elapsedMs=[r['elapsedMs']for r in p['runs']],parentHeapUsedBytes=[r['parentHeapUsedBytes']for r in p['runs']],
            score=p['runs'][0]['securityScore'],risk=p['runs'][0]['risk']['prioritySummary'],coverageStatus=p['runs'][0]['coverage'].get('status'),
            selection=p['runs'][0]['typescript'].get('selectionCoverage'))for p in raw['projects']],
        limitations=[truth['independence'],truth['scaScope'],'Parent heap samples are not child peak RSS',
            'Finding candidates are the product projection, not persisted user Reviews or runtime exploit results',
            'Grade A real vulnerable/fixed app pairs not added; source-free controlled study only'])
    if comparison_engine:
        result['baselineEvaluatorSha256']=truth['evaluatorSha256']
        result['scoringChange']='Exact framework-specific AUTH_SESSION evidence path lookup only; original labels, named targets and outcome rules retained. First report is not rewritten.'
    result['acceptanceChecks']={'precisionThresholdPassed':result['precision']is not None and result['precision']>=truth['acceptance']['precisionTarget'],
        'recallThresholdPassed':result['supportedInspectedRecall']is not None and result['supportedInspectedRecall']>=truth['acceptance']['recallTarget'],
        'noSupportedExposureSsrfFN':not any(r['area']in {'EXPOSURE','SSRF'}and r['outcome']=='FN'for r in rows),
        'everySupportedCoreRiskDetected':not any(r['truth']=='RISK'and r['area']in {'EXPOSURE','SSRF'}and r['outcome']!='TP'for r in rows),
        'allUncertaintyChecksPassed':all(r['uncertaintyCheckPassed'] is True for r in rows if r['truth']=='UNKNOWN'and r['support']!='LOOKUP_REQUIRED'),'repeatConsistencyPassed':True,
        'independentExternalReview':False}
    write(output,result)
    print(json.dumps({k:result[k]for k in ['counts','byArea','precision','supportedInspectedRecall','allRiskDetectionFraction','allCaseInspectionFraction']}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();sub=parser.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('prepare');p.add_argument('original_root',type=Path);p.add_argument('destination',type=Path)
    p=sub.add_parser('report');p.add_argument('root',type=Path);p.add_argument('raw_file',type=Path);p.add_argument('output',type=Path)
    p=sub.add_parser('compare');p.add_argument('root',type=Path);p.add_argument('raw_file',type=Path);p.add_argument('output',type=Path);p.add_argument('comparison_engine')
    args=vars(parser.parse_args());cmd=args.pop('cmd');globals()['report'if cmd=='compare'else cmd](**args)
