"""Authored authorization requirements and isolated SQL oracle; no external SQL execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from application_track import read, write

A='11111111-1111-1111-1111-111111111111'
B='22222222-2222-2222-2222-222222222222'
OWN='auth.uid()=user_id'
BASE="CREATE TABLE public.items(id integer,user_id uuid,payload text,role text DEFAULT 'member',is_admin boolean DEFAULT false);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT SELECT ON public.items TO limited_admin;CREATE POLICY admin_read ON public.items FOR SELECT TO limited_admin USING(true);"
GRANT='GRANT SELECT,INSERT,UPDATE,DELETE ON public.items TO authenticated;'
def policy(command='ALL',using=OWN,check=OWN,name='p'):
    return f'CREATE POLICY {name} ON public.items FOR {command} TO authenticated'+(f' USING({using})' if using is not None else '')+(f' WITH CHECK({check})' if check is not None else '')+';'

# Row counts and SQLSTATE expectations are fixed before either engine or oracle run.
OWNER=[1,0,1,0,'42501',1,'42501',0,1,0,1,0,1,0]
BROAD=[2,1,1,1,1,1,1,1,1,1,1,1,1,1]
POLICIES=[
 dict(id='owner',sql=BASE+GRANT+policy(),expect=OWNER),
 dict(id='broad',sql=BASE+GRANT+policy(using='true',check='true'),expect=BROAD),
 dict(id='open-replacement',sql=BASE+GRANT+policy('SELECT','true',None,'read')+policy('UPDATE',OWN,'true','change'),expect=[2,1,1,0,1,'42501','42501',0,0,0,1,0,1,0]),
 dict(id='open-existing',sql=BASE+GRANT+policy('SELECT','true',None,'read')+policy('UPDATE','true',OWN,'change'),expect=[2,1,1,'42501','42501','42501','42501',1,0,0,1,'42501',1,'42501']),
 dict(id='insert-open',sql=BASE+GRANT+policy('SELECT',OWN,None,'read')+policy('INSERT',None,'true','add_row'),expect=[1,0,0,0,0,1,1,0,0,0,0,0,0,0]),
 dict(id='delete-open',sql=BASE+'GRANT SELECT,DELETE ON public.items TO authenticated;'+policy('SELECT','true',None,'read')+policy('DELETE','true',None,'remove'),expect=[2,1]+['42501']*6+[1,1]+['42501']*4),
 dict(id='read-open',sql=BASE+'GRANT SELECT ON public.items TO anon,authenticated;CREATE POLICY read ON public.items FOR SELECT TO public USING(true);',expect=[2,1]+['42501']*12,anonRead=True),
 dict(id='columns',sql=BASE+'GRANT SELECT,UPDATE(payload) ON public.items TO authenticated;'+policy(),expect=[1,0,1,0]+['42501']*10),
 dict(id='read-only',sql=BASE+'GRANT SELECT ON public.items TO authenticated;'+policy(),expect=[1,0]+['42501']*12),
 dict(id='permissive',sql=BASE+GRANT+policy()+policy('SELECT','true',None,'read')+policy('UPDATE','true','true','widen'),expect=[2,1,1,1,1,1,'42501',1,1,0,1,1,1,1]),
]

# No owner/admin inference from a field name: requirements explicitly name protected actions.
SCENARIOS=[
 ('own-title','owner','NORMAL','UPDATE',"update({payload:body.payload}).eq('user_id',user.id)",'update-own','Only own document title may change.'),
 ('other-title','broad','RISK','UPDATE',"update({payload:body.payload}).eq('id',body.id)",'update-other','Other users private document titles must not change.'),
 ('transfer-owner','open-replacement','RISK','UPDATE',"update({user_id:body.user_id}).eq('user_id',user.id)",'transfer-owner','Ownership transfer to another user is forbidden.'),
 ('claim-other','open-existing','RISK','UPDATE',"update({user_id:user.id}).eq('id',body.id)",'claim-other','A user must not claim another users document.'),
 ('insert-other','insert-open','RISK','INSERT',"insert({user_id:body.user_id,payload:body.payload})",'insert-other','New private documents must belong to the caller.'),
 ('delete-other','delete-open','RISK','DELETE',"delete().eq('id',body.id)",'delete-other','Deleting another users private document is forbidden.'),
 ('private-read','read-open','RISK','SELECT',"select().eq('id',body.id)",'select-other','Reading another users private document is forbidden.'),
 ('role-field','owner','RISK','UPDATE',"update({role:body.role}).eq('user_id',user.id)",'set-role-own','role is consumed by the authored management gate; ordinary users must not change it.'),
 ('admin-field','owner','RISK','UPDATE',"update({is_admin:body.is_admin}).eq('user_id',user.id)",'set-admin-own','is_admin is consumed by the authored management gate; ordinary users must not change it.'),
 ('column-denial','columns','NORMAL','UPDATE',"update({role:body.role}).eq('user_id',user.id)",'set-role-own','Column privileges must reject ordinary users role changes.'),
 ('intentional-share','broad','NORMAL','UPDATE',"update({payload:body.payload}).eq('id',body.id)",'update-other','Authenticated users may edit this explicitly shared bulletin.'),
 ('constant-own','owner','NORMAL','UPDATE',"update({payload:'fixed'}).eq('user_id',user.id)",'update-own','Caller may set a fixed title only on their own document.'),
 ('no-update-grant','read-only','NORMAL','UPDATE',"update({payload:body.payload}).eq('user_id',user.id)",'update-own','Read-only roles must not modify documents.'),
 ('widened-policy','permissive','RISK','UPDATE',"update({payload:body.payload}).eq('id',body.id)",'update-other','A second permissive policy must not allow cross-user document writes.'),
 ('missing-sql','owner','UNKNOWN','UPDATE',"update({payload:body.payload}).eq('user_id',user.id)",None,'Migration context is missing; no runtime authorization verdict.'),
 ('external-auth','owner','UNKNOWN','UPDATE',"update({payload:body.payload}).eq('user_id',user.id)",None,'External authentication helper semantics are not supplied.'),
 ('partial-sql','owner','UNKNOWN','UPDATE',"update({payload:body.payload}).eq('user_id',user.id)",None,'One migration is uninspected; final policy state is unknown.'),
 ('opaque-policy','owner','UNKNOWN','UPDATE',"update({payload:body.payload}).eq('user_id',user.id)",None,'External policy function semantics are unavailable; do not infer protection or risk.'),
]
PROBE_NAMES=['select-own','select-other','update-own','update-other','transfer-owner','insert-own','insert-other','claim-other','delete-own','delete-other','set-role-own','set-role-other','set-admin-own','set-admin-other']
def probes(subject):
    own,other=(1,2) if subject!=B else (2,1);opposite=B if subject!=B else A
    return [
      'SELECT count(*) FROM public.items;',f'SELECT count(*) FROM public.items WHERE id={other};',
      f"UPDATE public.items SET payload='changed' WHERE id={own};",f"UPDATE public.items SET payload='changed' WHERE id={other};",
      f"UPDATE public.items SET user_id='{opposite}' WHERE id={own};",f"INSERT INTO public.items VALUES(3,'{subject or A}','new');",f"INSERT INTO public.items VALUES(3,'{opposite}','new');",
      f"UPDATE public.items SET user_id='{subject or A}' WHERE id={other};",f'DELETE FROM public.items WHERE id={own};',f'DELETE FROM public.items WHERE id={other};',
      f"UPDATE public.items SET role='admin' WHERE id={own};",f"UPDATE public.items SET role='admin' WHERE id={other};",
      f'UPDATE public.items SET is_admin=true WHERE id={own};',f'UPDATE public.items SET is_admin=true WHERE id={other};']

def packet(scenario,layout):
    ident,pid,truth,op,action,probe,requirement=scenario;pol=next(p for p in POLICIES if p['id']==pid)
    actionMode=layout=='action';prefix='src/' if actionMode else '';file=prefix+('app/actions.ts' if actionMode else 'app/api/items/route.ts')
    factory="import {cookies} from 'next/headers';import {createServerClient} from '@supabase/ssr';export async function make(){const jar=await cookies();return createServerClient(process.env.SERVICE_URL,process.env.PUBLIC_ANON_KEY,{cookies:{getAll(){return jar.getAll();}}});}"
    code=("'use server';" if actionMode else '')+f"import {{make}} from '{'../lib/client' if actionMode else '../../../lib/client'}';export async function {'change(body)' if actionMode else 'POST(req)'}{{"+('' if actionMode else 'const body=await req.json();')+"const db=await make();"+("const user=await externalAuth();" if ident=='external-auth' else "const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');")+"return db.from('items')."+action+';}'
    sql=[] if ident=='missing-sql' else [dict(filePath='supabase/migrations/20260101000000_authored.sql',status='SELECTED',content=pol['sql'])]
    if ident=='partial-sql':sql.append(dict(filePath='supabase/migrations/20260102000000_missing.sql',status='LIMIT_EXCEEDED'))
    if ident=='opaque-policy':sql[0]['content']=sql[0]['content'].replace(OWN,'external_owner_check(user_id)')
    return dict(files=[dict(filePath=file,content=code),dict(filePath=prefix+'lib/client.ts',content=factory),dict(filePath=prefix+'lib/management.ts',content='export function mayManage(profile){return profile.role === "admin" || profile.is_admin === true;}')],nodeManifests=[dict(filePath='package.json',next='15.2.0')],policyFiles=sql)

def freeze():
    rows=[]
    for layout in ['route','action']:
        for s in SCENARIOS:
            p=packet(s,layout);blob=json.dumps(p,sort_keys=True,separators=(',',':')).encode()
            rows.append(dict(caseId=layout+'-'+s[0],scenario=s[0],policy=s[1],truth=s[2],operation=s[3],oracleProbe=s[5],requirement=s[6],packet=p,sourceSha256=hashlib.sha256(blob).hexdigest()))
    return dict(schemaVersion=1,baseline='2d88ce37e2a93b44fa10c07656efd33302971c67',grade='B',sourceOrigin='AUTHOR_ORIGINAL_NO_EXTERNAL_CODE_COPIED',license='SecureDeploy repository terms; no root license file declared',truthFrozenBeforeEngine=True,independentReview=False,
      premises=['Private document scenarios require A/B isolation; shared bulletin explicitly permits authenticated cross-user title edits.',
        'role/is_admin are protected only where the requirement and supplied management gate give them authorization meaning.',
        'SQL oracle stipulates DB roles and subjects, not actual Next/Supabase HTTP authentication or deployed configuration.'],
      policies=[dict(p,sqlSha256=hashlib.sha256(p['sql'].encode()).hexdigest()) for p in POLICIES],cases=rows)

def engine(plan,analyzer,version='ts-server-v26'):
    expected=freeze()
    if plan!=expected:raise ValueError('FROZEN_TRUTH_CHANGED')
    rows=[];tool=Path(__file__).with_name('node_probe_worker.mjs')
    for c in plan['cases']:
        p=subprocess.run(['node','--max-old-space-size=192',str(tool),str(analyzer)],input=json.dumps(c['packet']).encode(),capture_output=True,timeout=10,check=True)
        r=json.loads(p.stdout)
        if r['analyzerVersion']!=version:raise ValueError('ENGINE_VERSION_CHANGED')
        s=r['supabaseAnalysis'];a=s['accesses'][0] if s['accesses'] else None
        hits=[f for f in s['findings'] if f['table']=='public.items' and c['operation'] in f['operations']]
        rows.append(dict(caseId=c['caseId'],truth=c['truth'],operation=c['operation'],sourceSha256=c['sourceSha256'],files=r['files'],access=a,findings=hits,allPolicyFindings=s['findings'],budget=s['budgetUsage'],limitations=s['limitations']))
    return dict(scope='FROZEN_GRADE_B_NOT_PRODUCTION_HTTP_AUTHORIZATION_PROOF',worker=version,rows=rows)

def database(plan):
    if plan!=freeze():raise ValueError('FROZEN_TRUTH_CHANGED')
    env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG','LC_ALL']}
    binaries={k:shutil.which(k) for k in ['initdb','pg_ctl','psql']}
    if not all(binaries.values()):raise RuntimeError('LOCAL_POSTGRES_REQUIRED')
    folder=Path(tempfile.mkdtemp(prefix='sd-auth11-',dir='/private/tmp'));folder.chmod(0o700);data=folder/'data';sock=folder/'sock';sock.mkdir(mode=0o700);started=False
    def command(args):return subprocess.run(args,env=env,capture_output=True,text=True,timeout=20)
    def sql(query,role=None,subject=''):
        prefix=f"SET ROLE {role};SET request.jwt.claim.sub='{subject}';" if role else ''
        p=command([binaries['psql'],'-X','-h',str(sock),'-p','65489','-U','bench_admin','-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-At','-c',prefix+query])
        if p.returncode:
            m=re.search(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):',p.stderr)
            if not m:raise RuntimeError('UNCLASSIFIED_SQL_ERROR')
            if not role:raise RuntimeError('CONTROL_SETUP_SQL_FAILED_'+m[1])
            return m[1]
        lines=[l for l in p.stdout.splitlines() if l not in ['SET','BEGIN','COMMIT','ROLLBACK']]
        if not lines:return None
        v=lines[-1];tag=re.fullmatch(r'(?:UPDATE|DELETE|INSERT 0) (\d+)',v)
        return int(v) if v.isdigit() else int(tag[1]) if tag else v
    try:
        if command([binaries['initdb'],'-D',str(data),'-U','bench_admin','--auth-local=trust','--auth-host=reject','--no-locale','-E','UTF8']).returncode:raise RuntimeError('INITDB_FAILED')
        p=command([binaries['pg_ctl'],'-D',str(data),'-l',str(folder/'server.log'),'-w','start','-o',f"-h '' -k {sock} -p 65489 -c shared_buffers=16MB -c max_connections=10 -c statement_timeout=2000 -c idle_in_transaction_session_timeout=2000"]);started=(data/'postmaster.pid').exists()
        if p.returncode or sql('SHOW data_directory;')!=str(data) or sql('SHOW listen_addresses;')!='':raise RuntimeError('ISOLATION_FAILED')
        sql("CREATE ROLE anon NOLOGIN NOBYPASSRLS;CREATE ROLE authenticated NOLOGIN NOBYPASSRLS;CREATE ROLE limited_admin NOLOGIN NOBYPASSRLS;CREATE SCHEMA auth;CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$SELECT nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;GRANT USAGE ON SCHEMA auth,public TO anon,authenticated,limited_admin;GRANT EXECUTE ON FUNCTION auth.uid() TO anon,authenticated,limited_admin;")
        if sql("SELECT count(*) FROM pg_roles WHERE rolname IN ('anon','authenticated','limited_admin') AND NOT rolsuper AND NOT rolbypassrls;")!=3:raise RuntimeError('ROLE_ISOLATION_FAILED')
        rows=[]
        for c in plan['policies']:
            try:sql('DROP TABLE IF EXISTS public.items;'+c['sql'])
            except RuntimeError as error:raise RuntimeError(c['id']+':'+str(error)) from None
            for role,subject in [('authenticated',A),('authenticated',B),('anon',''),('limited_admin','')]:
                expected=c['expect'] if role=='authenticated' else ([2,1]+['42501']*12 if role=='limited_admin' or c.get('anonRead') else ['42501']*14)
                for i,query in enumerate(probes(subject)):
                    sql(f"TRUNCATE public.items;INSERT INTO public.items VALUES(1,'{A}','a'),(2,'{B}','b');")
                    actual=sql(query,role,subject)
                    rows.append(dict(policy=c['id'],role=role,subject='A' if subject==A else 'B' if subject==B else 'NO_SUBJECT',probe=PROBE_NAMES[i],expected=expected[i],actual=actual,match=actual==expected[i],resultKind='SQLSTATE' if isinstance(actual,str) else 'ROW_COUNT'))
        return dict(postgres=sql('SHOW server_version;'),tcpListening=False,clusterRemoved=True,source='AUTHORED_FROZEN_CONSTANTS_ONLY',authUid='CURRENT_SETTING_STUB_NOT_SUPABASE_AUTH',userDatabaseAccessed=False,externalSqlExecuted=False,policyHashes={c['id']:c['sqlSha256'] for c in plan['policies']},rows=rows,total=len(rows),matched=sum(r['match'] for r in rows))
    finally:
        if started and command([binaries['pg_ctl'],'-D',str(data),'-w','stop','-m','immediate']).returncode:raise RuntimeError('POSTGRES_CLEANUP_FAILED')
        shutil.rmtree(folder)

def export_controls(plan,root):
    if plan!=freeze() or root.exists():raise ValueError('NEW_FROZEN_EXPORT_REQUIRED')
    root.mkdir(mode=0o700);batches=[]
    for offset in range(0,len(plan['cases']),8):
        batch=root/f'batch-{offset//8}';batch.mkdir(mode=0o700);projects=[]
        for c in plan['cases'][offset:offset+8]:
            dest=batch/'sources'/c['caseId'];dest.mkdir(parents=True,mode=0o700);files=[];omitted=[];packet=c['packet']
            content={f['filePath']:f['content'] for f in packet['files']}
            content['package.json']=json.dumps({'dependencies':{'next':'15.2.0'}})
            for f in packet['policyFiles']:
                if f['status']=='SELECTED':content[f['filePath']]=f['content']
                else:omitted.append(dict(filePath=f['filePath'],kind='FILE',fileType='SUPABASE_SQL',status='LIMIT_EXCEEDED',reason='AUTHORED_MISSING_MIGRATION'))
            for name,text in content.items():
                p=dest/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);b=text.encode();p.write_bytes(b);p.chmod(0o600);files.append(dict(path=name,bytes=len(b),sha256=hashlib.sha256(b).hexdigest()))
            projects.append(dict(projectId=c['caseId'],commitSha='',controlledSourceSha256=c['sourceSha256'],collectionStatus='COLLECTED_AUTHORED_CONTROL',grade='B',files=files,omitted=omitted))
        write(batch/'application-plan.json',dict(schemaVersion=1,track='AUTHORED_AUTHORIZATION_CONTROLS_NOT_REAL_APPLICATIONS',projects=projects));batches.append(str(batch))
    return dict(batches=batches,sourceOrigin='AUTHORED_NOT_EXTERNAL_OR_PRODUCTION')

def metrics(plan,engine_result,oracle):
    if plan!=freeze() or oracle['matched']!=oracle['total'] or oracle.get('policyHashes')!={c['id']:c['sqlSha256'] for c in plan['policies']}:raise ValueError('UNVERIFIED_GROUND_TRUTH')
    observed={r['caseId']:r for r in engine_result['rows']}
    if len(observed)!=len(plan['cases']) or len(observed)!=len(engine_result['rows']):raise ValueError('CASE_SET')
    counts={k:0 for k in ['TP','FP','FN','TN','UNKNOWN']};rows=[]
    for c in plan['cases']:
        r=observed[c['caseId']]
        if r['sourceSha256']!=c['sourceSha256']:raise ValueError('SOURCE_CHANGED')
        if c['truth']!='UNKNOWN':
            checks=[x for x in oracle['rows'] if x['policy']==c['policy'] and x['role']=='authenticated' and x['probe']==c['oracleProbe']]
            if len(checks)!=2 or {x['subject'] for x in checks}!={'A','B'} or c['truth']=='RISK' and not all(isinstance(x['actual'],int) and x['actual']>0 for x in checks):raise ValueError('RISK_NOT_CONFIRMED_BY_ORACLE')
        hit=bool(r['findings']);label='UNKNOWN' if c['truth']=='UNKNOWN' else ('TP' if hit else 'FN') if c['truth']=='RISK' else ('FP' if hit else 'TN');counts[label]+=1
        a=r['access'];e=(a or {}).get('authorizationEvidence') or {};reason=None
        if c['scenario']=='private-read':reason='PRIVATE_READ_INTENT_NOT_MODELED'
        elif c['scenario'] in ['role-field','admin-field']:reason='PROTECTED_PROPERTY_SEMANTICS_NOT_MODELED'
        elif c['scenario']=='intentional-share':reason='EXPLICIT_SHARED_INTENT_NOT_AVAILABLE_TO_ENGINE'
        elif c['scenario']=='column-denial':reason='COLUMN_GRANT_CONTRACT_NOT_SUPPORTED'
        elif c['scenario']=='no-update-grant':reason='ABSENT_GRANT_NOT_RUNTIME_DENIAL_PROOF'
        elif c['truth']=='UNKNOWN':reason={'missing-sql':'MIGRATION_CONTEXT_MISSING','external-auth':'EXTERNAL_AUTHENTICATION_UNKNOWN','partial-sql':'MIGRATION_NOT_INSPECTED','opaque-policy':'OPAQUE_POLICY_FUNCTION_NOT_SUPPORTED'}[c['scenario']]
        rows.append(dict(caseId=c['caseId'],truth=c['truth'],label=label,matchingReviewCandidates=len(r['findings']),reason=reason,
          requestLinked=bool(e.get('requestEntry')),clientLinked=(a or {}).get('clientStatus')=='CLIENT_DECLARATION_LINKED',policyState=e.get('state'),writeEvidence=bool((a or {}).get('writeEvidence')),
          noAlertIsNotConfirmedProtection=label=='TN' and e.get('state')=='UNKNOWN'))
    return dict(metric='CONDITIONAL_GRADE_B_REVIEW_CANDIDATE_MATCH_NOT_PRODUCTION_HTTP_VULNERABILITY_DETECTION',counts=counts,rows=rows,
      knownRiskDetection=counts['TP']/(counts['TP']+counts['FN']) if counts['TP']+counts['FN'] else None,reviewCandidatePrecision=counts['TP']/(counts['TP']+counts['FP']) if counts['TP']+counts['FP'] else None,
      knownNormalNoAlertButPolicyUnknown=sum(r['noAlertIsNotConfirmedProtection'] for r in rows),
      limitation='Unsupported risk targets remain FN in the all-target metric; they are not removed to increase recall. TN is known-normal absence of alert, not proof of full inspection or safety.')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['freeze','engine','database','export']);p.add_argument('output',type=Path);p.add_argument('--plan',type=Path);p.add_argument('--analyzer',type=Path);p.add_argument('--root',type=Path);p.add_argument('--version',choices=['ts-server-v26','ts-server-v27'],default='ts-server-v26');a=p.parse_args()
    result=freeze() if a.mode=='freeze' else engine(read(a.plan),a.analyzer.resolve(),a.version) if a.mode=='engine' else export_controls(read(a.plan),a.root) if a.mode=='export' else database(read(a.plan))
    write(a.output,result);print(dict(mode=a.mode,cases=len(result.get('cases',result.get('rows',[]))),matched=result.get('matched')))
    if a.mode=='database' and result['matched']!=result['total']:raise SystemExit(2)
