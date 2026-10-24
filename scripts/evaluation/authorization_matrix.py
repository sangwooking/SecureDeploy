"""Authored policy truth; external application SQL is NEVER executed by this tool."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

A='11111111-1111-1111-1111-111111111111'
B='22222222-2222-2222-2222-222222222222'
OWN='auth.uid()=user_id'
BASE='CREATE TABLE public.items(id integer,user_id uuid,payload text);ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;GRANT SELECT ON public.items TO limited_admin;CREATE POLICY admin_read ON public.items FOR SELECT TO limited_admin USING(true);'
GRANT='GRANT SELECT,INSERT,UPDATE,DELETE ON public.items TO authenticated;'
def policy(name='owner',command='ALL',using=OWN,check=None,mode='',role='authenticated'):
    return f'CREATE POLICY {name} ON public.items {mode} FOR {command} TO {role}'+(f' USING({using})' if using is not None else '')+(f' WITH CHECK({check})' if check is not None else '')+';'

# Expectations are fixed before engine evaluation; each operation resets the rows.
# None means no requested DML privilege (expected SQLSTATE 42501), not zero rows.
CASES=[
 dict(id='owner-all',sql=BASE+GRANT+policy(),truth='NORMAL',expect=[1,0,1,0,'42501',1,'42501',0,1,0]),
 dict(id='broad-all',sql=BASE+GRANT+policy(using='true',check='true'),truth='REVIEW',expect=[2,1,1,1,1,1,1,1,1,1]),
 dict(id='insert-unrestricted',sql=BASE+GRANT+policy(command='SELECT')+policy('insert','INSERT',None,'true'),truth='REVIEW',expect=[1,0,0,0,0,1,1,0,0,0]),
 dict(id='update-new-open',sql=BASE+GRANT+policy('read','SELECT','true')+policy('change','UPDATE',OWN,'true'),truth='REVIEW',expect=[2,1,1,0,1,'42501','42501',0,0,0]),
 dict(id='update-old-open',sql=BASE+GRANT+policy('read','SELECT','true')+policy('change','UPDATE','true',OWN),truth='REVIEW',expect=[2,1,1,'42501','42501','42501','42501',1,0,0]),
 dict(id='update-fallback',sql=BASE+GRANT+policy('read','SELECT','true')+policy('change','UPDATE',OWN),truth='NORMAL',expect=[2,1,1,0,'42501','42501','42501',0,0,0]),
 dict(id='permissive-widening',sql=BASE+GRANT+policy()+policy('read','SELECT','true')+policy('widen','UPDATE','true','true'),truth='REVIEW',expect=[2,1,1,1,1,1,'42501',1,1,0]),
 dict(id='restrictive-owner',sql=BASE+GRANT+policy(using='true')+policy('restrict','ALL',OWN,None,'AS RESTRICTIVE'),truth='NORMAL',expect=[1,0,1,0,'42501',1,'42501',0,1,0]),
 dict(id='restrictive-only',sql=BASE+GRANT+policy('restrict','ALL','true',None,'AS RESTRICTIVE'),truth='NORMAL',expect=[0,0,0,0,0,'42501','42501',0,0,0]),
 dict(id='no-grant',sql=BASE+policy(using='true'),truth='NORMAL',expect=['42501']*10),
 dict(id='public-read',sql=BASE+'GRANT SELECT ON public.items TO anon,authenticated;'+policy('read','SELECT','true',None,role='public'),truth='NORMAL',expect=[2,1,'42501','42501','42501','42501','42501','42501','42501','42501']),
 dict(id='anon-writes',sql=BASE+'GRANT SELECT,UPDATE ON public.items TO anon;'+policy('open','ALL','true',None,role='anon'),truth='REVIEW',expect=['42501']*10),
]

# Separate post-implementation validation: same author, not a blind holdout.
VALIDATION=[
 dict(id='altered-replacement',sql=BASE+GRANT+policy('read','SELECT','true')+policy('change','UPDATE',OWN)+"ALTER POLICY change ON public.items WITH CHECK(true);",truth='REVIEW',expect=[2,1,1,0,1,'42501','42501',0,0,0]),
 dict(id='revoked-update',sql=BASE+GRANT+policy()+"REVOKE UPDATE ON public.items FROM authenticated;",truth='NORMAL',expect=[1,0,'42501','42501','42501',1,'42501','42501',1,0]),
 dict(id='restrictive-replacement',sql=BASE+GRANT+policy('read','SELECT','true')+policy('change','UPDATE',OWN,'true')+policy('check_owner','UPDATE','true',OWN,'AS RESTRICTIVE'),truth='NORMAL',expect=[2,1,1,0,'42501','42501','42501',0,0,0]),
]

PROBES=[('select-own','SELECT count(*) FROM public.items;'),
 ('select-other','SELECT count(*) FROM public.items WHERE id=2;'),
 ('update-own',"UPDATE public.items SET payload='changed' WHERE id=1;"),
 ('update-other',"UPDATE public.items SET payload='changed' WHERE id=2;"),
 ('transfer-owner',f"UPDATE public.items SET user_id='{B}' WHERE id=1;"),
 ('insert-own',f"INSERT INTO public.items VALUES(3,'{A}','new');"),
 ('insert-other',f"INSERT INTO public.items VALUES(3,'{B}','new');"),
 ('claim-other',f"UPDATE public.items SET user_id='{A}' WHERE id=2;"),
 ('delete-own','DELETE FROM public.items WHERE id=1;'),
 ('delete-other','DELETE FROM public.items WHERE id=2;')]

def packet(case):
    operation='INSERT' if case['id']=='insert-unrestricted' else 'SELECT' if case['id']=='public-read' else 'UPDATE'
    action={'INSERT':"insert({user_id:user.id})",'SELECT':"select().eq('user_id',user.id)",'UPDATE':"update({}).eq('user_id',user.id)"}[operation]
    code="import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.ANON_KEY);export async function POST(){const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');return db.from('items')."+action+';}'
    return dict(files=[dict(filePath='app/api/items/route.ts',content=code)],
                nodeManifests=[dict(filePath='package.json',next='15.2.0')],
                policyFiles=[dict(filePath='supabase/migrations/20260101000000_authored.sql',status='SELECTED',content=case['sql'])])

def engine(analyzer,cases=CASES):
    tool=Path(__file__).with_name('node_probe_worker.mjs')
    rows=[]
    for c in cases:
        result=subprocess.run(['node','--max-old-space-size=192',str(tool),str(analyzer)],input=json.dumps(packet(c)).encode(),capture_output=True,timeout=10,check=True)
        r=json.loads(result.stdout);s=r['supabaseAnalysis']
        rows.append(dict(caseId=c['id'],truth=c['truth'],sqlSha256=hashlib.sha256(c['sql'].encode()).hexdigest(),
                         policyOperations=s['tables'][0]['operations'],findings=s['findings'],
                         access=s['accesses'][0],budget=s['budgetUsage'],worker=r['analyzerVersion']))
    return dict(scope='AUTHORED_POLICY_DECLARATION_NOT_RUNTIME_APP_SECURITY',rows=rows)

def contexts(analyzer):
    rows=[];tool=Path(__file__).with_name('node_probe_worker.mjs')
    for name in ['session','ignored-result','external-auth','unknown-client','missing-sql','omitted-migration','dynamic-policy','jwt-unverified','admin-key-hint','shared-intent-unknown']:
        c=next(x for x in CASES if x['id']==('broad-all' if name=='shared-intent-unknown' else 'owner-all'))
        p=packet(c);code=p['files'][0]['content']
        verified="const {data:{user}}=await db.auth.getUser();if(!user)throw new Error('missing');"
        replacement={'session':'await db.auth.getSession();const user=external;',
                     'ignored-result':'await db.auth.getUser();const user=external;',
                     'external-auth':'const user=await externalAuth(db);'}.get(name)
        if replacement:code=code.replace(verified,replacement)
        if name=='unknown-client':code=code.replace("createClient('https://example.invalid',process.env.ANON_KEY)",'externalFactory()')
        if name=='admin-key-hint':code=code.replace('process.env.ANON_KEY','process.env.SERVICE_ROLE_KEY')
        p['files'][0]['content']=code
        if name=='missing-sql':p['policyFiles']=[]
        if name=='omitted-migration':p['policyFiles'].append(dict(filePath='supabase/migrations/20260102000000_missing.sql',status='LIMIT_EXCEEDED'))
        if name=='dynamic-policy':p['policyFiles'][0]['content']=p['policyFiles'][0]['content'].replace(OWN,'external_owner_check(user_id)')
        result=subprocess.run(['node','--max-old-space-size=192',str(tool),str(analyzer)],input=json.dumps(p).encode(),capture_output=True,timeout=10,check=True)
        r=json.loads(result.stdout);s=r['supabaseAnalysis'];a=s['accesses'][0];e=a['authorizationEvidence']
        rows.append(dict(caseId=name,truth='END_TO_END_AUTHORIZATION_UNKNOWN',client=a['clientStatus'],
                         authStatus=e['authStatus'],policyState=e['state'],effectiveRole=e['effectiveRole'],
                         guardReferences=sum(bool(x.get('resultEvidence')) for x in e['authChecks']),
                         declarationCandidates=len(s['findings']),worker=r['analyzerVersion']))
    return dict(scope='UNCERTAIN_RUNTIME_AUTHORIZATION_NOT_SAFE_OR_VULNERABLE_LABEL',rows=rows)

def database(cases=CASES):
    # Never inherit PGHOST/PGPORT/PGDATABASE, service files, passwords or user env.
    env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}}
    folder=Path(tempfile.mkdtemp(prefix='sd-auth8-',dir='/private/tmp'));folder.chmod(0o700)
    data=folder/'data';sock=folder/'sock';sock.mkdir(mode=0o700)
    binaries={n:shutil.which(n) for n in ['initdb','pg_ctl','psql']}
    if not all(binaries.values()):raise RuntimeError('LOCAL_POSTGRES_BINARIES_REQUIRED')
    def command(args,**kw):return subprocess.run(args,env=env,capture_output=True,text=True,timeout=20,**kw)
    initialized=command([binaries['initdb'],'-D',str(data),'-U','bench_admin','--auth-local=trust','--auth-host=reject','--no-locale','-E','UTF8'])
    if initialized.returncode:raise RuntimeError('ISOLATED_INITDB_FAILED')
    started=False;rows=[]
    def sql(text,role=None,subject=A):
        pre=f"SET ROLE {role};SET request.jwt.claim.sub='{subject}';" if role else ''
        p=command([binaries['psql'],'-X','-h',str(sock),'-p','65488','-U','bench_admin','-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-At','-c',pre+text])
        if p.returncode:
            code=re.search(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):',p.stderr)
            if not code:raise RuntimeError('UNCLASSIFIED_CONTROL_SQL_ERROR')
            return code[1]
        lines=[x for x in p.stdout.splitlines() if x not in {'SET','BEGIN','COMMIT','ROLLBACK'}]
        if not lines:return None
        value=lines[-1]
        if value.isdigit():return int(value)
        tag=re.fullmatch(r'(?:UPDATE|DELETE|INSERT 0) (\d+)',value)
        return int(tag[1]) if tag else value
    try:
        p=command([binaries['pg_ctl'],'-D',str(data),'-l',str(folder/'server.log'),'-w','start','-o',f"-h '' -k {sock} -p 65488 -c shared_buffers=16MB -c max_connections=10 -c statement_timeout=2000 -c idle_in_transaction_session_timeout=2000"])
        if p.returncode:raise RuntimeError('ISOLATED_START_FAILED')
        started=True
        if sql('SHOW data_directory;')!=str(data) or sql('SHOW listen_addresses;')!='':raise RuntimeError('ISOLATION_ASSERTION_FAILED')
        bootstrap="CREATE ROLE anon NOLOGIN;CREATE ROLE authenticated NOLOGIN;CREATE ROLE limited_admin NOLOGIN NOBYPASSRLS;CREATE SCHEMA auth;CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('request.jwt.claim.sub',true),'')::uuid $$;GRANT USAGE ON SCHEMA auth,public TO anon,authenticated,limited_admin;GRANT EXECUTE ON FUNCTION auth.uid() TO anon,authenticated,limited_admin;"
        sql(bootstrap)
        for c in cases:
            sql('DROP TABLE IF EXISTS public.items;'+c['sql'])
            for subject in [A,B]:
                for i,(name,query) in enumerate(PROBES):
                    if subject==B:
                        query=query.replace('id=1','id=TEMP').replace('id=2','id=1').replace('id=TEMP','id=2').replace(A,'TEMP_UUID').replace(B,A).replace('TEMP_UUID',B)
                    reset=f"TRUNCATE public.items;INSERT INTO public.items VALUES(1,'{A}','a'),(2,'{B}','b');"
                    sql(reset)
                    actual=sql(query,'authenticated',subject);expected=c['expect'][i]
                    rows.append(dict(caseId=c['id'],role='authenticated',subject='A' if subject==A else 'B',probe=name,expected=expected,actual=actual,match=actual==expected))
            sql(f"TRUNCATE public.items;INSERT INTO public.items VALUES(1,'{A}','a'),(2,'{B}','b');")
            for role,query,expected in [('anon',"UPDATE public.items SET payload='anon' WHERE id=2;",1 if c['id']=='anon-writes' else '42501'),
                                         ('limited_admin','SELECT count(*) FROM public.items;',2),
                                         ('limited_admin',"UPDATE public.items SET payload='admin' WHERE id=2;",'42501')]:
                actual=sql(query,role,'');rows.append(dict(caseId=c['id'],role=role,subject='NO_JWT',probe='role-access',expected=expected,actual=actual,match=actual==expected))
        version=sql('SHOW server_version;')
        return dict(postgres=version,tcpListening=False,userDatabaseAccessed=False,externalSqlExecuted=False,clusterRemoved=True,
                    source='AUTHORED_CONSTANTS_ONLY',rows=rows,matched=sum(r['match'] for r in rows),total=len(rows))
    finally:
        if started:
            stopped=command([binaries['pg_ctl'],'-D',str(data),'-w','stop','-m','immediate'])
            if stopped.returncode:raise RuntimeError('ISOLATED_POSTGRES_CLEANUP_FAILED')
        shutil.rmtree(folder)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['database','engine','contexts']);p.add_argument('output',type=Path);p.add_argument('--analyzer',type=Path);p.add_argument('--validation',action='store_true')
    a=p.parse_args();cases=VALIDATION if a.validation else CASES
    result=database(cases) if a.mode=='database' else contexts(a.analyzer.resolve()) if a.mode=='contexts' else engine(a.analyzer.resolve(),cases)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(mode=a.mode,rows=len(result['rows']),matched=result.get('matched'))))
    if a.mode=='database' and result['matched']!=result['total']:raise SystemExit(2)
