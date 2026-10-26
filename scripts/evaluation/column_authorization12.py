"""Authored column ACL truth, static replay and private PostgreSQL oracle only."""
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
from authorization_truth11 import A, B, packet, BASE, OWN, policy

BASELINE='a6ee81153f292edb2344a3293b6e0497ef1ff3d9'
CONFIGS=[
 ('table','GRANT SELECT,UPDATE ON public.items TO authenticated;',{'payload','role','is_admin','user_id'},'TABLE_GRANT'),
 ('column-revoke-table-stays','GRANT SELECT,UPDATE ON public.items TO authenticated;REVOKE UPDATE(role) ON public.items FROM authenticated;',{'payload','role','is_admin','user_id'},'TABLE_GRANT'),
 ('column-only','GRANT SELECT,UPDATE(payload) ON public.items TO authenticated;',{'payload'},'NOT_ESTABLISHED'),
 ('two-columns','GRANT SELECT,UPDATE(payload,role) ON public.items TO authenticated;',{'payload','role'},'COLUMN_GRANT'),
 ('column-revoke','GRANT SELECT,UPDATE(payload,role) ON public.items TO authenticated;REVOKE UPDATE(role) ON public.items FROM authenticated;',{'payload'},'NOT_ESTABLISHED'),
 ('table-revoke-clears-columns','GRANT SELECT,UPDATE(payload) ON public.items TO authenticated;REVOKE UPDATE ON public.items FROM authenticated;',set(),'NOT_ESTABLISHED'),
 ('table-revoke-then-column','GRANT SELECT,UPDATE ON public.items TO authenticated;REVOKE UPDATE ON public.items FROM authenticated;GRANT UPDATE(payload) ON public.items TO authenticated;',{'payload'},'NOT_ESTABLISHED'),
 ('public-table','GRANT SELECT ON public.items TO authenticated;GRANT UPDATE ON public.items TO PUBLIC;REVOKE UPDATE(role) ON public.items FROM authenticated;',{'payload','role','is_admin','user_id'},'TABLE_GRANT'),
 ('public-column','GRANT SELECT ON public.items TO authenticated;GRANT UPDATE(role) ON public.items TO PUBLIC;',{'role'},'COLUMN_GRANT'),
 ('public-revoke-direct-stays','GRANT SELECT,UPDATE(payload) ON public.items TO authenticated;GRANT UPDATE ON public.items TO PUBLIC;REVOKE UPDATE ON public.items FROM PUBLIC;',{'payload'},'NOT_ESTABLISHED'),
 ('inherited','GRANT SELECT ON public.items TO authenticated;GRANT UPDATE ON public.items TO writers;GRANT writers TO authenticated;',{'payload','role','is_admin','user_id'},'UNKNOWN'),
 ('read-only','GRANT SELECT ON public.items TO authenticated;',set(),'NOT_ESTABLISHED'),
]

def configuration(name):
    return next(c for c in CONFIGS if c[0]==name)

def sql_for(name,broad=False):
    return BASE+configuration(name)[1]+policy(using='true' if broad else OWN,check='true' if broad else OWN)

def freeze():
    cases=[]
    specs=[(c[0],'role','RISK' if 'role' in c[2] else 'NORMAL',c[3]) for c in CONFIGS]
    specs += [('column-only','payload','NORMAL','COLUMN_GRANT'),('table-revoke-clears-columns','payload','NORMAL','NOT_ESTABLISHED'),
      ('column-revoke-table-stays','payload','RISK','TABLE_GRANT'),('table','dynamic','UNKNOWN','UNKNOWN'),
      ('table','missing','UNKNOWN','UNKNOWN'),('table','opaque','UNKNOWN','UNKNOWN')]
    for layout in ['route','action']:
        for index,(name,field,truth,expected) in enumerate(specs):
            broad=index==14;target=field if field in ['payload','role'] else 'role'
            p=packet(('columns12','owner',truth,'UPDATE',f"update({{{target}:body.{target}}}).eq('user_id',user.id)",None,''),layout)
            p['files']=p['files'][:2]
            p['policyFiles'][0]['content']=sql_for(name,broad)
            if field=='dynamic':p['files'][0]['content']=p['files'][0]['content'].replace("{role:body.role}","{...body}")
            if field=='missing':p['policyFiles'].append(dict(filePath='supabase/migrations/20260202000000_missing.sql',status='NOT_RUN',reason='AUTHORED_OMISSION'))
            if field=='opaque':p['policyFiles'][0]['content']+='DO $$BEGIN NULL; END$$;'
            # Validation uses a different declaration layout, identifiers and statement form.
            validation=layout=='action'
            if validation:
                for f in p['files']:f['content']=f['content'].replace("'items'","'records'").replace('role','classification').replace('payload','display_name')
                for f in p['policyFiles']:
                    if 'content' in f:f['content']=f['content'].replace('public.items','public.records').replace('payload','display_name').replace('role','classification')
                target={'role':'classification','payload':'display_name'}[target]
            blob=json.dumps(p,sort_keys=True,separators=(',',':')).encode()
            cases.append(dict(caseId=f'{layout}-{index:02}-{name}-{field}',split='VALIDATION_SAME_AUTHOR_NOT_BLIND' if validation else 'REGRESSION',
              config=name,field=target,truth=truth,expectedColumnDeclaration=expected,broad=broad,packet=p,sourceSha256=hashlib.sha256(blob).hexdigest(),
              requirement='Ordinary users may change only their own display text. The designated classification field must not be user-editable; this is an explicit fixture requirement, not inferred from its name.',
              runtimeAuthorization='UNKNOWN',grade='B'))
    return dict(schemaVersion=1,baseline=BASELINE,gradeA=0,independentReview=False,truthFrozenBeforeEngine=True,
      premises=['Column declaration is not effective runtime privilege or a full SQL query permission decision.','Protected-property requirements are not supplied to the product engine.','Known risk is not removed from metrics when its semantics is unsupported.'],
      configs=[dict(id=n,sql=sql_for(n),sqlSha256=hashlib.sha256(sql_for(n).encode()).hexdigest(),allowedColumns=sorted(cols),expectedRoleDeclaration=e) for n,_,cols,e in CONFIGS],cases=cases)

def engine(plan,analyzer,version):
    if plan!=freeze():raise ValueError('FROZEN_TRUTH_CHANGED')
    rows=[]
    for c in plan['cases']:
        r=subprocess.run(['node','--max-old-space-size=192',str(Path(__file__).with_name('node_probe_worker.mjs')),str(analyzer.resolve())],input=json.dumps(c['packet']).encode(),capture_output=True,timeout=10,check=True)
        s=json.loads(r.stdout)
        if s['analyzerVersion']!=version:raise ValueError('VERSION_MISMATCH')
        rows.append(dict(caseId=c['caseId'],sourceSha256=c['sourceSha256'],truth=c['truth'],supabase=s['supabaseAnalysis'],files=s['files']))
    return dict(worker=version,rows=rows,targetExecuted=False)

def export_controls(plan,root):
    if plan!=freeze() or root.exists():raise ValueError('NEW_FROZEN_EXPORT_REQUIRED')
    root.mkdir(mode=0o700);batches=[]
    for offset in range(0,len(plan['cases']),8):
        batch=root/f'batch-{offset//8}';batch.mkdir(mode=0o700);projects=[]
        for c in plan['cases'][offset:offset+8]:
            dest=batch/'sources'/c['caseId'];dest.mkdir(parents=True,mode=0o700);files=[];omitted=[]
            content={f['filePath']:f['content'] for f in c['packet']['files']};content['package.json']=json.dumps({'dependencies':{'next':'15.2.0'}})
            for f in c['packet']['policyFiles']:
                if f['status']=='SELECTED':content[f['filePath']]=f['content']
                else:omitted.append(dict(filePath=f['filePath'],kind='FILE',status='LIMIT_EXCEEDED',reason='AUTHORED_MISSING_MIGRATION'))
            for name,text in content.items():
                target=dest/name;target.parent.mkdir(parents=True,exist_ok=True);data=text.encode();target.write_bytes(data);target.chmod(0o600)
                files.append(dict(path=name,bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
            projects.append(dict(projectId=c['caseId'],commitSha='',collectionStatus='COLLECTED_AUTHORED_GRADE_B',files=files,omitted=omitted))
        write(batch/'application-plan.json',dict(schemaVersion=1,track='AUTHORED_COLUMN_ACL_CONTROLS_NOT_REAL_APPLICATIONS',projects=projects));batches.append(str(batch))
    return dict(batches=batches,sourceOrigin='AUTHOR_ORIGINAL_NO_EXTERNAL_CODE_COPIED')

def database(plan):
    if plan!=freeze():raise ValueError('FROZEN_TRUTH_CHANGED')
    env={k:v for k,v in os.environ.items() if k in ['PATH','HOME','LANG','LC_ALL']}
    bins={n:shutil.which(n) for n in ['initdb','pg_ctl','psql']}
    if not all(bins.values()):raise RuntimeError('LOCAL_POSTGRES_REQUIRED')
    folder=Path(tempfile.mkdtemp(prefix='sd-column12-',dir='/private/tmp'));folder.chmod(0o700);data=folder/'data';sock=folder/'sock';sock.mkdir(mode=0o700);started=False
    def command(args):return subprocess.run(args,env=env,capture_output=True,text=True,timeout=20)
    def sql(q,role=None,subject=''):
        prefix=f"SET ROLE {role};SET request.jwt.claim.sub='{subject}';" if role else ''
        p=command([bins['psql'],'-X','-h',str(sock),'-p','65489','-U','bench_admin','-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-At','-c',prefix+q])
        if p.returncode:
            m=re.search(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):',p.stderr)
            if not m or not role:raise RuntimeError('CONTROL_SQL_SETUP_FAILED')
            return dict(sqlstate=m[1],rowCount=None)
        lines=[s for s in p.stdout.splitlines() if s not in ['SET','BEGIN','COMMIT','ROLLBACK']]
        v=lines[-1] if lines else '';tag=re.fullmatch(r'(?:UPDATE|DELETE|INSERT 0) (\d+)',v)
        return dict(sqlstate=None,rowCount=int(tag[1]) if tag else int(v) if v.isdigit() else None,value=v)
    try:
        if command([bins['initdb'],'-D',str(data),'-U','bench_admin','--auth-local=trust','--auth-host=reject','--no-locale','-E','UTF8']).returncode:raise RuntimeError('INITDB_FAILED')
        p=command([bins['pg_ctl'],'-D',str(data),'-l',str(folder/'server.log'),'-w','start','-o',f"-h '' -k {sock} -p 65489 -c shared_buffers=16MB -c max_connections=10 -c statement_timeout=2000 -c idle_in_transaction_session_timeout=2000"]);started=(data/'postmaster.pid').exists()
        if p.returncode or sql('SHOW data_directory;')['value']!=str(data) or sql('SHOW listen_addresses;')['value']!='':raise RuntimeError('ISOLATION_FAILED')
        sql("CREATE ROLE anon NOLOGIN NOBYPASSRLS;CREATE ROLE authenticated NOLOGIN NOBYPASSRLS INHERIT;CREATE ROLE writers NOLOGIN NOBYPASSRLS;CREATE ROLE limited_admin NOLOGIN NOBYPASSRLS;CREATE SCHEMA auth;CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$SELECT nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;GRANT USAGE ON SCHEMA auth,public TO anon,authenticated,limited_admin,writers;GRANT EXECUTE ON FUNCTION auth.uid() TO anon,authenticated,limited_admin,writers;")
        rows=[]
        # Existing frozen packet 14 has a broad row policy; check its exact SQL too.
        broad_sql=plan['cases'][14]['packet']['policyFiles'][0]['content']
        if broad_sql!=sql_for('column-revoke-table-stays',True):raise ValueError('BROAD_PACKET_SQL_CHANGED')
        configs=[*plan['configs'],dict(id='broad-column-revoke',sql=broad_sql,sqlSha256=hashlib.sha256(broad_sql.encode()).hexdigest(),allowedColumns=['payload','role','is_admin','user_id'],broad=True)]
        for c in configs:
            sql('REVOKE writers FROM authenticated;DROP TABLE IF EXISTS public.items;'+c['sql'])
            for role,subject in [('authenticated',A),('authenticated',B),('anon',''),('limited_admin','')]:
                own,other=(2,1) if subject==B else (1,2)
                probes=[('payload-own','payload',own,"'changed'"),('protected-own','role',own,"'admin'"),('admin-own','is_admin',own,'true'),('payload-other','payload',other,"'changed'"),('protected-other','role',other,"'admin'"),('transfer-owner','user_id',own,f"'{A if subject==B else B}'")]
                for ident,col,target,value in probes:
                    sql(f"TRUNCATE public.items;INSERT INTO public.items VALUES(1,'{A}','a'),(2,'{B}','b');")
                    actual=sql(f'UPDATE public.items SET {col}={value} WHERE id={target};',role,subject)
                    # PUBLIC privilege alone does not supply the missing authenticated SELECT grant or RLS role.
                    public_cols={'payload','role','is_admin','user_id'} if c['id']=='public-table' else {'role'} if c['id']=='public-column' else set()
                    allowed=role=='authenticated' and col in c['allowedColumns']
                    expected=0 if role=='limited_admin' and col in public_cols else '42501' if not allowed else 1 if c.get('broad') else 0 if target==other else '42501' if col=='user_id' else 1
                    state=json.loads(sql('SELECT json_agg(row_to_json(i) ORDER BY id) FROM public.items i;')['value'])
                    expected_state=[dict(id=1,user_id=A,payload='a',role='member',is_admin=False),dict(id=2,user_id=B,payload='b',role='member',is_admin=False)]
                    if expected==1:expected_state[target-1][col]='changed' if col=='payload' else 'admin' if col=='role' else (A if subject==B else B) if col=='user_id' else True
                    matched=actual['sqlstate']==expected if isinstance(expected,str) else actual['sqlstate'] is None and actual['rowCount']==expected
                    rows.append(dict(config=c['id'],role=role,subject='A' if subject==A else 'B' if subject==B else 'NONE',probe=ident,expected=expected,actual=actual,valuesMatch=state==expected_state,match=matched and state==expected_state))
        return dict(postgres=sql('SHOW server_version;')['value'],rows=rows,total=len(rows),matched=sum(r['match'] for r in rows),tcpListening=False,clusterRemoved=True,userDatabaseAccessed=False,externalSqlExecuted=False,authUid='CURRENT_SETTING_STUB_NOT_JWT_AUTH',configHashes={c['id']:c['sqlSha256'] for c in configs},extension='Exact already-frozen broad policy packet added to the oracle; original requirements, packets and earlier 288 results retained.')
    finally:
        if started and command([bins['pg_ctl'],'-D',str(data),'-w','stop','-m','immediate']).returncode:raise RuntimeError('CLEANUP_FAILED')
        shutil.rmtree(folder)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['freeze','engine','database']);p.add_argument('output',type=Path);p.add_argument('--plan',type=Path);p.add_argument('--analyzer',type=Path);p.add_argument('--version',default='ts-server-v27');a=p.parse_args()
    r=freeze() if a.mode=='freeze' else engine(read(a.plan),a.analyzer,a.version) if a.mode=='engine' else database(read(a.plan));write(a.output,r)
    print(dict(mode=a.mode,cases=len(r.get('cases',r.get('rows',[]))),matched=r.get('matched'),total=r.get('total')))
    if a.mode=='database' and r['matched']!=r['total']:raise SystemExit(2)
