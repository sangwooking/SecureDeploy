"""Authored SQL declaration/runtime differential, not production authorization."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from application_track import outside, write

A = '11111111-1111-1111-1111-111111111111'
B = '22222222-2222-2222-2222-222222222222'
BASE = 'CREATE TABLE public.notes(id integer PRIMARY KEY, owner_id uuid, body text, protected text);ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;'
OWN = 'auth.uid()=owner_id'


def policy(using='true', check='true', name='p', mode='PERMISSIVE', role='authenticated'):
    return f'CREATE POLICY {name} ON public.notes AS {mode} FOR ALL TO {role} USING({using}) WITH CHECK({check});'


def cases():
    column = 'GRANT SELECT,UPDATE(body) ON public.notes TO authenticated;'
    table = 'GRANT SELECT,INSERT,UPDATE,DELETE ON public.notes TO authenticated;'
    # Expectations fixed separately from engine output: SELECT-other, INSERT-other,
    # UPDATE-own, UPDATE-other, protected-own, transfer-owner, DELETE-other.
    own = [0, '42501', 1, 0, 1, '42501', 0]
    denied = ['42501'] * 7
    rows = [
        ('column-broad', column + policy(), True, [1, '42501', 1, 1, '42501', '42501', '42501']),
        ('column-owner-fixed', column + policy(OWN, OWN), False, [0, '42501', 1, 0, '42501', '42501', '42501']),
        ('table-owner', table + policy(OWN, OWN), False, own),
        ('table-broad', table + policy(), True, [1, 1, 1, 1, 1, 1, 1]),
        ('column-revoke', column + 'REVOKE UPDATE(body) ON public.notes FROM authenticated;' + policy(), False, [1] + ['42501'] * 6),
        ('table-survives-column-revoke', table + 'REVOKE UPDATE(protected) ON public.notes FROM authenticated;' + policy(), True, [1] * 7),
        ('public-column', 'GRANT SELECT ON public.notes TO PUBLIC;GRANT UPDATE(body) ON public.notes TO PUBLIC;' + policy(role='public'), True, [1, '42501', 1, 1, '42501', '42501', '42501']),
        ('restrictive-owner', column + policy() + policy(OWN, OWN, 'guard', 'RESTRICTIVE'), False, [0, '42501', 1, 0, '42501', '42501', '42501']),
        ('restrictive-alone', column + policy(name='guard', mode='RESTRICTIVE'), False, [0, '42501', 0, 0, '42501', '42501', '42501']),
        ('permissive-widens', column + policy(OWN, OWN) + policy(name='extra'), True, [1, '42501', 1, 1, '42501', '42501', '42501']),
        ('omitted-check', table + f'CREATE POLICY p ON public.notes TO authenticated USING({OWN});', False, own),
        ('open-new-row', table + policy(OWN, 'true') + 'CREATE POLICY read ON public.notes FOR SELECT TO authenticated USING(true);', True, [1, 1, 1, 0, 1, 1, 0]),
        ('open-old-row', table + policy('true', OWN), True, [1, '42501', 1, '42501', 1, '42501', 1]),
        ('rls-disabled', column + 'ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;', True, [1, '42501', 1, 1, '42501', '42501', '42501']),
    ]
    return [dict(id=n, sql=BASE + s, expectedCandidate=c, expectedAuthenticated=e,
                 sqlSha256=hashlib.sha256((BASE + s).encode()).hexdigest()) for n, s, c, e in rows]


def packet(case):
    return dict(files=[], policyFiles=[dict(filePath='supabase/migrations/001_notes.sql', status='SELECTED', content=case['sql'])])


def static(repo):
    worker = repo / 'analyzers/typescript'
    rows = []
    for c in cases():
        runs = []
        for _ in range(2):
            p = subprocess.run(['node', '--permission', '--no-addons', '--max-old-space-size=192',
                                '--allow-fs-read=' + str(worker), str(worker / 'worker.mjs')],
                               input=json.dumps(packet(c)).encode(), capture_output=True, timeout=15, check=True)
            runs.append(json.loads(p.stdout))
        if runs[0] != runs[1]:
            raise ValueError('NONDETERMINISM')
        s = runs[0]['supabaseAnalysis']
        operation = next(o for o in s['tables'][0]['operations'] if o['role'] == 'authenticated' and o['operation'] == 'UPDATE')
        rows.append(dict(id=c['id'], sqlSha256=c['sqlSha256'], expectedCandidate=c['expectedCandidate'],
                         candidate=operation['candidate'], operation=operation, updatePrivileges=s['tables'][0]['updatePrivileges'],
                         findings=len(s['findings']), repeatIdentical=True))
    return dict(worker=runs[0]['analyzerVersion'], rls=s['analyzerVersion'], rows=rows,
                total=len(rows), matched=sum(r['candidate'] == r['expectedCandidate'] for r in rows))


def export(root):
    root = outside(root)
    if root.exists():
        raise ValueError('NEW_EXPORT_REQUIRED')
    projects = []
    for name, case, omitted in [('broad', cases()[0], False), ('fixed', cases()[1], False), ('unknown', cases()[0], True)]:
        source = "import {createClient} from '@supabase/supabase-js';const db=createClient('https://example.invalid',process.env.SUPABASE_ANON_KEY);export async function PATCH(req){const body=await req.json();return db.from('notes').update({body:body.body}).eq('id',body.id);}"
        contents = {'app/api/notes/route.ts': source, 'package.json': json.dumps({'dependencies': {'next': '15.3.0'}}),
                    'supabase/migrations/001_notes.sql': case['sql']}
        inventory = []
        for path, text in contents.items():
            dest = root / 'sources' / name / path
            dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = text.encode()
            dest.write_bytes(data)
            dest.chmod(0o600)
            inventory.append(dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        projects.append(dict(projectId=name, commitSha='AUTHORED_NOT_UPSTREAM_' + case['sqlSha256'], files=inventory,
                             collectionStatus='COLLECTED_AUTHORED_GRADE_B', omitted=[dict(filePath='supabase/migrations/002_missing.sql', kind='FILE', status='LIMIT_EXCEEDED', reason='AUTHORED_MISSING_MIGRATION')] if omitted else []))
    write(root / 'application-plan.json', dict(schemaVersion=1, projects=projects))
    return dict(projects=len(projects), grade='B_AUTHORED_NOT_UPSTREAM_FIX', targetExecuted=False)


def database():
    bins = Path('/opt/homebrew/opt/postgresql@16/bin')
    env = {k: v for k, v in os.environ.items() if k in ['PATH', 'HOME', 'LANG', 'LC_ALL']}
    folder = Path(tempfile.mkdtemp(prefix='sd-rls23-', dir='/private/tmp'))
    folder.chmod(0o700)
    data, sock = folder / 'data', folder / 'sock'
    sock.mkdir(mode=0o700)
    started = False

    def command(args):
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)

    def sql(query, role=None, subject=''):
        prefix = f"SET ROLE {role};SET request.jwt.claim.sub='{subject}';" if role else ''
        p = command([str(bins / 'psql'), '-X', '-h', str(sock), '-p', '65488', '-U', 'bench_admin', '-d', 'postgres',
                     '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose', '-At', '-c', prefix + query])
        if p.returncode:
            m = re.search(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5}):', p.stderr)
            if not m or not role:
                raise RuntimeError('CONTROL_SQL_SETUP_FAILED')
            return dict(sqlstate=m[1], rows=None, returned=[])
        lines = [s for s in p.stdout.splitlines() if s not in ['SET', 'BEGIN', 'ROLLBACK', 'COMMIT']]
        return dict(sqlstate=None, lines=lines)

    try:
        if command([str(bins / 'initdb'), '-D', str(data), '-U', 'bench_admin', '--auth-local=trust', '--auth-host=reject', '--no-locale', '-E', 'UTF8']).returncode:
            raise RuntimeError('INITDB_FAILED')
        p = command([str(bins / 'pg_ctl'), '-D', str(data), '-l', str(folder / 'server.log'), '-w', 'start', '-o',
                     f"-h '' -k {sock} -p 65488 -c shared_buffers=16MB -c max_connections=10 -c statement_timeout=2000"])
        started = (data / 'postmaster.pid').exists()
        if p.returncode or sql('SHOW data_directory;')['lines'] != [str(data)] or sql('SHOW listen_addresses;')['lines'] != ['']:
            raise RuntimeError('ISOLATION_FAILED')
        version = sql('SHOW server_version;')['lines'][0]
        if not version.startswith('16.'):
            raise RuntimeError('POSTGRES_16_REQUIRED')
        sql("CREATE ROLE anon NOLOGIN NOBYPASSRLS;CREATE ROLE authenticated NOLOGIN NOBYPASSRLS;CREATE ROLE limited_admin NOLOGIN NOBYPASSRLS;CREATE SCHEMA auth;CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$SELECT nullif(current_setting('request.jwt.claim.sub',true),'')::uuid$$;GRANT USAGE ON SCHEMA auth,public TO anon,authenticated,limited_admin;GRANT EXECUTE ON FUNCTION auth.uid() TO anon,authenticated,limited_admin;")
        rows = []
        for c in cases():
            sql('DROP TABLE IF EXISTS public.notes;' + c['sql'] + 'GRANT SELECT,INSERT,UPDATE,DELETE ON public.notes TO limited_admin;' + policy(name='admin', role='limited_admin'))
            for role, subject, label in [('authenticated', A, 'A'), ('authenticated', B, 'B'), ('anon', '', 'NONE'), ('limited_admin', '', 'ADMIN')]:
                own, other = (2, 1) if subject == B else (1, 2)
                opposite = A if subject == B else B
                queries = [f'SELECT id FROM public.notes WHERE id={other};',
                           f"INSERT INTO public.notes VALUES(3,'{opposite}','new','member') RETURNING id;",
                           f"UPDATE public.notes SET body='changed' WHERE id={own} RETURNING id;",
                           f"UPDATE public.notes SET body='changed' WHERE id={other} RETURNING id;",
                           f"UPDATE public.notes SET protected='admin' WHERE id={own} RETURNING id;",
                           f"UPDATE public.notes SET owner_id='{opposite}' WHERE id={own} RETURNING id;",
                           f'DELETE FROM public.notes WHERE id={other} RETURNING id;',
                           f"UPDATE public.notes SET owner_id='{subject or A}' WHERE id={other} RETURNING id;"]
                expected = c['expectedAuthenticated'] if role == 'authenticated' else [1] * 7 if role == 'limited_admin' else c['expectedAuthenticated'] if c['id'] == 'public-column' else ['42501'] * 7
                claim = 1 if c['id'] in ['table-broad', 'table-survives-column-revoke', 'open-old-row'] else 0 if c['id'] in ['table-owner', 'omitted-check', 'open-new-row'] else '42501'
                expected = [*expected, claim if role == 'authenticated' else 1 if role == 'limited_admin' else '42501']
                for i, q in enumerate(queries):
                    sql(f"TRUNCATE public.notes;INSERT INTO public.notes VALUES(1,'{A}','a','member'),(2,'{B}','b','member');")
                    before = json.loads(sql('SELECT jsonb_agg(n ORDER BY id) FROM public.notes n;')['lines'][0])
                    actual = sql(q, role, subject)
                    returned = [int(x) for x in actual.get('lines', []) if x.isdigit()]
                    tag = next((re.fullmatch(r'(?:UPDATE|DELETE|INSERT 0) (\d+)', x) for x in actual.get('lines', []) if re.fullmatch(r'(?:UPDATE|DELETE|INSERT 0) (\d+)', x)), None)
                    count = int(tag[1]) if tag else len(returned) if actual['sqlstate'] is None else None
                    after = json.loads(sql('SELECT jsonb_agg(n ORDER BY id) FROM public.notes n;')['lines'][0])
                    wanted = [dict(r) for r in before]
                    e = expected[i]
                    if e == 1:
                        if i == 1:
                            wanted.append(dict(id=3, owner_id=opposite, body='new', protected='member'))
                        elif i in [2, 3, 4, 5, 7]:
                            target = other if i in [3, 7] else own
                            col = 'owner_id' if i in [5, 7] else 'protected' if i == 4 else 'body'
                            wanted[target-1][col] = (subject or A) if i == 7 else opposite if i == 5 else 'admin' if i == 4 else 'changed'
                        elif i == 6:
                            wanted = [r for r in wanted if r['id'] != other]
                    matched = (actual['sqlstate'] == e if isinstance(e, str) else actual['sqlstate'] is None and count == e)
                    returned_expected = [] if isinstance(e, str) or e == 0 else [3 if i == 1 else other if i in [0, 3, 6, 7] else own]
                    rows.append(dict(case=c['id'], role=role, subject=label, probe=i, expected=e, sqlstate=actual['sqlstate'],
                                     affectedRows=count, returned=returned, before=before, after=after,
                                     match=matched and returned == returned_expected and after == wanted))
        sql('CREATE ROLE object_owner NOLOGIN NOBYPASSRLS;CREATE ROLE bypass NOLOGIN BYPASSRLS;GRANT USAGE ON SCHEMA auth,public TO object_owner,bypass;GRANT EXECUTE ON FUNCTION auth.uid() TO object_owner,bypass;')
        exceptions = []
        for force in [False, True]:
            for role in ['object_owner', 'bypass']:
                sql('DROP TABLE public.notes;' + BASE + 'ALTER TABLE public.notes OWNER TO object_owner;GRANT SELECT,UPDATE ON public.notes TO bypass;' + policy(OWN, OWN, role='object_owner') + ('ALTER TABLE public.notes FORCE ROW LEVEL SECURITY;' if force else ''))
                for operation in ['SELECT', 'UPDATE']:
                    sql(f"TRUNCATE public.notes;INSERT INTO public.notes VALUES(1,'{A}','a','member'),(2,'{B}','b','member');")
                    q = 'SELECT id FROM public.notes WHERE id=2;' if operation == 'SELECT' else "UPDATE public.notes SET body='changed' WHERE id=2 RETURNING id;"
                    r = sql(q, role, A)
                    got = [int(v) for v in r.get('lines', []) if v.isdigit()]
                    count = 0 if force and role == 'object_owner' else 1
                    state = json.loads(sql('SELECT jsonb_agg(n ORDER BY id) FROM public.notes n;')['lines'][0])
                    expected_body = 'changed' if operation == 'UPDATE' and count else 'b'
                    exceptions.append(dict(force=force, role=role, operation=operation, expectedRows=count,
                                           sqlstate=r['sqlstate'], returned=got, state=state,
                                           match=r['sqlstate'] is None and got == ([2] if count else []) and state[0]['body'] == 'a' and state[1]['body'] == expected_body))
        prerequisites = []
        updates = 'CREATE POLICY u ON public.notes FOR UPDATE TO authenticated USING(true) WITH CHECK(true);'
        setups = [
            ('no-select-grant', 'GRANT UPDATE(body) ON public.notes TO authenticated;', [
                ("UPDATE public.notes SET body='changed';", 2, []),
                ("UPDATE public.notes SET body='changed' WHERE id=1;", '42501', []),
                ("UPDATE public.notes SET body='changed' RETURNING body;", '42501', [])]),
            ('column-select', 'GRANT UPDATE(body),SELECT(body) ON public.notes TO authenticated;CREATE POLICY r ON public.notes FOR SELECT TO authenticated USING(true);', [
                ("UPDATE public.notes SET body='changed' RETURNING body;", 2, ['changed', 'changed']),
                ("UPDATE public.notes SET body='changed' RETURNING id;", '42501', []),
                ("UPDATE public.notes SET body='changed' WHERE id=1;", '42501', []),
                ("UPDATE public.notes SET body='changed' WHERE body='a' RETURNING body;", 1, ['changed'])]),
            ('no-select-policy', 'GRANT SELECT,UPDATE(body) ON public.notes TO authenticated;', [
                ("UPDATE public.notes SET body='changed';", 2, []),
                ("UPDATE public.notes SET body='changed' WHERE id=1;", 0, []),
                ("UPDATE public.notes SET body='changed' RETURNING id;", 0, [])]),
            ('owner-select-policy', 'GRANT SELECT,UPDATE ON public.notes TO authenticated;CREATE POLICY r ON public.notes FOR SELECT TO authenticated USING(auth.uid()=owner_id);', [
                ("UPDATE public.notes SET body='changed' WHERE id=1 RETURNING id;", 1, ['1']),
                ("UPDATE public.notes SET body='changed' WHERE id=2 RETURNING id;", 0, []),
                (f"UPDATE public.notes SET owner_id='{B}' WHERE id=1 RETURNING id;", '42501', [])]),
        ]
        for name, acl, probes in setups:
            sql('DROP TABLE public.notes;' + BASE + acl + updates)
            for q, expected, returned in probes:
                sql(f"TRUNCATE public.notes;INSERT INTO public.notes VALUES(1,'{A}','a','member'),(2,'{B}','b','member');")
                before = json.loads(sql('SELECT jsonb_agg(n ORDER BY id) FROM public.notes n;')['lines'][0])
                r = sql(q, 'authenticated', A)
                lines = r.get('lines', [])
                tag = re.fullmatch(r'UPDATE (\d+)', lines[-1]) if lines else None
                count = int(tag[1]) if tag else None
                got = lines[:-1] if tag else lines
                after = json.loads(sql('SELECT jsonb_agg(n ORDER BY id) FROM public.notes n;')['lines'][0])
                wanted = [dict(row) for row in before]
                if isinstance(expected, int) and expected:
                    for row in wanted[:expected]:
                        row['body'] = 'changed'
                matched = r['sqlstate'] == expected if isinstance(expected, str) else r['sqlstate'] is None and count == expected
                prerequisites.append(dict(case=name, query=q, expected=expected, sqlstate=r['sqlstate'], affectedRows=count,
                                          returned=got, before=before, after=after,
                                          match=matched and got == returned and after == wanted))
        return dict(postgres=version, total=len(rows), matched=sum(r['match'] for r in rows), rows=rows,
                    exceptionChecks=exceptions, exceptionMatched=sum(r['match'] for r in exceptions),
                    prerequisiteChecks=prerequisites, prerequisiteMatched=sum(r['match'] for r in prerequisites),
                    authUid='CURRENT_SETTING_STUB_NOT_SUPABASE_AUTH', userDatabaseAccessed=False, tcpListening=False,
                    externalSqlExecuted=False, requirements='AUTHORED_NOT_OWNER_APPROVED', clusterRemoved=True)
    finally:
        if started and command([str(bins / 'pg_ctl'), '-D', str(data), '-w', 'stop', '-m', 'immediate']).returncode:
            raise RuntimeError('CLEANUP_FAILED')
        shutil.rmtree(folder)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['static', 'database', 'export'])
    p.add_argument('--repo', type=Path)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    if args.mode == 'export':
        print(json.dumps(export(args.output)))
        raise SystemExit(0)
    r = static(args.repo.resolve()) if args.mode == 'static' else database()
    write(outside(args.output), r)
    print(json.dumps({k: v for k, v in r.items() if k not in ['rows', 'exceptionChecks', 'prerequisiteChecks']}))
    if r['matched'] != r['total'] or args.mode == 'database' and (r['exceptionMatched'] != len(r['exceptionChecks']) or r['prerequisiteMatched'] != len(r['prerequisiteChecks'])):
        raise SystemExit(2)
