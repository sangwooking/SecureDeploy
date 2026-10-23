"""Pinned public static intake. Never installs, imports or executes target code."""
import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import time
from pathlib import Path
import urllib.request
from application_track import collect, outside, relative, write, CREDENTIAL
from benchmark import stable
from collections import Counter

PINS = {
    'dvna-vulnerable': ('appsecco/dvna', '9ba473add536f66ac9007966acb2a775dd31277a'),
    'dvna-fixed': ('appsecco/dvna', '56c5e82c1a000e26ae19afb67b6696d634ceab2e'),
    'dvna-remediated': ('appsecco/dvna', '4b16c488839ac5428b9c2573c96d886bee885b02'),
    'juice-shop': ('juice-shop/juice-shop', '717f5efa886b0417eeecb52378b03cf10567b7e2'),
    'next-supabase': ('vercel/next.js', '2998a2e801caab665d603daefc7445c04309285a'),
}

def fetch(url, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'SecureDeploy-static-deep-dive', 'Accept-Encoding': 'identity'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('DOWNLOAD_LIMIT')
    return data

def example(root):
    repo, sha = PINS['next-supabase']
    def tree(ref):
        return json.loads(fetch(f'https://api.github.com/repos/{repo}/git/trees/{ref}', 2_000_000))
    top = tree(sha)
    examples = next(e['sha'] for e in top['tree'] if e['path'] == 'examples')
    sub = next(e['sha'] for e in tree(examples)['tree'] if e['path'] == 'with-supabase')
    entries = json.loads(fetch(f'https://api.github.com/repos/{repo}/git/trees/{sub}?recursive=1', 2_000_000))
    if entries.get('truncated') or len(entries['tree']) > 200:
        raise ValueError('EXAMPLE_TREE_LIMIT')
    license_path = next(e['path'] for e in top['tree'] if e['path'].lower() in {'license', 'license.md', 'license.txt'})
    project_id = repo.replace('/', '--')
    source = root / 'sources' / project_id
    source.mkdir(parents=True, mode=0o700)
    candidates = [(license_path, None)] + [('examples/with-supabase/' + e['path'], e) for e in entries['tree'] if e['type'] != 'tree']
    files, omitted, total = [], [], 0
    for name, entry in candidates:
        relative(name)
        if entry and (entry['type'] != 'blob' or entry.get('mode') == '120000' or entry.get('size', 0) > 256_000):
            omitted.append(dict(filePath=name, status='EXCLUDED', reason='PUBLIC_EXAMPLE_TYPE_OR_SIZE_LIMIT'))
            continue
        data = fetch(f'https://raw.githubusercontent.com/{repo}/{sha}/{name}', 256_000)
        total += len(data)
        if total > 4_000_000:
            raise ValueError('EXAMPLE_TOTAL_LIMIT')
        try:
            data.decode('utf8')
        except UnicodeDecodeError:
            omitted.append(dict(filePath=name, status='EXCLUDED', reason='BINARY_NOT_ANALYZED'))
            continue
        if CREDENTIAL.search(data):
            omitted.append(dict(filePath=name, status='EXCLUDED', reason='CREDENTIAL_SHAPED_CONTENT_NOT_PERSISTED'))
            continue
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open('xb') as output:
            target.chmod(0o600)
            output.write(data)
        files.append(dict(path=name, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
    write(root / 'application-plan.json', dict(schemaVersion=1, projects=[dict(projectId=project_id,
        full_name=repo, commitSha=sha, license='MIT', collectionStatus='COLLECTED_WITH_EXPLICIT_OMISSIONS',
        sourceScope='PINNED_WITH_SUPABASE_EXAMPLE_ONLY_NOT_WHOLE_NEXT_REPOSITORY',
        discoveredArchiveFiles=len(candidates), retainedFiles=len(files), files=files, omitted=omitted)],
        externalLookups='NOT_RUN', targetExecuted=False))
    print(json.dumps(dict(project=project_id, files=len(files), omitted=len(omitted))))

def intake(root):
    root = outside(root)
    root.mkdir(mode=0o700)
    for name, (repo, sha) in PINS.items():
        if name == 'next-supabase':
            (root / name).mkdir(mode=0o700)
            example(root / name)
        else:
            collect(dict(candidates=[dict(full_name=repo, commitSha=sha, license='MIT', selected=True)]), root / name)
    write(root / 'receipt.json', dict(schemaVersion=1, engineBaseline='45f205c2e8b5b59e62906cd6788a5d7189dcd543',
        pins={k:dict(repository=v[0], sha=v[1]) for k,v in PINS.items()},
        targetExecuted=False, groundTruth='REQUIRES_PATH_REVIEW_BEFORE_ENGINE_RUN',
        split='OBSERVED_RESEARCH_NOT_BLIND_HOLDOUT'))

def freeze_truth(root):
    root=outside(root)
    cases=[]
    # Path-scoped judgments reviewed before executing SecureDeploy; never whole-app SAFE labels.
    specs=[
        ('dvna-sql','dvna-vulnerable','core/appHandler.js',11,'RISK','CWE-89','docs/solution/a1-injection.md'),
        ('dvna-shell','dvna-vulnerable','core/appHandler.js',39,'RISK','CWE-78','docs/solution/a1-injection.md'),
        ('dvna-deserialization','dvna-vulnerable','core/appHandler.js',218,'RISK','CWE-502','docs/solution/a8-insecure-deserialization.md'),
        ('dvna-2017-sql-still-present','dvna-fixed','core/appHandler.js',11,'RISK','CWE-89','docs/solution/a1-injection.md'),
        ('dvna-2017-shell-still-present','dvna-fixed','core/appHandler.js',39,'RISK','CWE-78','docs/solution/a1-injection.md'),
        ('dvna-model-query-counterpart','dvna-remediated','core/appHandler.js',10,'NORMAL_FOR_TARGET','CWE-89','docs/solution/a1-injection.md'),
        ('dvna-execfile-counterpart','dvna-remediated','core/appHandler.js',43,'NORMAL_FOR_TARGET','CWE-78','docs/solution/a1-injection.md'),
        ('juice-search-sql','juice-shop','routes/search.ts',23,'RISK','CWE-89','data/static/challenges.yml'),
        ('juice-login-sql','juice-shop','routes/login.ts',34,'RISK','CWE-89','data/static/challenges.yml'),
        ('juice-profile-ssrf','juice-shop','routes/profileImageUrlUpload.ts',24,'RISK','CWE-918','data/static/challenges.yml'),
    ]
    for case_id,project,path,line,truth,cwe,doc in specs:
        repo,sha=PINS[project];base=root/project/'sources'/repo.replace('/','--')
        doc_project='dvna-vulnerable' if project.startswith('dvna-') else project
        doc_base=root/doc_project/'sources'/repo.replace('/','--')
        data=(base/path).read_bytes();documentation=(doc_base/doc).read_bytes()
        expected='execFile(' if 'execfile' in case_id else 'exec(' if 'shell' in case_id else '.find(' if 'model-query' in case_id else '.query(' if cwe=='CWE-89' else 'unserialize(' if cwe=='CWE-502' else 'fetch('
        if expected not in data.decode().splitlines()[line-1]:raise ValueError('GROUND_TRUTH_SOURCE_LOCATION_MISMATCH')
        cases.append(dict(caseId=case_id,project=project,repository=repo,sha=sha,grade='A_DOCUMENTED_PATH_NOT_CVE_CLAIM',
            filePath=path,line=line,truth=truth,cwe=cwe,fileSha256=hashlib.sha256(data).hexdigest(),
            documentation=doc,documentationCommit=PINS[doc_project][1],documentationSha256=hashlib.sha256(documentation).hexdigest(),
            pairedCase={'dvna-sql':'dvna-model-query-counterpart','dvna-shell':'dvna-execfile-counterpart'}.get(case_id),
            supportStatus='TO_BE_MEASURED_SEPARATELY',split='OBSERVED_REGRESSION_NOT_BLIND',
            limits=['No target execution or exploitation.','Normal label applies only to the named injection mechanism.','Branch name is not a safety label.']))
    write(root/'ground-truth-v2.json',dict(schemaVersion=1,baseline='45f205c2e8b5b59e62906cd6788a5d7189dcd543',
        workerVersions=dict(typescript='ts-server-v17',python='py-django-v8',java='java-sql-v4'),cases=cases,
        nextSupabaseGrade='C_CONTEXT_ONLY_NEVER_TN',externalIndependentReview=False,
        truthFrozenBeforeResultReview=True,locationMetadataCorrectedDuringBaselineExecution=True,
        sca='Static manifest extraction only; live advisory lookups excluded to isolate engine effects.'))

def freeze_validation(root):
    root=outside(root)
    project=json.loads((root/'application-plan.json').read_text())['projects'][0]
    if project['full_name']!='snyk-labs/nodejs-goof' or project['commitSha']!='add14ba59e98240d9e00a235dd7d42cd61ae9912':
        raise ValueError('VALIDATION_IDENTITY')
    base=root/'sources'/project['projectId']
    checks={'app.js':[(29,"require('./routes')"),(60,"app.post('/create', routes.create)")],
            'routes/index.js':[(11,"require('child_process').exec"),(168,'req.body.content'),(171,'item.match(imgRegex)[1]'),(174,"exec('identify ' + url")]}
    for path,locations in checks.items():
        lines=(base/path).read_text().splitlines()
        for line,expected in locations:
            if expected not in lines[line-1]:raise ValueError('VALIDATION_LOCATION')
    write(root/'validation-truth.json',dict(schemaVersion=1,project=project['full_name'],sha=project['commitSha'],
        grade='A_DOCUMENTED_VULNERABLE_APP_PATH_NO_VERIFIED_FIX_PAIR',truth='RISK',cwe='CWE-78',
        source=dict(filePath='routes/index.js',line=168),sink=dict(filePath='routes/index.js',line=174),
        context=checks,fileHashes={p:hashlib.sha256((base/p).read_bytes()).hexdigest() for p in checks},
        basis='Pinned request routing and command concatenation; regex extraction is not shell escaping.',
        limitations=['No paired patch validated.','No independent reviewer.','No runtime execution.'],
        split='CROSS_REPOSITORY_VALIDATION_NOT_BLIND_AFTER_REVIEW',frozenBeforeNewEngineResultReview=True))

def probe(root, worker, label=None):
    root=outside(root);worker=Path(worker).resolve()
    reports=[]
    for name in ['dvna-vulnerable','dvna-fixed','dvna-remediated','juice-shop','next-supabase']:
        plan=json.loads((root/name/'application-plan.json').read_text())['projects'][0]
        baseline=json.loads((root/(name+'-baseline.json')).read_text())['projects'][0]['runs'][0]
        source=root/name/'sources'/plan['projectId'];index={f['path']:f for f in plan['files']}
        def read_source(path):
            target=source/relative(path)
            if target.is_symlink() or not target.resolve().is_relative_to(source.resolve()):raise ValueError('SOURCE_PATH')
            data=target.read_bytes()
            if hashlib.sha256(data).hexdigest()!=index[path]['sha256']:raise ValueError('SOURCE_HASH')
            return data.decode()
        files=[dict(filePath=f['filePath'],content='\n'.join(read_source(f['filePath']).splitlines())) for f in baseline['typescript']['files'] if f['parseStatus']=='PARSED']
        manifests=[]
        for path in sorted(index):
            if not path.endswith('package.json'):continue
            try:package=json.loads(read_source(path))
            except (ValueError,UnicodeError):continue
            deps=package.get('dependencies',{})
            manifests.append(dict(filePath=path,**{k:v for k,v in deps.items() if k in {'express','mongodb','next'} and isinstance(v,str) and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v)}))
        packet=json.dumps(dict(files=files,nodeManifests=manifests),separators=(',',':')).encode()
        if len(packet)>1_200_000:raise ValueError('PACKET_LIMIT')
        command=['/usr/bin/time','-l','node','--max-old-space-size=192',str(Path(__file__).with_name('node_probe_worker.mjs')),str(worker/'analyzer.mjs')]
        start=time.monotonic();child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}},start_new_session=True)
        try:stdout,stderr=child.communicate(packet,timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL);child.wait();raise ValueError('WORKER_TIMEOUT')
        if child.returncode or len(stdout)>2_000_000:raise ValueError('WORKER_FAILURE')
        result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
        reports.append(dict(project=name,inputHash=hashlib.sha256(packet).hexdigest(),analysis=result,wallMs=round((time.monotonic()-start)*1000),
            maxRssBytes=int(rss.group(1)) if rss else None))
        print(json.dumps(dict(project=name,version=result['analyzerVersion'],findings=len(result['findings']),
            shellCandidates=sum(f['ruleId']=='JS_SHELL_COMMAND_INPUT_FLOW' for f in result['findings']))))
    version=reports[0]['analysis']['analyzerVersion']
    if label is not None and not re.fullmatch('[A-Za-z0-9_-]{1,40}',label):raise ValueError('PROBE_LABEL')
    write(root/('probe-'+version+('-'+label if label else '')+'.json'),dict(schemaVersion=1,scope='EXACT_BASELINE_SELECTED_INPUT_NOT_NEW_COLLECTION',
        workerHashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(worker.glob('*.mjs'))},projects=reports))

def outcome(case, row):
    ts=row['typescript'];path=case['filePath'];line=case['line'];cwe=case['cwe']
    rules={'CWE-78':{'JS_SHELL_COMMAND_INPUT_FLOW'},'CWE-89':{'TS_SQL_INPUT_FLOW'},'CWE-918':{'TS_SSRF_INPUT_FLOW'}}
    matching=[f for f in ts.get('validatedFindings') or [] if f['location']['filePath']==path and f['location']['line']==line
              and f['ruleId'] in rules.get(cwe,set())]
    if matching:return 'TP' if case['truth']=='RISK' else 'FP'
    # Explicit reviewed contracts, not an absence-of-warning safety heuristic.
    if case['caseId']=='dvna-execfile-counterpart' and any(u['kind']=='ARGV_WITHOUT_SHELL_DECLARED'
            and u['location']['filePath']==path and u['location']['line']==line for u in ts.get('nodeUses') or []):return 'TN'
    file=next((f for f in ts['files'] if f['filePath']==path),None)
    if not file or file['parseStatus']!='PARSED':return 'NOT_INSPECTED'
    if cwe in {'CWE-89','CWE-502'}:return 'NOT_SUPPORTED'
    if file['entrypoints']==0:return 'NOT_SUPPORTED'
    if cwe=='CWE-78' and ts['analyzerVersion']=='ts-server-v17':return 'NOT_SUPPORTED'
    return 'FN' if case['truth']=='RISK' else 'UNKNOWN'

def audit(root):
    root=outside(root);truth=json.loads((root/'ground-truth-v2.json').read_text());assets={};rows=[];checks=[]
    names=list(PINS)+['goof-validation']
    for name in names:
        before=json.loads((root/(name+'-baseline.json')).read_text())
        after=json.loads((root/(name+'-after.json')).read_text())
        if before['planSha256']!=after['planSha256']:raise ValueError('PLAN_CHANGED')
        a,b=before['projects'][0],after['projects'][0]
        if a['commitSha']!=b['commitSha'] or len(a['runs'])!=2 or len(b['runs'])!=2:raise ValueError('IDENTITY_OR_REPEAT')
        for p in [a,b]:
            if stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('NONDETERMINISTIC_RESULTS')
        assets[name]=(a['runs'][0],b['runs'][0])
        unchanged={k:stable(a['runs'][0][k])==stable(b['runs'][0][k]) for k in ['raw','filtered','securityScore','risk','sca']}
        checks.append(dict(project=name,sha=a['commitSha'],legacyUnchanged=unchanged,
            elapsedMsBefore=[r['elapsedMs'] for r in a['runs']],elapsedMsAfter=[r['elapsedMs'] for r in b['runs']],
            entrypointsBefore=sum(f['entrypoints'] for f in a['runs'][0]['typescript']['files']),
            entrypointsAfter=sum(f['entrypoints'] for f in b['runs'][0]['typescript']['files']),
            parsedBefore=sum(f['parseStatus']=='PARSED' for f in a['runs'][0]['typescript']['files']),
            parsedAfter=sum(f['parseStatus']=='PARSED' for f in b['runs'][0]['typescript']['files']),
            coverageBefore=a['runs'][0]['coverage']['status'],coverageAfter=b['runs'][0]['coverage']['status']))
    for c in truth['cases']:
        a,b=assets[c['project']]
        if c['project'].startswith('juice-'):cause='TARGET_ROUTE_NOT_SELECTED; server setup/wrappers also unmodeled, not proven as the first failure.'
        elif c['cwe']=='CWE-89':cause='Sequelize/model query API and dynamically created model origin outside declared SQL contract.'
        elif c['cwe']=='CWE-502':cause='Uploaded file source and node-serialize sink outside declared contract.'
        else:cause='Verified Node builtin shell sink added; no inference from function name alone.'
        rows.append(dict(caseId=c['caseId'],truth=c['truth'],cwe=c['cwe'],grade=c['grade'],sha=c['sha'],
            filePath=c['filePath'],line=c['line'],fileSha256=c['fileSha256'],before=outcome(c,a),after=outcome(c,b),
            rawRuleMatchedBefore=any(f['filePath']==c['filePath'] and f['line']==c['line'] for f in a['raw']),
            rawRuleMatchedAfter=any(f['filePath']==c['filePath'] and f['line']==c['line'] for f in b['raw']),
            reviewedFailureCause=cause,split='OBSERVED_REGRESSION_NOT_BLIND'))
    a,b=assets['goof-validation'];v=json.loads((root/'goof-validation'/'validation-truth.json').read_text())
    case=dict(caseId='goof-create-shell',truth='RISK',filePath=v['sink']['filePath'],line=v['sink']['line'],cwe=v['cwe'])
    validation=dict(**case,grade=v['grade'],sha=v['sha'],before=outcome(case,a),after=outcome(case,b),
        verifiedFirstGap='Express receiver mutation/setup uncertainty; zero registered request entries.',
        untestedLaterHypothesis='Regex match extraction may also require a separate supported transform contract.',
        split='CROSS_REPOSITORY_OBSERVED_VALIDATION_NO_EXTERNAL_REVIEW')
    counts={phase:dict(Counter(r[phase] for r in rows)) for phase in ['before','after']}
    if not all(all(c['legacyUnchanged'].values()) for c in checks):raise ValueError('LEGACY_SIGNAL_CHANGED')
    packs=[dict(caseId=r['caseId'],repository=PINS[next(c['project'] for c in truth['cases'] if c['caseId']==r['caseId'])][0],
        sha=r['sha'],filePath=r['filePath'],line=r['line'],fileSha256=r['fileSha256'],groundTruth=r['grade'],
        before=r['before'],after=r['after'],verifiedGap=r['reviewedFailureCause'],
        improvementCommit=json.loads((root/'dvna-vulnerable-after.json').read_text())['engineCommit'],
        limits=['No execution, exploit or whole-project safety claim.','No original code persisted in this pack.']) for r in rows if r['truth']=='RISK']
    result=dict(schemaVersion=1,baseline=truth['baseline'],engineCommit=json.loads((root/'dvna-vulnerable-after.json').read_text())['engineCommit'],
        frozenTruthSha256=hashlib.sha256((root/'ground-truth-v2.json').read_bytes()).hexdigest(),
        counts=counts,cases=rows,validation=validation,projectChecks=checks,failureCasePacks=packs,
        knownPatchCommits=['4fe36fcfbd615fc9ea340e1238be33dd0d140ef8','dc1f9c54685eb04f55e444370d6d622834e4cc00'],
        knownLimits=['Two shell positives are related DVNA revisions, not independent projects.',
            'Grade C Next example is never a TN; next=latest cannot establish the versioned route contract.',
            'No external independent reviewer or verified real-world CVE precision claim.',
            'Live SCA/OSV/EPSS/KEV not run; static component extraction only.',
            'Ground-truth locations corrected during baseline execution before result review; labels unchanged.'],
        policyChanges=False,userPostgresModified=False,targetExecuted=False)
    write(root/'source-free-summary.json',result)
    print(json.dumps(dict(counts=counts,validation=validation['after'],repeatConsistency=True,legacySignalsUnchanged=True)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('--freeze-truth',action='store_true')
    parser.add_argument('--probe-worker',type=Path)
    parser.add_argument('--probe-label')
    parser.add_argument('--freeze-validation',action='store_true')
    parser.add_argument('--audit',action='store_true')
    args=parser.parse_args()
    if args.audit:audit(args.output)
    elif args.probe_worker:probe(args.output,args.probe_worker,args.probe_label)
    elif args.freeze_validation:freeze_validation(args.output)
    elif args.freeze_truth:freeze_truth(args.output)
    else:intake(args.output)
