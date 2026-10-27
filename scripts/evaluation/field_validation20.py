"""Source-free #20 differential receipt. Never imports or executes target code."""
import argparse
import hashlib
import json
from pathlib import Path
from application_track import outside, write
from benchmark import stable

RULE = 'JS_MONGOOSE_SELECTOR_INPUT_FLOW'
SHA = 'add14ba59e98240d9e00a235dd7d42cd61ae9912'
ROUTE_HASH = 'a13d03f614346d07173ca0a4bb0917c35c8690ba5e14cdd3d091aa3810ea6d22'
README_HASH = '70c6c5b816dd3c24a6e5a83e3b3424b952ee10a11b134f0c38900bc9b4ce87cb'


def read(path):
    return json.loads(path.read_text())


def truth():
    return dict(project='snyk-labs/nodejs-goof', sha=SHA, license='Apache-2.0',
        grade='DOCUMENTED_VULNERABLE_APPLICATION_NO_VERIFIED_FIX_PAIR', split='REGRESSION_NOT_BLIND',
        target='Login object selector via an independently unvalidated request field',
        reference='https://github.com/snyk-labs/nodejs-goof/blob/'+SHA+'/README.md#nosql-injection',
        sourceEvidence=[dict(path='README.md', lines=[110,127], sha256=README_HASH),
                        dict(path='routes/index.js', lines=[50,52], sha256=ROUTE_HASH)],
        source=dict(path='routes/index.js', line=52, column=56),
        sink=dict(path='routes/index.js', line=52), callback=dict(line=52, column=77),
        registration=dict(path='app.js', line=55), model=dict(path='mongoose-db.js', line=17),
        validator=dict(declared='^13.5.2', locked='13.5.2', installed='UNKNOWN'),
        mongoose=dict(declared='4.2.4', locked='4.2.4', installed='UNKNOWN'),
        rule=RULE, expected='SOURCE_REVIEWED_STATIC_CANDIDATE', runtimeExploitVerified=False,
        independentReviewer=False, upstreamFixedPair=False,
        limits=['Uses the prior documented-path standard, not a new relaxed CVE ground truth.',
                'No target execution, attack, runtime database or plaintext-storage assertion.',
                'Authored type guards are a differential control, not an upstream fix or real-app TN.'])


def prepare(root, dest):
    root=outside(root);dest=outside(dest)
    if dest.exists() or dest.is_relative_to(root) or root.is_relative_to(dest):
        raise ValueError('FRESH_DISJOINT_DESTINATION_REQUIRED')
    plan=read(root/'application-plan.json');assert len(plan['projects'])==1
    project=plan['projects'][0];assert project['commitSha']==SHA
    source=root/'sources'/project['projectId'];blobs={}
    for f in project['files']:
        path=source/f['path']
        if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
            raise ValueError('UNSAFE_SOURCE_PATH')
        data=path.read_bytes()
        assert len(data)==f['bytes'] and hashlib.sha256(data).hexdigest()==f['sha256']
        blobs[f['path']]=data
    assert hashlib.sha256(blobs['routes/index.js']).hexdigest()==ROUTE_HASH
    assert hashlib.sha256(blobs['README.md']).hexdigest()==README_HASH
    anchor=b'exports.loginHandler = function (req, res, next) {\n'
    assert blobs['routes/index.js'].count(anchor)==1
    guards=b'  if (typeof req.body.username !== "string") return res.status(400).end();\n  if (typeof req.body.password !== "string") return res.status(400).end();\n'
    blobs['routes/index.js']=blobs['routes/index.js'].replace(anchor,anchor+guards)
    dest.mkdir(mode=0o700,parents=True)
    project['projectId']='goof-authored-field-type-control20'
    project['commitSha']='AUTHORED_DIFFERENTIAL_NOT_UPSTREAM_'+hashlib.sha256(blobs['routes/index.js']).hexdigest()
    project['collectionStatus']='COLLECTED_GRADE_B_DIFFERENTIAL_NOT_UPSTREAM_FIX'
    for f in project['files']:
        data=blobs[f['path']];p=dest/'sources'/project['projectId']/f['path']
        p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o600)
        f.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
    write(dest/'application-plan.json',plan)
    write(dest/'ground-truth-before-evaluation.json',truth())


def one(path):
    report=read(path);assert len(report['projects'])==1
    project=report['projects'][0];a,b=project['runs']
    assert stable(a)==stable(b),'NONDETERMINISM'
    return report,project,a


def audit(before, after, control, output):
    old,op,a=one(before);new,np,b=one(after);diff,dp,c=one(control)
    assert old['planSha256']==new['planSha256'] and op['commitSha']==np['commitSha']==SHA
    assert dp['commitSha'].startswith('AUTHORED_DIFFERENTIAL_NOT_UPSTREAM_')
    target=lambda r:[f for f in r['typescript']['validatedFindings'] if f['ruleId']==RULE
                     and f['location']['filePath']=='routes/index.js' and f['location']['line']==52]
    assert not target(a) and len(target(b))==1
    assert not [f for f in c['typescript']['validatedFindings'] if f['ruleId']==RULE]
    assert any(u['ruleId']==RULE and u['kind']=='STATIC_OR_STRING_FILTER'
               and u['location']['filePath']=='routes/index.js' and u['location']['line']==54
               for u in c['typescript']['nodeUses'])
    command=lambda r:[f for f in r['typescript']['validatedFindings'] if f['ruleId']=='JS_SHELL_COMMAND_INPUT_FLOW']
    assert len(command(a))==len(command(b))==len(command(c))==1
    f=target(b)[0];e=f['evidence'][0]
    assert e['source']['line']==52 and e['source']['column']==56
    assert e['source']['kind']=='HTTP_FIELD_SOURCE'
    assert any(p['kind']=='FIELD_EMAIL_ACCEPTED_BRANCH' for p in e['defenses'])
    assert any(p['kind']=='MONGOOSE_CALLBACK_EXECUTION_REQUEST' for p in e['flow'])
    assert f['priority']=='REVIEW_REQUIRED' and f['comparisonPolicy']=='NOT_COMPARED'
    unchanged={k:stable(a[k])==stable(b[k]) for k in ['raw','filtered','securityScore','risk','sca']}
    assert all(unchanged.values()),'LEGACY_REGRESSION'
    result=dict(schemaVersion=1,truth=truth(),baseline=old['engineCommit'],engine=new['engineCommit'],
        planSha256=new['planSha256'],legacyUnchanged=unchanged,
        before='UNKNOWN',after='SOURCE_REVIEWED_STATIC_CANDIDATE',control='STATIC_OR_STRING_FILTER',
        sourceReviewedKnownPathTP=1,newIndependentProjectTP=0,runtimeVerifiedTP=0,
        candidateEvidence=e,controlGrade='B_AUTHORED_DIFFERENTIAL_NOT_UPSTREAM_FIX',
        runs=[dict(label=label,entries=sum(f['entrypoints'] for f in r['typescript']['files']),
            findings=len(r['typescript']['validatedFindings']),score=r['securityScore'],
            elapsedMs=[p['elapsedMs'] for p in project['runs']],
            parentHeapUsedBytes=[p['parentHeapUsedBytes'] for p in project['runs']],
            budget=r['typescript']['supabaseAnalysis']['budgetUsage'])
            for label,project,r in [('before',op,a),('after',np,b),('control',dp,c)]],
        repeatIdentical=True,policyChanged=False,serverRestarted=False,userDatabaseModified=False,
        targetExecuted=False,paidAiCalls=0,sourceIncluded=False)
    write(outside(output),result)
    print(json.dumps({k:v for k,v in result.items() if k not in ['truth','candidateEvidence','runs']}))


if __name__=='__main__':
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    prep=sub.add_parser('prepare');prep.add_argument('root',type=Path);prep.add_argument('destination',type=Path)
    check=sub.add_parser('audit')
    for key in ['before','after','control','output']:check.add_argument(key,type=Path)
    a=p.parse_args()
    if a.command=='prepare':prepare(a.root,a.destination)
    else:audit(a.before,a.after,a.control,a.output)
