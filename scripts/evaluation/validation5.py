"""Static, source-free validation receipts. Never executes benchmark runners or targets."""
import argparse
from collections import Counter
import hashlib
import json
import shutil
from pathlib import Path
import os
import re
import signal
import subprocess
import time
from application_track import outside,read,write,run
from benchmark import stable
from detection_deep_dive import PINS,outcome

BASE='f20966b1b789c1353e36583a359ce46e91d527da'

def target_status(file_record):
    if file_record is None:return 'NOT_INSPECTED'
    if file_record['parseStatus']=='LIMIT_EXCEEDED':return 'RESOURCE_LIMIT'
    if file_record['parseStatus']=='PARSE_FAILED':return 'ANALYSIS_FAILED'
    if file_record['parseStatus']!='PARSED':return 'NOT_INSPECTED'
    return 'NOT_SUPPORTED'

def controlled_outcome(findings,uses):
    # A disappearance alone is neither TN nor RESOLVED.
    if findings:return 'TP'
    if any(u['kind'] in ['ARGV_WITHOUT_SHELL_DECLARED','STATIC_OR_DATA_ONLY'] for u in uses):return 'TN_TARGET_ONLY'
    return 'UNKNOWN'

def target_findings(findings,file,line,rule):
    return [f for f in findings if f['ruleId']==rule and f['location']['filePath']==file and f['location']['line']==line]
CASES=[
 dict(cve='CVE-2017-18354',track='WEB_APPLICATION',repository='GoogleChrome/rendertron',cwe='CWE-22',
      file='src/renderer.js',line=75,source='src/main.js:99 request.params.url',
      route='src/main.js:91 /render/:url(*) -> renderer.serialize -> _loadPage -> Page.navigate',
      patch='src/main.js isRestricted adds a protocol check; local file URL path is the target, not all SSRF.',
      gaps=['CHROME_DEVTOOLS_NAVIGATION_SINK_UNSUPPORTED','CLASS_AND_PROMISE_CALL_CONTEXT_PARTIAL'],
      reference='https://github.com/GoogleChrome/rendertron/commit/324ac99732c943d7b16aead2fceaa8b31a458eaa'),
 dict(cve='CVE-2018-3783',track='WEB_APPLICATION',repository='JasonEtco/flintcms',cwe='CWE-943',
      file='server/apps/routes/auth.js',line=80,source='server/apps/routes/auth.js:79 req.body.email',
      route='server/index.js:53 /admin -> server/apps/admin.js:12 auth factory -> POST /forgotpassword',
      patch='Three request-derived Mongo query values are converted to strings. No SQL query or verified runtime authorization claim.',
      gaps=['MONGOOSE_OBJECT_OPERATOR_QUERY_CONTRACT_UNSUPPORTED','FACTORY_ACTIVATION_AND_GLOBAL_INITIALIZATION_CONTEXT'],
      reference='https://github.com/JasonEtco/flintcms/commit/4ae34238ce39fde00dfa15082397541758c07af1'),
 dict(cve='CVE-2017-16100',track='NPM_LIBRARY',repository='skoranga/node-dns-sync',cwe='CWE-78',
      file='lib/dns-sync.js',line=21,source='lib/dns-sync.js:14 exported resolve(hostname)',
      route='public resolve -> util.format -> shelljs.exec (not child_process.exec)',
      patch='Adds isValidHostName and rejects failed checks before command construction; dynamic RegExp.test is outside v21 proof.',
      gaps=['LIBRARY_PUBLIC_ARGUMENT_SOURCE_UNSUPPORTED','SHELLJS_EXEC_CONTRACT_UNSUPPORTED','UTIL_FORMAT_AND_VALIDATOR_UNSUPPORTED'],
      reference='https://github.com/skoranga/node-dns-sync/commit/d9abaae384b198db1095735ad9c1c73d7b890a0d'),
 dict(cve='CVE-2018-3772',track='NPM_LIBRARY',repository='vvo/node-whereis',cwe='CWE-78',
      file='index.js',line=4,source='index.js:3 exported whereis(name,cb)',
      route='public whereis -> child_process.exec, followed by nested fallback callbacks',
      patch='First three exec calls change to execFile argv; fourth shell command at line 12 remains. Do not label whole patch safe.',
      gaps=['LIBRARY_PUBLIC_ARGUMENT_SOURCE_UNSUPPORTED','NESTED_CALLBACK_FALLBACK_NOT_INSPECTED'],
      reference='https://github.com/vvo/node-whereis/commit/0f64e3780235004fb6e43bfd153ea3e0e210ee2b')]

def freeze(root):
    root=outside(root);cases=[]
    for case in CASES:
        row=read(root/'ossf'/(case['cve']+'.json'));versions=[]
        for stage in ['before','after']:
            plan=read(root/(case['cve']+'-'+stage)/'application-plan.json')['projects'][0]
            file=next(f for f in plan['files'] if f['path']==case['file'])
            versions.append(dict(stage=stage,sha=plan['commitSha'],fileSha256=file['sha256'],license=plan['license'],
                omissions=plan['omissionCounts']))
        cases.append(dict(case,versions=versions,grade='A_UPSTREAM_ADVISORY_AND_REAL_PATCH_STATICALLY_REVIEWED',
            groundTruthLimit='Static review only; no exploit execution, external reviewer or whole-project safe truth.'))
    write(root/'validation-truth.json',dict(engineBaseline=BASE,cases=cases,sourceExecution=False,
        protocol='Labels frozen before v21 baseline; web and library tracks separate; post-patch residual risk not TN.',
        datasetReview=dict(ossfPin=read(root/'ossf-pin.json'),ossfMetadataCount=223,
            secbench='README reviewed; explicit repository license not verified. No benchmark code or PoC copied/executed.',
            xjs='Paper reviewed; usable public corpus URL, code/data license and pinned metadata not verified. Excluded from scored corpus.'),
        libraryResidual=dict(cve='CVE-2018-3772',file='index.js',line=12,stage='after',truth='RISK_REMAINS',
            limitation='Nested callback execution condition and platform are not dynamically confirmed.')))
    print(json.dumps({'frozenCases':len(cases),'families':len({c['repository'] for c in cases})}))

def evaluate(root):
    root=outside(root);read(root/'validation-truth.json')
    for case in CASES:
        for stage in ['before','after']:
            name=case['cve']+'-'+stage
            print(run(root/name,root/(name+'-v21.json')),flush=True)

def controlled(root):
    root=outside(root)
    variants=[('risk','before','const value=req.body.program;','TP'),
              ('argv-target','after','const value=req.body.program;','TN_TARGET_ONLY'),
              ('overwrite','before',"let value=req.body.program;value='node';",'TN_TARGET_ONLY'),
              ('unknown-transform','before','const value=externalTransform(req.body.program);','UNKNOWN')]
    labels=[]
    for name,stage,binding,expected in variants:
        original=root/('CVE-2018-3772-'+stage)
        plan=read(original/'application-plan.json');p=plan['projects'][0]
        dest=root/('controlled-'+name);dest.mkdir(mode=0o700)
        source=dest/'sources'/p['projectId'];source.parent.mkdir(mode=0o700)
        shutil.copytree(original/'sources'/p['projectId'],source)
        adapter="const app=require('express')();const lookup=require('./index');app.post('/lookup',(req,res)=>{"+binding+"lookup(value,()=>{});});"
        manifest=json.loads((source/'package.json').read_text());manifest['dependencies']={**manifest.get('dependencies',{}),'express':'4.21.2'}
        for file,data in [('sd-evaluation-adapter.cjs',adapter.encode()),('package.json',json.dumps(manifest).encode())]:
            path=source/file;path.write_bytes(data);path.chmod(0o600)
            p['files']=[f for f in p['files'] if f['path']!=file]+[dict(path=file,sha256=hashlib.sha256(data).hexdigest(),bytes=len(data))]
        p['files'].sort(key=lambda f:f['path']);p['retainedFiles']=len(p['files']);p['discoveredArchiveFiles']+=1
        p['groundTruth']='GRADE_B_SYNTHETIC_HTTP_ADAPTER_NOT_ACTUAL_UPSTREAM_WEB_SOURCE'
        p['controlledVariant']=name
        write(dest/'application-plan.json',plan)
        labels.append(dict(variant=name,expected=expected,track='GRADE_B_ADAPTER',sourceSHA=p['commitSha'],
            target='index.js:4',targetSha256=next(f['sha256'] for f in p['files'] if f['path']=='index.js'),
            limit='Only first native process call. Nested Windows fallback is not inspected; this is not real web-app CVE detection.'))
    write(root/'controlled-truth.json',dict(labels=labels,authorIndependent=False,externalReviewer=False))
    for label in labels:
        name=label['variant'];print(run(root/('controlled-'+name),root/('controlled-'+name+'-v21.json')),flush=True)

def report(root,output):
    root=outside(root);truth=read(root/'validation-truth.json');receipts=[]
    location_corrections=[]
    for frozen_case in truth['cases']:
        case=dict(frozen_case)
        if case['cve']=='CVE-2017-18354' and case['line']==69:
            # Correct our handwritten location typo, not labels or source bytes.
            # Both full-project snapshots have zero structural findings, so no score changes.
            location_corrections.append(dict(cve=case['cve'],frozenSinkLine=69,verifiedSinkLine=75,
                frozenRequestLines='94/83',verifiedRequestLines='99/91',reason='Local numbered source review corrected evaluator transcription; no labels, SHA or engine result changed.'))
            case.update(line=75,source='src/main.js:99 request.params.url',route='src/main.js:91 /render/:url(*) -> renderer.serialize -> _loadPage -> Page.navigate')
        versions=[]
        for stage in ['before','after']:
            raw=read(root/(case['cve']+'-'+stage+'-v21.json'));p=raw['projects'][0]
            plan_path=root/(case['cve']+'-'+stage)/'application-plan.json'
            assert raw['planSha256']==hashlib.sha256(plan_path.read_bytes()).hexdigest(),'SOURCE_PLAN_CHANGED'
            assert raw['engineCommit']==BASE and p['commitSha']==next(v['sha'] for v in case['versions'] if v['stage']==stage)
            assert len(p['runs'])==2 and stable(p['runs'][0])==stable(p['runs'][1]),'REPEAT_MISMATCH'
            row=p['runs'][0];ts=row['typescript'];f=next((f for f in ts['files'] if f['filePath']==case['file']),None)
            target=[f for f in ts['validatedFindings'] if f['location']['filePath']==case['file'] and f['location']['line']==case['line']]
            assert not target,'TARGET_FINDING_REQUIRES_MANUAL_SEMANTIC_REVIEW'
            legacy=[f for f in row['filtered'] if f.get('filePath')==case['file']]
            versions.append(dict(stage=stage,sha=p['commitSha'],engine=raw['engineCommit'],
                targetFile=f,targetFindings=target,targetFileLegacy=legacy,allStructuralCount=len(ts['validatedFindings']),
                initializationFile=next((f for f in ts['files'] if f['filePath']=='index.js'),None),
                selectionCoverage=ts['selectionCoverage'],
                parsedFiles=sum(f['parseStatus']=='PARSED' for f in ts['files']),entries=sum(f['entrypoints'] for f in ts['files']),
                legacyCount=len(row['filtered']),score=row['securityScore'],coverage=row['coverage']['status'],
                elapsedMs=[r['elapsedMs'] for r in p['runs']],repeatIdentical=True,
                budget=ts.get('supabaseAnalysis',{}).get('budgetUsage'),
                risk=row['risk']['prioritizedDeploymentAssessment'],rawRuleCount=len(row['raw']),filteredRuleCount=len(row['filtered']),
                sourceAndSinkConnected=False,engineSourceObserved=False,engineSinkObserved=False,
                outcome=target_status(f)))
        receipts.append(dict(case,observations=versions,knownUnsupported=case['gaps'],
            finalOutcome=versions[0]['outcome'],postPatchNoWarningIsNotTN=True,
            failureCasePack=dict(confirmedMissingContracts=case['gaps'],
                unverified='Other framework/heap limitations may also apply; no unsupported condition is auto-promoted.',
                regressionProposal='Preserve original API source contract; use explicit HTTP adapters only as Grade B, never as actual web-app truth.')))
    result=dict(schemaVersion=1,engine=BASE,worker='ts-server-v21',engineModified=False,riskModified=False,
        evaluationToolSha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        truthSha256=hashlib.sha256((root/'validation-truth.json').read_bytes()).hexdigest(),
        datasetReview=truth['datasetReview'],cases=receipts,residual=truth['libraryResidual'],locationCorrections=location_corrections,
        web=dict(families=2,vulnerabilities=2,riskPaths=2,TP=0,FP=0,FN=0,TN=0,NOT_SUPPORTED=2,
            supportedPrecision=None,supportedRecall=None,wholeTargetRiskDetectionRatio=0,
            interpretation='Unsupported targets are not supported-scope FN or patched TN; do not omit them from whole-target coverage.'),
        libraries=dict(families=2,vulnerabilities=2,riskPaths=3,TP=0,FP=0,FN=0,TN=0,NOT_SUPPORTED=2,NOT_INSPECTED=1,
            supportedPrecision=None,supportedRecall=None,wholeTargetRiskDetectionRatio=0,
            interpretation='Two public API sources and one residual callback path; not a web-service accuracy metric.'),
        newActualProjectTP=0,externalIndependentReview=False,paidAiCalls=0,targetExecuted=False,userDatabaseModified=False)
    labels=read(root/'controlled-truth.json')['labels'];observed=[]
    for label in labels:
        raw=read(root/('controlled-'+label['variant']+'-v21.json'));p=raw['projects'][0]
        plan_path=root/('controlled-'+label['variant'])/'application-plan.json'
        assert raw['engineCommit']==BASE and raw['planSha256']==hashlib.sha256(plan_path.read_bytes()).hexdigest()
        assert len(p['runs'])==2 and stable(p['runs'][0])==stable(p['runs'][1])
        row=p['runs'][0];ts=row['typescript']
        findings=target_findings(ts['validatedFindings'],'index.js',4,'JS_SHELL_COMMAND_INPUT_FLOW')
        uses=[u for u in ts.get('nodeUses',[]) if u['location']['filePath']=='index.js' and u['location']['line']==4]
        expected=label['expected'];actual=controlled_outcome(findings,uses)
        assert actual==expected,'CONTROLLED_EXPECTATION_MISMATCH'
        observed.append(dict(label,outcome=actual,findings=findings,uses=uses,coverage=row['coverage']['status'],repeatIdentical=True))
    result['controlled']=dict(cases=observed,TP=1,TN=2,FP=0,FN=0,UNKNOWN=1,
        supportedPrecision=1.0,supportedRecall=1.0,
        limitation='Four author-controlled adapters, only first process call; no independent web vulnerability recall claim.')
    result['priorMetadataExposure']=dict(projects=['GoogleChrome/rendertron','skoranga/node-dns-sync'],
        provenance='Existing CVEfixes fixes.json catalog contains repository metadata; no prior source/engine observations found in evaluation receipts.',
        interpretation='New source-level evaluation, not a fully unseen repository name or blind external validation.')
    result['metadataSemanticReview']=dict(flintcms='Upstream CWE-089 label describes MongoDB operator-object injection here, reviewed as CWE-943. No SQL-string success claimed.',
        whereis='First native calls changed to argv while a fourth shell command remains. Fixed SHA is not a whole-project safe label.',
        rendertron='Protocol/file access condition, not a complete SSRF fix. Our handwritten line typos are preserved as explicit location corrections.')
    result['implementationDecision']=dict(engineChange='NONE',
        reason='No supported-contract defect reproduced. Existing native command and argv handling distinguishes the controlled adapter pair; actual targets require new activation/source/API contracts.',
        nextCandidates=[
            dict(area='Explicit request activation and relevant initialization-file completeness',priority=1,
                 evidence='Both web targets parsed but registered zero engine entries; FlintCMS root index.js also exceeded file-count selection.',
                 limit='The exact first state-loss expression was not isolated. Do not promise that activation alone detects either target.'),
            dict(area='Bounded Mongoose query-operator input and authentication context',priority=2,
                 evidence='FlintCMS request object goes to User.findOne, with actual string-conversion patch.',
                 limit='New contract requiring design approval, model origin and version semantics; not solved by adding findOne name matching.'),
            dict(area='Explicit library API profiles and native process callback contexts',priority=3,
                 evidence='Library sources absent; whereis fourth shell fallback remains after real patch.',
                 limit='Separate library track, not default taint of every export. Windows fallback is not observed execution.'),
            dict(area='Chrome DevTools navigation',priority='DEFER',
                 evidence='Rendertron file URL navigation is outside supported HTTP sinks.',
                 limit='Higher framework cost and weaker direct relevance to current Vite/Supabase focus.')],
        frontendChanged=False,backendChanged=False,dbMigration=False,serverRestartRequired=False,
        liveGitHubAppAndBrowser='NOT_RERUN; no product code changes, isolated API evaluations and frontend regression only.',
        externalVulnerabilityLookups='OSV/EPSS/KEV NOT_RUN in isolated evaluation; public source/advisory acquisition only.')
    assert all(v['outcome']=='NOT_SUPPORTED' for c in receipts for v in c['observations']), 'SCORING_REVIEW_REQUIRED'
    write(Path(output),result)
    print(json.dumps({'families':4,'web':result['web'],'libraries':result['libraries']}))

def profile(root,output):
    root=outside(root);reports=[];repo=Path(__file__).resolve().parents[2]
    for case in CASES:
      for stage in ['before','after']:
        name=case['cve']+'-'+stage;base=root/name
        p=read(base/'application-plan.json')['projects'][0]
        row=read(root/(name+'-v21.json'))['projects'][0]['runs'][0]
        inventory={f['path']:f for f in p['files']};source=base/'sources'/p['projectId']
        def content(file):
            target=source/file
            if target.is_symlink() or not target.resolve().is_relative_to(source.resolve()):raise ValueError('SOURCE_PATH')
            data=target.read_bytes()
            if hashlib.sha256(data).hexdigest()!=inventory[file]['sha256']:raise ValueError('SOURCE_HASH')
            return '\n'.join(data.decode().splitlines())
        ts=row['typescript'];files=[dict(filePath=f['filePath'],content=content(f['filePath'])) for f in ts['files'][:ts['selectionCoverage']['submittedFiles']]]
        manifests=[]
        for file in sorted(inventory):
            if not file.endswith('package.json'):continue
            try:deps=json.loads(content(file)).get('dependencies',{})
            except ValueError:continue
            manifests.append(dict(filePath=file,**{k:v for k,v in deps.items() if k in {'express','mongodb','next','sequelize'}
                and isinstance(v,str) and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?',v)}))
        data=json.dumps(dict(files=files,nodeManifests=manifests)).encode()
        if len(data)>1200000:raise ValueError('PROFILE_INPUT_LIMIT')
        runs=[]
        for _ in range(2):
            start=time.monotonic()
            child=subprocess.Popen(['/usr/bin/time','-l','node','--max-old-space-size=192',str(repo/'scripts/evaluation/node_probe_worker.mjs'),str(repo/'analyzers/typescript/analyzer.mjs')],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,
                env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL'}})
            try:stdout,stderr=child.communicate(data,timeout=10)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait();raise ValueError('PROFILE_TIMEOUT')
            if child.returncode or len(stdout)>2000000:raise ValueError('WORKER_PROFILE_FAILURE')
            result=json.loads(stdout);rss=re.search(rb'(\d+)\s+maximum resident set size',stderr)
            if result['analyzerVersion']!='ts-server-v21':raise ValueError('WORKER_VERSION')
            runs.append(dict(wallMs=round((time.monotonic()-start)*1000),maxRssBytes=int(rss[1]) if rss else None,
                budget=result['supabaseAnalysis']['budgetUsage'],findings=len(result['findings'])))
        reports.append(dict(case=name,inputSha256=hashlib.sha256(data).hexdigest(),runs=runs))
    write(Path(output),dict(scope='ISOLATED_SELECTED_WORKER_PROFILE_NOT_WHOLE_BACKEND_RSS',heapMiB=192,
        libraryInventoryContract='No Sequelize registry present; omitted inventory/SQL metadata, not a second whole-product evaluation.',
        reports=reports,targetExecuted=False))
    print(json.dumps({'profiles':len(reports),'peakRssBytes':max(x['maxRssBytes'] for r in reports for x in r['runs'])}))

def regression(root,reference,output):
    root=outside(root);reference=outside(reference);projects=[];rows={}
    for name in [*PINS,'goof-validation']:
        a=read(reference/(name+'-hardening4-verified.json'));b=read(root/('regression-'+name+'-v21.json'))
        assert a['planSha256']==b['planSha256']
        x,y=a['projects'][0],b['projects'][0]
        assert x['commitSha']==y['commitSha'] and len(y['runs'])==2 and stable(y['runs'][0])==stable(y['runs'][1])
        old,new=x['runs'][0],y['runs'][0];rows[name]=new
        same={k:stable(old[k])==stable(new[k]) for k in ['raw','filtered','risk','sca','securityScore','typescript']}
        assert all(same.values()),'REGRESSION_CHANGED'
        projects.append(dict(project=name,sha=y['commitSha'],unchanged=same,repeatIdentical=True))
    truth=read(reference/'ground-truth-v2.json')
    counts=dict(Counter(outcome(c,rows[c['project']]) for c in truth['cases']))
    assert counts=={'TP':4,'TN':1,'NOT_SUPPORTED':5}
    goof=target_findings(rows['goof-validation']['typescript']['validatedFindings'],'routes/index.js',174,'JS_SHELL_COMMAND_INPUT_FLOW')
    assert len(goof)==1
    a=read(reference/'four-app-hardening4-verified.json');b=read(root/'regression-four-app-v21.json')
    assert a['planSha256']==b['planSha256'];old={p['projectId']:p for p in a['projects']};apps=[]
    for p in b['projects']:
        prior=old[p['projectId']]
        assert prior['commitSha']==p['commitSha'] and stable(p['runs'][0])==stable(p['runs'][1])
        same={k:stable(prior['runs'][0][k])==stable(p['runs'][0][k]) for k in ['raw','filtered','risk','sca','securityScore','typescript']}
        assert all(same.values())
        apps.append(dict(project=p['projectId'],sha=p['commitSha'],unchanged=same,repeatIdentical=True))
    write(Path(output),dict(engine=BASE,originalRiskDenominator=8,originalPaths=10,counts=counts,goofSeparateTP=1,
        projects=projects,apps=apps,engineModified=False,userDatabaseModified=False,targetExecuted=False))
    print(json.dumps({'counts':counts,'goofSeparateTP':1,'apps':len(apps)}))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('command',choices=['freeze','run','controlled','profile','report','regression']);p.add_argument('root',type=Path);p.add_argument('--output',type=Path);p.add_argument('--reference',type=Path)
    args=p.parse_args()
    if args.command=='freeze':freeze(args.root)
    elif args.command=='run':evaluate(args.root)
    elif args.command=='controlled':controlled(args.root)
    elif args.command=='profile':profile(args.root,args.output)
    elif args.command=='regression':regression(args.root,args.reference,args.output)
    else:report(args.root,args.output)
