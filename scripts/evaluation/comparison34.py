"""Compare pinned engines over the same retained public text, never target execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from benchmark import outside, read, stable, write

ENGINES={
    'v40':('032fc53b3ea2000d294d29ee282d23435c2c6023','ts-server-v40'),
    'v41':('4dac021a25ed310d334f5f21ca1831a154eea0e9','ts-server-v41'),
    'v42':('d58f69bf33ca4f938decf29d15ad5196c07bcdf5','ts-server-v42'),
}
COMMON=[
    'src/test/java/com/securedeploy/evaluation/ApplicationEvaluationRunner.java',
    'src/main/java/com/securedeploy/analysis/typescript/TypeScriptSourceSelector.java',
    'src/main/java/com/securedeploy/project/service/ProjectScanner.java',
    'src/main/java/com/securedeploy/rule/engine/VulnerabilityRuleEngine.java',
    'src/main/java/com/securedeploy/rule/filter/FalsePositiveAnalyzer.java',
    'src/main/java/com/securedeploy/risk/service/RiskPrioritizationEngine.java',
]
def digest(data):return hashlib.sha256(data).hexdigest()
def git(repo,*args):return subprocess.check_output(['git',*args],cwd=repo)

def validate_results(plan,versions,plan_hash):
    expected={p['projectId'] for p in plan['projects']}
    if len(expected)!=len(plan['projects']):raise ValueError('DUPLICATE_PROJECT')
    inputs={}
    for version,result in versions.items():
        if result['engineCommit']!=ENGINES[version][0] or result['planSha256']!=plan_hash:
            raise ValueError('ENGINE_OR_PLAN_DRIFT')
        if result.get('externalLookups')!='NOT_RUN' or result.get('userDatabase')!='NOT_USED':
            raise ValueError('EVALUATION_ISOLATION')
        projects={p['projectId']:p for p in result['projects']}
        if len(projects)!=len(result['projects']) or set(projects)!=expected:raise ValueError('PROJECT_SET')
        for ident,p in projects.items():
            original=next(q for q in plan['projects'] if q['projectId']==ident)
            if p['commitSha']!=original['commitSha']:raise ValueError('PROJECT_SHA_DRIFT')
            if p['status']!='ANALYZED_WITH_SCOPE_LIMITS_NOT_SAFETY_CERTIFICATION':raise ValueError('INCOMPLETE_PROJECT')
            if len(p['runs'])!=2 or stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('NONDETERMINISTIC_OR_MISSING_REPEAT')
            run=p['runs'][0]
            if run['typescript']['analyzerVersion']!=ENGINES[version][1]:raise ValueError('WORKER_VERSION_DRIFT')
            selected=(run['ruleInputs'],[(f['filePath'],f['parseStatus']) for f in run['typescript']['files']])
            if ident in inputs and selected!=inputs[ident]:raise ValueError('INPUT_OR_PARSE_SCOPE_DRIFT')
            inputs[ident]=selected

def summarize(root,raw_folder,inventory):
    root=outside(root);raw_folder=outside(raw_folder)
    plan=read(root/'application-plan.json');plan_hash=digest((root/'application-plan.json').read_bytes())
    versions={v:read(raw_folder/(v+'.json')) for v in ENGINES}
    validate_results(plan,versions,plan_hash)
    inventory_by_id={p['projectId']:p for p in inventory['projects']}
    projects=[]
    for original in plan['projects']:
        ident=original['projectId'];source=root/'sources'/ident
        for f in original['files']:
            file=source/f['path']
            if file.is_symlink() or not file.resolve().is_relative_to(source.resolve()) or digest(file.read_bytes())!=f['sha256']:
                raise ValueError('FROZEN_SOURCE_CHANGED')
        rows={}
        for v,result in versions.items():
            p=next(p for p in result['projects'] if p['projectId']==ident);r=p['runs'][0];ts=r['typescript']
            coverage=r['coverage'];selection=ts['selectionCoverage']
            rows[v]={
                'parsedFiles':sum(f['parseStatus']=='PARSED' for f in ts['files']),
                'workerSelectedFiles':selection['submittedFiles'],'sourceCandidates':selection['discoveredFiles'],
                'notSubmittedSources':selection['omittedFiles'],'omittedSourceDetails':selection['omittedDetails'],
                'staticModuleReferences':len(inventory_by_id[ident]['references']),
                'connectedModules':None,'functionArgumentTransfers':None,'functionReturnConnections':None,
                'registeredEntrypoints':sum(f['entrypoints'] for f in ts['files']),
                'registeredEntryFilesNotTraced':[f['filePath'] for f in ts['files'] if f['entrypoints'] and not f['functionsAnalyzed']],
                'reachedFunctions':sum(f['functionsAnalyzed'] for f in ts['files']),
                'wrapperBindings':sum(u.get('operation')=='STATIC_NEXT_WRAPPER_BINDING' for u in ts['nodeUses'] or []),
                'highSourceSinkCandidates':sum(f['confidence']=='HIGH' for f in ts['findings']),
                'structuralValidatedFindings':len(ts['validatedFindings']),
                'legacyRuleFindings':len(r['filtered']),
                'legacySignals':[{k:f[k] for k in ('ruleId','filePath','line')} for f in r['filtered']],
                'observedSinkContracts':{k:len(ts.get(k) or []) for k in ['sqlUses','httpUses','exposureUses','resourceUses']},
                'unresolvedResourceUses':sum('UNRESOLVED' in u['kind'] for u in ts['resourceUses'] or []),
                'staticSqlExecutions':sum(u['kind']=='STATIC_QUERY' and u['executionObserved'] for u in ts['sqlUses'] or []),
                'verifiedNewRealVulnerabilityTP':0,'wholeProjectTP':None,'wholeProjectFP':None,'wholeProjectFN':None,'wholeProjectTN':None,
                'elapsedMs':[a['elapsedMs'] for a in p['runs']],
                'parentHeapSamplesBytes':[a['parentHeapUsedBytes'] for a in p['runs']],
                'workerPeakRssBytes':None,'coverageStatus':coverage['status'],'workerStatus':ts['status'],
                'failedCoverageEntries':[{k:f.get(k) for k in ('filePath','status','reason')}
                    for f in coverage['entries'] if f.get('status') in {'FAILED','LIMIT_EXCEEDED','PARSE_FAILED'}],
                'limitations':sorted({q for f in ts['files'] for q in f['limitations']}),
                'budgetUsage':ts['supabaseAnalysis']['budgetUsage'],
                'securityScore':r['securityScore'],'risk':r['risk']['prioritizedDeploymentAssessment'],
                'sca':r['sca'],'repeatIdentical':True,
            }
        base=next(p for p in versions['v40']['projects'] if p['projectId']==ident)['runs'][0]
        unchanged={}
        for v in ['v41','v42']:
            current=next(p for p in versions[v]['projects'] if p['projectId']==ident)['runs'][0]
            unchanged[v]={key:stable(base[key])==stable(current[key]) for key in ['raw','filtered','securityScore','risk','sca','java','python','deployment']}
        projects.append({k:original.get(k) for k in ['projectId','full_name','commitSha','license','repositoryUrl','priorUse','excludedSourcePrefixes','discoveredArchiveFiles','retainedFiles','omissionCounts','licenseFiles']}
                        |{'groundTruth':'GRADE_C_UNVERIFIED_NOT_SAFE_OR_VULNERABLE','versions':rows,'legacyUnchanged':unchanged,
                          'retainedFileManifest':original['files'],'omitted':original['omitted'],
                          'moduleSyntaxInventory':inventory_by_id[ident]})
    return {'schemaVersion':1,'evaluation':'34-C','planSha256':plan_hash,'engines':ENGINES,
            'receipt':read(raw_folder/'run-receipt.json'),
            'rawResultSha256':{v:digest((raw_folder/(v+'.json')).read_bytes()) for v in ENGINES},
            'candidateSelection':plan['selection'],'projects':projects,'moduleResolutionDiagnostics':inventory['diagnostics'],
            'method':'PREVIOUSLY_UNUSED_SOURCE_NONBLIND_NO_ENGINE_TUNING_NO_INDEPENDENT_GROUND_TRUTH',
            'metricsPolicy':{
                'null':'NOT_VERIFIED, not zero or safety','moduleReferences':'Auxiliary AST syntax over the same selected source files; not successful Worker binding counts',
                'connectedModules':'No complete module-edge/call/argument/return counters in frozen Worker snapshots; not inferred from function counts',
                'registeredEntrypoints':'Registration is not complete security flow execution; inspect registeredEntryFilesNotTraced',
                'sourceSink':'HIGH candidates and unresolved uses are separate; neither is exploit proof',
                'memory':'Parent JVM heap samples, not peak, retained-source size or Worker RSS; no performance improvement claim',
                'sca':'External lookup disabled; manifest observations are not an advisory/vulnerability assessment',
                'datasets':'Development Grade B, prior real-app regression and new Grade C results must not be pooled'},
            'workerChanges':False,'productApiDbUiRiskChanges':False,'newVerifiedRealVulnerabilityTP':0,'independentHoldout':0}

def run(root,output,engines):
    root=outside(root);output=outside(output)
    if set(engines)!=set(ENGINES):raise ValueError('ALL_THREE_PINNED_ENGINES_REQUIRED')
    if output.exists():raise ValueError('NEW_OUTPUT_REQUIRED')
    checks={};hashes={}
    for name,folder in engines.items():
        repo=Path(folder).resolve();commit,version=ENGINES[name]
        if git(repo,'rev-parse','HEAD').decode().strip()!=commit:raise ValueError('ENGINE_HEAD_DRIFT')
        if git(repo,'diff','HEAD','--name-only','--','src/main','analyzers').strip():raise ValueError('DIRTY_ENGINE')
        if git(repo,'ls-files','--others','--exclude-standard','--','src/main','analyzers').strip():raise ValueError('UNTRACKED_ENGINE')
        source=(repo/'analyzers/typescript/analyzer.mjs').read_text()
        if not re.search(r"export const VERSION = '"+re.escape(version)+"';",source):raise ValueError('WORKER_SOURCE_VERSION')
        common={path:digest((repo/path).read_bytes()) for path in COMMON}
        hashes[name]=common
        checks[name]={'commit':commit,'workerVersion':version,'analyzerSha256':digest(source.encode())}
    if len({json.dumps(h,sort_keys=True) for h in hashes.values()})!=1:raise ValueError('SHARED_PIPELINE_CHANGED')
    output.mkdir(mode=0o700)
    plan_bytes=(root/'application-plan.json').read_bytes();plan_hash=digest(plan_bytes)
    receipt={'schemaVersion':1,'planSha256':plan_hash,'engines':checks,'sharedPipelineHashes':hashes['v40'],
             'toolSha256':digest(Path(__file__).read_bytes()),'targetCodeExecuted':False,'externalScaLookups':False,
             'separateEngineWorktrees':True,'sameRetainedInput':True,'requestedRepeats':2}
    write(output/'run-receipt.json',receipt)
    env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL','JAVA_HOME','TMPDIR'}}
    for name in ENGINES:
        with (output/(name+'.log')).open('xb') as log:
            subprocess.run(['gradle','--offline','applicationEvaluation','-PapplicationRoot='+str(root),
                '-PapplicationOutput='+str(output/(name+'.json'))],cwd=engines[name],env=env,
                stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
        if (root/'application-plan.json').read_bytes()!=plan_bytes:raise ValueError('PLAN_CHANGED_DURING_RUN')
        print(name,'COMPLETE',flush=True)
    versions={name:read(output/(name+'.json')) for name in ENGINES}
    validate_results(json.loads(plan_bytes),versions,plan_hash)
    print('SAME_INPUT_AND_REPEAT_VALIDATION_PASS',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root');parser.add_argument('output')
    parser.add_argument('--engine',action='append',required=True)
    args=parser.parse_args();engines={}
    for item in args.engine:
        name,folder=item.split('=',1)
        if name in engines:raise ValueError('DUPLICATE_ENGINE')
        engines[name]=folder
    run(args.root,args.output,engines)
