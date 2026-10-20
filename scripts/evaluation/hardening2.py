"""Version-bound improvement history; public metadata only, never source bodies."""
import argparse
from collections import Counter
from pathlib import Path
import subprocess
from application_track import read,write,outside,digest,relative
from benchmark import stable

BASELINE='80ef248d79b55ad0212ec09beadc8b37af64742d'

def summarize_run(row):
    java=row['java']['analysis'];files=java['files']
    return dict(ruleCount=len(row['filtered']),rules=dict(Counter(f['ruleId']for f in row['filtered'])),
                securityScore=row['securityScore'],deploymentAssessment=row['risk']['prioritizedDeploymentAssessment'],
                prioritySummary=row['risk']['prioritySummary'],riskPolicyVersion=row['risk']['policyVersion'],
                supplementalCandidates=len(row['reviewCandidates']),coverageStatus=row['coverage']['status'],
                java=dict(version=java['version'],status=java['status'],files=dict(Counter(f['parseStatus']for f in files)),
                          entrypoints=sum(f['entrypoints']for f in files),functions=sum(f['functions']for f in files),
                          sqlSyntaxCandidates=sum(f['sqlCallSites']for f in files),tracedSqlCalls=sum(f['tracedCallSites']for f in files),
                          limitations=java['limitations']))

def identity(signal):
    return signal['ruleId'],signal['filePath'],signal['line']

def report(root,cve_root,before_probe,after_probe,earlier_probe,output,packs):
    root=outside(root);cve_root=outside(cve_root)
    names=['raw-after-a.json','hardening2-after-a-final.json','hardening2-after-b.json']
    raws=[read(root/name)for name in names];plan=read(root/'application-plan.json')
    plan_hash=digest((root/'application-plan.json').read_bytes())
    if any(raw['planSha256']!=plan_hash for raw in raws):raise ValueError('PLAN_VERSION_MISMATCH')
    # Baseline milestone changed only evaluation tooling, not the production engine.
    if subprocess.check_output(['git','diff',raws[0]['engineCommit'],BASELINE,'--','src/main','analyzers']).strip():
        raise ValueError('BASELINE_PRODUCTION_NOT_EQUIVALENT')
    projects={p['projectId']:p for p in plan['projects']};maps=[{p['projectId']:p for p in raw['projects']}for raw in raws]
    if any(set(m)!=set(projects)for m in maps):raise ValueError('PROJECT_SET_CHANGED')
    for project in projects.values():
        for file in project.get('files',[]):
            path=root/'sources'/project['projectId']/relative(file['path'])
            if path.is_symlink()or digest(path.read_bytes())!=file['sha256']:raise ValueError('SOURCE_CHANGED')
    rows=[];removed=[];added=[]
    for ident,project in projects.items():
        row=dict(projectId=ident,repositoryUrl=project['repositoryUrl'],commitSha=project['commitSha'])
        runs=[m[ident].get('runs',[])for m in maps]
        if not all(runs):
            if any(runs):raise ValueError('COLLECTION_FAILURE_STATE_CHANGED')
            row['status']='COLLECTION_FAILED_NOT_ANALYZED';rows.append(row);continue
        if any(len(r)!=2 or stable(r[0])!=stable(r[1])for r in runs):raise ValueError('REPEAT_INCONSISTENCY')
        row['stages']={name:summarize_run(run[0])for name,run in zip(['baseline','afterA','afterB'],runs)}
        row['elapsedMs']={name:[r['elapsedMs']for r in run]for name,run in zip(['baseline','afterA','afterB'],runs)}
        old={identity(f)for f in runs[0][0]['filtered']};new={identity(f)for f in runs[2][0]['filtered']}
        removed.extend(dict(projectId=ident,ruleId=f[0],filePath=f[1],line=f[2])for f in sorted(old-new))
        added.extend(dict(projectId=ident,ruleId=f[0],filePath=f[1],line=f[2])for f in sorted(new-old))
        row['comparisonFingerprintChanged']=runs[0][0]['engineFingerprint']!=runs[2][0]['engineFingerprint']
        if len({r[0]['risk']['policyVersion']for r in runs})!=1:raise ValueError('RISK_POLICY_CHANGED')
        rows.append(row)
    before=read(before_probe);after=read(after_probe);early=read(earlier_probe)
    for b,a,e in zip(before['results'],after['results'],early['results']):
        if not b['inputSha256']==a['inputSha256']==e['inputSha256']:raise ValueError('PROBE_INPUT_CHANGED')
    cve=read(cve_root/'hardening2-score-all.json');old_cve=read(cve_root/'after-url-score-all.json')
    if cve['manifestSha256']!=old_cve['manifestSha256']:raise ValueError('CVE_CORPUS_CHANGED')
    result=dict(schemaVersion=1,baselineMilestone=BASELINE,sourcePlanSha256=plan_hash,
                engineCommits=dict(zip(['baseline','afterA','afterB'],[r['engineCommit']for r in raws])),
                sourcePrivacy='Original v2 omissions retained; no excluded source downloaded again.',
                projects=rows,removedWarningObservations=removed,newWarningObservations=added,
                memory=dict(before=before,after=after,earlierAfterObservation=early,
                            explanation='Per-file SourcePositions retained separate JavacTrees/tasks and compiler services. JDK metadata confirms the reference chain; one shared parse-only context removes that multiplicity. No heap dump or exact per-context retained-byte attribution.'),
                cveRegression=dict(cases=len(cve['results']),beforeCounts=old_cve['summary']['finalUser']['counts'],
                                   afterCounts=cve['summary']['finalUser']['counts'],allRepeatsConsistent=cve['allRepeatsConsistent']),
                riskPolicyChanged=False,scoreFormulaChanged=False,userDatabaseUsed=False,oldReviewsRecomputed=False,
                externalLookups='NOT_RUN',targetCodeExecuted=False,
                evaluationLimits=['Same observed corpus is regression, not a blind generalization claim.',
                                  'No supported SQL execution in these Spring applications; JPA/MyBatis and broader object flow remain unknown.',
                                  'Heap exit sample is not peak; GC high-water sample and maximum RSS are separate measures.',
                                  'Product API tests use isolated H2 and real workers with mocked GitHub acquisition; no live private GitHub E2E.'])
    review=read(Path(__file__).with_name('application-review.json'));history=[]
    selected={'next-svg-namespace-alerts':('SVG_NAMESPACE_IDENTIFIER','analyzers/typescript/url-context.mjs'),
              'netbox-secret-button-label':('REGEX_CROSSED_DISPLAY_LITERAL_BOUNDARY','analyzers/typescript/url-context.mjs'),
              'northwind-generated-type-comment':('BOUNDED_PREFIX_COMMENT_CONTEXT','src/main/java/com/securedeploy/rule/rules/InsecureApiUrlContext.java'),
              'spring-projects--spring-petclinic-java-worker-memory':('PER_FILE_COMPILER_CONTEXT_RETENTION','src/main/java/com/securedeploy/analysis/javaflow/JavaSqlWorker.java'),
              'macrozheng--mall-tiny-java-worker-memory':('PER_FILE_COMPILER_CONTEXT_RETENTION','src/main/java/com/securedeploy/analysis/javaflow/JavaSqlWorker.java')}
    packs=outside(packs);packs.mkdir(mode=0o700)
    for case in review['pathReviews']:
        if case['caseId']not in selected:continue
        row=next(r for r in rows if r['projectId']==case['projectId'])
        cause,code=selected[case['caseId']]
        item=dict(originalPackCaseId=case['caseId'],originalObservation=case['observed'],
                  rootCause=cause,codeChanged=code,engineCommits=result['engineCommits'],
                  repositoryUrl=row['repositoryUrl'],commitSha=row['commitSha'],sourcePlanSha256=plan_hash,
                  before=row['stages']['baseline'],after=row['stages']['afterB'],sites=case['sites'],
                  remainingLimitations=result['evaluationLimits'],status='IMPROVED_ON_SAME_OBSERVED_SOURCE',
                  reproduction='application_track.py run DATA_ROOT NEW_OUTPUT --project '+row['projectId'])
        write(packs/(case['caseId']+'.json'),item);history.append(item)
    result['failureCaseHistory']=history
    write(output,result)
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root');parser.add_argument('cve_root');parser.add_argument('before_probe');parser.add_argument('after_probe');parser.add_argument('earlier_probe');parser.add_argument('output');parser.add_argument('packs');args=parser.parse_args()
    data=report(**vars(args))
    print(dict(projects=len(data['projects']),removed=len(data['removedWarningObservations']),added=len(data['newWarningObservations']),histories=len(data['failureCaseHistory'])))
