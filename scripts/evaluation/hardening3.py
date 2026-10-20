"""Same-source Java data-access follow-up; metadata only, never source bodies."""
import argparse
from collections import Counter
from pathlib import Path
import subprocess
from application_track import read,write,outside,digest,relative
from benchmark import stable
from hardening2 import summarize_run

BASELINE='038ef5492bb12a8a8fa0e0b9f14ae133d66d711f'

def summary(row):
    result=summarize_run(row)
    analysis=row['java']['analysis']
    accesses=analysis.get('dataAccess',[])
    result['java']['dataAccess']=dict(Counter(a['framework']+':'+a['status'] for a in accesses))
    result['java']['sqlUseKinds']=dict(Counter(a['kind'] for a in analysis['uses']))
    result['java']['independentCandidates']=len(row['java']['findings'])
    return result

def report(root,output,packs):
    root=outside(root);plan=read(root/'application-plan.json')
    before=read(root/'hardening2-after-b.json');after=read(root/'hardening3-after.json')
    plan_hash=digest((root/'application-plan.json').read_bytes())
    if before['planSha256']!=plan_hash or after['planSha256']!=plan_hash:raise ValueError('PLAN_CHANGED')
    if subprocess.check_output(['git','diff',before['engineCommit'],BASELINE,'--','src/main','analyzers']).strip():raise ValueError('BASELINE_ENGINE_NOT_EQUIVALENT')
    previous={p['projectId']:p for p in before['projects']};current={p['projectId']:p for p in after['projects']}
    if previous.keys()!=current.keys():raise ValueError('PROJECT_SET_CHANGED')
    rows=[]
    for project in plan['projects']:
        ident=project['projectId']
        for entry in project.get('files',[]):
            path=root/'sources'/ident/relative(entry['path'])
            if path.is_symlink() or digest(path.read_bytes())!=entry['sha256']:raise ValueError('SOURCE_CHANGED')
        old=previous[ident].get('runs',[]);new=current[ident].get('runs',[])
        row=dict(projectId=ident,repositoryUrl=project['repositoryUrl'],commitSha=project['commitSha'])
        if not old or not new:
            if bool(old)!=bool(new):raise ValueError('ACQUISITION_STATE_CHANGED')
            row['status']='COLLECTION_FAILED_NOT_ANALYZED';rows.append(row);continue
        if len(new)!=2 or stable(new[0])!=stable(new[1]):raise ValueError('REPEAT_MISMATCH')
        if old[0]['risk']['policyVersion']!=new[0]['risk']['policyVersion']:raise ValueError('RISK_POLICY_CHANGED')
        row.update(before=summary(old[0]),after=summary(new[0]),elapsedMs=[r['elapsedMs']for r in new],
                   comparisonFingerprintChanged=old[0]['engineFingerprint']!=new[0]['engineFingerprint'])
        old_alerts={(f['ruleId'],f['filePath'],f['line'])for f in old[0]['filtered']}
        new_alerts={(f['ruleId'],f['filePath'],f['line'])for f in new[0]['filtered']}
        row['removedWarningLocations']=[dict(ruleId=a,filePath=b,line=c)for a,b,c in sorted(old_alerts-new_alerts)]
        row['newWarningLocations']=[dict(ruleId=a,filePath=b,line=c)for a,b,c in sorted(new_alerts-old_alerts)]
        rows.append(row)
    packs=outside(packs);packs.mkdir(mode=0o700)
    histories=[]
    for ident,family in [('spring-projects--spring-petclinic','SPRING_DATA_JPA'),('macrozheng--mall-tiny','MYBATIS_PLUS')]:
        row=next(r for r in rows if r['projectId']==ident)
        item=dict(originalPackCaseId=ident+'-java-worker-memory',followupCaseId=ident+'-data-access-contracts',
                  repositoryUrl=row['repositoryUrl'],sourceCommit=row['commitSha'],sourcePlanSha256=plan_hash,
                  originalFailure='Worker memory failure previously repaired; zero traced JDBC SQL remained after parsing recovered.',
                  rootCause='Framework proxy/API contracts and typed DI resolution were outside v2 scope, not proof of missing vulnerable SQL.',
                  framework=family,before=row['before']['java'],after=row['after']['java'],
                  engineCommit=after['engineCommit'],baselineMilestone=BASELINE,
                  syntheticRegression='JavaDataAccessTest: typed unique DI, binding/substitution, ambiguous/conditional targets, mutable fields, dynamic XML, XXE and unknown transformations.',
                  limits='Source-only bounded resolution. Proxy execution, dynamic SQL, inherited MyBatis-Plus implementation and arbitrary object transformations are UNKNOWN.',
                  replay='application_track.py run DATA_ROOT NEW_OUTPUT --project '+ident)
        write(packs/(item['followupCaseId']+'.json'),item);histories.append(item)
    result=dict(schemaVersion=1,baselineMilestone=BASELINE,engineCommit=after['engineCommit'],sourcePlanSha256=plan_hash,
                projects=rows,failureCaseHistory=histories,riskPolicyChanged=False,scoreFormulaChanged=False,
                userDatabaseUsed=False,oldReviewsRecomputed=False,targetCodeExecuted=False,externalVulnerabilityAndAiLookups='NOT_RUN',
                interpretation=['SQL name candidates are not confirmed execution sites.',
                                'JPA and Mapper declarations are separate from SQL execution and whole-project safety.',
                                'Observed projects are regression material, not an independent accuracy benchmark.',
                                'Source omissions, fixed SHAs and external vulnerability-query state are unchanged.'])
    write(output,result)
    print(dict(projects=len(rows),followupPacks=len(histories),engineCommit=after['engineCommit']))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('output');p.add_argument('packs');args=p.parse_args()
    report(**vars(args))
