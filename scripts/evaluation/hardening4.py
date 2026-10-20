"""Express follow-up on frozen application evidence. Public metadata, no source bodies."""
import argparse
import subprocess
from pathlib import Path
from collections import Counter
from application_track import read,write,outside,digest,relative
from benchmark import stable
from hardening3 import summary as previous_summary

BASELINE='cd80bfa4b4c0c1d6a249b4d641a3acea752a663b'

def summary(row):
    result=previous_summary(row);ts=row['typescript']
    result['typescript']=dict(version=ts['analyzerVersion'],status=ts['status'],files=dict(Counter(f['parseStatus']for f in ts['files'])),
        entrypoints=sum(f['entrypoints']for f in ts['files']),functions=sum(f['functionsAnalyzed']for f in ts['files']),
        findings=dict(Counter(f['ruleId']+':'+f['confidence']for f in ts['findings'])),
        nodeUses=dict(Counter(u['ruleId']+':'+u['kind']for u in ts.get('nodeUses')or[])),
        validatedFindings=dict(Counter(f['ruleId']for f in ts.get('validatedFindings')or[])),
        limitations=dict(Counter(l for f in ts['files']for l in f['limitations'])))
    return result

def report(root,output,packs,probe):
    root=outside(root);before=read(root/'hardening3-after.json');after=read(root/'hardening4-after.json')
    plan=read(root/'application-plan.json');hash=digest((root/'application-plan.json').read_bytes())
    if before['planSha256']!=hash or after['planSha256']!=hash:raise ValueError('PLAN_CHANGED')
    if subprocess.check_output(['git','diff',before['engineCommit'],BASELINE,'--','src/main','analyzers'],cwd=Path(__file__).resolve().parents[2]).strip():raise ValueError('BASELINE_ENGINE_CHANGED')
    old={p['projectId']:p for p in before['projects']};new={p['projectId']:p for p in after['projects']}
    if old.keys()!=new.keys():raise ValueError('PROJECT_SET_CHANGED')
    rows=[]
    for project in plan['projects']:
        ident=project['projectId']
        for entry in project.get('files',[]):
            path=root/'sources'/ident/relative(entry['path'])
            if path.is_symlink()or digest(path.read_bytes())!=entry['sha256']:raise ValueError('SOURCE_CHANGED')
        b=old[ident].get('runs',[]);a=new[ident].get('runs',[])
        row=dict(projectId=ident,repositoryUrl=project['repositoryUrl'],commitSha=project['commitSha'])
        if not b or not a:
            if bool(b)!=bool(a):raise ValueError('ACQUISITION_STATE_CHANGED')
            row['status']='COLLECTION_FAILED_NOT_ANALYZED';rows.append(row);continue
        if len(a)!=2 or stable(a[0])!=stable(a[1]):raise ValueError('REPEAT_INCONSISTENCY')
        if a[0]['risk']['policyVersion']!=b[0]['risk']['policyVersion']:raise ValueError('RISK_POLICY_CHANGED')
        row.update(before=summary(b[0]),after=summary(a[0]),elapsedMs=[r['elapsedMs']for r in a],
                   comparisonFingerprintChanged=b[0]['engineFingerprint']!=a[0]['engineFingerprint'])
        rows.append(row)
    node=next(p for p in after['projects']if p['projectId']=='OWASP--NodeGoat')['runs'][0]['typescript']
    probe=read(outside(probe))
    if probe['engineCommit']!=after['engineCommit']:raise ValueError('PROBE_ENGINE_CHANGED')
    for ident in {r['projectId']for r in probe['results']}:
        selected=[r for r in probe['results']if r['projectId']==ident]
        if len(selected)!=2 or selected[0]['inputSha256']!=selected[1]['inputSha256']:raise ValueError('PROBE_INPUT_CHANGED')
    packs=outside(packs);packs.mkdir(mode=0o700);history=[]
    for ident,status in [('nodegoat-request-eval','STATIC_REQUEST_EVAL_PATH_CONNECTED'),
                         ('nodegoat-nosql-query-construction','UNKNOWN_RECEIVER_OR_OBJECT_FLOW_REMAINS'),
                         ('nodegoat-owner-selection','AUTHORIZATION_NOT_VERIFIED_NO_FINDING')]:
        anchors=[f['sink']for f in node['findings']if f['ruleId']=='JS_EVAL_INPUT_FLOW'and f['confidence']=='HIGH']
        observations=[u for u in node.get('nodeUses')or[]if u['ruleId']=='JS_MONGO_WHERE_INPUT_FLOW']
        if ident.endswith('eval')and not anchors:status='STATIC_PATH_NOT_CONNECTED'
        if 'nosql'in ident and any(u['kind']=='INPUT_TO_EXECUTION'for u in observations):status='STATIC_MONGO_PATH_CONNECTED'
        item=dict(originalPackCaseId=ident,sourceCommit=next(r['commitSha']for r in rows if r['projectId']=='OWASP--NodeGoat'),
                  baselineMilestone=BASELINE,engineCommit=after['engineCommit'],status=status,
                  confirmedStaticAnchors=anchors if ident.endswith('eval')else[],nodeObservations=observations if 'nosql'in ident else[],
                  noRuntimeAttack=True,groundTruth='Original manually reviewed conditional path label retained; not whole-project truth.',
                  remainingLimits='Unknown middleware, mutable objects, callback/prototype behavior, runtime library version and ownership policy are not proven.',
                  replay='application_track.py run DATA_ROOT NEW_OUTPUT --project OWASP--NodeGoat')
        write(packs/(ident+'.json'),item);history.append(item)
    result=dict(schemaVersion=1,baselineMilestone=BASELINE,engineCommit=after['engineCommit'],sourcePlanSha256=hash,
                projects=rows,failureCaseHistory=history,workerProbe=probe,riskPolicyChanged=False,scoreFormulaChanged=False,
                databaseMigration='NONE; optional nodeUses JSON only; historical snapshots not recomputed',userDatabaseUsed=False,
                externalVulnerabilityAndAiLookups='NOT_RUN',targetCodeExecuted=False,
                evaluationLimits=['Observed NodeGoat is development/regression material, not a blind test.',
                                  'Three eval anchors are one teaching defect family, not three independent CVEs.',
                                  'MongoDB $where synthetic paths are supported, but this application path still lacks verified receiver provenance.',
                                  'Official Express self-package examples are scope observations; not scored as TN when registration is unsupported.',
                                  'Java v3 external inheritance, object flow, SQL API gaps, 200-evidence cap and performance cost remain separate follow-up work.'])
    write(output,result);print(dict(projects=len(rows),failureFollowups=len(history),engineCommit=after['engineCommit']))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('output');p.add_argument('packs');p.add_argument('probe');args=p.parse_args();report(**vars(args))
