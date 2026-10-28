"""Path-scoped offline result audit. Never loads or executes evaluated source."""
import argparse
from collections import Counter
import json
from pathlib import Path
from benchmark import stable

def at(location, spec):
    return (location or {}).get('filePath') == spec['filePath'] and (location or {}).get('line') in spec['lines']

def target_findings(run, target):
    result=[]
    for finding in run['typescript'].get('validatedFindings',[]):
        if finding['ruleId']!=target['ruleId'] or not at(finding['location'],target['sink']):
            continue
        if any(at(e.get('source'),target['source']) and at(e.get('sink'),target['sink']) for e in finding.get('evidence',[])):
            result.append(finding)
    return result

def inspect(run, target, normal=False):
    ts=run['typescript'];files={f['filePath']:f for f in ts['files']}
    file=files.get(target['sink']['filePath']);findings=target_findings(run,target)
    limits=[] if file is None else file['limitations']
    candidates=[f for f in ts.get('findings',[]) if f['ruleId']==target['ruleId']
        and at(f.get('source'),target['source']) and at(f.get('sink'),target['sink'])]
    proof=[]
    if normal:
        spec=target.get('normalProof')
        if spec:
            observations=(ts.get('nodeUses',[]) if spec['field']=='nodeUses' else
                [d for c in ts.get('authorizationContexts',[]) for d in c.get('defenses',[])])
            proof=[o for o in observations if o.get('kind')==spec['kind'] and at(o.get('location',o),spec)]
    if findings:
        status='FP' if normal else 'TP'
    elif normal and candidates:
        status='FP_REVIEW_CANDIDATE'
    elif file is None or file['parseStatus'] not in ['PARSED','PARSE_FAILED','LIMIT_EXCEEDED']:
        status='NOT_INSPECTED'
    elif file['parseStatus']=='PARSE_FAILED':
        status='PARSING_FAILED'
    elif file['parseStatus']=='LIMIT_EXCEEDED' or any('BUDGET_EXCEEDED' in reason for reason in limits):
        status='RESOURCE_LIMIT'
    elif normal and proof and file['functionsAnalyzed']>0:
        status='TN_TARGET_ONLY'
    elif sum(f['entrypoints'] for f in files.values())==0:
        status='NOT_SUPPORTED_REQUEST_CONNECTION'
    elif normal:
        status='UNKNOWN_NORMAL_PROTECTION_NOT_ESTABLISHED'
    else:
        # A missing warning alone cannot prove that every required contract was supported.
        status='UNKNOWN_MISSING_TARGET_FLOW'
    return dict(status=status,findings=findings,candidates=candidates,normalProof=proof,
        parsed=file is not None and file['parseStatus']=='PARSED',
        targetFunctions=0 if file is None else file['functionsAnalyzed'],limitations=limits,
        legacyRawTarget=[f for f in run.get('raw',[]) if f['ruleId']==target['ruleId'] and at(f,target['sink'])],
        legacyFilteredTarget=[f for f in run.get('filtered',[]) if f['ruleId']==target['ruleId'] and at(f,target['sink'])])

def pair_status(before, after):
    if before['status']=='TP' and after['status']=='TN_TARGET_ONLY':
        return 'VERIFIED_STATIC_TARGET_CONTRAST_NOT_RUNTIME_OR_RESOLVED'
    return 'NOT_VERIFIED_AS_SUCCESSFUL_REPAIR'

def audit(catalog, inputs):
    if catalog['baseline']!='9f1ba7625af1cea65eeb9d2ff1ad9a884dd408cc':
        raise ValueError('BASELINE')
    results={}
    for key,path in inputs.items():
        data=json.loads(Path(path).read_text());expected=catalog['inputs'][key]
        if data['engineCommit']!=catalog['engines'][key.split('-',1)[0]]:
            raise ValueError('ENGINE_COMMIT')
        if data['planSha256']!=expected['planSha256']:
            raise ValueError('PLAN_HASH')
        p=next(p for p in data['projects'] if p['projectId']==expected['projectId'])
        if p['commitSha']!=expected['sourceSha'] or len(p.get('runs',[]))!=2:
            raise ValueError('SOURCE_OR_RUNS')
        if stable(p['runs'][0])!=stable(p['runs'][1]):
            raise ValueError('NONDETERMINISTIC')
        if p['runs'][0]['typescript']['analyzerVersion']!=expected['worker']:
            raise ValueError('WORKER')
        results[key]=p
    rows=[]
    for case in catalog['cases']:
        for worker in ['v40','v44']:
            before=inspect(results[worker+'-'+case['before']]['runs'][0],case)
            row=dict(caseId=case['caseId'],worker=worker,before=before)
            if case.get('after'):
                target={**case,**case.get('afterTarget',{})}
                after=inspect(results[worker+'-'+case['after']]['runs'][0],target,normal=True)
                row.update(after=after,pair=pair_status(before,after))
            rows.append(row)
    return dict(schemaVersion=1,baseline=catalog['baseline'],rows=rows,
        truth='OBSERVED_NONBLIND_STATIC_GROUND_TRUTH_NO_RUNTIME_EXPLOIT',
        independentReviewer=False,newRealVulnerabilityTP=0,
        productEngineChanged=False,autoPatchImplemented=False,
        unknownIsNotSafe=True,structuralComparisonPolicy='NOT_COMPARED')

def public_summary(catalog, report, inputs):
    counts={}
    for worker in ['v40','v44']:
        rows=[r for r in report['rows'] if r['worker']==worker]
        counts[worker]=dict(before=dict(Counter(r['before']['status'] for r in rows)),
            after=dict(Counter(r['after']['status'] for r in rows if 'after' in r)),
            targetContrasts=sum(r.get('pair')=='VERIFIED_STATIC_TARGET_CONTRAST_NOT_RUNTIME_OR_RESOLVED' for r in rows))
    metrics=[]
    for key,path in inputs.items():
        d=json.loads(Path(path).read_text());expected=catalog['inputs'][key]
        project=next(p for p in d['projects'] if p['projectId']==expected['projectId'])
        r=project['runs'][0];ts=r['typescript'];selection=ts['selectionCoverage']
        metrics.append(dict(input=key,parsed=sum(f['parseStatus']=='PARSED' for f in ts['files']),
            selected=selection['submittedFiles'],discovered=selection['discoveredFiles'],
            entries=sum(f['entrypoints'] for f in ts['files']),functions=sum(f['functionsAnalyzed'] for f in ts['files']),
            steps=ts['supabaseAnalysis']['budgetUsage'],elapsedMs=[r['elapsedMs'] for r in project['runs']],
            parentHeapUsedBytesNotPeak=[r['parentHeapUsedBytes'] for r in project['runs']],
            rawLegacy=len(r['raw']),filteredLegacy=len(r['filtered']),securityScore=r['securityScore'],
            risk=r['risk']['prioritizedDeploymentAssessment'],coverage=r['coverage']['status'],
            sca=r['sca'],repeatIdentical=True))
    return dict(schemaVersion=1,baseline=catalog['baseline'],engineChanged=False,counts=counts,
        scope=catalog['counts'],metrics=metrics,caseStatuses=[dict(caseId=r['caseId'],worker=r['worker'],
            before=r['before']['status'],after=r.get('after',{}).get('status','NO_FIXED_COUNTERPART'),
            pair=r.get('pair'),warningCount=len(r['before']['findings'])) for r in report['rows']],
        riskPolicyChanged=False,automaticPatchTypesAdded=0,remediationReadyCount=0,
        newIndependentGroundTruth=0,newRealVulnerabilityTP=0,
        caveats=['Four matching sink paths belong to two causes in one NodeGoat family, not four independent vulnerabilities.',
            'Three known risk paths remain missed by the product; do not hide them behind supported-only recall.',
            'Only FlintCMS is a real upstream fixed pair; NodeGoat/Juice controlled copies are Grade B, not upstream fixes.',
            'Nonblind observed regression; no target execution or external reviewer. No whole-project SAFE or runtime repair guarantee.',
            'No automatic RESOLVED: structural findings retain NOT_COMPARED. Scores/Risk do not include these candidates.'])

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('catalog',type=Path)
    parser.add_argument('inputs',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
    if args.output.exists() or args.output.resolve().is_relative_to(Path(__file__).resolve().parents[2]):
        raise ValueError('NEW_EXTERNAL_OUTPUT_REQUIRED')
    catalog=json.loads(args.catalog.read_text());inputs=json.loads(args.inputs.read_text());result=audit(catalog,inputs)
    with args.output.open('x')as output:json.dump(result,output,indent=2)
    for row in result['rows']:print(row['worker'],row['caseId'],row['before']['status'],row.get('after',{}).get('status','NO_FIXED_COUNTERPART'))
