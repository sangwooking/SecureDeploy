"""Source-free, same-plan scheduling comparison; no target execution or truth inflation."""
from collections import Counter
from pathlib import Path
import argparse

from benchmark import read, stable
from application_track import write


def summarize(project):
    runs=project.get('runs',[])
    if len(runs)!=2 or stable(runs[0])!=stable(runs[1]):raise ValueError('REPEAT_OR_COMPLETENESS')
    run=runs[0];ts=run['typescript'];sql=ts['supabaseAnalysis']
    if ts['status'] in {'UNAVAILABLE','TIMEOUT','DISABLED'}:raise ValueError('WORKER_NOT_COMPLETED')
    files=ts['files'];flow=run['reviewCandidates']
    return dict(projectId=project['projectId'],sourceCommit=project['commitSha'],repeatConsistent=True,
        inventory={k:run['coverage'][k]for k in ('discoveredFiles','selectedFiles','unsupportedFiles','excludedFiles','failedFiles')},
        selection=ts.get('selectionCoverage'),recordedJsFiles=len(files),parsedJs=sum(f['parseStatus']=='PARSED'for f in files),
        limitedJs=sum(f['parseStatus']=='LIMIT_EXCEEDED'for f in files),entries=len(ts['authorizationContexts']),
        tracedFunctions=sum(f['functionsAnalyzed']for f in files),
        selectedRelatedHelpers=sum(f.get('selectionReason')=='TS_RELATED_IMPORT_HINT'and f['parseStatus']!='LIMIT_EXCEEDED'for f in files),
        tracedRelatedHelpers=sum(f.get('selectionReason')=='TS_RELATED_IMPORT_HINT'and f['functionsAnalyzed']>0 for f in files),
        selectedJsReasons=dict(Counter(f.get('selectionReason')or'UNRECORDED'for f in files if f['parseStatus']!='LIMIT_EXCEEDED')),
        sqlStatuses=dict(Counter(f['status']for f in sql['files'])),sqlStatements=sum(f['statements']for f in sql['files']),
        tables=len(sql['tables']),policies=sum(len(t['policies'])for t in sql['tables']),
        policyOperationStates=dict(Counter(o['state']for t in sql['tables']for o in t['operations'])),
        clients=len(sql['clients']),accesses=len(sql['accesses']),clientLinked=sum(a['clientStatus']=='CLIENT_DECLARATION_LINKED'for a in sql['accesses']),
        structural=[dict(rule=f['ruleId'],file=f['location']['filePath'],line=f['location']['line'])for f in flow],
        httpUses=dict(Counter(u['kind']for u in ts.get('httpUses',[]))),
        exposureUses=dict(Counter(u['status']for u in ts.get('exposureUses',[]))),
        ruleSignals=run['filtered'],score=run['securityScore'],risk=run['risk']['prioritySummary'],
        limitations=sorted(set(ts['limitations']+sql['limitations'])),
        elapsedMs=[r['elapsedMs']for r in runs],sampledParentHeapBytes=[r['parentHeapUsedBytes']for r in runs])


def next_summary(raw):
    from next_flows import CASES
    counts={};seen=set()
    for p in raw['projects']:
        runs=p.get('runs',[])
        if len(runs)!=2 or stable(runs[0])!=stable(runs[1]):raise ValueError('NEXT_REPEAT')
        name=p['projectId'].removeprefix('next-boundary-');seen.add(name)
        if name=='original':continue
        if name not in CASES:raise ValueError('NEXT_UNEXPECTED_CASE')
        file,_,truth,rule,split=CASES[name]
        matches=[f for f in runs[0]['typescript'].get('validatedFindings',[])if f['ruleId']==rule and f['location']['filePath']==file]
        final=[f for f in runs[0]['reviewCandidates']if f['ruleId']==rule and f['location']['filePath']==file]
        if bool(matches)!=bool(final):raise ValueError('NEXT_FINAL_CONNECTION_CHANGED')
        if bool(matches)!=(truth=='TP'):raise ValueError('NEXT_TARGET_DIFFERENCE')
        if any(f.get('priority')!='REVIEW_REQUIRED'or f.get('comparisonPolicy')!='NOT_COMPARED'for f in matches):raise ValueError('NEXT_PRIORITY_CHANGED')
        counts.setdefault(split,dict(TP=0,TN=0,FP=0,FN=0,UNKNOWN=0))[truth]+=1
    if seen!=set(CASES)|{'original'}:raise ValueError('NEXT_CASE_SET')
    return dict(counts=counts,projects=len(seen),repeatConsistent=True,independence='Existing same-curator controlled regression, not external independent validation')


def report(before_file,after_file,output,next_file=None):
    before=read(before_file);after=read(after_file)
    if before['planSha256']!=after['planSha256']:raise ValueError('DIFFERENT_SOURCE_PLAN')
    old={p['projectId']:summarize(p)for p in before['projects']}
    new={p['projectId']:summarize(p)for p in after['projects']}
    if set(old)!=set(new):raise ValueError('PROJECT_SET_CHANGED')
    rows=[]
    for ident,b in old.items():
        a=new[ident]
        if b['sourceCommit']!=a['sourceCommit']:raise ValueError('SOURCE_COMMIT_CHANGED')
        if b['ruleSignals']!=a['ruleSignals']or b['score']!=a['score']or b['risk']!=a['risk']:raise ValueError('RULE_SCORE_RISK_DIFFERENCE')
        if not all(f in a['structural']for f in b['structural']):raise ValueError('PRIOR_STRUCTURAL_FINDING_LOST')
        rows.append(dict(projectId=ident,before=b,after=a,newStructural=[f for f in a['structural']if f not in b['structural']]))
    regression=None
    if next_file:
        raw=read(next_file)
        if raw['engineCommit']!=after['engineCommit']:raise ValueError('NEXT_ENGINE_MISMATCH')
        regression=next_summary(raw)
    write(output,dict(schemaVersion=1,baselineEngine=before['engineCommit'],engineCommit=after['engineCommit'],nextRegression=regression,
        planSha256=after['planSha256'],projects=rows,
        invariants='Same source plan, two semantic repeats, existing Rule/FPR signals, score, Risk summary and structural findings preserved',
        scope='Grade C observed public apps; additional entries or declarations are not TP, safety, ownership or deployment proof',
        policy='RLS grammar and Risk formulas unchanged; incomplete migrations remain UNKNOWN; no P0-2/P0-3 implementation',
        limits=dict(combinedFiles=100,fileCharacters=100000,totalCharacters=1000000,steps=100000,policyWorkShareWithCode=0.25,policyWorkShareSqlOnly=0.9,nodeHeapMiB=192,depth=3),
        limitations=['Parent heap samples are not worker peak RSS','Input quotas do not promise that all selected files finish analysis',
                     'Previously observed sources and one curator; not blind or independent validation','OSV/EPSS/KEV/AI calls not run; H2 only']))


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ('before_file','after_file','output'):p.add_argument(name,type=Path)
    p.add_argument('--next-file',type=Path)
    report(**vars(p.parse_args()))
