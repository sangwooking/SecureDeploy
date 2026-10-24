"""Write-origin classification receipts, explicitly separate from vulnerability metrics."""
import argparse
from pathlib import Path
from application_track import read, write


def compare_origins(before, after):
    a={r['caseId']:r for r in before['rows']};b={r['caseId']:r for r in after['rows']}
    if len(a)!=len(before['rows']) or len(b)!=len(after['rows']) or set(a)!=set(b):
        raise ValueError('ORIGIN_CASE_SET_CHANGED')
    for key,old in a.items():
        if old['expected']!=b[key]['expected'] or old['operation']!=b[key]['operation']:
            raise ValueError('ORIGIN_TRUTH_CHANGED')
        if b[key]['runtimeAuthorization']!='UNKNOWN':
            raise ValueError('RUNTIME_AUTHORIZATION_OVERCLAIM')
        if old['policyWarnings']!=b[key]['policyWarnings']:
            raise ValueError('POLICY_FINDING_CHANGED')
    return dict(metric='LOCAL_ORIGIN_CLASSIFICATION_NOT_VULNERABILITY_DETECTION',before=before,after=after)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('spec',type=Path);p.add_argument('output',type=Path);args=p.parse_args();s=read(args.spec)
    report=dict(schemaVersion=1,baseline='e620a4cbf3ae1629ad58c9c9f8cc3cd83d1e167a',worker='ts-server-v26',policyAnalyzer='supabase-rls-v3',
        implementationCommit=s['implementationCommit'],stageA=read(Path(s['stageA'])),applications=read(Path(s['applications'])),
        controls=compare_origins(read(Path(s['before'])),read(Path(s['after']))),validation=read(Path(s['validation'])),
        policyRegression=read(Path(s['policyRegression'])),policyValidation=read(Path(s['policyValidation'])),
        policyLinks=read(Path(s['policyLinks'])),resources=read(Path(s['resources'])),writeSites=s['writeSites'],
        tests=s['tests'],failureCasePack=s['failureCasePack'],newRealVulnerabilityTP=0,independentHumanReview=False,
        userDatabaseModified=False,paidAiCalls=0,targetExecuted=False,liveGithubAppTested=False,oracleReexecuted=False,
        limitations=['Local source classification is not a vulnerability TP/FN/precision/recall metric.',
          'Grade C applications have no whole-project safe/vulnerable truth; absence of findings is not TN.',
          'Code evidence from getUser/getClaims and absence exits does not prove runtime authentication or database role.',
          'Write fields and row filters are independent; field names do not establish the ownership model.',
          'Same-author controls and validation are not independent blind/external evaluation.',
          'Two-step payload-object alias and earlier ID argument use can conservatively remain UNKNOWN.',
          'Helpers, dynamic wrappers, UPSERT, arrays and additional query/params extraction were not added.',
          'PostgreSQL oracle receipts are inherited from validation #9; no external SQL or database executed here.',
          'Resource measurements are parsed subset Worker replay, not whole-backend peak RSS or full SQL execution.',
          'Mock GitHub regression and real H2/React browser tests are not live GitHub App validation.'])
    write(args.output,report)
    print(dict(projects=len(report['applications']),controls=len(report['controls']['after']['rows']),validation=report['validation']['matches'],newRealVulnerabilityTP=0))
