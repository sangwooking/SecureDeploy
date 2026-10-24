"""Source-free Next/Supabase path receipts with declaration/runtime separation."""
import argparse
from pathlib import Path
from application_track import read, write
from authorization_report import metrics


def controls(result):
    before,after=result['before'],result['after']
    old={r['caseId']:r for r in before['rows']};new={r['caseId']:r for r in after['rows']}
    if len(old)!=len(before['rows']) or len(new)!=len(after['rows']) or set(old)!=set(new):raise ValueError('CONTROL_CASE_SET')
    for key,a in old.items():
        b=new[key]
        if a['truth']!=b['truth'] or a['operation']!=b['operation']:raise ValueError('CONTROL_TRUTH_CHANGED')
        if a['runtimeAuthorization']!='UNKNOWN' or b['runtimeAuthorization']!='UNKNOWN':raise ValueError('RUNTIME_AUTHORIZATION_OVERCLAIM')
    if before['counts']['finalPolicyWarnings']!=after['counts']['finalPolicyWarnings']:raise ValueError('POLICY_WARNING_REGRESSION')
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('spec',type=Path);p.add_argument('output',type=Path);a=p.parse_args();s=read(a.spec)
    result=dict(schemaVersion=1,baseline='04540d6587c13bd48b140e9d05210352ba50e938',worker='ts-server-v25',policyAnalyzer='supabase-rls-v3',
                applications=read(Path(s['applications'])),controls=controls(read(Path(s['controls']))),
                policyRegression=metrics(*(read(Path(s[k])) for k in ['policyBefore','policyAfter','database'])),
                policyValidation=metrics(*(read(Path(s[k])) for k in ['policyValidationBefore','policyValidationAfter','validationDatabase'])),
                database=read(Path(s['database'])),validationDatabase=read(Path(s['validationDatabase'])),
                resources=[read(Path(x)) for x in s['resources']],sources=s['sources'],manualPaths=s['manualPaths'],
                excludedCandidates=s['excludedCandidates'],failureCasePack=s['failureCasePack'],
                newRealVulnerabilityTP=0,independentHumanReview=False,targetExecuted=False,paidAiCalls=0,userDatabaseAccessed=False,
                limitations=['Final policy warnings and connected policy evidence are separate metrics; this is not a measured increase in real vulnerability recall.',
                             'FormData/request input to mutation arguments is manually reviewed in controls and public paths, not new automatic write-argument taint analysis.',
                             'Next request declarations are not evidence of deployed invocation. Auth calls/results are not actual JWT validation or authorization.',
                             'PostgreSQL validates authored policy semantics only, using a current_setting-based auth.uid stub, not external migrations or Supabase Auth.',
                             'Grade C apps have no whole-project SAFE/TN label; all observed sources become regression material.',
                             'Source-backed controls are same-author Grade B, not independent human review or a blind holdout.',
                             'Worker resource replay uses parsed source/completed SQL subsets and is not whole-backend RSS or complete policy execution.',
                             'Live GitHub App, real Supabase, actual AI Provider and public deployment were not tested.'])
    write(a.output,result)
    print(dict(applications=len(result['applications']),controls=len(result['controls']['after']['rows']),newRealVulnerabilityTP=0))
