"""Policy declaration metrics, deliberately separate from real application breaches."""
import argparse
from collections import Counter
from pathlib import Path
from application_track import read, write


def metrics(before, after, oracle):
    if oracle['matched']!=oracle['total'] or not all(r['match'] for r in oracle['rows']):
        raise ValueError('ORACLE_TRUTH_NOT_VERIFIED')
    old={r['caseId']:r for r in before['rows']};new={r['caseId']:r for r in after['rows']}
    if len(old)!=len(before['rows']) or len(new)!=len(after['rows']):raise ValueError('DUPLICATE_CASE')
    if set(old)!=set(new) or set(new)!=set(oracle['policyHashes']):raise ValueError('CASE_SET')
    counts={k:Counter({v:0 for v in ['TP','FP','FN','TN','UNKNOWN','NOT_SUPPORTED','NOT_INSPECTED']}) for k in ['before','after']}
    rows=[]
    for key,a in old.items():
        b=new[key]
        if a['truth'] not in {'REVIEW','NORMAL'} or a['truth']!=b['truth'] or a['sqlSha256']!=b['sqlSha256'] or a['sqlSha256']!=oracle['policyHashes'][key] or a['access']['operation']!=b['access']['operation']:raise ValueError('TRUTH_OR_SQL_CHANGED')
        states={}
        for label,row in [('before',a),('after',b)]:
            operation=row['access']['operation']
            hit=any(f['table']==row['access']['table'] and operation in f['operations'] for f in row['findings'])
            states[label]=('TP' if hit else 'FN') if row['truth']=='REVIEW' else ('FP' if hit else 'TN')
            counts[label][states[label]]+=1
            if any(f['priority']!='REVIEW_REQUIRED' or f['comparisonPolicy']!='NOT_COMPARED' for f in row['findings']):raise ValueError('POLICY_CHANGED')
        rows.append(dict(caseId=key,truth=a['truth'],sqlSha256=a['sqlSha256'],before=states['before'],after=states['after'],
                         beforeAccessState=a['access']['authorizationEvidence']['state'],afterAccessState=b['access']['authorizationEvidence']['state'],
                         targetOperation=b['access']['operation'],beforeOperations=a['policyOperations'],afterOperations=b['policyOperations']))
    return dict(metric='GRADE_B_DECLARED_POLICY_REVIEW_NOT_CONFIRMED_APPLICATION_VULNERABILITY',cases=rows,
                counts={k:dict(v) for k,v in counts.items()},
                precision={k:c['TP']/(c['TP']+c['FP']) if c['TP']+c['FP'] else None for k,c in counts.items()},
                recall={k:c['TP']/(c['TP']+c['FN']) if c['TP']+c['FN'] else None for k,c in counts.items()},
                independentHumanReview=False)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('spec',type=Path);p.add_argument('output',type=Path);args=p.parse_args()
    spec=read(args.spec)
    regression=metrics(*(read(Path(spec[k])) for k in ['before','after','database']))
    validation=metrics(*(read(Path(spec[k])) for k in ['validationBefore','validationAfter','validationDatabase']))
    contexts=read(Path(spec['contexts']))
    if any(r['effectiveRole']!='UNKNOWN' for r in contexts['rows']):raise ValueError('RUNTIME_ROLE_OVERCLAIM')
    result=dict(schemaVersion=1,baseline='9c628f92dc1d129f7c51ff7da6fb353d896203e2',worker='ts-server-v24',policyAnalyzer='supabase-rls-v3',
                regression=regression,validation=validation,uncertainContexts=contexts,
                database=read(Path(spec['database'])),validationDatabase=read(Path(spec['validationDatabase'])),
                truthDraftAudit=spec['truthDraftAudit'],applications=read(Path(spec['applications'])),sources=spec['sources'],sourceFacts=spec['sourceFacts'],
                resources=read(Path(spec['resources'])),failureCasePack=spec['failureCasePack'],
                newRealVulnerabilityTP=0,gradeARealPairs=0,paidAiCalls=0,targetExecuted=False,userDatabaseAccessed=False,
                limitations=['Matrix TP means a justified declaration review candidate, not an exploited HTTP authorization flaw.',
                             'Application filters, verified identity calls, GRANT and RLS declarations are separate evidence.',
                             'Actual JWT application, deployed policies, role inheritance, triggers and administrative bypass are not verified.',
                             'PostgreSQL uses authored SQL only; public source SQL is never executed.',
                             'New public apps are Grade C; no warning is not a TN. All observed apps become regression material.',
                             'Validation is same-author post-implementation material, not an independent blind holdout.',
                             'Live GitHub App, paid Provider, public deployment and actual Supabase access were not tested.'])
    write(args.output,result)
    print({'regression':regression['counts'],'validation':validation['counts'],'applications':len(result['applications'])})
