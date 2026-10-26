"""Three-layer adjudication of frozen controls and product pipeline receipts."""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
from application_track import read, write
from benchmark import stable
from authorization_truth11 import metrics


def product_receipts(paths,plan,engine,strict=True):
    actual={};summaries=[];disagreements=[]
    by_id={c['caseId']:c for c in plan['cases']};direct={r['caseId']:r for r in engine['rows']}
    for path in paths:
        data=read(Path(path))
        for p in data['projects']:
            if len(p.get('runs',[]))!=2 or stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('PRODUCT_REPEAT_FAILED')
            ident=p['projectId']
            if ident in actual or ident not in by_id:raise ValueError('PRODUCT_CASE_SET')
            r=p['runs'][0];s=r['typescript']['supabaseAnalysis'];c=by_id[ident]
            access=next((a for a in s['accesses'] if a['location']['filePath']==c['packet']['files'][0]['filePath'] and a['operation']==c['operation']),None)
            expected_access=dict(direct[ident]['access']) if direct[ident]['access'] else None
            if expected_access is not None:expected_access.setdefault('writeEvidence',None)
            if access!=expected_access:
                disagreements.append(dict(caseId=ident,expectedState=(expected_access or {}).get('authorizationEvidence',{}).get('state'),productState=(access or {}).get('authorizationEvidence',{}).get('state')))
                if strict:raise ValueError('DIRECT_AND_PRODUCT_ACCESS_DIFFER')
            hits=[f for f in s['findings'] if f['table']=='public.items' and c['operation'] in f['operations']]
            if hits!=direct[ident]['findings']:raise ValueError('PRODUCT_TARGET_FINDING_DIFFER')
            if any(not any(x['ruleId']==f['ruleId'] and x['location']==f['location'] for x in r['reviewCandidates']) for f in hits):raise ValueError('TARGET_NOT_IN_PRODUCT_CANDIDATES')
            actual[ident]=dict(caseId=ident,reviewCandidates=hits,legacyRuleCounts=dict(Counter(f['ruleId'] for f in r['filtered'])),
                score=r['securityScore'],risk=r['risk'],coverageStatus=r['coverage']['status'],access=access,sqlFiles=s['files'],
                sourceSqlOmissions=[e for e in r['coverage']['entries'] if e['filePath'].endswith('.sql') and e['status']!='SELECTED'],repeatIdentical=True)
            summaries.append(dict(caseId=ident,score=r['securityScore'],coverageStatus=r['coverage']['status'],legacyRuleCount=len(r['filtered']),matchingSupplementalCandidates=len(hits)))
    if set(actual)!=set(by_id):raise ValueError('PRODUCT_CASES_MISSING')
    return dict(cases=list(actual.values()),summary=summaries,directProductDisagreements=disagreements)


def public_context(paths):
    rows=[]
    for path in paths:
        data=read(Path(path))
        for p in data['projects']:
            if len(p.get('runs',[]))!=2 or stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('PUBLIC_CONTEXT_REPEAT_FAILED')
            r=p['runs'][0];ts=r['typescript'];sb=ts['supabaseAnalysis']
            rows.append(dict(project=p['projectId'],sha=p['commitSha'],grade='C_CONTEXT_NOT_WHOLE_PROJECT_SAFE_OR_VULNERABLE',
                entries=sum(f.get('entrypoints',0) for f in ts['files']),files=ts['files'],accesses=sb['accesses'],sqlFiles=sb['files'],
                policyCandidates=sb['findings'],legacyRuleCounts=dict(Counter(f['ruleId'] for f in r['filtered'])),score=r['securityScore'],coverage=r['coverage']['status'],
                repeatIdentical=True,truth='NO_TN_OR_TP_LABEL',collectionPlanSha256=data['planSha256']))
    return rows


def policy_expected(c):
    if c['scenario'] in ['missing-sql','partial-sql','opaque-policy','column-denial','no-update-grant']:return 'UNKNOWN'
    if c['policy']=='read-open':return 'PUBLIC_READ_DECLARATION'
    if c['policy'] in ['broad','open-replacement','open-existing','insert-open','delete-open','permissive']:return 'BROAD_ACCESS_REVIEW'
    return 'CONFIRMED_POLICY_EVIDENCE'


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('spec',type=Path);p.add_argument('output',type=Path);a=p.parse_args();s=read(a.spec)
    plan=read(Path(s['truth']));engine=read(Path(s['engine']));oracle=read(Path(s['database']));first=read(Path(s['firstDatabase']))
    if first['rows']!=oracle['rows']:raise ValueError('ORACLE_REPEAT_DIFFER')
    adjudication=metrics(plan,engine,oracle);product_before=product_receipts(s['productsBefore'],plan,engine,False);product=product_receipts(s['products'],plan,engine)
    direct={r['caseId']:r for r in engine['rows']};policy=[]
    for c in plan['cases']:
        actual=next(r['access']['authorizationEvidence']['state'] for r in product['cases'] if r['caseId']==c['caseId']);expected=policy_expected(c)
        before=next(r['access']['authorizationEvidence']['state'] for r in product_before['cases'] if r['caseId']==c['caseId'])
        policy.append(dict(caseId=c['caseId'],expected=expected,before=before,actual=actual,match=expected==actual,beforeMatch=before==expected))
    accesses=[r['access'] for r in engine['rows']];writes=[a['writeEvidence'] for a in accesses if a.get('writeEvidence')]
    r=dict(schemaVersion=1,date='2026-10-26',baseline=plan['baseline'],worker='ts-server-v27',policyAnalyzer='supabase-rls-v3',engineChanged=True,implementationCommit=s['implementationCommit'],stageB='PROPAGATE_KNOWN_SOURCE_SQL_OMISSIONS_TO_EXISTING_UNKNOWN_CONTRACT_ONLY',
      truthPlanSha256=hashlib.sha256(Path(s['truth']).read_bytes()).hexdigest(),truthProtocol='Original 34 frozen before first engine run; reserved SQL identifier corrected with unchanged requirements/outcomes; two opaque-policy UNKNOWN cases added and frozen before their first run. Earlier truth/results retained.',
      truthCorrections=[read(Path(x)) for x in s['corrections']],gradeAValidatedPairs=0,newRealProductionVulnerabilityTP=0,independentReview=False,
      sources=s['sources'],excludedCandidates=s['excludedCandidates'],controlledRequirements=[{k:c[k] for k in ['caseId','scenario','policy','truth','operation','oracleProbe','requirement','sourceSha256']} for c in plan['cases']],
      conditionalAuthorizationMetrics=adjudication,policyMeaning=dict(rows=policy,expectedStateMatches=sum(x['match'] for x in policy),beforeExpectedStateMatches=sum(x['beforeMatch'] for x in policy),unknownStates=sum(x['actual']=='UNKNOWN' for x in policy),scope='CONDITIONAL_DECLARATION_STATE_NOT_OPERATING_AUTHORIZATION'),
      sourceConnections=dict(requestDeclarations=sum(bool(a['authorizationEvidence'].get('requestEntry')) for a in accesses),clientDeclarations=sum(a['clientStatus']=='CLIENT_DECLARATION_LINKED' for a in accesses),writeEvidence=len(writes),runtimeRolesUnknown=sum(a['authorizationEvidence']['effectiveRole']=='UNKNOWN' for a in accesses),
         fieldOrigins=dict(Counter(v['source'] for w in writes for v in w['dataFields'])),filterOrigins=dict(Counter(v['source'] for w in writes for v in w['filters']))),
      productBefore=dict(summary=product_before['summary'],directProductDisagreements=product_before['directProductDisagreements'],
        receiptSha256=[hashlib.sha256(Path(x).read_bytes()).hexdigest() for x in s['productsBefore']]),
      product=product,publicContext=public_context(s['publicContext']),oracle=oracle,oracleRepeatedIdentically=True,regressions=read(Path(s['regressions'])),resources=read(Path(s['resources'])),tests=s['tests'],
      failureCasePack=[dict(reason=reason,cases=[row['caseId'] for row in adjudication['rows'] if row['reason']==reason],currentEvidence='See conditionalAuthorizationMetrics and product case snapshots',implementation='Known source omissions fixed in backend bridge; no field-name/intent heuristic added') for reason in sorted({row['reason'] for row in adjudication['rows'] if row['reason']})],
      sqlOmissionFailure=dict(beforeDisagreements=product_before['directProductDisagreements'],afterDisagreements=product['directProductDisagreements'],
        cause='Acquisition Coverage Ledger omissions were not forwarded to the SQL policy worker; selected policy files alone could appear complete.',
        fix='Forward supported omitted SQL as bounded NOT_RUN descriptors; preserve UNKNOWN on ambiguous or truncated inventory.',commit=s['implementationCommit'],
        detectionCountsChanged=False,riskFormulaChanged=False),
      userDatabaseModified=False,externalSqlExecuted=False,targetApplicationExecuted=False,paidAiCalls=0,evaluationRequiredUserBackendRestart=False,
      limitations=['Grade B metrics are conditional on authored roles, data requirements and controlled SQL; no HTTP/JWT/Supabase deployment breach was reproduced.',
       'RLS broad-write review candidates are not confirmed exploit findings. Shared-intent FP labels mean extra review burden against explicit requirements, not a false factual claim that the policy is broad.',
       'All known risk targets stay in the recall denominator, including unsupported private-read and protected-property meanings.',
       'Four known-normal no-alert cases have UNKNOWN policy evidence and are not verified protective TN decisions.',
       'auth.uid is a current_setting stub; limited_admin is NOBYPASSRLS with SELECT only. Every probe resets data; zero affected rows are not mutation success.',
       'External original SQL/tests were not run. Public reproduction material is not a verified production vulnerable/fixed commit pair.',
       'Authored management helper illustrates the protected-field requirement; its deployed invocation and real application privilege escalation were not verified.',
       'Paired Worker timings use identical parsed subsets, not whole-backend latency or complete SQL execution; host OS load/CPU affinity are not controlled.',
       'Actual React plus isolated H2 browser checks cover both request layouts at 1440/390/320px. Live GitHub App, operating Supabase and real AI-provider validation were not performed.'])
    write(a.output,r);print(dict(cases=len(plan['cases']),counts=adjudication['counts'],oracle=oracle['matched'],policyStateMatches=r['policyMeaning']['expectedStateMatches']))
