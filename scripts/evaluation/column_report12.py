"""Source-free, separate declaration/requirement/product authorization metrics."""
import argparse
from collections import Counter
import hashlib
from pathlib import Path
from application_track import read,write
from benchmark import stable
from authorization_truth11 import metrics as original_metrics
from column_authorization12 import freeze,BASELINE
from modern_supabase_summary import compare

def declaration(access,field):
    e=(access.get('writeEvidence') or {}).get('columnUpdate') or {}
    role=next((r for r in e.get('roles',[]) if r['role']=='authenticated'),{})
    return next((f['grant'] for f in role.get('fields',[]) if f['name']==field),'UNKNOWN')

def adjudicate(plan,engine):
    if plan!=freeze():raise ValueError('FROZEN_TRUTH_CHANGED')
    rows=[];counts=Counter()
    by_id={c['caseId']:c for c in plan['cases']}
    if len(engine['rows'])!=len(by_id) or {r['caseId'] for r in engine['rows']}!=set(by_id):raise ValueError('MISSING_ENGINE_CASES')
    for r in engine['rows']:
        c=by_id[r['caseId']]
        if c['sourceSha256']!=r['sourceSha256']:raise ValueError('SOURCE_CHANGED')
        sb=r['supabase'];a=sb['accesses'][0] if sb['accesses'] else {}
        target='public.records' if c['split'].startswith('VALIDATION') else 'public.items'
        hits=[f for f in sb['findings'] if f['table']==target and 'UPDATE' in f['operations']]
        label='UNKNOWN' if c['truth']=='UNKNOWN' else ('TP' if hits else 'FN') if c['truth']=='RISK' else ('FP' if hits else 'TN')
        counts[label]+=1;actual=declaration(a,c['field'])
        rows.append(dict(caseId=c['caseId'],split=c['split'],truth=c['truth'],sourceSha256=c['sourceSha256'],label=label,
          expectedColumnDeclaration=c['expectedColumnDeclaration'],columnDeclaration=actual,match=actual==c['expectedColumnDeclaration'],
          requestLinked=bool((a.get('authorizationEvidence')or{}).get('requestEntry')),clientLinked=a.get('clientStatus')=='CLIENT_DECLARATION_LINKED',
          rowState=(a.get('authorizationEvidence')or{}).get('state','UNKNOWN'),columnEvidence=(a.get('writeEvidence')or{}).get('columnUpdate'),
          sourceFields=(a.get('writeEvidence')or{}).get('dataFields',[]),reviewCandidates=hits,
          inspection='NOT_INSPECTED' if c['caseId'].endswith('-missing') else 'NOT_SUPPORTED' if c['config']=='inherited' or c['caseId'].endswith(('-dynamic','-opaque')) else 'ANALYZED_DECLARATION_ONLY',
          runtimeRole='UNKNOWN',
          gap='ROLE_INHERITANCE_NOT_SUPPORTED' if c['config']=='inherited' else 'DYNAMIC_FIELDS_OR_INCOMPLETE_SQL' if c['truth']=='UNKNOWN' else 'PROTECTED_REQUIREMENTS_NOT_PRODUCT_INPUTS' if label=='FN' else None))
    return dict(counts={k:counts[k] for k in ['TP','FP','FN','TN','UNKNOWN']},rows=rows,
      declarationMatches=sum(r['match'] for r in rows),declarationKnown=sum(r['columnDeclaration']!='UNKNOWN' for r in rows),
      metric='CONDITIONAL_GRADE_B_POLICY_REVIEW_NOT_PRODUCTION_VULNERABILITY_TP',
      precision=counts['TP']/(counts['TP']+counts['FP']) if counts['TP']+counts['FP'] else None,
      allKnownRiskDetection=counts['TP']/(counts['TP']+counts['FN']) if counts['TP']+counts['FN'] else None)

def product(paths,plan,direct):
    result=[];expected={r['caseId']:r for r in direct['rows']};seen=set()
    for path in paths:
        raw=read(Path(path))
        for p in raw['projects']:
            if p['projectId'] in seen or p['projectId'] not in expected or len(p.get('runs',[]))!=2:raise ValueError('PRODUCT_CASE_SET')
            seen.add(p['projectId']);a,b=p['runs']
            if stable(a)!=stable(b):raise ValueError('PRODUCT_NONDETERMINISM')
            d=expected[p['projectId']];sb=a['typescript']['supabaseAnalysis'];access=sb['accesses'][0]
            if (access.get('writeEvidence')or{}).get('columnUpdate')!=d['columnEvidence']:raise ValueError('PRODUCT_COLUMN_EVIDENCE_DIFFER')
            if sb['findings']!=d['reviewCandidates']:raise ValueError('PRODUCT_POLICY_FINDINGS_DIFFER')
            if any(not any(f['ruleId']==x['ruleId'] and f['location']==x['location'] for x in a['reviewCandidates']) for f in sb['findings']):raise ValueError('MISSING_FINAL_REVIEW_CANDIDATE')
            result.append(dict(caseId=p['projectId'],score=a['securityScore'],risk=a['risk'],coverage=a['coverage']['status'],
              finalTargetCandidates=len(sb['findings']),columnUpdate=access['writeEvidence'].get('columnUpdate'),
              rawRules=dict(Counter(f['ruleId'] for f in a['raw'])),filteredRules=dict(Counter(f['ruleId'] for f in a['filtered'])),
              elapsedMs=[x['elapsedMs'] for x in p['runs']],parentHeapUsedBytes=[x['parentHeapUsedBytes'] for x in p['runs']],repeatIdentical=True))
    if seen!=set(expected):raise ValueError('PRODUCT_CASE_MISSING')
    return result

def original_product(paths,direct):
    expected={r['caseId']:r for r in direct['rows']};rows=[]
    for path in paths:
        for p in read(Path(path))['projects']:
            if len(p.get('runs',[]))!=2 or stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('ORIGINAL_PRODUCT_REPEAT')
            r=p['runs'][0];sb=r['typescript']['supabaseAnalysis'];a=sb['accesses'][0];d=expected[p['projectId']]
            if sb['findings']!=d['allPolicyFindings'] or a['authorizationEvidence']!=d['access']['authorizationEvidence']:raise ValueError('ORIGINAL_PRODUCT_EVIDENCE_CHANGED')
            rows.append(dict(caseId=p['projectId'],policyState=a['authorizationEvidence']['state'],candidates=len(sb['findings']),score=r['securityScore'],coverage=r['coverage']['status'],repeatIdentical=True))
    if len(rows)!=36 or {r['caseId'] for r in rows}!=set(expected):raise ValueError('ORIGINAL_PRODUCT_CASES')
    return rows

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('spec',type=Path);p.add_argument('output',type=Path);a=p.parse_args();s=read(a.spec)
    plan=read(Path(s['truth']));before=adjudicate(plan,read(Path(s['before'])));after=adjudicate(plan,read(Path(s['after'])))
    db=read(Path(s['database']));repeat=read(Path(s['databaseRepeat']))
    if db['rows']!=repeat['rows'] or db['matched']!=db['total'] or db['total']!=312:raise ValueError('DATABASE_ORACLE_FAILED')
    for c in plan['configs']:
        if db['configHashes'][c['id']]!=c['sqlSha256']:raise ValueError('ORACLE_SOURCE_CHANGED')
    regression=[]
    for pair in s['regressions']:regression+=compare(read(Path(pair['before'])),read(Path(pair['after'])))
    old_plan=read(Path(s['oldTruth']));old_db=read(Path(s['oldDatabase']));old_before=original_metrics(old_plan,read(Path(s['oldBefore'])),old_db);old_after=original_metrics(old_plan,read(Path(s['oldAfter'])),old_db)
    if old_before['counts']!=old_after['counts']:raise ValueError('ORIGINAL_METRICS_CHANGED')
    product_rows=product(s['products'],plan,after)
    result=dict(schemaVersion=1,baseline=BASELINE,implementationCommit=s['implementationCommit'],worker='ts-server-v28',rowPolicyAnalyzer='supabase-rls-v3',columnAnalyzer='column-update-v1',
      truthSha256=hashlib.sha256(Path(s['truth']).read_bytes()).hexdigest(),gradeA=0,independentReview=False,newProductionVulnerabilityTP=0,
      before=before,after=after,original36=dict(before=old_before,after=old_after,product=original_product(s['oldProducts'],read(Path(s['oldAfter'])))),product=product_rows,productCoverageCounts=dict(Counter(r['coverage'] for r in product_rows)),
      regression=regression,oracle=db,oracleRepeatedIdentically=True,firstOracleReceiptSha256=hashlib.sha256(Path(s['firstDatabase']).read_bytes()).hexdigest(),
      resources=read(Path(s['resources'])),tests=s['tests'],sourceExecuted=False,externalSqlExecuted=False,userDatabaseModified=False,paidAiCalls=0,riskFormulaChanged=False,databaseMigration=False,
      failureCasePack=[dict(caseIds=[r['caseId'] for r in after['rows'] if r['label']=='TP'],
        cause='Valid column REVOKE was unsupported and invalidated the scope, hiding a broad row-policy review even though table UPDATE remained.',
        before='UNKNOWN and no matching policy review candidate',after='TABLE_GRANT declaration plus existing BROAD_ACCESS_REVIEW/REVIEW_REQUIRED/NOT_COMPARED',
        fix='Separate direct/PUBLIC table UPDATE and per-column UPDATE grants; preserve table privilege through column REVOKE and clear column grants on table REVOKE.',
        implementationCommit=s['implementationCommit'],tests='column-update.test.mjs, original 36 regression, new 36 frozen controls and isolated PostgreSQL')],
      limitations=['Grade B protected-property requirements are explicit oracle inputs, not product inputs. Field names do not determine sensitivity.',
        'Two restored candidates describe broad row-policy declarations, not new protected-property detection or confirmed HTTP privilege bypass. Application user-ID filters do not prove direct DB policy isolation.',
        'Validation uses Server Functions and renamed schema fields, but the same author and scenario family; not independent projects or blind holdout.',
        'Inherited privileges, owners/admins, grantor/column existence, deployed state and actual DB roles remain unknown. NOT_ESTABLISHED is not denial.',
        'Column SELECT/INSERT and all query prerequisites are not implemented. DELETE is not a column privilege.',
        'Two FAILED Coverage ledgers represent deliberately injected missing SQL marked LIMIT_EXCEEDED by the evaluation acquisition plan, not Worker crashes or newly exhausted execution budgets. Their Worker/RLS snapshots remain PARTIAL/UNKNOWN. Score 100 does not certify whole-project safety.',
        'The initial 288 oracle results are retained; 24 checks for the exact already-frozen broad SQL packet were added without modifying truth or sources.',
        'No new Grade A pair was acquired, no operating Supabase/HTTP attack or live GitHub App was tested. Mock provider tests do not validate a real AI model.'])
    write(a.output,result);print(dict(before=before['counts'],after=after['counts'],columnMatches=after['declarationMatches'],knownColumnDeclarations=after['declarationKnown'],oracle=db['matched'],regressionProjects=len(regression)))
