"""Post-score factual audit. Never changes frozen labels, scope or primary counts."""
import argparse
import copy
from collections import Counter
from pathlib import Path
from benchmark import read,write,digest


def audit(root):
    primary=read(root/'report.json');raw=read(root/'results.json');receipt=read(root/'pre-run-receipt.json')
    if raw['engineCommit']!=primary['engineCommit']or raw['planSha256']!=primary['planSha256']:raise ValueError('PRIMARY_MISMATCH')
    rows={p['projectId']:p['runs'][0]for p in raw['projects']}
    sessions=[];misses=[]
    for c in primary['caseResults']:
        snapshot=rows[c['projectId']]['typescript']['supabaseAnalysis']
        if c.get('uncertaintyDimension')=='AUTH_SESSION':
            source='supabase/functions/freeze-policy-links/index.ts'if c['framework']=='EDGE'else'app/api/freeze/policy-links/route.ts'
            matches=[a for a in snapshot['accesses']if a.get('table')==c['table']and a['location']['filePath']==source]
            if len(matches)!=1:raise ValueError('EXACT_SESSION_ACCESS_REQUIRED')
            e=matches[0].get('authorizationEvidence')or{}
            table=next(t for t in snapshot['tables']if t['table']==c['table'])
            operation=next(o for o in table['operations']if o['role']==c['role']and o['operation']==c['operation'])
            actual=dict(policyState=operation['state'],authStatus=e.get('authStatus'),effectiveRole=e.get('effectiveRole'))
            sessions.append(dict(caseId=c['caseId'],frozenOutcome=c['outcome'],primaryObservedDimensions=c['observedDimensions'],
                auditedObservedDimensions=actual,sessionCorrectlyUnverified=actual['authStatus']=='SESSION_READ_UNVERIFIED'and actual['effectiveRole']=='UNKNOWN',
                metadataLookupIssue=c['observedDimensions'].get('authStatus')is None,
                assessment='Composite expectation still fails when policyState is UNKNOWN; this is not authenticated access or unsafe certainty.'))
        if c['outcome']=='FN':
            table=next(t for t in snapshot['tables']if t['table']==c.get('table'))
            misses.append(dict(caseId=c['caseId'],ruleId=c['targetRule'],filePath=c['targetFile'],line=c['targetLine'],
                table=c['table'],rlsState=table['rls'],limitations=table['limitations'],
                observation='Explicit grant and broad policy parsed, no final review candidate; scope remains UNKNOWN.',
                codeCause='rls.mjs sets scope unknown if any migration filename does not match 14-digit timestamp prefix; unknown scope affects later table finalization.',
                classification='Frozen FN retained. Conservative analyzer abstention is not application protection, a safe result or proof of exploitation.',
                nextCheck='Define accepted migration ordering contract and expose its exact unsupported reason; do not infer ordering or weaken unknown states to force TP.'))
    result=copy.deepcopy(primary)
    result.update(primaryReportSha256=digest((root/'report.json').read_bytes()),rawResultsSha256=digest((root/'results.json').read_bytes()),
        preRunReceipt=receipt,auditEvaluatorSha256=digest(Path(__file__).read_bytes()),
        frozenCountsUnchanged=True,sessionEvidenceAudit=sessions,failureCasePack=misses,
        reviewSignalLayers=dict(structuralTruePositives=sum(c['outcome']=='TP'and bool(c['structuralCandidates'])for c in primary['caseResults']),
            ruleTruePositives=sum(c['outcome']=='TP'and bool(c['ruleSignals'])for c in primary['caseResults'])),
        primaryScorerMetadataIssue='Next session lookup used an Edge-only path substring. Correct fields are recorded here, without changing the primary outcome or counts; policy UNKNOWN still fails the composite expectation.',
        recommendation='CONDITIONAL_GO',
        decisionMeaning='Bounded-core continuation only; not final freeze approval, public deployment approval or a passed acceptance suite.',
        freezeConditions=[
            'Approve exact bounded core contract; Next RLS with unverified migration order remains Preview/UNKNOWN. Frozen FN2 remain reported, not rescored.',
            'Before user release, Risk/UI must prevent score/READY/confidence from claiming whole-app safety and surface supplemental candidates plus incomplete scope.',
            'Resolve or explicitly reject nonstandard migration-order support, with precise per-file/scope diagnostics; repeat these frozen targets before calling RLS readiness complete.',
            'Complete a separately bounded live SCA verification or clearly retain unverified lookup status; these six cases remain NOT_INSPECTED.',
            'Before applying edits, acquire exact source revision and file hashes, byte ranges/context anchors and explicit retention consent; current evidence is navigation-only.'],
        noAutomaticFreezeOrPolicyChange=True,
        evidenceReadiness=dict(navigationLocations=True,traceOrPolicyLocations='PARTIAL',perFileHashInProductionFinding=False,
            sourceRecovery='GitHub exact commit plus reauthorization; ZIP reupload or explicit encrypted expiring session retention required',
            patchApplicationReady=False),
        supportContract={
            'ReactViteSupabaseEdge':{'exposure':'VALIDATED_FLOW: supported request/header/private environment to recognized response/log sinks; four normal absence paths lack exact persisted negative proof',
                'ssrf':'VALIDATED_FLOW: bounded initial destination control; not redirects/DNS/reachability',
                'supabaseRls':'STRUCTURAL/PARTIAL_FLOW: supported client origin and policy declarations; not actual identity, DB role or deployed policy',
                'html':'PATTERN_ONLY plus narrow passive-static negative proof; not general DOM taint or sanitizer verification',
                'keys':'STRUCTURAL source/name/format hints, not effective privileges',
                'sca':'Static identity/version extraction plus existing lookup implementation; live lookup not run in this study',
                'deployment':'STRUCTURAL configuration declarations, not runtime deployment validation',
                'authOwnership':'PARTIAL/UNKNOWN: identity/session calls and declarations, not successful authentication or object authorization'},
            'NextAppRouterSupabase':'PREVIEW: supported 13.2-16 version declarations, route handlers and bounded server functions; middleware/action invocation/bundles unverified; RLS ordering gap retained',
            'Legacy':'Existing bounded Express, Java/Spring and Django contracts retained by regressions; no new whole-framework accuracy claim'},
        studyExecutionHistory={'infrastructureFailureAttempts':1,'unscoredRetiredBatch':1,
            'retiredReason':'Raw location.hash encoding weakened HTML risk ground truth; batch never opened/scored, corrected query dataset frozen before primary results',
            'primaryRunsPerProject':2,'bestRunSelection':False,'externalIndependentReviewer':False,
            'secondaryReview':'Same-model read-only ground-truth and readiness review'},
        versionReceipt={'typescript':'ts-server-v16','python':'py-django-v8','java':'java-sql-v4','htmlContext':'string-context-v5','supabase':'supabase-rls-v1','risk':'risk-v1.2',
            'ruleTree':'b0c773f492736d5cb324e7e1a550eebefb557502'},
        analysisFingerprints=sorted({r['engineFingerprint']for p in raw['projects']for r in p['runs']if 'engineFingerprint'in r}))
    assert result['counts']==primary['counts']
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args();result=audit(args.root);write(args.output,result)
    print({'recommendation':result['recommendation'],'countsUnchanged':True,
        'sessionChecks':[s['sessionCorrectlyUnverified']for s in result['sessionEvidenceAudit']]})
