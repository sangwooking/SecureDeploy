"""Source-free closeout receipt; preserve the first frozen study verbatim."""
import argparse
from pathlib import Path
from benchmark import read,write,digest,stable


def freeze_checks(report):
    counts=report['counts'];checks=report['acceptanceChecks']
    return dict(noScoredFalsePositive=counts.get('FP',0)==0,noScoredFalseNegative=counts.get('FN',0)==0,
        coreRisksDetected=checks.get('everySupportedCoreRiskDetected') is True,
        uncertaintyPreserved=checks.get('allUncertaintyChecksPassed') is True,
        repeatsConsistent=checks.get('repeatConsistencyPassed') is True)


def audit(root,application_root):
    before=read(root/'report.json');after=read(root/'closeout-report.json')
    if before['groundTruthSha256']!=after['groundTruthSha256'] or before['planSha256']!=after['planSha256']:
        raise ValueError('FROZEN_INPUT_CHANGED')
    raw=read(root/'closeout-results.json')
    if raw['engineCommit']!=after['engineCommit']:raise ValueError('ENGINE_MISMATCH')
    old_apps=read(application_root/'freeze-final-regression.json')
    new_apps=read(application_root/'freeze-closeout-regression.json')
    if old_apps['planSha256']!=new_apps['planSha256']:raise ValueError('APPLICATION_INPUT_CHANGED')
    originals={p['projectId']:p for p in old_apps['projects']};apps=[]
    for p in new_apps['projects']:
        old=originals[p['projectId']]
        if p['commitSha']!=old['commitSha'] or len(p['runs'])!=2 or stable(p['runs'][0])!=stable(p['runs'][1]):
            raise ValueError('APPLICATION_IDENTITY_OR_REPEATS')
        a,b=old['runs'][0],p['runs'][0]
        unchanged={key:stable(a[key])==stable(b[key]) for key in ['raw','filtered','reviewCandidates','securityScore','sca']}
        unchanged['riskPriorities']=a['risk']['prioritySummary']==b['risk']['prioritySummary']
        s=b['typescript']['supabaseAnalysis']
        apps.append(dict(projectId=p['projectId'],commitSha=p['commitSha'],unchanged=unchanged,
            elapsedMs=[r['elapsedMs']for r in p['runs']],parentHeapUsedBytes=[r['parentHeapUsedBytes']for r in p['runs']],
            sqlStatusCounts={status:sum(f['status']==status for f in s['files'])for status in sorted({f['status']for f in s['files']})},
            clients=len(s['clients']),accesses=len(s['accesses']),coverage=b['coverage']['status']))
    previous={c['caseId']:c for c in before['caseResults']}
    changes=[dict(caseId=c['caseId'],before=previous[c['caseId']]['outcome'],after=c['outcome'])
        for c in after['caseResults']if previous[c['caseId']]['outcome']!=c['outcome']]
    if not all(all(a['unchanged'].values())for a in apps):raise ValueError('APPLICATION_SIGNAL_REGRESSION')
    return dict(schemaVersion=1,engineCommit=after['engineCommit'],baselineEngineCommit=before['engineCommit'],
        primaryReportSha256=digest((root/'report.json').read_bytes()),groundTruthSha256=before['groundTruthSha256'],
        planSha256=before['planSha256'],comparisonReport=after,originalCounts=before['counts'],changes=changes,
        applicationRegressions=apps,originalRawSha256=digest((root/'results.json').read_bytes()),
        comparisonRawSha256=digest((root/'closeout-results.json').read_bytes()),
        contractSources=[
            'https://supabase.com/docs/guides/deployment/database-migrations',
            'https://github.com/supabase/cli/blob/7e3035c644f4528833dd7a6a992535ded7158a8f/apps/cli-go/pkg/migration/file.go',
            'https://github.com/supabase/cli/blob/7e3035c644f4528833dd7a6a992535ded7158a8f/apps/cli-go/pkg/migration/list.go',
            'https://google.github.io/osv.dev/api/'],
        migrationContract=dict(generatedTimestamp='14 digits recommended by CLI generation',
            acceptedStaticOrder='Numeric version prefix, lexical directory order, unique version; repository declarations only',
            customManifestOrScriptOrder='NOT_INTERPRETED; no script execution or inferred custom application order',
            unknown='Unrecognized filenames, duplicate versions, omitted SQL, dynamic effects, legacy init skip or ambiguous sources',
            declarationEvidence='Parsed policy bodies/locations retained under UNKNOWN, no final broad-write candidate. DROP/ALTER/revoke evaluated only within the accepted bounded order.',
            liveDatabase='NOT_VERIFIED; no migration execution, role inheritance or effective user proof'),
        htmlContract='Closed static HTML only, intrinsic passive container, quoted absolute HTTPS href only; no other anchor attributes, entities, backslashes, credentials, nested anchors or dynamic input. Not a general sanitizer.',
        confidenceContract=dict(confidenceScope='SINK_PATTERN',sourceLink='NOT_ESTABLISHED',defense='NOT_VERIFIED',runtime='NOT_VERIFIED',
            uiRequirement='HIGH/LOW describes pattern confidence and FPR, not proven exploitability or verified absence of defense.'),
        liveOsvReceipt=dict(executed=True,requests=6,identities=3,advisories=5,
            evidenceSource='Recorded opt-in FreezeOsvSmokeTest run on 2026-10-22, not a network call by this audit tool',
            packages=['npm:lodash@4.17.20','npm:is-number@7.0.0','npm:securedeploy-nonexistent-smoke-package-20261022@1.0.0'],
            assertions=['Named lodash advisory returned','is-number empty response','nonexistent identity empty response does not validate package existence',
                'ScaResult JSON snapshot round-trip','Captured responses replayed with identical status, summary and advisories'],
            failureValidation='Mock socket timeout, connection failure, HTTP400, invalid JSON and unavailable detail; no network fault injection',
            persistence='Live result JSON round-trip in memory; existing H2 integration covers saved Review/SCA snapshots with Mock provider, not live database persistence',
            scope='Separate from 60-case study: its six SCA cases remain NOT_INSPECTED; no SCA-wide accuracy claim'),
        additionalVariants=dict(risk=3,normal=4,unknown=6,unexpectedWarningsOrMissedDeclaredCandidates=0,
            independence='Same-curator follow-up regression variants, not external validation or blind holdout'),
        riskUiHandoff=['Display legacy rule score separately from structural review candidates and coverage.',
            'Score 100, READY and Risk calculation COMPLETE never certify uninspected code, RLS or SCA.',
            'Separate source/sink proof, pattern confidence, verified defense, unknown auth/ownership and runtime verification.',
            'Show resource/unsupported/external failure states; keep version changes NOT_COMPARED, never auto-RESOLVED.',
            'Before edits: exact revision, raw-byte file hash, range/context/semantic anchor, stale-source rejection and source recovery consent.'],
        engineScopeChecks=freeze_checks(after),
        recommendation='GO_FOR_ENGINE_SCOPE_FREEZE'if all(freeze_checks(after).values())else'CONDITIONAL_FREEZE',
        decisionScope='Bounded React/Vite + Supabase Edge core; Next App Router + Supabase Preview; legacy bounded contracts retained. Not public release approval, whole-app safety or externally independent accuracy.',
        remaining=['CopyMonster Auth.tsx:241 retained, not proven safe','CopyMonster SQL 62 NOT_RUN retained',
            'Four exposure normal targets lack exact persisted negative evidence','General DOM/file upload/ORM and live Supabase authorization unsupported or unverified',
            'No new Grade A vulnerable/fixed pair; the 60 observed cases are Regression from now on',
            'Live product ZIP/GitHub E2E not performed; common pipeline/API tests and browser Mock only',
            'Parent heap samples are not worker peak RSS; existing 192 MiB Node cap and other limits unchanged'],
        policyChanges=False,userPostgresModified=False,dbMigration=False)


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('application_root',type=Path);p.add_argument('output',type=Path)
    a=p.parse_args();result=audit(a.root,a.application_root);write(a.output,result)
    print({'recommendation':result['recommendation'],'changedTargets':len(result['changes']),'applicationRegressions':len(result['applicationRegressions'])})
