"""Public evidence summary. Original application/CVE source stays outside Git."""
import argparse
from collections import Counter
from pathlib import Path
from application_track import read, write, outside, digest, relative
from benchmark import stable
from hardening4 import summary

BASELINE='186c186674ae4c4ab884e1dee82e4f11053ad328'

def report(root,external,pilot,realworld,output,packs):
    root=outside(root);external=outside(external);packs=outside(packs)
    before=read(root/'hardening4-after.json');after=read(root/'hardening5-after.json')
    plan=read(root/'application-plan.json');plan_hash=digest((root/'application-plan.json').read_bytes())
    if before['planSha256']!=plan_hash or after['planSha256']!=plan_hash:raise ValueError('PLAN_CHANGED')
    old={p['projectId']:p for p in before['projects']};rows=[]
    for project in after['projects']:
        ident=project['projectId'];prior=old[ident]
        original=next(p for p in plan['projects']if p['projectId']==ident)
        for entry in original.get('files',[]):
            path=root/'sources'/ident/relative(entry['path'])
            if path.is_symlink()or digest(path.read_bytes())!=entry['sha256']:raise ValueError('SOURCE_CHANGED')
        row=dict(projectId=ident,commitSha=original['commitSha'])
        if not project.get('runs'):
            if prior.get('runs'):raise ValueError('ACQUISITION_CHANGED')
            rows.append(dict(row,status='COLLECTION_FAILED_NOT_ANALYZED'));continue
        if len(project['runs'])!=2 or stable(project['runs'][0])!=stable(project['runs'][1]):raise ValueError('REPEAT_CHANGED')
        b=summary(prior['runs'][0]);a=summary(project['runs'][0])
        for field in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
            if b[field]!=a[field]:raise ValueError('UNEXPECTED_RULE_RISK_OR_JAVA_CHANGE')
        rows.append(dict(row,before=b,after=a,elapsedMs=[r['elapsedMs']for r in project['runs']],
            comparisonFingerprintChanged=prior['runs'][0]['engineFingerprint']!=project['runs'][0]['engineFingerprint']))
    pilot=outside(pilot);realworld=outside(realworld)
    regressions={}
    for name,directory in [('pilot',pilot),('realworld',realworld)]:
        b=read(directory/'hardening4-score-regression.json')['summary'];a=read(directory/'hardening5-score-regression.json')['summary']
        if b!=a:raise ValueError('REGRESSION_CHANGED')
        regressions[name]=a
    probe=read(external/'probe-committed.json')
    if probe['engineHead']!=after['engineCommit']:raise ValueError('ENGINE_CHANGED')
    receipt=read(external/'verified/receipt.json')
    public_probe=[]
    for row in probe['rows']:
        stages={}
        if row['before']['inputSha256']!=row['after']['inputSha256']:raise ValueError('PROBE_INPUT_CHANGED')
        for name in ['before','after']:
            stage=row[name]
            stages[name]={**stage,'fileStatuses':dict(Counter(f['parseStatus']for f in stage['files']))}
        public_probe.append(dict(project=row['project'],sourceCommit=row['sourceCommit'],**stages))
    node=next(row for row in rows if row['projectId']=='OWASP--NodeGoat')
    followup=dict(originalPackCaseId='nodegoat-nosql-query-construction',previousMilestone=BASELINE,
        engineCommit=after['engineCommit'],sourceCommit=node['commitSha'],status='UNKNOWN_CALL_DEPTH_BOUNDARY_REMAINS',
        confirmedCause=['Cached exports were rejected before a depth check; cache order corrected.',
            'The nested DAO constructor then reaches the unchanged max call depth of three; mutation freedom is not proven.',
            'File-wide limitation notes also incorrectly invalidated independent calls; per-call identity effects replace them in Node mode.'],
        verifiedChange='Supported constructor/field/alias/helper-return paths retain library origin; unknown escapes and branch effects invalidate aliases.',
        before=node['before']['typescript'],after=node['after']['typescript'],
        externalOutcome='Mongoose populate API unsupported; mongo-express candidate pair lacks confirmed source-level fix truth. No general accuracy claim.')
    packs.mkdir(mode=0o700);write(packs/'nodegoat-nosql-query-construction.json',followup)
    result=dict(schemaVersion=1,baselineMilestone=BASELINE,engineCommit=after['engineCommit'],sourcePlanSha256=plan_hash,
        projects=rows,probe=public_probe,externalSourceReceipt=receipt,failureCaseFollowup=followup,regression=regressions,
        externalGroundTruth=[dict(repository='Automattic/mongoose',cve='CVE-2024-53900',cwe='CWE-943',license='MIT; LICENSE.md acquired',
            source='https://github.com/advisories/GHSA-m7xq-9374-9rvx',fix='c9e86bff7eef477da75a29af62a06d41a835a156',
            parent='b34aba65bd64540e330665477f542eb79c877909',truth='PATCH_AND_ADDED_TESTS_CONFIRMED_FOR_NARROW_CHANGE',
            scope='Populate match restriction; does not establish full application safety or later bypass protection.',
            result='NOT_SUPPORTED; two library files parsed, large test exceeds per-file cap. Neither TN nor successful detection.'),
        dict(repository='mongo-express/mongo-express',cve='CVE-2020-24391',license='MIT declared in package.json; no standalone license acquired',
            source='https://securitylab.github.com/advisories/GHSL-2020-131-mongo-express/',
            testedRelease='7d365141deadbd38fa961cd835ce68eab5731494',reportedFix='3a26b079e7821e0e209c3ee0cc2ae15ad467b91a',
            rejectedParent='5fabde9b0893ca4c7835cb29fbf7fb3576fdf947',truth='CANDIDATE_PAIR_EXCLUDED_FROM_GROUND_TRUTH',
            reason='Linked commit only changes version/history; immediate parent and acquired release use a parser wrapper. Dependency internals/fix causality not established.',
            result='NOT_SUPPORTED_ACQUIRED_SUBSET; zero confirmed entries is not a true negative.')],
        independentEvaluation='One source-level library patch pair verified; second candidate excluded from truth. Neither provides supported Express danger/safe accuracy evidence. Observed, not blind.',
        syntheticEvaluation=dict(subcases=15,expectedDanger=4,expectedNormal=3,expectedUncertain=8,unexpectedConfirmed=0,missedExpectedConfirmed=0,
            interpretation='Development regressions, not independent evaluation or whole-engine precision/recall.'),
        officialExpressCause='Two examples require their self-package via ../../; package implementation was not acquired. Missing evaluation context, not a proven routing defect or TN.',
        policy=dict(riskChanged=False,scoreChanged=False,databaseMigration=False,historicalSnapshotsRecomputed=False,
            protocol='ts-server-v8',newCandidates='REVIEW_REQUIRED/NOT_COMPARED',resourceLimitsChanged=False),
        validation=dict(backendTests=513,backendPassed=506,backendSkipped=7,typescriptTests=150,pythonTests=110,
            frontendTests=104,frontendBuild='PASS',browserWidths=[1440,390,320],evaluationToolTests=90,
            commonPaths='Actual ZIP/H2 snapshot/detail/access tests; public/private GitHub acquisition mocked.',livePrivateGithubE2E='NOT_RUN'),
        safety=dict(targetExecution=False,targetInstall=False,targetMutation=False,userDatabaseEvaluationWrites=False,
            externalVulnerabilityQueries=0,paidAiCalls=0,permissionDenials=0,sourceBodiesInGit=False),
        limits=['No general constructor summaries; nested constructors can exhaust existing depth.',
            'Mongo API contracts unchanged: declared 2.x callback Db and limited 3-6 client/db/collection.',
            'Actual installed driver, database server-side JavaScript, middleware and runtime exploitability unverified.',
            'Dynamic factories, ambiguous branches, mutable external code, NestJS and Next.js remain unsupported or unknown.',
            'Pilot six false alerts and CVE regression unsupported/resource limits remain; other holdout splits not rerun.',
            'Single time/RSS samples do not demonstrate general performance. No supported independent external TP/TN pair yet.'])
    write(output,result)
    print(dict(projects=len(rows),verifiedExternalSourcePatchPairs=1,excludedCandidatePairs=1,riskPolicyChanged=False))

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ['root','external','pilot','realworld','output','packs']:parser.add_argument(name)
    report(**vars(parser.parse_args()))
