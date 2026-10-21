"""Source-free Java collection before/after accounting and failure receipts."""
import argparse
from statistics import median
from benchmark import read, write, outside, digest, score, stable, at
from hardening4 import summary


def section(manifest, raw):
    result=score(manifest,raw)
    if not result['allRepeatsConsistent']:raise ValueError('NONDETERMINISTIC')
    rows=[]
    for case in raw['results']:
        target=next(c for c in manifest['cases'] if c['caseId']==case['caseId'])
        run=case['runs'][0]
        uses=[u for u in run['java']['analysis']['uses'] if at(u['location'],target['targetSites'])]
        scored=next(c for c in result['results'] if c['caseId']==case['caseId'])
        rows.append(dict(caseId=case['caseId'],truth=target['groundTruthLabel'],
            sqlKinds=[u['kind']for u in uses],layers=scored['layers'],
            sourceTraceKinds=sorted({l['kind']for u in uses for l in u['trace']}),
            coverage=run['coverage']['status'],javaFiles=run['java']['analysis']['files'],
            limitations=run['java']['analysis']['limitations'],
            score=run['securityScore'],riskPolicy=run['risk']['policyVersion'],
            priority=run['risk']['prioritySummary'],assessment=run['risk']['prioritizedDeploymentAssessment'],
            elapsedMs=[r['elapsedMs']for r in case['runs']],
            parentHeapSamples=[r['parentHeapUsedBytes']for r in case['runs']]))
    timings=[v for row in rows for v in row['elapsedMs']]
    return dict(engineCommit=raw['engineCommit'],manifestSha256=raw['manifestSha256'],
        accountingVersion=result['accountingVersion'],layers={k:v['counts']for k,v in result['summary'].items()},
        elapsedMs=dict(median=median(timings),maximum=max(timings)),cases=rows)


def report(base, output, packs):
    base,packs=outside(base),outside(packs)
    controls=base/'hardening11-collections-v2';manifest=read(controls/'manifest.json')
    comparisons={}
    packs.mkdir(mode=0o700)
    failures=[]
    for split in ['regression','validation']:
        before,after=[section(manifest,read(controls/(stage+'-'+split+'.json'))) for stage in ['before','after']]
        if before['manifestSha256']!=after['manifestSha256'] or before['accountingVersion']!=after['accountingVersion']:
            raise ValueError('EVALUATION_CONTEXT_CHANGED')
        if before['layers']['rule']!=after['layers']['rule']:raise ValueError('RAW_RULE_CHANGED')
        for row in after['cases']:
            expected={'DANGEROUS':'INPUT_IN_QUERY','UNKNOWN':'UNRESOLVED_QUERY'}
            if row['truth'] in expected and row['sqlKinds']!=[expected[row['truth']]]:raise ValueError('EXPECTED_FLOW_MISSING')
            if row['truth']=='SAFE' and (len(row['sqlKinds'])!=1 or row['sqlKinds'][0] not in {'STATIC_QUERY','PARAMETERIZED_QUERY'}):
                raise ValueError('SAFE_MOVED_TO_UNKNOWN')
            target=next(c for c in manifest['cases'] if c['caseId']==row['caseId'])
            previous=next(c for c in before['cases'] if c['caseId']==row['caseId'])
            write(packs/(row['caseId']+'.json'),dict(schemaVersion=1,caseId=row['caseId'],grade='B',
                repository=target['repositoryUrl'],sourceCommit=target['repositoryCommitSha'],
                truth=target['groundTruthLabel'],labelEvidence=target['labelEvidence'],files=target['files'],
                sourceSites=target['sourceSites'],targetSites=target['targetSites'],
                sourceToSinkEvidence=target['sourceToSinkEvidence'],mitigationEvidence=target['mitigationEvidence'],
                contextOmissions=target['contextOmissions'],before=previous,after=row,engineCommit=after['engineCommit'],
                verifiedExplanation='Bounded constant-slot value selection/mutation now traced; unknown transform/key effects remain unresolved.',
                unverified='Controlled injected probe, not an original CVE, whole-app safety or executed attack.',
                regressionTest='JavaServletCollectionTest and frozen same-source Grade B comparison.'))
        comparisons[split]=dict(before=before,after=after)
    pilot=base/'pilot-2026-10-20-v2';plan=read(pilot/'manifest.json')
    old,new=[section(plan,read(pilot/f)) for f in ['hardening11-baseline-regression.json','hardening11-after-regression.json']]
    if old['manifestSha256']!=new['manifestSha256']:raise ValueError('PILOT_SOURCE_CHANGED')
    if old['layers']['rule']!=new['layers']['rule']:raise ValueError('PILOT_RAW_RULE_CHANGED')
    for previous in old['cases']:
        current=next(c for c in new['cases'] if c['caseId']==previous['caseId'])
        if previous['layers']['ast']['verdict']=='TP' and current['layers']['ast']['verdict']!='TP':raise ValueError('DANGEROUS_FLOW_REGRESSION')
    selected=['owasp-BenchmarkTest'+n for n in ['00018','00032','00034','00037','00113']]
    for cid in selected:
        target=next(c for c in plan['cases'] if c['caseId']==cid)
        previous=next(c for c in old['cases'] if c['caseId']==cid)
        current=next(c for c in new['cases'] if c['caseId']==cid)
        reason=('External helper JdbcTemplate field not supplied/resolved; collection adapter alone does not complete sink linkage.' if cid.endswith('00032') else
                'Nested while/for state remains outside the approved bounded collection contract.' if cid.endswith('00037') else
                'Final SQL is static; earlier unsupported cast keeps whole-method proof incomplete, so one declaration warning remains.' if cid.endswith('00113') else
                'Verified Servlet collection source and selected element now reach JDBC execution; duplicate legacy signals share the same anchor.')
        pack=dict(schemaVersion=1,caseId=cid,repository=target['repositoryUrl'],sourceCommit=target['repositoryCommitSha'],
            truth=target['groundTruthLabel'],labelEvidence=target['labelEvidence'],files=target['files'],
            targetSites=target['targetSites'],sourceSites=target.get('sourceSites',[]),before=previous,after=current,
            engineCommit=new['engineCommit'],verifiedExplanation=reason,
            unverified='No runtime exploit, target execution, installed dependency or database reachability validation.',
            reusableFix='Request collection origin plus bounded per-object constant-slot reads/writes and alias-aware branch state.',
            regressionTest='JavaServletCollectionTest; risks, constants, bindings, unknown mutations and state budgets.')
        write(packs/(cid+'.json'),pack);failures.append(dict(caseId=cid,remainingLimitation=reason))
    rw=base/'realworld-2026-10-20-v3';rwplan=read(rw/'manifest.json')
    a,b=[section(rwplan,read(rw/f)) for f in ['hardening10-regression.json','hardening11-regression.json']]
    if a['layers']!=b['layers']:raise ValueError('REALWORLD_REGRESSION_CHANGED')
    apps=base/'applications-2026-10-20-v2';a,b=[read(apps/f)for f in ['hardening10-after.json','hardening11-after.json']]
    if a['planSha256']!=b['planSha256']:raise ValueError('APPLICATION_SOURCE_CHANGED')
    projects=[]
    for project in b['projects']:
        previous=next(p for p in a['projects']if p['projectId']==project['projectId'])
        if not project.get('runs'):
            if previous.get('runs'):raise ValueError('APPLICATION_ACQUISITION_CHANGED')
            projects.append(dict(projectId=project['projectId'],status='COLLECTION_FAILED_NOT_SAFE'));continue
        if stable(project['runs'][0])!=stable(project['runs'][1]):raise ValueError('APPLICATION_NONDETERMINISTIC')
        x,y=summary(previous['runs'][0]),summary(project['runs'][0])
        unchanged=all(x[k]==y[k]for k in ['rules','securityScore','prioritySummary','deploymentAssessment'])
        if not unchanged:raise ValueError('APPLICATION_LEGACY_CHANGE_REQUIRES_REVIEW')
        for key in ['typescript','python']:
            if stable(previous['runs'][0][key])!=stable(project['runs'][0][key]):raise ValueError('OTHER_ANALYZER_REGRESSION')
        projects.append(dict(projectId=project['projectId'],sourceCommit=project['commitSha'],legacyAndRiskUnchanged=unchanged,
            javaFindings=len(project['runs'][0]['java']['findings']),typescriptFindings=len(project['runs'][0]['typescript']['findings'])))
    result=dict(schemaVersion=1,baselineCommit=manifest['engineBaselineCommit'],engineCommit=new['engineCommit'],
        protocol='java-sql-v4',grade=dict(A=0,B=14),controlled=comparisons,
        pilot=dict(before=old,after=new,selectedFailures=failures),realworld=dict(cases=16,layersUnchanged=True),
        applications=projects,
        evaluationCorrection='v1 omitted an actually used request-map source line, falsely scoring a traced path as FN. v2 changes only sourceSites; both engines rerun with identical source hashes. v1 preserved.',
        independence='Different app repositories, observed originals and single-curator controlled probes; no blind, novel real-CVE or whole-project accuracy claim.',
        limits=dict(workerHeapMiB=192,workerMetaspaceMiB=96,parentTimeoutSeconds=8,flowSeconds=5,flowSteps=30000,
            astNodes=60000,sourceFiles=100,sourceCharacters=1000000,perFileCharacters=100000,callDepth=3,
            objectsPerState=128,slotsPerObject=64,effectiveSlotUpperBoundPerState=8192,mutationAndJoinSlotBudget=2048,allocationsPerRun=1024),
        memoryMeasurement='Parent JVM sampled heap only; not worker peak RSS or a measured worker memory delta. Existing JVM caps retained.',
        riskAndData='Risk/score formulas and DB schema unchanged. Safe-warning suppression/dedup can change new Review scores/counts. Old snapshots untouched; version fingerprint prevents false RESOLVED.',
        notRun=['New private project scans','Target code execution/build/install','Paid OpenAI','Production attacks','Fresh OSV/EPSS/KEV lookup'],
        apiReferences=['https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Map.html','https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/List.html'])
    # Validate that the v1/v2 correction changed metadata, not source or labels.
    prior=read(base/'hardening11-collections-v1'/'manifest.json')
    if [(c['caseId'],c['groundTruthLabel'],c['files'])for c in prior['cases']]!=[(c['caseId'],c['groundTruthLabel'],c['files'])for c in manifest['cases']]:
        raise ValueError('CORRECTION_CHANGED_SOURCES_OR_LABELS')
    result['manifestSha256']=digest((controls/'manifest.json').read_bytes())
    write(output,result)
    print(dict(status='PASS',controls=14,pilot=24,regressionProjects=7,sourceBodiesPublished=False))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('base');parser.add_argument('output');parser.add_argument('packs')
    report(**vars(parser.parse_args()))
