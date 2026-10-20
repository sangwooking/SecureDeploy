"""Final entry-isolation evidence. No target source is copied to the report."""
import argparse
from collections import Counter
from pathlib import Path
from application_track import read, write, outside, digest, relative
from benchmark import stable
from hardening4 import summary


def report(applications, controls, pilot, realworld, output, packs):
    applications = outside(applications)
    controls = outside(controls)
    before = read(applications / 'hardening5-after.json')
    intermediate = read(applications / 'hardening6-after.json')
    after = read(applications / 'hardening6-isolation-after.json')
    plan = read(applications / 'application-plan.json')
    plan_hash = digest((applications / 'application-plan.json').read_bytes())
    if any(r['planSha256'] != plan_hash for r in [before, intermediate, after]):
        raise ValueError('PLAN_CHANGED')
    projects = []
    for project in after['projects']:
        previous = next(p for p in before['projects'] if p['projectId'] == project['projectId'])
        middle = next(p for p in intermediate['projects'] if p['projectId'] == project['projectId'])
        source_plan = next(p for p in plan['projects'] if p['projectId'] == project['projectId'])
        for source in source_plan.get('files', []):
            path = applications / 'sources' / project['projectId'] / relative(source['path'])
            if path.is_symlink() or digest(path.read_bytes()) != source['sha256']:
                raise ValueError('SOURCE_CHANGED')
        row = dict(projectId=project['projectId'],sourceCommit=source_plan['commitSha'])
        if not project.get('runs'):
            if previous.get('runs') or middle.get('runs'):
                raise ValueError('ACQUISITION_CHANGED')
            projects.append(dict(row,status='COLLECTION_FAILED_NOT_ANALYZED'))
            continue
        if len(project['runs']) != 2 or stable(project['runs'][0]) != stable(project['runs'][1]):
            raise ValueError('REPEAT_CHANGED')
        old, mid, new = [summary(p['runs'][0]) for p in [previous, middle, project]]
        for key in ['rules', 'securityScore', 'prioritySummary', 'deploymentAssessment', 'java']:
            if old[key] != mid[key] or mid[key] != new[key]:
                raise ValueError('LEGACY_OR_POLICY_CHANGED')
        projects.append(dict(row,before=old,preIsolation=mid,after=new,repeatConsistent=True,
            elapsedMs=[r['elapsedMs'] for r in project['runs']],
            fingerprintChanged=previous['runs'][0]['engineFingerprint'] != project['runs'][0]['engineFingerprint']))
    regression = read(controls / 'regression-isolation-committed.json')
    if (regression['engineCommit'] != after['engineCommit'] or regression['split'] != 'REGRESSION'
            or not regression['previousHoldoutObserved'] or regression['workingTreeDiffSha256'] != digest(b'')
            or regression['manifestSha256'] != digest((controls / 'manifest.json').read_bytes())):
        raise ValueError('CONTROL_PROVENANCE')
    groups = {}
    for topology in sorted({c['topology'] for c in regression['cases']}):
        cases = [c for c in regression['cases'] if c['topology'] == topology]
        if any(c['before']['inputSha256'] != c['after']['inputSha256'] for c in cases):
            raise ValueError('INPUT_CHANGED')
        groups[topology] = dict(cases=len(cases),labels=dict(Counter(c['label'] for c in cases)),
            before=dict(Counter(c['beforeOutcome'] for c in cases)),after=dict(Counter(c['afterOutcome'] for c in cases)))
    benchmarks = {}
    for name, root in [('pilot', outside(pilot)), ('realworld', outside(realworld))]:
        old = read(root / 'hardening5-score-regression.json')['summary']
        new = read(root / 'hardening6-isolation-score-regression.json')['summary']
        if old != new:
            raise ValueError('BENCHMARK_REGRESSION')
        benchmarks[name] = new
    node = next(p for p in after['projects'] if p['projectId'] == 'OWASP--NodeGoat')['runs'][0]['typescript']
    findings = node.get('findings') or []
    mongo = [f for f in findings if f['ruleId'] == 'JS_MONGO_WHERE_INPUT_FLOW' and f['confidence'] == 'HIGH']
    if len(mongo) != 1 or mongo[0]['sink']['kind'] != 'MONGODB_CURSOR_TOARRAY':
        raise ValueError('MONGO_FLOW_CHANGED')
    uses = node.get('nodeUses') or []
    effects = [u for u in uses if u['kind'] == 'CONSTRUCTOR_SUMMARY_MUST']
    if not effects:
        raise ValueError('CONSTRUCTOR_PROOF_MISSING')
    followup = dict(caseId='nodegoat-nosql-query-construction',engineCommit=after['engineCommit'],
        sourceCommit=next(p['sourceCommit'] for p in projects if p['projectId'] == 'OWASP--NodeGoat'),
        status='STATIC_INPUT_TO_WHERE_AND_CURSOR_CONSUMPTION_CONFIRMED',constructorEvidence=effects,mongoEvidence=mongo,
        runtime='Installed driver, Mongo server settings, middleware, and exploit success remain unverified.',
        entryIsolation='Fresh initialized symbolic graph for each request; aliases, closures, lexical this and runtime relative require share one entry graph.',
        remaining='Actual multi-request global lifecycle and the separate fifth-module import-depth gap remain unverified.')
    packs = outside(packs)
    packs.mkdir(mode=0o700)
    write(packs / 'nodegoat-nosql-query-construction.json', followup)
    probe = regression['nodegoatRegression']
    result = dict(schemaVersion=1,stage='FINAL_AFTER_ENTRY_ISOLATION',engineCommit=after['engineCommit'],
        preIsolationEngineCommit=intermediate['engineCommit'],baselineEngineCommit=before['engineCommit'],
        sourcePlanSha256=plan_hash,projects=projects,gradeBTopologyResults=groups,
        gradeB=dict(split='REGRESSION',cases=len(regression['cases']),previousHoldoutObserved=True,
            independentOrBlind=False,manifestSha256=regression['manifestSha256'],
            casesSummary=[dict(caseId=c['caseId'],label=c['label'],topology=c['topology'],
                before=c['beforeOutcome'],after=c['afterOutcome'],inputSha256=c['after']['inputSha256']) for c in regression['cases']]),
        gradeA=dict(newSupportedPatchPairs=0),gradeC=dict(scored=False,sourceCommit=regression['gradeCScope']['sourceCommit']),
        failureCaseFollowup=followup,nodeUseKinds=dict(Counter(u['kind'] for u in uses)),benchmarks=benchmarks,
        performanceObservation={stage:{k:probe[stage].get(k) for k in ['wallMs','maximumRssBytes']} for stage in ['before','after']},
        limitsChanged=False,riskChanged=False,scoreChanged=False,databaseMigration=False,historicalSnapshotsRecomputed=False,
        protocol='ts-server-v10',comparison='Analyzer version/fingerprint differ; structural candidates remain REVIEW_REQUIRED and NOT_COMPARED.',
        validation=dict(backendTests=513,backendPassed=506,backendSkipped=7,typescriptTests=164,frontendTests=105,
            pythonTests=110,evaluationTools=95,frontendBuild='PASS',browserWidths=[1440,390,320],
            commonInputs='Real ZIP/H2 snapshot/detail/access isolation; public/private GitHub acquisition mocked.',
            livePrivateGithub='NOT_RUN',backendRestart='v10; protected environment preserved; schema validate'),
        limitations=['State isolation removes analysis-order contamination, not actual cross-request global-state vulnerabilities.',
            'Single timing/RSS samples are observations, not guarantees; copy work consumes unchanged step/time/heap limits.',
            'Only five of 17 controlled cases yield TP/TN; UNKNOWN and NOT_INSPECTED are not safety or zero missed vulnerabilities.',
            'Previously observed held-out cases are now regression. No newly independent external holdout or Grade A supported pair.',
            'Strict constructor summaries are immediate-effect proof only; arbitrary DI/factories/prototypes/asynchrony remain unsupported.',
            'Pilot six false alerts and CVE fourteen unsupported/two resource-limited cases remain.'],
        safety=dict(targetExecution=False,targetInstall=False,targetMutation=False,userDatabaseEvaluationWrites=False,
            paidAiCalls=0,externalVulnerabilityLookups=0,originalSourcesInGit=False,permissionDenials=0))
    write(output, result)
    print(dict(stage=result['stage'],projects=len(projects),controls=len(regression['cases']),
        nodegoatMongoCandidates=len(mongo),nodeUseKinds=result['nodeUseKinds']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['applications', 'controls', 'pilot', 'realworld', 'output', 'packs']:
        parser.add_argument(name)
    report(**vars(parser.parse_args()))
