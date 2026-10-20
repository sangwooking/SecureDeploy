"""Summarize fixed application and Grade B evidence, without original source."""
import argparse
from collections import Counter
from pathlib import Path
from application_track import read,write,outside,digest,relative
from benchmark import stable
from hardening4 import summary

BASELINE='b59bc764d872629112b7075ecc86bc6b71a201e7'

def report(applications,controls,pilot,realworld,output,packs):
    applications=outside(applications);controls=outside(controls);packs=outside(packs)
    before=read(applications/'hardening5-after.json');after=read(applications/'hardening6-after.json')
    plan=read(applications/'application-plan.json');plan_hash=digest((applications/'application-plan.json').read_bytes())
    if before['planSha256']!=plan_hash or after['planSha256']!=plan_hash:raise ValueError('PLAN_CHANGED')
    old={p['projectId']:p for p in before['projects']};projects=[]
    for p in after['projects']:
        original=next(o for o in plan['projects']if o['projectId']==p['projectId'])
        for f in original.get('files',[]):
            source=applications/'sources'/p['projectId']/relative(f['path'])
            if source.is_symlink()or digest(source.read_bytes())!=f['sha256']:raise ValueError('SOURCE_CHANGED')
        row=dict(projectId=p['projectId'],commitSha=original['commitSha'])
        if not p.get('runs'):
            if old[p['projectId']].get('runs'):raise ValueError('ACQUISITION_CHANGED')
            projects.append(dict(row,status='COLLECTION_FAILED_NOT_ANALYZED'));continue
        if len(p['runs'])!=2 or stable(p['runs'][0])!=stable(p['runs'][1]):raise ValueError('REPEAT_CHANGED')
        b=summary(old[p['projectId']]['runs'][0]);a=summary(p['runs'][0])
        for key in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
            if b[key]!=a[key]:raise ValueError('UNEXPECTED_POLICY_OR_LEGACY_CHANGE')
        projects.append(dict(row,before=b,after=a,elapsedMs=[r['elapsedMs']for r in p['runs']],
            fingerprintChanged=old[p['projectId']]['runs'][0]['engineFingerprint']!=p['runs'][0]['engineFingerprint']))
    validation=read(controls/'validation-committed.json');holdout=read(controls/'holdout-committed.json')
    manifest=read(controls/'manifest.json');mh=digest((controls/'manifest.json').read_bytes())
    for report in [validation,holdout]:
        if report['engineCommit']!=after['engineCommit']or report['manifestSha256']!=mh:raise ValueError('CONTROL_VERSION')
        if any(c['before']['inputSha256']!=c['after']['inputSha256']for c in report['cases']):raise ValueError('INPUT_CHANGED')
    all_cases=validation['cases']+holdout['cases'];groups={}
    for topology in {c['topology']for c in all_cases}:
        cases=[c for c in all_cases if c['topology']==topology]
        groups[topology]=dict(cases=len(cases),labels=dict(Counter(c['label']for c in cases)),
            before=dict(Counter(c['beforeOutcome']for c in cases)),after=dict(Counter(c['afterOutcome']for c in cases)))
    regression={}
    for name,root in [('pilot',outside(pilot)),('realworld',outside(realworld))]:
        b=read(root/'hardening5-score-regression.json')['summary'];a=read(root/'hardening6-score-regression.json')['summary']
        if b!=a:raise ValueError('REGRESSION_CHANGED')
        regression[name]=a
    node=next(p for p in after['projects']if p['projectId']=='OWASP--NodeGoat')['runs'][0]['typescript']
    mongo=[f for f in node['findings']if f['ruleId']=='JS_MONGO_WHERE_INPUT_FLOW'and f['confidence']=='HIGH']
    if len(mongo)!=1 or mongo[0]['sink']['kind']!='MONGODB_CURSOR_TOARRAY':raise ValueError('NODEGOAT_PATH_NOT_CONFIRMED')
    effects=[u for u in node['nodeUses']if u['kind']=='CONSTRUCTOR_SUMMARY_MUST']
    if not effects:raise ValueError('SUMMARY_PROOF_MISSING')
    followup=dict(originalPackCaseId='nodegoat-nosql-query-construction',sourceCommit=next(p['commitSha']for p in projects if p['projectId']=='OWASP--NodeGoat'),
        previousMilestone=BASELINE,engineCommit=after['engineCommit'],status='STATIC_INPUT_TO_WHERE_AND_CURSOR_CONSUMPTION_CONFIRMED',
        cause='Route mounting -> handler constructor -> DAO constructor -> nested user DAO exceeded depth three. Strict immediate constructor effects preserve Db origin without tracing deferred methods.',
        constructorEvidence=effects,mongoEvidence=mongo,
        counterEvidence='Active threshold interpolation is not the commented numeric-validation example. Actual installed driver, server-side JavaScript, middleware and runtime exploitability are unverified.',
        normalControls='Fixed where/numeric comparison, unconsumed cursor and ambiguous mutation regressions; local-helper Grade B pairs.',
        gradeBTopologyResults=groups,remaining='Separate fifth import module still exceeds the independent module-loading boundary; no limit increase.')
    packs.mkdir(mode=0o700);write(packs/'nodegoat-nosql-query-construction.json',followup)
    result=dict(schemaVersion=1,stage='PRE_ENTRY_ISOLATION_NOT_FINAL',baselineMilestone=BASELINE,engineCommit=after['engineCommit'],sourcePlanSha256=plan_hash,
        projects=projects,gradeBManifest=manifest,gradeBValidation=validation,gradeBHoldout=holdout,gradeBTopologyResults=groups,
        gradeA=dict(newSupportedPatchPairs=0,interpretation='Prior Mongoose library patch and unverified mongo-express candidate are not repurposed as supported truth.'),
        gradeC=validation['gradeCScope'],failureCaseFollowup=followup,regression=regression,
        constructorContract=dict(cache='AST plan only; fresh state for every application',must='Whitelisted immediate const aliases/fresh fields/deferred methods/verified literal collection factory',
            may='Not applied as proof',unknown='Unsupported branches/calls/computed writes, uncertain receiver or exceeded budget',
            resourceLimitsChanged=False,fullFunctionTrace=False),
        cursorContract='find is construction only; supported toArray/next consumption or eager findOne/countDocuments provides separate execution evidence. No runtime attack proof.',
        riskChanged=False,scoreChanged=False,databaseMigration=False,historicalSnapshotsRecomputed=False,
        comparison='Protocol v9 and fingerprint differ; structural findings remain REVIEW_REQUIRED/NOT_COMPARED.',
        validation=dict(backendTests=513,backendPassed=506,backendSkipped=7,typescriptTests=157,frontendTests=105,
            frontendBuild='PASS',pythonTests=110,evaluationTools=94,browserWidths=[1440,390,320],
            commonInputPath='Real ZIP/H2 save/detail/access isolation with summary evidence; public/private GitHub acquisition mocked.',livePrivateGithubE2E='NOT_RUN'),
        safety=dict(targetExecution=False,targetInstall=False,targetMutation=False,userDatabaseEvaluationWrites=False,paidAiCalls=0,externalVulnerabilityLookups=0,
            networkScope='Public official documentation/search only; existing pinned public source reused for explicit Grade B controls.',permissionDenials=0,originalSourcesInGit=False),
        limitations=['Grade B derives from an external scaffold but is same-curator controlled data, not independently authored or blind.',
            'Original separate-module failures are retained; local-helper variants were added after observing validation failures.',
            'Observed holdout is now regression material. No engine tuning followed its execution; family/project-independent holdout was not established.',
            'Reported zero FP/FN excludes UNKNOWN and NOT_INSPECTED; no general precision/recall claim.',
            'Only strict function constructors and supported Mongo contracts; no arbitrary DI, dynamic factories, prototype, full asynchronous or middleware semantics.',
            'Next.js/NestJS and import-depth gaps remain; existing file/text/node/work/memory/output caps retained.',
            'Pilot six false alerts and CVE 14 unsupported/two resource-limited cases remain; other old holdout splits not rerun.',
            'Timing/RSS are single observations, not performance guarantees.'])
    write(output,result);print(dict(projects=len(projects),gradeB=len(all_cases),gradeANewPairs=0,nodegoatVerifiedMongoCandidates=len(mongo)))

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ['applications','controls','pilot','realworld','output','packs']:p.add_argument(name)
    report(**vars(p.parse_args()))
