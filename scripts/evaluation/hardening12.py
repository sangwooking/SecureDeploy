"""SQL structural-vs-user-warning deltas; original sources remain external."""
import argparse
from benchmark import read, write, outside, score, stable
from hardening11 import section
from hardening4 import summary

FP_CAUSES={
    'owasp-BenchmarkTest00107':('FACTORY_RETURN_AND_TRANSFORMS',{89:'SQL_CONSTRUCTION',92:'STATEMENT_DECLARATION',94:'EXECUTION_OPTION_TYPE_REFERENCE'}),
    'owasp-BenchmarkTest00110':('FACTORY_RETURN_AND_TRANSFORMS',{89:'SQL_CONSTRUCTION',92:'STATEMENT_DECLARATION'}),
    'owasp-BenchmarkTest00113':('KNOWN_STRING_CAST_COMPLETENESS',{77:'STATEMENT_DECLARATION'}),
    'owasp-BenchmarkTest00197':('LIST_REMOVE_AND_EXTERNAL_JDBC_FIELD',{63:'SQL_CONSTRUCTION'}),
    'owasp-BenchmarkTest00200':('LIST_REMOVE_AND_EXTERNAL_JDBC_FIELD',{64:'SQL_CONSTRUCTION'}),
    'owasp-BenchmarkTest00201':('FACTORY_RETURN_TRANSFORMS_AND_EXTERNAL_JDBC_FIELD',{75:'SQL_CONSTRUCTION'}),
}


def compare(root, before, after):
    manifest=read(root/'manifest.json')
    raw=[read(root/name)for name in [before,after]]
    sections=[section(manifest,r)for r in raw]
    a,b=sections
    if a['manifestSha256']!=b['manifestSha256'] or a['accountingVersion']!=b['accountingVersion']:
        raise ValueError('SOURCE_TRUTH_OR_ACCOUNTING_CHANGED')
    if a['layers']['rule']!=b['layers']['rule']:raise ValueError('RAW_RULE_CHANGED')
    for previous in a['cases']:
        current=next(c for c in b['cases']if c['caseId']==previous['caseId'])
        for layer in ['ast','finalUser']:
            if previous['layers'][layer]['verdict']=='TP' and current['layers'][layer]['verdict']!='TP':
                raise ValueError('KNOWN_DANGEROUS_FLOW_REGRESSION')
        if previous['riskPolicy']!=current['riskPolicy']:raise ValueError('RISK_POLICY_CHANGED')
    return manifest,raw,dict(before=a,after=b)


def report(base,output,packs):
    base,packs=outside(base),outside(packs);packs.mkdir(mode=0o700)
    root=base/'pilot-2026-10-20-v2'
    plan,raw,pilot=compare(root,'hardening12-before-regression.json','hardening12-after-regression.json')
    oldscore=score(plan,raw[0]);newscore=score(plan,raw[1])
    ids={c['caseId']for c in oldscore['results']if c['layers']['finalUser']['verdict']=='FP'}
    if ids!=set(FP_CAUSES):raise ValueError('BASELINE_FP_SET_CHANGED')
    classification=[]
    for cid in sorted(ids):
        target=next(c for c in plan['cases']if c['caseId']==cid)
        old=next(c for c in pilot['before']['cases']if c['caseId']==cid)
        new=next(c for c in pilot['after']['cases']if c['caseId']==cid)
        run=next(c['runs'][0]for c in raw[0]['results']if c['caseId']==cid)
        cause,locations=FP_CAUSES[cid]
        warnings=[dict(ruleId=m['ruleId'],filePath=m['filePath'],line=m['line'],
            surface=locations.get(m['line'],'UNCLASSIFIED'))for m in run['filtered']if m['ruleId']=='DANGEROUS_SQL']
        if any(m['surface']=='UNCLASSIFIED'for m in warnings):raise ValueError('WARNING_LOCATION_CHANGED')
        finding=dict(caseId=cid,cause=cause,warnings=warnings,before=old,after=new,
            verifiedScope='Frozen case and expected benchmark label, not executed attack or whole helper/runtime verification.',
            remaining='External factory/helper/transforms or List.remove unresolved; warning retained.' if cid!='owasp-BenchmarkTest00113' else
                'Known String/null value shape preserved through cast; final static SQL now permits the existing complete-method negative proof. No warning-position heuristic broadened.')
        classification.append(finding)
        write(packs/(cid+'.json'),dict(schemaVersion=1,repository=target['repositoryUrl'],sourceCommit=target['repositoryCommitSha'],
            truth=target['groundTruthLabel'],files=target['files'],labelEvidence=target['labelEvidence'],
            sourceSites=target.get('sourceSites',[]),targetSites=target['targetSites'],
            engineCommit=pilot['after']['engineCommit'],evidence=finding,
            implementation='JavaSqlWorker.Val.stringCompatible, safe identity cast, primitive-array unknown fallback.',
            regression='JavaSqlCastEvidenceTest, common ZIP/GitHub ServerAnalysisIntegrationTest.'))
    fixed=next(c for c in pilot['after']['cases']if c['caseId']=='owasp-BenchmarkTest00113')
    if fixed['layers']['ast']['verdict']!='TN' or fixed['layers']['finalUser']['verdict']!='TN':raise ValueError('TARGET_FALSE_POSITIVE_REMAINS')
    if pilot['after']['layers']['finalUser'].get('FP')!=5:raise ValueError('UNEXPECTED_USER_WARNING_DELTA')
    controls={};oldcontrols={}
    for split in ['regression','validation']:
        path=base/'hardening12-cast-controls-v1'
        manifest,runs,delta=compare(path,'before-'+split+'.json','after-'+split+'.json')
        for c in delta['after']['cases']:
            expected={'DANGEROUS':'TP','SAFE':'TN','UNKNOWN':'UNKNOWN'}[c['truth']]
            if any(c['layers'][layer]['verdict']!=expected for layer in ['ast','finalUser']):raise ValueError('CONTROL_EXPECTATION_FAILED')
            target=next(t for t in manifest['cases']if t['caseId']==c['caseId'])
            write(packs/(c['caseId']+'.json'),dict(caseId=c['caseId'],grade='B',sourceCommit=target['repositoryCommitSha'],
                repository=target['repositoryUrl'],files=target['files'],sourceSites=target['sourceSites'],targetSites=target['targetSites'],
                truth=target['groundTruthLabel'],labelScope=target['labelScope'],contextOmissions=target['contextOmissions'],
                before=next(p for p in delta['before']['cases']if p['caseId']==c['caseId']),after=c,engineCommit=delta['after']['engineCommit']))
        controls[split]=delta
        _,_,previous=compare(base/'hardening11-collections-v2','after-'+split+'.json','hardening12-'+split+'.json')
        if previous['before']['layers']!=previous['after']['layers']:raise ValueError('COLLECTION_CONTROL_REGRESSION')
        oldcontrols[split]=previous
    rw=base/'realworld-2026-10-20-v3'
    _,_,realworld=compare(rw,'hardening11-regression.json','hardening12-regression.json')
    if realworld['before']['layers']!=realworld['after']['layers']:raise ValueError('REALWORLD_REGRESSION')
    apps=base/'applications-2026-10-20-v2'
    a,b=[read(apps/name)for name in ['hardening11-after.json','hardening12-after.json']]
    if a['planSha256']!=b['planSha256']:raise ValueError('APPLICATION_SOURCE_CHANGED')
    projects=[]
    for project in b['projects']:
        previous=next(p for p in a['projects']if p['projectId']==project['projectId'])
        if not project.get('runs'):
            if previous.get('runs'):raise ValueError('APPLICATION_ACQUISITION_CHANGED')
            projects.append(dict(projectId=project['projectId'],status='COLLECTION_FAILED_NOT_SAFE'));continue
        if stable(project['runs'][0])!=stable(project['runs'][1]):raise ValueError('APPLICATION_NONDETERMINISTIC')
        x,y=summary(previous['runs'][0]),summary(project['runs'][0])
        if any(x[k]!=y[k]for k in ['rules','securityScore','prioritySummary','deploymentAssessment']):raise ValueError('APPLICATION_USER_WARNING_CHANGE_REQUIRES_REVIEW')
        for language in ['python','typescript']:
            if stable(previous['runs'][0][language])!=stable(project['runs'][0][language]):raise ValueError('OTHER_ANALYZER_REGRESSION')
        projects.append(dict(projectId=project['projectId'],sourceCommit=project['commitSha'],legacyRiskAndOtherLanguagesUnchanged=True,
            javaFindings=len(project['runs'][0]['java']['findings']),typescriptFindings=len(project['runs'][0]['typescript']['findings'])))
    result=dict(schemaVersion=1,baselineCommit=raw[0]['engineCommit'],engineCommit=raw[1]['engineCommit'],protocol='java-sql-v4',
        productionChange='Preserve proven String/null value shape through identity casts without erasing input provenance or widening rule reconciliation.',
        fpClassification=classification,pilot=pilot,newGradeB=controls,oldGradeB=oldcontrols,
        realworldLayers=realworld['after']['layers'],applications=projects,
        independence='12 new Grade B variants of already observed public app controllers; single curator and shared cast contract, not blind or new Grade A CVE evidence.',
        comparison='Source hashes, labels, accounting and two-repeat semantic stability checked per comparison. #11 Grade B baseline engine cf87e2d has identical production sources to baseline 1303c7e.',
        policy='Risk/score/BLOCKING formulas and reconciliation boundaries unchanged. Suppressed false positives can change new Review counts and reference scores.',
        resource='Existing Java v4 parser/shared task and all file/time/heap/AST/depth/collection caps retained. Memory samples are parent heap, not worker peak RSS.',
        snapshots='No user PostgreSQL or existing Review writes; no migration; compiled analyzer fingerprint changes prevent false RESOLVED.',
        notRun=['Fresh private scans','Target code execution/compilation/install','Production attacks','Paid AI','New vulnerability database lookups'],
        apiReference='https://docs.oracle.com/javase/specs/jls/se21/html/jls-5.html#jls-5.5')
    write(output,result);print(dict(status='PASS',remainingPilotFalsePositives=5,newGradeB=12,oldGradeB=14,packs=18))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('base');parser.add_argument('output');parser.add_argument('packs')
    report(**vars(parser.parse_args()))
