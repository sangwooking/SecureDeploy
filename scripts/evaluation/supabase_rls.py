"""Source-free RLS evaluation receipts and an explicitly controlled public-app pair."""
import argparse
import copy
from pathlib import Path
import shutil

import application_track as app
from benchmark import read, outside, digest, stable
from vibe_track import validate_sources


def prepare(root, destination):
    root=outside(root); destination=outside(destination)
    plan=read(root/'application-plan.json'); validate_sources(root,plan['selection'],plan)
    project=next(p for p in plan['projects'] if p['projectId']=='TinyikoMamban--workflowai-pro')
    destination.mkdir(mode=0o700); (destination/'sources').mkdir(mode=0o700)
    variants=[]
    for name in ('broad','owner'):
        p=copy.deepcopy(project); p['projectId']='workflowai-controlled-'+name
        source=destination/'sources'/p['projectId']
        shutil.copytree(root/'sources'/project['projectId'], source)
        sql=next(f for f in p['files'] if f['path'].endswith('20260630171322_e6e2b889-b9e3-4bb7-8251-8de1206b405c.sql'))
        if name=='broad':
            path=source/sql['path']; text=path.read_text()
            # Add one permissive policy; preserve real routing, client and GRANT context.
            text+='\nCREATE POLICY controlled_shared_tasks ON public.tasks FOR ALL TO authenticated USING(true) WITH CHECK(true);\n'
            path.write_text(text);path.chmod(0o600)
            sql['sha256']=digest(path.read_bytes());sql['bytes']=path.stat().st_size
        p.update(grade='B',evaluationSplit='REGRESSION',provenanceKind='CONTROLLED_VARIANT',
                 variant=name,groundTruth='CONTROLLED_POLICY_DECLARATION_NOT_A_REAL_CVE',
                 sourceCommitMeaning='Pinned original source; controlled copy has its own file hashes, not a Git revision')
        variants.append(p)
    controlled=copy.deepcopy(plan);controlled['projects']=variants
    controlled['knownTruthPolicy']='One controlled broad write policy versus original owner condition; not whole-project truth'
    app.write(destination/'application-plan.json',controlled)


def summary(raw):
    out=[]
    for p in raw['projects']:
        runs=p.get('runs',[])
        if len(runs)!=2 or stable(runs[0])!=stable(runs[1]):raise ValueError('RLS_REPEAT_MISMATCH')
        r=runs[0];s=r['typescript'].get('supabaseAnalysis')
        out.append(dict(projectId=p['projectId'],sourceCommit=p['commitSha'],repeatConsistent=True,
                        ruleCount=len(r['filtered']),structureCount=len(r['reviewCandidates']),
                        risk=r['risk']['prioritySummary'],score=r['securityScore'],
                        rls=s,elapsedMs=[v['elapsedMs'] for v in runs],
                        sampledParentHeapBytes=[v['parentHeapUsedBytes'] for v in runs]))
    return out


def report(root, raw_file, controlled_root, controlled_raw, output):
    root=outside(root);plan=read(root/'application-plan.json')
    validate_sources(root,plan['selection'],plan)
    raw=read(raw_file);controlled=read(controlled_raw)
    if raw['planSha256']!=digest((root/'application-plan.json').read_bytes()) or controlled['planSha256']!=digest((controlled_root/'application-plan.json').read_bytes()):raise ValueError('RLS_PLAN_HASH')
    original=summary(raw);pair=summary(controlled)
    if raw['engineCommit']!=controlled['engineCommit']:raise ValueError('RLS_ENGINE_MISMATCH')
    by_id={p['projectId']:p for p in pair}
    risk=by_id['workflowai-controlled-broad']['rls']['findings'];normal=by_id['workflowai-controlled-owner']['rls']['findings']
    if len(risk)!=1 or risk[0]['table']!='public.tasks' or normal:raise ValueError('CONTROLLED_RLS_EXPECTATION')
    before=read(root/'v1-hardening-final.json')
    baseline={p['projectId']:p['runs'][0] for p in before['projects']}
    for row in original:
        b=baseline[row['projectId']]
        if row['ruleCount']!=len(b['filtered']) or row['score']!=b['securityScore'] or row['risk']!=b['risk']['prioritySummary']:raise ValueError('LEGACY_POLICY_REGRESSION')
    app.write(output,dict(schemaVersion=1,engineCommit=raw['engineCommit'],baselineEngine=before['engineCommit'],
        originalPlanSha256=raw['planSha256'],controlledPlanSha256=controlled['planSha256'],
        originalGrade='C',controlledGrade='B',original=original,controlled=pair,
        controlledResult=dict(TP=1,TN=1,FP=0,FN=0,unit='One policy-declaration condition per controlled app; not whole-app truth'),
        failureCases=[dict(caseId='workflow-owner-policy',before='NOT_SUPPORTED',after='UID_COLUMN_EQUALITY_DECLARATIONS',runtime='UNKNOWN'),
                      dict(caseId='workflow-controlled-broad',cause='Additional permissive policy ORs with owner policy',after='REVIEW_REQUIRED',runtime='NOT_TESTED')],
        independence='Previously observed project and same curator; not blind or independent external validation',
        safety='No target execution/install/build/PoV, no external lookup, no user DB access',
        resourceNote='Parent heap samples are not peak RSS or worker peak memory'))


if __name__=='__main__':
    parser=argparse.ArgumentParser(); sub=parser.add_subparsers(dest='cmd',required=True)
    p=sub.add_parser('prepare');p.add_argument('root',type=Path);p.add_argument('destination',type=Path)
    p=sub.add_parser('report')
    for name in ('root','raw_file','controlled_root','controlled_raw','output'):p.add_argument(name,type=Path)
    args=vars(parser.parse_args()); command=args.pop('cmd')
    (prepare if command=='prepare' else report)(**args)
