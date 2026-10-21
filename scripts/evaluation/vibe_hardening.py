"""Same-source delta receipt; never exports source, evidence text or whole-app truth."""
import argparse
from collections import Counter
from pathlib import Path

import application_track as app
from benchmark import digest, read, stable
from vibe_track import validate_sources, matching_signals


def identity(finding):
    return finding['ruleId'], finding['filePath'], finding['line']


def summarize(run):
    ts = run['typescript']
    return dict(ruleCounts=dict(Counter(f['ruleId'] for f in run['filtered'])),
                structuralCounts=dict(Counter(f['ruleId'] for f in run['reviewCandidates'])),
                entrypoints=sum(f['entrypoints'] for f in ts['files']),
                parsedFiles=sum(f['parseStatus'] == 'PARSED' for f in ts['files']),
                limitedFiles=sum(f['parseStatus'] == 'LIMIT_EXCEEDED' for f in ts['files']),
                exposureStatuses=dict(Counter(u['status'] for u in ts.get('exposureUses', []))),
                coverage={k: run['coverage'].get(k) for k in
                          ('status', 'discoveredFiles', 'selectedFiles', 'unsupportedFiles', 'excludedFiles', 'failedFiles')},
                score=run['securityScore'], assessment=run['risk']['prioritizedDeploymentAssessment'],
                priorities=run['risk']['prioritySummary'], sca=run['sca'])


def compare(plan, before, after, review):
    if before['planSha256'] != after['planSha256'] or review['planSha256'] != before['planSha256']:
        raise ValueError('PLAN_MISMATCH')
    if review['engineCommit'] != before['engineCommit']:
        raise ValueError('BASELINE_REVIEW_MISMATCH')
    left = {p['projectId']: p for p in before['projects']}
    right = {p['projectId']: p for p in after['projects']}
    if len(left) != len(before['projects']) or len(right) != len(after['projects']) or set(left) != set(right):
        raise ValueError('PROJECT_SET')
    rows = []
    for project in plan['projects']:
        key = project['projectId']; b = left[key]['runs']; a = right[key]['runs']
        if any(p.get('commitSha') != project['commitSha'] for p in (left[key], right[key])):
            raise ValueError('SOURCE_COMMIT_MISMATCH')
        if len(a) != 2 or len(b) != 2 or stable(a[0]) != stable(a[1]) or stable(b[0]) != stable(b[1]):
            raise ValueError('REPEAT_MISMATCH')
        old = set(map(identity, b[0]['filtered'])); new = set(map(identity, a[0]['filtered']))
        row = dict(projectId=key, sourceCommit=project['commitSha'], grade=project['grade'],
                   before=summarize(b[0]), after=summarize(a[0]), repeatConsistent=True,
                   removedSignals=[dict(ruleId=r, filePath=p, line=n) for r, p, n in sorted(old-new)],
                   addedSignals=[dict(ruleId=r, filePath=p, line=n) for r, p, n in sorted(new-old)],
                   structuralLocationsAfter=[dict(ruleId=f['ruleId'], priority=f['priority'],
                       location={k: f['location'].get(k) for k in ('filePath', 'line', 'column', 'kind')},
                       trace=[{k: t.get(k) for k in ('filePath', 'line', 'column', 'kind')} for t in f.get('trace', [])])
                       for f in a[0]['reviewCandidates']],
                   elapsedMsBefore=[r['elapsedMs'] for r in b], elapsedMsAfter=[r['elapsedMs'] for r in a],
                   sampledParentHeapBytesBefore=[r['parentHeapUsedBytes'] for r in b],
                   sampledParentHeapBytesAfter=[r['parentHeapUsedBytes'] for r in a])
        rows.append(row)
    packs = []
    for case in review['cases']:
        if case['outcome'] != 'FP':
            continue
        key = case['projectId']; b = left[key]['runs'][0]; a = right[key]['runs'][0]
        old = matching_signals(case, b); remaining = matching_signals(case, a)
        packs.append(dict(caseId=case['caseId'], projectId=key, originalOutcome='FP',
                          targetWarningsBefore=len(old), targetWarningsAfter=len(remaining),
                          status='NEGATIVE_PROOF_REMOVED' if old and not remaining else 'UNRESOLVED',
                          evidencePolicy='Original reviewed path condition only; not whole-application safety',
                          beforeEngine=before['engineCommit'], afterEngine=after['engineCommit']))
    return dict(schemaVersion=1, track='AI_VIBE_CODED_WEB_HARDENING',
                beforeEngine=before['engineCommit'], afterEngine=after['engineCommit'],
                planSha256=before['planSha256'], projects=rows, failurePacks=packs,
                truthPolicy='Grade C projects; static candidates are not confirmed exploits or TP labels',
                independence='Observed development/regression material; same curator; no blind evaluation',
                omissions='Original intake and credential-shaped-file omissions unchanged',
                externalLookups='NOT_RUN', userDatabase='NOT_USED',
                resourceNote='Parent heap samples are not peak worker RSS; server flow budgets unchanged')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path); parser.add_argument('before', type=Path)
    parser.add_argument('after', type=Path); parser.add_argument('review', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    plan = read(args.root/'application-plan.json')
    validate_sources(args.root, plan['selection'], plan)
    result = compare(plan, read(args.before), read(args.after), read(args.review))
    if digest((args.root/'application-plan.json').read_bytes()) != result['planSha256']:
        raise ValueError('PLAN_HASH')
    app.write(args.output, result)


if __name__ == '__main__':
    main()
