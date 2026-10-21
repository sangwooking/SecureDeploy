"""Source-free, pinned-tree HTML regression projection; no acquisition or DB access."""
import hashlib
import json
from pathlib import Path
import sys


def project(before, after):
    assert before['planSha256'] == after['planSha256']
    old = {p['projectId']: p for p in before['projects']}
    new = {p['projectId']: p for p in after['projects']}
    assert old.keys() == new.keys()
    rows = []
    for name, current in new.items():
        prior = old[name]
        assert prior['commitSha'] == current['commitSha']
        assert len(prior['runs']) == len(current['runs']) == 2
        for first, second in zip(prior['runs'], current['runs']):
            for key in ['raw', 'filtered']:
                assert [f for f in first[key] if f['ruleId'] != 'REACT_DANGEROUS_HTML'] == [f for f in second[key] if f['ruleId'] != 'REACT_DANGEROUS_HTML']
            assert first['reviewCandidates'] == second['reviewCandidates']
            assert first['typescript'] == second['typescript']
            if first['filtered'] == second['filtered']:
                assert first['securityScore'] == second['securityScore']
                assert first['risk']['prioritySummary'] == second['risk']['prioritySummary']
                assert first['risk']['prioritizedDeploymentAssessment'] == second['risk']['prioritizedDeploymentAssessment']
        for key in ['raw', 'filtered', 'reviewCandidates', 'typescript', 'securityScore']:
            assert current['runs'][0][key] == current['runs'][1][key]
        a, b = prior['runs'][0], current['runs'][0]
        html = lambda r: [f for f in r['filtered'] if f['ruleId'] == 'REACT_DANGEROUS_HTML']
        rows.append({'projectId': name, 'commitSha': current['commitSha'],
            'baselineHtml': html(a), 'currentHtml': html(b),
            'baselineScore': a['securityScore'], 'currentScore': b['securityScore'],
            'prioritySummary': b['risk']['prioritySummary'],
            'deploymentAssessment': b['risk']['prioritizedDeploymentAssessment'],
            'structuralCandidateCount': len(b['reviewCandidates']),
            'structuralAndNonHtmlUnchanged': True,
            'baselineElapsedMs': [r['elapsedMs'] for r in prior['runs']],
            'elapsedMs': [r['elapsedMs'] for r in current['runs']],
            'parentHeapUsedBytes': [r['parentHeapUsedBytes'] for r in current['runs']],
            'semanticRepeatable': True})
    return {'schemaVersion': 1, 'baselineEngine': before['engineCommit'], 'engineCommit': after['engineCommit'],
        'planSha256': after['planSha256'], 'projects': rows,
        'limitations': ['Previously observed public apps; no new blind evaluation',
            'SCA/threat intelligence external lookups disabled; same engine-only scope as baseline',
            'Parent heap samples are not worker peak RSS', 'No whole-app SAFE labels or new runtime XSS tests']}


if __name__ == '__main__':
    before, after, output = map(Path, sys.argv[1:])
    for path in (before, after):
        if path.stat().st_size > 12_000_000:
            raise ValueError('INPUT_LIMIT')
    result = project(json.loads(before.read_text()), json.loads(after.read_text()))
    result['inputSha256'] = {kind: hashlib.sha256(path.read_bytes()).hexdigest()
        for kind, path in [('baseline', before), ('current', after)]}
    with output.open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'projects': len(result['projects']), 'sameShaAndStructuralEvidence': True}))
