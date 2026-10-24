"""Source-free comparison of fixed application receipts, not a security score."""
from collections import Counter
import argparse
import json
from pathlib import Path
from benchmark import stable
from application_track import read, write
from node_entry_b1 import identities, summary


def evidence(row):
    accesses = row['typescript']['supabaseAnalysis']['accesses']
    checks = [c for a in accesses for c in (a.get('authorizationEvidence') or {}).get('authChecks', [])]
    guards = {json.dumps(c['resultEvidence']['guardLocation'], sort_keys=True)
              for c in checks if c.get('resultEvidence')}
    filters = {json.dumps(loc, sort_keys=True) for c in checks if c.get('resultEvidence')
               for loc in c['resultEvidence']['userIdFilters']}
    return dict(linkedAccesses=sum(a['clientStatus'] == 'CLIENT_DECLARATION_LINKED' for a in accesses),
                resultGuards=len(guards), identityIdFilters=len(filters),
                directNextDeclarations=sum(bool((a.get('authorizationEvidence') or {}).get('requestEntry')) for a in accesses),
                policyStates=dict(Counter((a.get('authorizationEvidence') or {}).get('state', 'UNKNOWN') for a in accesses)))


def compare(before, after):
    if before['planSha256'] != after['planSha256']:
        raise ValueError('SOURCE_PLAN_CHANGED')
    old = {p['projectId']: p for p in before['projects']}
    if set(old) != {p['projectId'] for p in after['projects']}:
        raise ValueError('PROJECT_SET_CHANGED')
    rows = []
    for project in after['projects']:
        previous = old[project['projectId']]
        if previous['commitSha'] != project['commitSha'] or len(project['runs']) != 2:
            raise ValueError('SHA_OR_REPEAT_CHANGED')
        a, b = previous['runs'][0], project['runs'][0]
        legacy = {k: stable(a[k]) == stable(b[k]) for k in ['raw', 'filtered', 'securityScore', 'risk', 'sca']}
        if not all(legacy.values()) or stable(project['runs'][0]) != stable(project['runs'][1]):
            raise ValueError('LEGACY_OR_REPEAT_REGRESSION')
        if not set(identities(a)).issubset(identities(b)):
            raise ValueError('STRUCTURAL_FINDING_REGRESSION')
        rows.append(dict(project=project['projectId'], sha=project['commitSha'],
                         planSha256=after['planSha256'], engine=after['engineCommit'],
                         before=dict(summary(a), authorization=evidence(a)),
                         after=dict(summary(b), authorization=evidence(b)),
                         elapsedMs=[r['elapsedMs'] for r in project['runs']],
                         parentHeapUsedBytes=[r['parentHeapUsedBytes'] for r in project['runs']],
                         legacyUnchanged=legacy, repeatIdentical=True,
                         truth='OBSERVED_REGRESSION_NOT_WHOLE_PROJECT_SAFE_OR_NEW_TP'))
    return rows


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('spec', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    spec = read(args.spec)
    rows = [r for pair in spec['receipts'] for r in compare(read(Path(pair['before'])), read(Path(pair['after'])))]
    result = dict(schemaVersion=1, worker='ts-server-v23', projects=rows,
                  controls=read(Path(spec['controls'])), resources=read(Path(spec['resources'])),
                  sources=spec['sources'], targetExecuted=False, paidAiCalls=0, userDatabaseModified=False,
                  newRealVulnerabilityTP=0, independentReview=False,
                  limitations=['Grade B counts measure connected policy classification, not new CVE detection.',
                               'Grade C applications have no whole-project safe/vulnerable truth.',
                               'Auth calls, absence guards, ID filters and declared policies do not prove authorization.',
                               'React.cache, Proxy, dynamic context, ambiguous schema and deployed DB state remain unknown.',
                               'Resource replay measures trusted Worker RSS, not the whole backend or a hard RSS cap.',
                               'Live GitHub App acquisition and external reviewer evaluation were not run.'])
    write(args.output, result)
    print(json.dumps(dict(projects=len(rows), repeatIdentical=True, legacyPreserved=True, newRealVulnerabilityTP=0)))
