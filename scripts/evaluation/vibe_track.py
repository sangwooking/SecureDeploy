"""Source-free provenance and path-review adapter for the existing app runner.

Original projects stay outside Git. A reviewed condition is not whole-app truth;
uninspected or unsupported code never becomes a true negative.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

import application_track as app
from benchmark import digest, outside, read, relative, stable

TRACK = 'AI_VIBE_CODED_WEB'
PROVENANCE = {'AI_ASSISTED_HUMAN_EDITED', 'ORIGINAL_GENERATED',
              'SECURITY_PROMPT_GENERATED', 'CONTROLLED_VARIANT'}
OUTCOMES = {'TP', 'FP', 'FN', 'TN', 'UNKNOWN', 'NOT_SUPPORTED',
            'NOT_INSPECTED', 'RESOURCE_LIMIT', 'ANALYSIS_FAILED'}


def validate_case(case):
    if case['outcome'] not in OUTCOMES or case['truth'] not in {'DANGEROUS', 'SAFE', 'UNKNOWN'}:
        raise ValueError('CASE_ACCOUNTING')
    if case['truth'] == 'UNKNOWN' and case['outcome'] in {'TP', 'FP', 'FN', 'TN'}:
        raise ValueError('UNKNOWN_NOT_CLASSIFICATION')
    if case['truth'] == 'SAFE' and case['outcome'] in {'TP', 'FN'} or case['truth'] == 'DANGEROUS' and case['outcome'] in {'FP', 'TN'}:
        raise ValueError('TRUTH_OUTCOME_MISMATCH')
    if not case.get('sites'):
        raise ValueError('REVIEW_LOCATION')
    for key in ('condition', 'evidence', 'limitations', 'fixDirection', 'verification'):
        if not case.get(key):
            raise ValueError('REVIEW_EVIDENCE_REQUIRED')
    if case['outcome'] in {'TP', 'FP', 'FN', 'TN'} and not case.get('targetRules'):
        raise ValueError('TARGET_RULE_REQUIRED')
    if case['outcome'] in {'FN', 'TN'} and not case.get('inspectionEvidence'):
        raise ValueError('INSPECTION_REQUIRED_FOR_NEGATIVE')


def matching_signals(case, run):
    return [f for f in run.get('filtered', []) if f['ruleId'] in case.get('targetRules', [])
            and any(f['filePath'] == s['filePath'] and s['line'] <= f['line'] <= s.get('endLine', s['line']) for s in case['sites'])]


def validate_catalog(catalog):
    if catalog.get('schemaVersion') != 1 or catalog.get('track') != TRACK:
        raise ValueError('TRACK_SCHEMA')
    selected = [c for c in catalog['candidates'] if c.get('selected')]
    if not 1 <= len(selected) <= 8:
        raise ValueError('PROJECT_LIMIT')
    groups = {}; repos = set()
    for c in selected:
        repo = c['full_name']
        if repo in repos or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo):
            raise ValueError('REPOSITORY_IDENTITY')
        repos.add(repo)
        if c['repositoryUrl'] != 'https://github.com/' + repo or not re.fullmatch('[0-9a-f]{40}', c['commitSha']):
            raise ValueError('PINNED_IDENTITY')
        if not c.get('license') or not c.get('provenancePaths') or c.get('provenanceKind') not in PROVENANCE:
            raise ValueError('LICENSE_OR_PROVENANCE')
        for path in [c['licensePath'], *c['provenancePaths']]:
            relative(path)
        if c['grade'] not in {'A', 'B', 'C'} or c['evaluationSplit'] not in {'REGRESSION', 'VALIDATION', 'HOLDOUT'}:
            raise ValueError('TRUTH_OR_SPLIT')
        for key in ('repositoryFamily', 'promptFamily'):
            group = (key, c[key])
            if not c[key] or group in groups and groups[group] != c['evaluationSplit']:
                raise ValueError('FAMILY_SPLIT_LEAKAGE')
            groups[group] = c['evaluationSplit']
    return selected


def collect(catalog, destination):
    validate_catalog(catalog)
    # The original collector enforces bounds, root licenses, exact hashes and
    # credential-shaped-file omissions. Never weaken those guards for an app.
    return app.collect(catalog, destination)


def validate_sources(root, catalog, plan):
    selected = validate_catalog(catalog)
    original = {c['full_name']: c for c in selected}
    if len(plan['projects']) != len(original):
        raise ValueError('PROJECT_SET')
    groups = {}; checked = []
    for project in plan['projects']:
        candidate = original[project['full_name']]
        if candidate['commitSha'] != project['commitSha']:
            raise ValueError('SOURCE_REVISION')
        if not project['collectionStatus'].startswith('COLLECTED'):
            checked.append({'projectId': project['projectId'], 'status': 'COLLECTION_FAILED_NOT_SAFE'})
            continue
        source = root / 'sources' / project['projectId']
        retained = {f['path']: f for f in project['files']}
        if any('enterprise' in Path(p).parts for p in retained):
            raise ValueError('SEPARATE_LICENSE_REVIEW_REQUIRED')
        for path in [candidate['licensePath'], *candidate['provenancePaths']]:
            if path not in retained:
                raise ValueError('LICENSE_OR_PROVENANCE_NOT_RETAINED')
        for name, record in retained.items():
            path = source / relative(name)
            if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()) or digest(path.read_bytes()) != record['sha256']:
                raise ValueError('SOURCE_HASH_OR_PATH')
            if Path(name).suffix in {'.ts', '.tsx', '.js', '.jsx', '.py', '.java', '.sql'} and record['bytes'] >= 200:
                # Shared third-party UI scaffolding is evidence of correlation,
                # not independent risk examples; report, do not hide it.
                normalized = digest(re.sub(rb'\s+', b'', path.read_bytes()))
                groups.setdefault(normalized, set()).add((project['projectId'], candidate['evaluationSplit']))
        checked.append({'projectId': project['projectId'], 'status': 'HASH_AND_PROVENANCE_VERIFIED'})
    overlap = [sorted({p for p, _ in g}) for g in groups.values() if len({s for _, s in g}) > 1]
    return {'projects': checked, 'crossSplitSharedCodeGroups': overlap,
            'independence': 'NOT_BLIND; shared scaffolding must not count as independent cases'}


def report(root, raw_file, review_file, output):
    root = outside(root)
    plan = read(root / 'application-plan.json'); raw = read(raw_file); review = read(review_file)
    catalog = plan['selection']
    source_check = validate_sources(root, catalog, plan)
    plan_hash = digest((root / 'application-plan.json').read_bytes())
    if raw['planSha256'] != plan_hash or review['planSha256'] != plan_hash or review['engineCommit'] != raw['engineCommit']:
        raise ValueError('RESULT_VERSION')
    results = {r['projectId']: r for r in raw['projects']}
    if len(results) != len(raw['projects']) or set(results) != {p['projectId'] for p in plan['projects']}:
        raise ValueError('RESULT_PROJECT_SET')
    cases = review.get('cases', []); seen = set(); cases_by_project = Counter()
    summaries = []
    for p in plan['projects']:
        result = results[p['projectId']]
        row = {k: p.get(k) for k in ('projectId', 'repositoryUrl', 'commitSha', 'license', 'generator', 'provenanceKind', 'promptStatus', 'grade', 'evaluationSplit', 'discoveredArchiveFiles', 'retainedFiles', 'omissionCounts')}
        row['evaluationStatus'] = result['status']
        if result.get('runs'):
            runs = result['runs']
            if len(runs) != 2:
                raise ValueError('REPEAT_COUNT')
            r = runs[0]
            row.update(repeatConsistent=stable(r) == stable(runs[1]),
                       ruleCounts=dict(Counter(f['ruleId'] for f in r['filtered'])),
                       structuralCandidateCounts=dict(Counter(f['ruleId'] for f in r['reviewCandidates'])),
                       coverage={k: r['coverage'].get(k) for k in ('status', 'discoveredFiles', 'selectedFiles', 'unsupportedFiles', 'excludedFiles', 'failedFiles')},
                       sca=r['sca'], securityScore=r['securityScore'],
                       deploymentAssessment=r['risk']['prioritizedDeploymentAssessment'],
                       prioritySummary=r['risk']['prioritySummary'],
                       elapsedMs=[v['elapsedMs'] for v in runs],
                       sampledParentHeapBytes=[v['parentHeapUsedBytes'] for v in runs])
            row['analyzers'] = {}
            for language in ('java', 'python', 'typescript'):
                worker = r[language]['analysis'] if language == 'java' else r[language]
                files = worker.get('files', [])
                row['analyzers'][language] = {'status': worker['status'],
                    'fileRecords': len(files), 'entrypoints': sum(f.get('entrypoints', 0) for f in files),
                    'parseStatuses': dict(Counter(f.get('parseStatus') for f in files))}
        summaries.append(row)
    for case in cases:
        if case['caseId'] in seen or case['projectId'] not in results:
            raise ValueError('CASE_IDENTITY')
        seen.add(case['caseId']); cases_by_project[case['projectId']] += 1
        validate_case(case)
        runs = results[case['projectId']].get('runs', [])
        matches = matching_signals(case, runs[0]) if runs else []
        if (case['outcome'] in {'TP', 'FP'} and not matches
                or case['outcome'] in {'FN', 'TN'} and matches):
            raise ValueError('OBSERVED_SIGNAL_MISMATCH')
        case['matchedRuleSignals'] = matches
        inspected = []
        for language in ('java', 'python', 'typescript'):
            if not runs:
                continue
            worker = runs[0][language]['analysis'] if language == 'java' else runs[0][language]
            for record in worker.get('files', []):
                if any(record.get('filePath') == s['filePath'] for s in case['sites']):
                    inspected.append(dict(language=language, **{k: record.get(k) for k in
                        ('filePath', 'parseStatus', 'flowStatus', 'entrypoints', 'limitations')}))
        case['structuralInspection'] = inspected
        if case['outcome'] == 'RESOURCE_LIMIT' and not any(r['parseStatus'] == 'LIMIT_EXCEEDED' for r in inspected):
            raise ValueError('RESOURCE_LIMIT_EVIDENCE_REQUIRED')
        files = {f['path']: f for p in plan['projects'] if p['projectId'] == case['projectId'] for f in p.get('files', [])}
        for site in case['sites']:
            if site['filePath'] not in files or not isinstance(site['line'], int) or site['line'] < 1:
                raise ValueError('REVIEW_LOCATION')
            path = root / 'sources' / case['projectId'] / relative(site['filePath'])
            if not site['line'] <= site.get('endLine', site['line']) <= len(path.read_text().splitlines()):
                raise ValueError('REVIEW_LINE')
            site['sha256'] = files[site['filePath']]['sha256']
    result = {'schemaVersion': 1, 'track': TRACK, 'engineCommit': raw['engineCommit'],
        'planSha256': plan_hash, 'rawSha256': digest(Path(raw_file).read_bytes()),
        'reviewSha256': digest(Path(review_file).read_bytes()), 'sourceCheck': source_check,
        'projects': summaries, 'manualCases': cases, 'manualOutcomeCounts': dict(Counter(c['outcome'] for c in cases)),
        'truthPolicy': 'Named path/configuration only; Grade C apps remain unlabelled. No whole-app TN or recall estimate.',
        'externalLookups': 'NOT_RUN; SCA extraction only, OSV/EPSS/KEV and AI not called',
        'userDatabase': 'NOT_USED', 'holdout': 'NONE; analyst-observed pilot, no independent blinded accuracy claim',
        'failurePacks': review.get('failurePacks', []), 'nextPriorities': review.get('nextPriorities', []),
        'v1AcceptanceProposal': review.get('v1AcceptanceProposal', {})}
    app.write(Path(output), result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    c = sub.add_parser('collect'); c.add_argument('catalog'); c.add_argument('root')
    r = sub.add_parser('report'); r.add_argument('root'); r.add_argument('raw'); r.add_argument('review'); r.add_argument('output')
    args = parser.parse_args()
    if args.command == 'collect':
        collect(read(args.catalog), args.root)
    else:
        result = report(args.root, args.raw, args.review, args.output)
        print(json.dumps({'projects': len(result['projects']), 'manualCases': len(result['manualCases']), 'outcomes': result['manualOutcomeCounts']}))


if __name__ == '__main__':
    main()
