"""Source-free 2x2 entry-context replay receipts; never executes target modules."""
import argparse
from collections import Counter
from pathlib import Path
from benchmark import read, write, outside, digest, relative, validate, score, stable
from hardening4 import summary


BASELINE = '73f5d588736336c8f6023c469f2748c6d22f153c'
ENGINE = '31f4832c7df768a2692935ea6d25a7934afb2928'
GAPS = {
    'nodebb-api-token': {
        'confirmed': 'Passport bearer registration declaration resolves the verify callback; HTTP dispatch through startup/plugin and promise middleware remains unverified.',
        'remaining': ['Dynamic initialization and plugins', 'External Passport dispatch', 'Token lookup is not a SQL or authorization sink contract'],
    },
    'ghost-content-filter': {
        'confirmed': 'Express wrapper has an own Router field, but lazyUse/Promise/express-lazy-router bootstrap and external API-framework dispatch are not resolved.',
        'remaining': ['Lazy router initialization', 'External API wrapper', 'Bookshelf/Knex execution contract'],
    },
    'strapi-content-builder': {
        'confirmed': 'Added route registration delegates through Koa composition and dynamic controller registries, not supported Express registration.',
        'remaining': ['Koa/Strapi dispatch', 'Plugin configuration hydration', 'Knex raw SQL execution contract', 'Production-only patch guard is not universal safety'],
    },
}


def run_summary(runs):
    if len(runs) != 2 or stable(runs[0]) != stable(runs[1]):
        raise ValueError('REPEAT_CHANGED')
    first = runs[0]
    ts = first['typescript']
    files = ts['files']
    limitations = Counter(item for f in files for item in f.get('limitations', []))
    uses = Counter(u['kind'] for u in ts.get('nodeUses') or [])
    return dict(version=ts['analyzerVersion'], status=ts['status'],
        parsed=sum(f['parseStatus'] == 'PARSED' for f in files),
        entries=sum(f['entrypoints'] for f in files),
        functions=sum(f['functionsAnalyzed'] for f in files),
        nodeUseKinds=dict(uses), limitations=dict(sorted(limitations.items())),
        structuralFindingCount=len(ts.get('findings') or []),
        elapsedMs=[r['elapsedMs'] for r in runs],
        parentHeapSamples=[r['parentHeapUsedBytes'] for r in runs],
        repeatConsistent=True)


def verify_lineage(original, enriched):
    if enriched['parentManifestSha256'] != digest(original['_bytes']):
        raise ValueError('PARENT_MANIFEST_CHANGED')
    old = {c['caseId']: c for c in original['cases']}
    if set(old) != {c['caseId'] for c in enriched['cases']}:
        raise ValueError('CASE_SET_CHANGED')
    for case in enriched['cases']:
        parent = old[case['caseId']]
        if case['repositoryCommitSha'] != parent['repositoryCommitSha']:
            raise ValueError('SOURCE_COMMIT_CHANGED')
        files = {f['path']: f for f in case['files']}
        if any(files.get(f['path']) != f for f in parent['files']):
            raise ValueError('ORIGINAL_SOURCE_CHANGED')


def report(base, output, packs):
    base = outside(base)
    roots = {'original': base/'hardening7-pairs-v3', 'enriched': base/'hardening8-context-v1'}
    manifests = {name: read(root/'manifest.json') for name, root in roots.items()}
    for name, root in roots.items():
        validate(manifests[name], root)
    verify_lineage(dict(manifests['original'], _bytes=(roots['original']/'manifest.json').read_bytes()), manifests['enriched'])
    files = {
        'originalBefore': ('original', 'hardening8-original-baseline.json', BASELINE),
        'originalAfter': ('original', 'hardening8-original-after.json', ENGINE),
        'enrichedBefore': ('enriched', 'baseline-regression.json', BASELINE),
        'enrichedAfter': ('enriched', 'after-regression.json', ENGINE),
    }
    matrix = {}
    for name, (dataset, filename, engine) in files.items():
        raw = read(roots[dataset]/filename)
        if raw['engineCommit'] != engine or raw['manifestSha256'] != digest((roots[dataset]/'manifest.json').read_bytes()):
            raise ValueError('ENGINE_OR_MANIFEST_CHANGED')
        scored = score(manifests[dataset], raw)
        matrix[name] = dict(engineCommit=engine, inputManifestSha256=raw['manifestSha256'],
            targetOutcomes=scored['summary']['ast']['counts'],
            cases=[dict(caseId=r['caseId'], **run_summary(r['runs'])) for r in raw['results']])
    rows = []
    for case in manifests['enriched']['cases']:
        rows.append(dict(caseId=case['caseId'], pairId=case['pairId'], grade='A',
            repository=case['repositoryUrl'], sourceCommit=case['repositoryCommitSha'],
            cve=case['cve'], ghsa=case['ghsa'], targetSites=case['targetSites'],
            contextEnrichment=case['contextEnrichment'], gap=GAPS[case['pairId']],
            targetDetection='NOT_SUPPORTED_NOT_SAFE', split='REGRESSION', blind=False))
    app_root = base/'applications-2026-10-20-v2'
    app_plan = read(app_root/'application-plan.json')
    old = read(app_root/'hardening6-isolation-after.json')
    new = read(app_root/'hardening8-after.json')
    if new['engineCommit'] != ENGINE or old['planSha256'] != new['planSha256'] or new['planSha256'] != digest((app_root/'application-plan.json').read_bytes()):
        raise ValueError('APPLICATION_PROVENANCE_CHANGED')
    applications = []
    for p in new['projects']:
        previous = next(x for x in old['projects'] if x['projectId'] == p['projectId'])
        plan = next(x for x in app_plan['projects'] if x['projectId'] == p['projectId'])
        for file in plan.get('files', []):
            path = app_root/'sources'/p['projectId']/relative(file['path'])
            if path.is_symlink() or digest(path.read_bytes()) != file['sha256']:
                raise ValueError('APPLICATION_SOURCE_CHANGED')
        if not p.get('runs'):
            if previous.get('runs'):
                raise ValueError('ACQUISITION_CHANGED')
            applications.append(dict(projectId=p['projectId'], status='COLLECTION_FAILED_NOT_ANALYZED'))
            continue
        before, after = summary(previous['runs'][0]), summary(p['runs'][0])
        for key in ['rules', 'securityScore', 'prioritySummary', 'deploymentAssessment', 'java']:
            if before[key] != after[key]:
                raise ValueError('LEGACY_OR_POLICY_CHANGED')
        applications.append(dict(projectId=p['projectId'], sourceCommit=plan['commitSha'],
            result=run_summary(p['runs']), legacyRuleRiskJavaUnchanged=True))
    controls = read(base/'hardening6-controls-expanded'/'hardening8-committed-regression.json')
    if controls['engineCommit'] != ENGINE or controls['workingTreeDiffSha256'] != digest(b''):
        raise ValueError('CONTROLS_NOT_COMMITTED')
    benchmarks = {}
    for name, folder in [('pilot', 'pilot-2026-10-20-v2'), ('realworld', 'realworld-2026-10-20-v3')]:
        root = base/folder
        before = read(root/'hardening6-isolation-score-regression.json')['summary']
        after = read(root/'hardening8-score-regression.json')['summary']
        if before != after:
            raise ValueError('BENCHMARK_OUTCOMES_CHANGED')
        benchmarks[name] = after
    packs = outside(packs)
    packs.mkdir(mode=0o700)
    for pair in GAPS:
        path = packs/(pair+'.json')
        if path.exists():
            raise ValueError('PACK_ALREADY_EXISTS')
        write(path, dict(engineCommit=ENGINE, pairId=pair, findings=[r for r in rows if r['pairId'] == pair],
            matrix={k: [r for r in v['cases'] if r['caseId'].startswith(pair)] for k, v in matrix.items()},
            causalLimit='Observed source facts and bounded engine gaps, not runtime exploit proof. Prior packs are preserved.'))
    result = dict(schemaVersion=1, engineCommit=ENGINE, baselineCommit=BASELINE,
        accountingVersion='FLOW_BUDGET_LIMITS_V2',
        historicalCorrection='Old NodeBB parsed files include flow-budget exhaustion: classify two revisions RESOURCE_LIMIT, not solely NOT_SUPPORTED. Historical files unchanged.',
        matrix=matrix, patchPairs=rows, applications=applications,
        controls=dict(count=len(controls['cases']), outcomes=controls['afterCounts'], split='REGRESSION', independent=False),
        benchmarks=benchmarks, protocol='ts-server-v11', limitsChanged=False, riskFormulaChanged=False,
        databaseMigration=False, userDatabaseWrites=False, paidAiCalls=0,
        newIndependentPublicExample='NOT_EVALUATED; no new independent or blind generalization claim',
        limitations=['No target CVE path or HTTP entry confirmed in the three actual patch pairs.',
            'Passport declarations are not dispatch, authorization, signature verification, or exploit proof.',
            'Static cache stores AST write-name plans only; runtime symbolic states are not cached.',
            'Timing includes startup; parent heap samples are not peak worker RSS.',
            'Live private GitHub, full application execution, operational attacks and external vulnerability lookups were not performed.',
            'Existing live backend was not restarted by this evaluation; isolated tests use v11.'])
    write(output, result)
    print(dict(matrix={k:v['targetOutcomes'] for k,v in matrix.items()}, controls=result['controls'], applications=len(applications)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ['base', 'output', 'packs']:
        parser.add_argument(name)
    report(**vars(parser.parse_args()))
