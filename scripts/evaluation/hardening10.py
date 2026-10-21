"""Source-free controlled-path delta and bounded support-gap review."""
import argparse
from collections import Counter
from benchmark import read, write, outside, digest, validate, stable, score
from hardening4 import summary

SAMPLES = [
    ('pilot-2026-10-20-v2','owasp-BenchmarkTest00018','SOURCE_API_AND_CALL_LINKAGE',
     'Servlet route and JDBC sink exist; getHeaders Enumeration.nextElement input contract is not confirmed. Legacy pattern TP is not structural proof.'),
    ('pilot-2026-10-20-v2','django-28346-parent','LIBRARY_BOUNDARY_AND_CONTEXT',
     'ORM annotation alias library code is retained, not an application request-to-SQL compiler path. A patch truth label does not supply missing callers.'),
    ('realworld-2026-10-20-v3','vul4j-2-parent','UNSUPPORTED_SECURITY_API_AND_CONTEXT',
     'SAX parser feature defense is reviewed, but XML input caller and XXE execution contract are outside current Java SQL analysis.'),
    ('realworld-2026-10-20-v3','vul4j-18-parent','CALLER_CONTEXT_AND_UNSUPPORTED_SINK',
     'getPathInfo appears in a URL-construction helper; downstream servlet forward and Java path-flow contract are not complete.'),
    ('realworld-2026-10-20-v3','cvefixes-cve-2017-0881-parent','AUTHORIZATION_MODEL_AND_CONTEXT',
     'Zulip request endpoint exists, but custom decorators, private-stream policy and subscription side effects are not the supported DRF ownership contract.'),
    ('realworld-2026-10-20-v3','cvefixes-cve-2024-23334-parent','UNSUPPORTED_FRAMEWORK_AND_RUNTIME',
     'aiohttp StaticResource is not a Django view; follow_symlinks and filesystem state remain separate conditions.'),
    ('realworld-2026-10-20-v3','cvefixes-cve-2023-34110-parent','UNSUPPORTED_FRAMEWORK_AND_CONTEXT',
     'Flask-AppBuilder model exception messaging needs UI propagation; a logger/exception string alone is not client exposure.'),
    ('realworld-2026-10-20-v3','cvefixes-cve-2024-34351-parent','UNSUPPORTED_FRAMEWORK_INTERNAL_ENTRY',
     'Next server-action internals use a request-host redirect path, not the currently recognized Workers/Pages/Express request contract.'),
    ('hardening6-controls-expanded','validation-string','CALL_LINKAGE_AND_RESOURCE_BOUND',
     'Existing probe records NODE_MODULE_CYCLE_OR_DEPTH_LIMIT and CALL_TARGET_UNRESOLVED; not a time/memory failure or a safe negative.'),
    ('applications-2026-10-20-v2','vercel--nextjs-postgres-nextauth-tailwindcss-template','GROUND_TRUTH_AND_ENTRY_CONTRACT',
     'No whole-project truth label; Next application handler dispatch is not supported. No-warning cannot become TN.'),
    ('applications-2026-10-20-v2','wagtail--bakerydemo','GROUND_TRUTH_AND_EXTERNAL_INHERITANCE',
     'Function search route is supported as Grade B proves; Wagtail Page inheritance and framework runtime are not thereby fully analyzed.'),
]

TRACK_B = [
    dict(priority=1,area='Supported Java request collections',gap='Enumeration/array input APIs and bounded value propagation',
         reuse='Servlet/Spring request paths, demonstrated by retained BenchmarkTest00018',cost='Small/medium adapter with dangerous/static/binding pairs',risk='Do not treat every Enumeration as request-derived.'),
    dict(priority=2,area='Django/DRF external generic bases',gap='Known dispatch/queryset/permission inheritance with explicit overrides',
         reuse='Wagtail and Netbox-like class based applications; function views already work',cost='Medium/high; scope library versions and middleware',risk='Unknown mixins must not imply absent or proven ownership.'),
    dict(priority=3,area='Next.js / NestJS explicit server entries',gap='App handler or controller/decorator request contracts',
         reuse='Reuse SQL/SSRF value tracing; Next internals are a separate contract',cost='Medium per framework, separate fixtures required',risk='No retained canonical NestJS app was verified; do not claim measured Nest misses.'),
    dict(priority=4,area='Flowise static module/lifecycle linkage',gap='Workspace main/dist/barrels and proven startup method effects',
         reuse='Monorepo Express applications',cost='Medium/high; more than one current gap',risk='Conditional deny-list and redirects cannot be declared universally safe.'),
    dict(priority=5,area='Ghost Bookshelf/Knex',gap='Verified raw receiver and bindings plus API option propagation',
         reuse='Query builders across applications',cost='High for full Ghost path; narrow sink evidence may be smaller',risk='Do not certify raw SQL from a method name or route recognition.'),
    dict(priority=6,area='NodeBB Passport',gap='Proven strategy use/dispatch plus prototype-sensitive authorization decisions',
         reuse='Passport applications beyond one CVE',cost='High for full boundary; declaration evidence already exists',risk='Callback declaration is not HTTP execution or authorization proof.'),
    dict(priority=7,area='Strapi Koa dynamic registry',gap='Koa route/controller/config hydration and Knex schema effects',
         reuse='Koa/Strapi platforms',cost='High, needs versioned framework acceptance fixtures',risk='Production-only guard is not development or whole-project safety.'),
]


def report(base, output, packs):
    base = outside(base)
    root = base/'hardening10-format-v1'
    plan = read(root/'manifest.json')
    validate(plan,root)
    manifest_hash = digest((root/'manifest.json').read_bytes())
    comparisons = {}
    engine = None
    pack_rows = []
    for split in ['regression','validation']:
        stages = {}
        for stage in ['before','after']:
            raw = read(root/(stage+'-'+split+'.json'))
            if raw['manifestSha256'] != manifest_hash:
                raise ValueError('SOURCE_CHANGED')
            scored = score(plan,raw)
            rows = []
            for case in raw['results']:
                if len(case['runs']) != 2 or stable(case['runs'][0]) != stable(case['runs'][1]):
                    raise ValueError('NONDETERMINISTIC')
                run = case['runs'][0]
                target = next(c for c in plan['cases'] if c['caseId']==case['caseId'])
                uses = [u for u in run['python']['sqlUses'] if u['location']['filePath']==target['targetSites'][0]['filePath'] and u['location']['line']==target['targetSites'][0]['startLine']]
                if len(uses) != 1 or not uses[0]['executionObserved']:
                    raise ValueError('TARGET_NOT_INSPECTED')
                rows.append(dict(caseId=case['caseId'],label=target['groundTruthLabel'],sqlKind=uses[0]['kind'],
                    confidence=[f['confidence']for f in run['python']['findings'] if f['sink']==uses[0]['location']],
                    elapsedMs=[r['elapsedMs']for r in case['runs']],parentHeapSamples=[r['parentHeapUsedBytes']for r in case['runs']],
                    coverage=run['coverage']['status'],score=run['securityScore'],riskPolicy=run['risk']['policyVersion'],
                    priority=run['risk']['prioritySummary'],assessment=run['risk']['prioritizedDeploymentAssessment']))
            stages[stage] = dict(engineCommit=raw['engineCommit'],layers={k:v['counts']for k,v in scored['summary'].items()},cases=rows)
            if stage=='after':engine=raw['engineCommit']
        for row in stages['after']['cases']:
            previous = next(r for r in stages['before']['cases'] if r['caseId']==row['caseId'])
            if any(previous[key]!=row[key]for key in ['score','riskPolicy','priority','assessment']):
                raise ValueError('RISK_OR_SCORE_CHANGED')
            if row['label']=='DANGEROUS' and row['confidence']!=['HIGH']:
                raise ValueError('RISK_ABSTENTION_REGRESSION')
            if row['label']=='SAFE' and row['sqlKind'] not in {'STATIC_QUERY','PARAMETERIZED_QUERY'}:
                raise ValueError('FALSE_POSITIVE_MOVED_TO_UNKNOWN')
            pack_rows.append(dict(caseId=row['caseId'],before=previous,after=row))
        comparisons[split] = stages
    inventory = read(base/'hardening9-eligibility-inventory.json')
    unknown = [r for r in inventory['assets'] if r['endToEndEligible'] is None]
    samples = []
    for dataset,cid,cause,evidence in SAMPLES:
        item = next(r for r in unknown if r['assetId']==dataset+'/'+cid)
        samples.append(dict(assetId=item['assetId'],category=cause,evidence=evidence,
            source=item['source'],reference=item['manifestSha256'],
            reviewScope='Purposive source/retained-evidence and current-contract review; no new exploit, independent truth adjudication or blind source execution.'))
    benchmarks = {}
    for name,folder in [('pilot','pilot-2026-10-20-v2'),('realworld','realworld-2026-10-20-v3')]:
        directory = base/folder
        old = read(directory/'hardening8-regression.json')
        new = read(directory/'hardening10-regression.json')
        manifest = read(directory/'manifest.json')
        a,b = score(manifest,old),score(manifest,new)
        if a['summary']!=b['summary']:
            raise ValueError('OLD_BENCHMARK_CHANGED')
        benchmarks[name] = {k:v['counts']for k,v in b['summary'].items()}
    app_root = base/'applications-2026-10-20-v2'
    old,new = read(app_root/'hardening8-after.json'),read(app_root/'hardening10-after.json')
    if old['planSha256']!=new['planSha256']:
        raise ValueError('APPLICATION_INPUT_CHANGED')
    apps=[]
    for project in new['projects']:
        previous = next(p for p in old['projects']if p['projectId']==project['projectId'])
        if not project.get('runs'):
            if previous.get('runs'):raise ValueError('COLLECTION_CHANGED')
            apps.append(dict(projectId=project['projectId'],status='COLLECTION_FAILED_NOT_SAFE'));continue
        if stable(project['runs'][0])!=stable(project['runs'][1]):raise ValueError('APPLICATION_REPEAT_CHANGED')
        a,b = summary(previous['runs'][0]),summary(project['runs'][0])
        for key in ['rules','securityScore','prioritySummary','deploymentAssessment','java']:
            if a[key]!=b[key]:raise ValueError('APPLICATION_LEGACY_REGRESSION')
        for key in ['typescript','java']:
            if stable(previous['runs'][0][key])!=stable(project['runs'][0][key]):
                raise ValueError('APPLICATION_STRUCTURAL_REGRESSION')
        if previous['runs'][0]['python']['findings']!=project['runs'][0]['python']['findings']:
            raise ValueError('ORIGINAL_APPLICATION_PYTHON_FINDINGS_CHANGED')
        apps.append(dict(projectId=project['projectId'],sourceCommit=project['commitSha'],legacyRiskJavaUnchanged=True,
            pythonFindings=len(project['runs'][0]['python']['findings']),typescriptFindings=len(project['runs'][0]['typescript']['findings'])))
    result = dict(schemaVersion=1,baselineCommit=plan['engineBaselineCommit'],engineCommit=engine,
        productionChange='Bounded static str.format field selection; unknown dynamic/compound/spec cases remain reviewable.',
        protocol='py-django-v8',accountingVersion='PYTHON_SQL_NEGATIVE_EVIDENCE_V3',
        accountingCorrection='Old scorer ignored target-local Python STATIC_QUERY/PARAMETERIZED_QUERY call evidence; same raw outputs are rescored with the same new accounting on both sides.',
        manifestSha256=manifest_hash,grade=dict(A=0,B=len(plan['cases']),C='Seven observed public app regressions plus one preserved acquisition failure'),
        controlled=comparisons,unknownInventory=dict(total=len(unknown),byKind=dict(Counter(r['kind']for r in unknown)),samples=samples,
            interpretation='87 eligibility unknowns are not 87 engine UNKNOWN outcomes. 11 purposive reviews do not estimate population frequencies; old inventory is not overwritten.'),
        trackB=TRACK_B,benchmarks=benchmarks,applications=apps,
        runtime=dict(pythonProtocol='py-django-v8',typescriptProtocol='ts-server-v11',
            restart=read('/private/tmp/securedeploy-hardening10-runtime-receipt.json')['restart'],
            protectedConfigurationPreserved=read('/private/tmp/securedeploy-hardening10-runtime-receipt.json')['protectedConfigurationPreserved'],schema='validate'),
        riskFormulaChanged=False,limitsIncreased=False,migration=False,historicalSnapshotsRecomputed=False,
        validation=dict(backendTotal=514,backendPassed=507,backendSkipped=7,python=117,typescript=172,frontend=106,evaluationTools=122,
            frontendBuild='PASS',browserWidths=[1440,390,320],commonTransport='Real ZIP/H2 save/detail/access tests; public/private GitHub acquisition mocked.'),
        independence='Validation originates from a different repository, but shares the targeted weakness and is single-curator controlled educational-app variation. Not blind or new actual-CVE detection.',
        limitations=['Unrelated original request bodies retain unsupported framework calls; target sink is inserted before them. Scope is only the controlled sink, not whole app safety.',
            'No new Grade A pair or whole-project accuracy claim. Metrics on 12 binary cases plus two intended unknowns are not product-wide rates.',
            'No external target execution/install/build, paid AI, operational attack, OSV/EPSS/KEV lookup or user PostgreSQL write.',
            'Parent heap samples and short repeated timings are not peak worker RSS or a causal speedup proof.'])
    packs=outside(packs);packs.mkdir(mode=0o700)
    write(packs/'python-format-unused-argument.json',dict(engineCommit=engine,baselineCommit=plan['engineBaselineCommit'],
        sources=[dict(caseId=c['caseId'],repository=c['repositoryUrl'],sourceCommit=c['repositoryCommitSha'],target=c['targetSites'],files=c['files'])for c in plan['cases']],
        cause='All format arguments merged instead of only referenced fields; side effects already evaluated separately.',
        results=pack_rows,remaining=result['limitations'],regressionTests='analyzers/python/test_string_format.py',
        publicSourceRedistributed=False))
    write(output,result)
    print(dict(engineCommit=engine,gradeB=len(plan['cases']),unknownReviewed=len(samples),apps=len(apps)))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for arg in ['base','output','packs']:parser.add_argument(arg)
    report(**vars(parser.parse_args()))
