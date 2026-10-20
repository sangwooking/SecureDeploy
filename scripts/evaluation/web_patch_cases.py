"""Curated Grade A application patch pairs, kept outside the source checkout."""
import argparse
import json
import urllib.error
from benchmark import Fetcher, outside, write, digest, validate, relative
from prepare_realworld import patch_sites

BASELINE = 'd450c17b1adbb3c345f4152fad997c0a7992147c'
SPECS = [
    dict(id='nodebb-api-token',repository='NodeBB/NodeBB',ghsa='GHSA-hf2m-j98r-4fqw',cve='CVE-2021-43786',
        fixed='04dab1d550cdebf4c1567bca9a51f8b9ca48a500',parent='1783f918bc19568f421473824461ff2ed7755e4c',
        cwe='CWE-287',area='AUTHORIZATION',framework='Express + Passport bearer strategy',license='GPL-3.0',
        targets=['src/routes/authentication.js'],
        context=['src/routes/write/index.js','src/routes/index.js','src/middleware/index.js','src/middleware/user.js','src/meta/settings.js','src/meta/index.js','src/api/index.js','install/package.json','LICENSE'],
        flow='HTTP bearer token -> registered Passport BearerStrategy -> Auth.verifyToken(token, done) -> plain-object token lookup -> uid undefined/positive check -> master:true callback.',
        defense='Replace plain-object indexed lookup with strict token equality in Array.find and derive uid only from a found token record.',
        scope='Named inherited-property token lookup defect only, not all authentication or session behavior.',
        support='NOT_SUPPORTED',gap='Passport strategy callbacks and prototype-sensitive authorization decisions are not supported by the bounded Express data-flow contracts.',
        hypothesis='A framework callback source contract plus typed token lookup/decision evidence may generalize; no such extension is implemented.'),
    dict(id='ghost-content-filter',repository='TryGhost/Ghost',ghsa='GHSA-w52v-v783-gw97',cve='CVE-2026-26980',
        fixed='30868d632b2252b638bc8a4c8ebf73964592ed91',parent='ebf4bb79cb45e487e277318df61c6c559752fd0a',
        cwe='CWE-89',area='INPUT_INJECTION',framework='Express + Ghost API framework + Bookshelf/Knex',license='MIT',
        targets=['ghost/core/core/server/api/endpoints/utils/serializers/input/utils/slug-filter-order.js','ghost/core/core/server/models/base/plugins/crud.js'],
        context=['ghost/core/core/server/web/api/endpoints/content/app.js','ghost/core/core/server/web/api/endpoints/content/routes.js',
            'ghost/core/core/server/web/api/endpoints/content/middleware.js','ghost/core/core/server/web/api/app.js',
            'ghost/core/core/server/api/endpoints/tags.js',
            'ghost/core/core/server/api/endpoints/utils/serializers/input/tags.js',
            'ghost/core/core/server/api/endpoints/utils/serializers/input/posts.js',
            'ghost/core/core/server/api/endpoints/utils/serializers/input/index.js',
            'ghost/core/core/server/models/tag.js','ghost/core/package.json','LICENSE'],
        flow='Content API tags/posts filter -> input serializer autoOrder -> slug-filter-order interpolates slug into CASE SQL -> CRUD options.orderRaw -> external Bookshelf query plugin.',
        defense='CASE value/index placeholders and separate bindings; CRUD forwards orderRawBindings; patch also upgrades Bookshelf plugins.',
        scope='Slug filter ordering SQL only. The external query plugin implementation and live database behavior are not executed or fully retained.',
        support='NOT_SUPPORTED',gap='Node SQL sink contracts do not cover Bookshelf/Knex orderRaw; API serializer/ORM callback plumbing crosses unsupported library boundaries.',
        hypothesis='Explicit ORM raw-query/bindings contracts and API option propagation may be reusable; route recognition alone would not prove this flow.'),
    dict(id='strapi-content-builder',repository='strapi/strapi',ghsa='GHSA-3xcq-8mjw-h6mx',cve='CVE-2026-22599',
        fixed='0150b197100692b5bfb9eeb498f30f62c4067a4d',parent='f86041c89a8c1545c6437a881dc613e98bc52bd7',
        cwe='CWE-89',area='INPUT_INJECTION',framework='Strapi Koa route configuration + Knex schema builder',license='MIT (retained community core; enterprise excluded)',
        targets=['packages/core/content-type-builder/server/src/routes/admin.ts','packages/core/content-type-builder/server/src/middlewares/is-development-mode.ts'],
        context=['packages/core/content-type-builder/server/src/index.ts',
            'packages/core/content-type-builder/server/src/middlewares/index.ts',
            'packages/core/content-type-builder/server/src/controllers/content-types.ts',
            'packages/core/content-type-builder/server/src/controllers/validation/content-type.ts',
            'packages/core/content-type-builder/server/src/services/content-types.ts',
            'packages/core/content-type-builder/server/src/services/builder.ts',
            'packages/core/content-type-builder/server/src/services/api-handler.ts',
            'packages/core/content-type-builder/server/src/utils/index.ts',
            'packages/core/database/src/schema/schema.ts','packages/core/database/src/schema/builder.ts',
            'packages/core/content-type-builder/package.json','LICENSE'],
        flow='Admin content-type route -> controller ctx.request.body -> content-type service/schema metadata -> column.defaultTo tuple -> database raw schema default.',
        defense='Register isDevelopmentMode middleware on write routes; reject when autoReload is not exactly true.',
        scope='Production autoReload != true only. Patch intentionally leaves development schema editing available; it does not sanitize every raw schema value.',
        support='NOT_SUPPORTED',gap='Strapi route tables, Koa context, environment-dependent middleware and Knex schema defaults have no supported end-to-end contract.',
        hypothesis='Framework route/config guard evidence and schema option contracts are separate capabilities; no safe conclusion from a middleware name alone.')
]


def verify_patch(spec, texts):
    """Necessary reviewed patch facts, not an exploit or complete safety proof."""
    if spec['id']=='nodebb-api-token':
        name=spec['targets'][0];before=texts[('parent',name)];after=texts[('fixed',name)]
        checks=["tokens[token]" in before,"tokens.reduce" in before,
            "tokens.find(t => t.token === token)" in after,"new BearerStrategy({}, Auth.verifyToken)" in after]
    elif spec['id']=='ghost-content-filter':
        name=spec['targets'][0];before=texts[('parent',name)];after=texts[('fixed',name)]
        checks=["'${slug}'" in before,'bindings.push(slug.trim(), index)' in after,
            '= ? THEN ?' in after,'options.orderRawBindings = options.autoOrder.bindings' in texts[('fixed',spec['targets'][1])]]
    else:
        guard=texts[('fixed',spec['targets'][1])]
        checks=['autoReload !== true' in guard,'throw new errors.PolicyError' in guard,
            'middlewares: [isDevelopmentMode]' in texts[('fixed',spec['targets'][0])],
            'middlewares: [isDevelopmentMode]' not in texts[('parent',spec['targets'][0])],
            'db.connection.raw(value)' in texts[('parent','packages/core/database/src/schema/builder.ts')]]
    if not all(checks):raise ValueError('REVIEWED_PATCH_FACT_MISMATCH')
    return dict(checks=len(checks),status='STATIC_PATCH_FACTS_MATCH',runtimeVerified=False)


def build(root, survey_root):
    root = outside(root)
    root.mkdir(mode=0o700)
    (root / 'cases').mkdir(mode=0o700)
    fetcher = Fetcher(root.parent / 'cache')
    plan = dict(schemaVersion=1,engineBaselineCommit=BASELINE,cases=[],assets=[],
        grade='A',evaluationScope='Unmodified selected application context, not full repository coverage.',
        reviewer='Single curator; external sources and maintainer patches, not independent truth adjudication or blind evaluation.',
        splitPolicy='Both revisions/project/CVE/family stay VALIDATION; all observed results become regression. Reserved candidates are not validated holdout truth.')
    failures = []
    for spec in SPECS:
        repo = spec['repository']
        advisory = f'https://github.com/{repo}/security/advisories/{spec["ghsa"]}'
        commit_url = f'https://api.github.com/repos/{repo}/commits/{spec["fixed"]}'
        commit = json.loads(fetcher.fetch(commit_url))
        if commit['sha'] != spec['fixed'] or commit['parents'][0]['sha'] != spec['parent']:
            raise ValueError('PATCH_PARENT_IDENTITY')
        texts = {}; receipts = {}; omitted = []
        for revision in ['parent','fixed']:
            sha = spec[revision]
            directory = root / 'cases' / (spec['id'] + '-' + revision)
            directory.mkdir(mode=0o700)
            receipts[revision] = []
            for name in dict.fromkeys(spec['targets'] + spec['context']):
                path = directory / relative(name)
                url = f'https://raw.githubusercontent.com/{repo}/{sha}/{name}'
                try:
                    data = fetcher.fetch(url)
                except urllib.error.HTTPError as error:
                    if error.code != 404: raise
                    expected_added=revision=='parent'and any(f['filename']==name and f['status']=='added'for f in commit['files'])
                    omitted.append(dict(revision=revision,path=name,reason='ADDED_BY_PATCH_NOT_PRESENT_IN_PARENT'if expected_added else'NOT_PRESENT_AT_PINNED_SHA',httpStatus=404))
                    continue
                data.decode('utf-8')
                path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with path.open('xb') as stream:
                    path.chmod(0o600);stream.write(data)
                texts[(revision,name)] = data.decode()
                receipts[revision].append(dict(path=name,url=url,sha256=digest(data)))
            if not any(f['path']=='LICENSE' for f in receipts[revision]):
                raise ValueError('LICENSE_REQUIRED')
        patch_facts=verify_patch(spec,texts)
        sites = dict(parent=[],fixed=[])
        for target in spec['targets']:
            before = texts.get(('parent',target),''); after = texts.get(('fixed',target),'')
            if before == after: raise ValueError('NO_SECURITY_PATCH_CHANGE')
            changed = patch_sites(target,before,after)
            for revision in ['parent','fixed']:
                if (revision,target) in texts: sites[revision].extend(changed[revision])
        for revision in ['parent','fixed']:
            if not sites[revision]: raise ValueError('PATCH_TARGET_MISSING')
            sha = spec[revision]
            case = dict(caseId=spec['id']+'-'+revision,pairId=spec['id'],grade='A',sourceDataset='Maintainer advisory + original application security patch',
                repositoryUrl='https://github.com/'+repo,repositoryCommitSha=sha,vulnerableCommitSha=spec['parent'],fixedCommitSha=spec['fixed'],
                repositoryGroup=repo,forkGroup=repo,vulnerabilityFamily=spec['id'],cve=spec['cve'],ghsa=spec['ghsa'],cwe=spec['cwe'],
                language='JAVASCRIPT' if spec['id']!='strapi-content-builder' else 'TYPESCRIPT',framework=spec['framework'],area=spec['area'],license=spec['license'],
                groundTruthLabel='DANGEROUS' if revision=='parent' else 'SAFE',reviewed=True,evaluationSplit='VALIDATION',
                patchFacts=patch_facts,cweProvenance='Maintainer advisory or analyst classification of the named patch; not an engine inference',
                labelEvidence=[advisory,commit['html_url']],groundTruthConfidence='MAINTAINER_ADVISORY_AND_PATCH_STATIC_REVIEW',
                labelScope=spec['scope'],sourceToSinkEvidence=spec['flow'],mitigationEvidence=spec['defense'],
                targetSites=sites[revision],sourceSites=[],patternRules=[],flowRules=[],
                supportAtIntake=spec['support'],confirmedSupportGap=spec['gap'],unverifiedImprovementHypothesis=spec['hypothesis'],
                contextOmissions=omitted,files=receipts[revision],requiredExternalContext='Third-party runtime/API contracts are not assumed from imports.')
            plan['cases'].append(case)
        print(json.dumps(dict(pair=spec['id'],files={r:len(v)for r,v in receipts.items()},omissions=len(omitted))),flush=True)
    survey = json.loads((outside(survey_root)/'survey.json').read_text())
    # Separately researched SQL advisory was not among the six newest Ghost items.
    ghost_url='https://api.github.com/advisories/GHSA-w52v-v783-gw97'
    ghost_bytes=fetcher.fetch(ghost_url);ghost=json.loads(ghost_bytes)
    if ghost['cve_id']!='CVE-2026-26980':raise ValueError('ADVISORY_CVE_IDENTITY')
    survey['candidates'].append(dict(repository='TryGhost/Ghost',ghsa=ghost['ghsa_id'],cve=ghost['cve_id'],
        summary=ghost['summary'],advisoryUrl=ghost['html_url'],cwes=[c['cwe_id'] for c in ghost['cwes']],
        references=ghost['references'],metadataUrl=ghost_url,metadataSha256=digest(ghost_bytes),
        truthGrade='A',support='NOT_SUPPORTED'))
    survey['screenedCandidates']=len(survey['candidates'])
    selected = {s['ghsa'] for s in SPECS}
    for candidate in survey['candidates']:
        candidate['status'] = 'SELECTED_PATCH_PAIR' if candidate['ghsa'] in selected else 'NOT_SELECTED_FOR_ENGINE_REPLAY'
        if candidate['ghsa'] in selected:
            candidate['truthGrade']='A';candidate['support']='NOT_SUPPORTED'
            candidate['gradeBasis']='POST_COLLECTION_PATCH_FACT_REVIEW'
        candidate['review'] = ('Original patch + necessary local routing/helper subset reviewed; support separately evaluated.' if candidate['ghsa'] in selected
            else 'Metadata only: fixed SHA and sufficient local context not yet jointly verified. Not a truth-labelled pair or a safe result.')
        if candidate['repository'] in {'directus/directus','FlowiseAI/Flowise'}:
            candidate['reservation'] = 'FUTURE_REVIEW_CANDIDATE_NOT_ENGINE_EVALUATED_NOT_VALIDATED_HOLDOUT'
    write(root/'survey-review.json',survey)
    validate(plan,root)
    plan['collection'] = dict(requests=fetcher.requests,bytes=fetcher.total,failures=failures,
        knownExternalReferenceFailure=dict(url='https://api.github.com/advisories/GHSA-97xr-jchp-xm3c',status=404,
            impact='Global advisory lookup unavailable; repository advisory was readable. No bypass or authentication attempted.'))
    write(root/'manifest.json',plan)
    print(json.dumps(validate(plan,root)))


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('root');parser.add_argument('survey_root')
    build(**vars(parser.parse_args()))
