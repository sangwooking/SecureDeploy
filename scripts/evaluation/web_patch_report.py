"""Target-specific, grade-separated results. Original application code stays local."""
import argparse
from collections import Counter
from pathlib import Path
from benchmark import read, write, validate, digest, score, stable, relative
from web_patch_cases import BASELINE, SPECS, verify_patch


def location(root, case, name, needle):
    path=root/'cases'/case/relative(name)
    matches=[i for i,line in enumerate(path.read_text().splitlines(),1) if needle in line]
    if not matches:raise ValueError('EVIDENCE_ANCHOR_NOT_FOUND')
    return dict(filePath=name,lines=matches,contentSha256=digest(path.read_bytes()))


def asset_inventory(base):
    rows=[]
    for folder in ['pilot-2026-10-20-v2','realworld-2026-10-20-v3']:
        manifest=read(base/folder/'manifest.json')
        rows.append(dict(asset=folder,cases=len(manifest['cases']),
            datasets=dict(Counter(c['sourceDataset'] for c in manifest['cases'])),
            declaredSplits=dict(Counter(c['evaluationSplit'] for c in manifest['cases'])),
            reuse='Previously observed development/evaluation assets; no new blind claim. Split labels alone do not prove unread status.'))
    controls=read(base/'hardening6-controls-expanded'/'manifest.json')
    rows.append(dict(asset='hardening6-controls-expanded',grade='B',cases=len(controls['cases']),
        reuse='Observed held-out cases are regression; parent five-module failures remain alongside added local-helper variants.'))
    applications=read(base/'applications-2026-10-20-v2'/'application-plan.json')
    rows.append(dict(asset='applications-2026-10-20-v2',projects=len(applications['projects']),
        collected=sum(p['collectionStatus']!='COLLECTION_FAILED' for p in applications['projects']),
        reuse='Seven observed applications including NodeGoat; one collection failure. No whole-project truth label.'))
    return rows


def preserve_pack(path, pack):
    if path.is_symlink():raise ValueError('PACK_SYMLINK')
    if path.exists():
        if read(path)!=pack:raise ValueError('EXISTING_PACK_MUST_NOT_CHANGE')
    else:write(path,pack)


def report(root, output):
    root=Path(root).resolve()
    manifest=read(root/'manifest.json');validate(manifest,root)
    raw=read(root/'baseline-validation.json')
    if raw['engineCommit']!=BASELINE or raw['manifestSha256']!=digest((root/'manifest.json').read_bytes()):
        raise ValueError('BASELINE_OR_MANIFEST_CHANGED')
    scored=score(manifest,raw)
    if not scored['allRepeatsConsistent']:raise ValueError('REPEAT_INCONSISTENT')
    survey=read(root/'survey-review.json')
    for candidate in survey['candidates']:
        if candidate['ghsa'] in {s['ghsa'] for s in SPECS}:
            candidate['truthGrade']='A';candidate['support']='NOT_SUPPORTED'
            candidate['gradeBasis']='POST_COLLECTION_PATCH_FACT_REVIEW'
    survey['candidates'].append(dict(repository='FlowiseAI/Flowise',ghsa='GHSA-hr92-4q35-4j3m',cve='CVE-2025-59527',
        summary='SSRF in fetch-links endpoint',cwes=['CWE-918'],
        advisoryUrl='https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-hr92-4q35-4j3m',
        vulnerableSourceSha='5930f1119c655bcf8d2200ae827a1f5b9fec81d0',fixedCommitSha=None,
        status='NOT_SELECTED_PATCH_IDENTITY_AND_COMPLETE_CONTEXT_NOT_VERIFIED',truthGrade=None,
        review='Request query -> service -> webCrawl/xmlScrape fetch described by maintainer; fixed release 3.0.6 but precise causally reviewed patch not established in this intake.',
        retention='Advisory example bearer strings are not retained; body cache removed, values never used.',
        reservation='Not engine-evaluated; no validated or blind holdout claim.'))
    survey['screenedCandidates']=len(survey['candidates'])
    by_id={r['caseId']:r for r in raw['results']}
    cases={c['caseId']:c for c in manifest['cases']}
    rows=[];packs=[]
    for spec in SPECS:
        texts={}
        for revision in ['parent','fixed']:
            case=cases[spec['id']+'-'+revision]
            for item in case['files']:
                path=root/'cases'/case['caseId']/relative(item['path'])
                texts[(revision,item['path'])]=path.read_text()
        patch_facts=verify_patch(spec,texts)
        results=[]
        for revision in ['parent','fixed']:
            cid=spec['id']+'-'+revision;case=cases[cid];row=by_id[cid]['runs'][0]
            ts=row['typescript'];coverage=row['coverage']
            scored_case=next(r for r in scored['results']if r['caseId']==cid)
            results.append(dict(caseId=cid,revision=revision,sha=case['repositoryCommitSha'],
                label=case['groundTruthLabel'],labelScope=case['labelScope'],
                retainedFiles=len(case['files']),fileReceipts=case['files'],contextOmissions=case['contextOmissions'],
                coverage=coverage,parserStatus=ts['status'],parsedFiles=sum(f['parseStatus']=='PARSED'for f in ts['files']),
                recognizedEntries=sum(f['entrypoints']for f in ts['files']),
                functionsAnalyzed=sum(f['functionsAnalyzed']for f in ts['files']),
                analyzerFiles=ts['files'],sourceFlow='NOT_TRACED',sinkContract=spec['support'],
                defenseRecognition='STATIC_MANUAL_PATCH_FACTS_ONLY_NOT_ENGINE_PROOF',
                layers=scored_case['layers'],nonTargetRuleAlerts=row['filtered'],
                reviewCandidates=row['reviewCandidates'],elapsedMs=[r['elapsedMs']for r in by_id[cid]['runs']],
                parentHeapSamples=[r['parentHeapUsedBytes']for r in by_id[cid]['runs']],
                sca=row['sca'],repeatConsistent=stable(by_id[cid]['runs'][0])==stable(by_id[cid]['runs'][1])))
        pack=dict(pairId=spec['id'],grade='A',advisory=cases[spec['id']+'-parent']['labelEvidence'],
            cve=spec['cve'],ghsa=spec['ghsa'],repository='https://github.com/'+spec['repository'],
            parentSha=spec['parent'],fixedSha=spec['fixed'],cwe=spec['cwe'],framework=spec['framework'],
            sourceToDecisionOrSink=spec['flow'],patchDefense=spec['defense'],scope=spec['scope'],patchFacts=patch_facts,
            confirmedSupportGap=spec['gap'],unverifiedHypothesis=spec['hypothesis'],
            contextLimit='Selected original files only; bootstrap callers and third-party package implementation are not complete. No runtime reachability proof.',
            patchLocations={r:cases[spec['id']+'-'+r]['targetSites'] for r in ['parent','fixed']},
            evidenceAnchors=[],targetAlertCount=sum(r['layers']['finalUser']['matches']for r in results),
            recommendedRegression='Preserve both exact revisions and add minimal independent dangerous/normal/unknown cases for any future adapter; no source-name special cases.',
            independentTruthReview='Pending second curator. Sources are independently published, labels/results are not blinded.',
            runtimeAttack='NOT_RUN')
        if spec['id']=='nodebb-api-token':
            for revision,needle in [('parent','tokens[token]'),('fixed','tokens.find')]:
                pack['evidenceAnchors'].append(location(root,spec['id']+'-'+revision,spec['targets'][0],needle))
            pack['evidenceAnchors'].append(location(root,spec['id']+'-fixed','src/middleware/user.js',"passport.authenticate('core.api'"))
        elif spec['id']=='ghost-content-filter':
            for revision,needle in [('parent',"'${slug}'"),('fixed','bindings.push')]:
                pack['evidenceAnchors'].append(location(root,spec['id']+'-'+revision,spec['targets'][0],needle))
            pack['evidenceAnchors'].append(location(root,spec['id']+'-fixed','ghost/core/core/server/web/api/endpoints/content/routes.js',"router.get('/tags'"))
        else:
            pack['evidenceAnchors'].append(location(root,spec['id']+'-parent','packages/core/database/src/schema/builder.ts','db.connection.raw(value)'))
            pack['evidenceAnchors'].append(location(root,spec['id']+'-fixed',spec['targets'][1],'autoReload !== true'))
        rows.append(dict(pairId=spec['id'],grade='A',results=results));packs.append(pack)
    output=Path(output)
    result=dict(schemaVersion=1,engineCommit=BASELINE,engineChanged=False,riskPolicyChanged=False,
        runnerVersion=raw['runnerVersion'],accountingVersion=scored['accountingVersion'],manifestSha256=raw['manifestSha256'],
        assets=asset_inventory(root.parent),survey=survey,
        acquisitionStages=['v1 retained initial guessed-path 404s and baseline; v2 corrected routing; v3 final context and baseline. None discarded to select a positive outcome.'],
        gradeA=dict(pairs=3,revisions=6,projects=3,supportedEndToEndPairs=0,independentOfNodeGoat=True,
            independentCuratorOrBlind=False,groundTruth='Maintainer advisory plus reviewed original patch; condition-local fixed label.'),
        gradeB=dict(newCases=0),gradeC=dict(newScoredCases=0),
        languagePairs={'JavaScript':2,'TypeScript':1},cwePairs=dict(Counter(s['cwe']for s in SPECS)),
        pairs=rows,failureCasePacks=packs,targetResults=scored['summary'],
        interpretation='Six NOT_SUPPORTED revisions are not six false negatives or true negatives; no supported dangerous/normal pair was established. Unrelated package alerts are excluded from target success.',
        reservations='Directus/Flowise metadata candidates are not engine evaluated and not validated holdout pairs. Future exact-SHA truth freeze and second-curator review required; no blind claim.',
        commonImprovementCandidates=[
            dict(capability='Framework entry/callback and route-factory contracts',evidence=['nodebb-api-token','ghost-content-filter','strapi-content-builder'],
                limit='Framework adapters must be bounded and distinguish missing context from absent handlers.'),
            dict(capability='ORM raw SQL value/binding and option propagation',evidence=['ghost-content-filter','strapi-content-builder'],
                limit='Bookshelf orderRaw and Knex schema raw defaults are different APIs; no API-name-only safe or vulnerable label.'),
            dict(capability='Authorization decision and environment guard evidence',evidence=['nodebb-api-token','strapi-content-builder'],
                limit='Typed lookup/uid/master decisions and production-only middleware require distinct semantics; no generic missing-check Finding.')],
        repeatConsistent=scored['allRepeatsConsistent'],resourceLimitsChanged=False,
        memoryMeasurement='Parent JVM samples only, not worker peak/RSS. Time is per frozen context subset, not full application.',
        externalCalls='Anonymous GitHub/raw source and public advisory web research only; no AI/OSV/EPSS/KEV requests.',
        safety=dict(originalSourcesInGit=False,targetExecution=False,targetInstall=False,targetBuild=False,
            targetMutation=False,paidAiCalls=0,userDatabaseWrites=False,permissionDenials=0),
        accessLimits=['Global Directus advisory lookup returned HTTP 404; repository advisory remained readable. No authorization bypass attempted.',
            'Initial guessed source paths returned 404; corrected from pinned directory listings and retained as historical intake evidence.',
            'No full CVEfixes database download, service attack, patch test execution, independent second review or validated blind holdout.'])
    pack_root=root/'failure-packs'
    if pack_root.is_symlink():raise ValueError('PACK_SYMLINK')
    pack_root.mkdir(mode=0o700,exist_ok=True)
    for pack in packs:preserve_pack(pack_root/(pack['pairId']+'.json'),pack)
    write(output,result)
    print(dict(candidates=len(survey['candidates']),gradeAPairs=3,supportedPairs=0,targetResults=scored['summary']['finalUser']['counts'],repeatConsistent=result['repeatConsistent']))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('root');parser.add_argument('output')
    report(**vars(parser.parse_args()))
