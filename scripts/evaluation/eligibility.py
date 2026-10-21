"""Evidence-gated evaluation suitability; never infers safety from no findings."""
import argparse
from collections import Counter
from benchmark import read, write, outside, digest, ID, SHA


CONDITIONS = ('VERIFIED_GROUND_TRUTH', 'CONTEXT_COMPLETE', 'ANALYZER_COMPATIBLE')


def conjunction(*values):
    if False in values:
        return False
    return True if all(value is True for value in values) else None


def assess(review):
    if not isinstance(review, dict) or set(review) != set(CONDITIONS):
        raise ValueError('THREE_EXPLICIT_CONDITIONS_REQUIRED')
    states = {}
    for name in CONDITIONS:
        evidence = review[name]
        value = evidence.get('value')
        if value is not None and type(value) is not bool:
            raise ValueError('TRISTATE_BOOLEAN_REQUIRED')
        reason = evidence.get('reason')
        refs = evidence.get('references')
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise ValueError('REASON_REQUIRED')
        if not isinstance(refs, list) or len(refs) > 30 or any(not isinstance(r, str) or not r.strip() or len(r) > 1000 for r in refs):
            raise ValueError('BOUNDED_REFERENCES_REQUIRED')
        if value is not None and not refs:
            raise ValueError('DECISION_REQUIRES_EVIDENCE')
        states[name] = value
    truth, context, compatible = (states[key] for key in CONDITIONS)
    return dict(conditions=review,
        EXTENSION_CANDIDATE=conjunction(truth, context, None if compatible is None else not compatible),
        NOT_EVALUABLE=None if conjunction(truth, context) is None else not conjunction(truth, context),
        endToEndEligible=conjunction(truth, context, compatible),
        interpretation='Eligibility concerns only the declared evaluation path. An extension candidate needs separate scope/cost review, not automatic implementation. No vulnerability verdict, safety score, framework-wide support or exploit proof.')


def inventory(config, output):
    config_path = outside(config)
    plan = read(config_path)
    if plan.get('schemaVersion') != 1 or not isinstance(plan.get('datasets'), list) or len(plan['datasets']) > 30:
        raise ValueError('INVENTORY_SCHEMA_OR_LIMIT')
    if not SHA.fullmatch(plan.get('engineCommit', '')) or not isinstance(plan.get('scope'), str) or not plan['scope'].strip():
        raise ValueError('ENGINE_AND_SCOPE_REQUIRED')
    rows = []
    identities = set()
    for dataset in plan['datasets']:
        if not ID.fullmatch(dataset['id']):
            raise ValueError('DATASET_ID')
        manifest_path = outside(dataset['manifest'])
        manifest = read(manifest_path)
        items = manifest[dataset.get('itemsKey', 'cases')]
        if len(items) > 500:
            raise ValueError('ITEM_LIMIT')
        reviews = dataset['reviews']
        keys = {item[dataset.get('idKey', 'caseId')] for item in items}
        if set(reviews) != keys or len(items) != len(keys):
            raise ValueError('EXACT_REVIEW_COVERAGE_REQUIRED')
        for item in items:
            key = item[dataset.get('idKey', 'caseId')]
            identity = dataset['id']+'/'+key
            if identity in identities:
                raise ValueError('DUPLICATE_ASSET')
            identities.add(identity)
            source = {k:item[k] for k in ('repositoryUrl', 'repositoryCommitSha', 'cve', 'ghsa', 'language', 'framework', 'groundTruthLabel') if k in item}
            rows.append(dict(assetId=identity, dataset=dataset['id'], kind=dataset['kind'],
                source=source, manifestSha256=digest(manifest_path.read_bytes()),
                previousSplit=item.get('evaluationSplit', item.get('split')),
                independence=dataset['independence'], **assess(reviews[key])))
    counts = {key:dict(Counter('MET' if r[key] is True else 'NOT_MET' if r[key] is False else 'UNKNOWN' for r in rows))
        for key in ('endToEndEligible', 'EXTENSION_CANDIDATE', 'NOT_EVALUABLE')}
    result = dict(schemaVersion=1, scope=plan['scope'], engineCommit=plan['engineCommit'],
        inventoryConfigSha256=digest(config_path.read_bytes()), assetCount=len(rows),
        counts=counts, kinds=dict(Counter(r['kind'] for r in rows)), assets=rows,
        conditionCounts={key:dict(Counter('MET' if r['conditions'][key]['value'] is True else 'NOT_MET' if r['conditions'][key]['value'] is False else 'UNKNOWN' for r in rows)) for key in CONDITIONS},
        limits=['Curator assessments and their source versions are explicit; the tool does not adjudicate a CVE.',
            'No source is executed or parsed here. File availability, no findings and entry counts cannot establish completeness.',
            'Historical split names are provenance, not a claim that a new blind evaluation occurred.',
            'Different revisions and control variants are assets, not independent vulnerability families.'])
    write(outside(output), result)
    print(dict(assets=len(rows), counts=counts))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('config')
    parser.add_argument('output')
    inventory(**vars(parser.parse_args()))
