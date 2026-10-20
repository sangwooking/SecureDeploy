"""Public advisory survey and bounded patch metadata; never executes targets."""
import argparse
import json
from pathlib import Path
import re
from benchmark import Fetcher, outside, write, digest

REPOSITORIES = ['NodeBB/NodeBB', 'TryGhost/Ghost', 'directus/directus', 'strapi/strapi', 'FlowiseAI/Flowise']


def survey(root):
    root = outside(root)
    root.mkdir(mode=0o700)
    # Advisory bodies can contain unverified example credentials. Keep them in
    # memory only and persist the allowlisted metadata below, never the body.
    fetcher = Fetcher()
    candidates = []
    for repository in REPOSITORIES:
        url = f'https://api.github.com/repos/{repository}/security-advisories?per_page=6'
        data = fetcher.fetch(url)
        advisories = json.loads(data)
        if not isinstance(advisories, list) or len(advisories) > 6:
            raise ValueError('ADVISORY_RESPONSE')
        for advisory in advisories:
            refs = advisory.get('references') or []
            refs = [r if isinstance(r, str) else r['url'] for r in refs]
            body = advisory.get('description') or ''
            commits = re.findall(r'https://github\.com/([\w.-]+/[\w.-]+)/commit/([0-9a-f]{7,40})', body + '\n' + '\n'.join(refs))
            candidates.append(dict(repository=repository,ghsa=advisory['ghsa_id'],cve=advisory.get('cve_id'),
                summary=advisory['summary'],advisoryUrl=advisory['html_url'],
                cwes=[w['cwe_id'] for w in advisory.get('cwes', [])],references=refs,
                explicitCommitReferences=[dict(repository=r,commit=s) for r,s in commits],
                metadataUrl=url,metadataSha256=digest(data),status='SCREENED_NOT_PATCH_VERIFIED',
                truthGrade=None,support='NOT_YET_REVIEWED',
                review='Public advisory metadata screened; source/patch causality and request wiring require separate review.'))
        print(json.dumps(dict(repository=repository,screened=len(advisories))),flush=True)
    result = dict(schemaVersion=1,candidates=candidates,screenedCandidates=len(candidates),
        selectionPolicy='Six published advisories returned per named application; no selection by engine detection.',
        requests=fetcher.requests,bytes=fetcher.total,originalSourcesInGit=False,
        independence='New external provenance, not blind or independently labelled. Existing observed corpora stay regression.')
    write(root / 'survey.json', result)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('root')
    survey(Path(parser.parse_args().root))
