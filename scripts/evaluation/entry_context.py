"""Versioned context enrichment only; never runs or modifies upstream code."""
import argparse
import copy
from pathlib import Path
import shutil
import urllib.error
from benchmark import Fetcher, outside, read, write, relative, digest, validate

ADDITIONS = {
    'nodebb-api-token': ['src/webserver.js','app.js','src/start.js','src/routes/helpers.js',
        'src/middleware/helpers.js','src/controllers/write/index.js','src/routes/write/users.js'],
    'ghost-content-filter': ['ghost/core/core/shared/express.js','ghost/core/core/server/api/index.js',
        'ghost/core/core/server/api/endpoints/index.js','ghost/core/core/server/api/endpoints/tags-public.js',
        'ghost/core/core/server/api/endpoints/utils/index.js','ghost/core/core/server/web/api/index.js',
        'ghost/core/core/server/web/ghost-app.js'],
    'strapi-content-builder': ['packages/core/core/src/services/server/register-routes.ts',
        'packages/core/core/src/services/server/index.ts','packages/core/core/src/services/server/api.ts',
        'packages/core/core/src/services/server/routing.ts','packages/core/core/src/services/server/compose-endpoint.ts']
}


def enrich(source, destination):
    source=outside(source);destination=outside(destination)
    original=read(source/'manifest.json');validate(original,source)
    destination.mkdir(mode=0o700);(destination/'cases').mkdir(mode=0o700)
    plan=copy.deepcopy(original)
    plan['engineBaselineCommit']='73f5d588736336c8f6023c469f2748c6d22f153c'
    plan['parentManifestSha256']=digest((source/'manifest.json').read_bytes())
    plan['splitPolicy']='Previously observed exact pairs and enriched context are REGRESSION, never new holdout.'
    fetcher=Fetcher(destination.parent/'cache')
    for case in plan['cases']:
        target=destination/'cases'/case['caseId'];target.mkdir(mode=0o700)
        case['evaluationSplit']='REGRESSION'
        case['contextEnrichment']=dict(originalFiles=len(case['files']),added=[],notAvailable=[])
        for file in case['files']:
            path=target/relative(file['path']);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            shutil.copyfile(source/'cases'/case['caseId']/relative(file['path']),path);path.chmod(0o600)
        repo=case['repositoryUrl'].removeprefix('https://github.com/')
        for name in ADDITIONS[case['pairId']]:
            if name in {f['path']for f in case['files']}:continue
            url=f'https://raw.githubusercontent.com/{repo}/{case["repositoryCommitSha"]}/{name}'
            try:data=fetcher.fetch(url)
            except urllib.error.HTTPError as error:
                if error.code!=404:raise
                case['contextEnrichment']['notAvailable'].append(dict(filePath=name,reason='CONTEXT_MISSING',httpStatus=404));continue
            data.decode('utf-8')
            path=target/relative(name);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with path.open('xb')as stream:path.chmod(0o600);stream.write(data)
            case['files'].append(dict(path=name,url=url,sha256=digest(data)))
            case['contextEnrichment']['added'].append(name)
        if len(case['files'])>40:raise ValueError('CONTEXT_FILE_LIMIT')
        print(dict(case=case['caseId'],added=len(case['contextEnrichment']['added']),missing=len(case['contextEnrichment']['notAvailable'])),flush=True)
    plan['contextEnrichmentCollection']=dict(requests=fetcher.requests,bytes=fetcher.total,
        targetExecution=False,sourceSelection='Pinned local bootstrap/routing/import context; not a full dependency tree.')
    validate(plan,destination);write(destination/'manifest.json',plan)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('source');parser.add_argument('destination')
    enrich(**vars(parser.parse_args()))
