"""Replay selected local source strings into the evaluation-only route prototype.

No target code is executed. Metadata is reconstructed, not a full collector replay.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def packet(root, snapshot, project_id):
    root = Path(root).resolve()
    plan_bytes = (root / 'application-plan.json').read_bytes()
    if digest(plan_bytes) != snapshot['planSha256']:
        raise ValueError('PLAN_HASH_MISMATCH')
    plan = json.loads(plan_bytes)
    project = next(p for p in plan['projects'] if p['projectId'] == project_id)
    prior = next(p for p in snapshot['projects'] if p['projectId'] == project_id)
    if project_id in ('.', '..') or '/' in project_id or '\\' in project_id:
        raise ValueError('PROJECT_PATH_INVALID')
    base = root / 'sources' / project_id
    if base.is_symlink() or base.resolve() != base:
        raise ValueError('SOURCE_ROOT_SYMLINK')
    index = {f['path']: f for f in project['files']}
    if len(index) != len(project['files']):
        raise ValueError('DUPLICATE_SOURCE_PATH')
    for name in index:
        p = PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name:
            raise ValueError('SOURCE_PATH_INVALID')
    hashes = {}

    def source(name, cap=400000):
        p = PurePosixPath(name)
        if p.is_absolute() or '..' in p.parts or '\\' in name or ':' in name or name == '[redacted-path]':
            raise ValueError('SOURCE_PATH_INVALID')
        target = base / name
        if any(x.is_symlink() for x in (target, *target.parents)) or not target.resolve().is_relative_to(base):
            raise ValueError('SOURCE_SYMLINK_OR_ESCAPE')
        data = target.read_bytes()
        if len(data) > cap or digest(data) != index[name]['sha256']:
            raise ValueError('SOURCE_HASH_OR_SIZE_MISMATCH')
        hashes[name] = digest(data)
        return '\n'.join(data.decode('utf-8').splitlines())

    files = [dict(filePath=f['filePath'], content=source(f['filePath']))
             for f in prior['runs'][0]['typescript']['files'] if f['parseStatus'] == 'PARSED']
    if len(files) > 100 or any(len(f['content']) > 100000 for f in files) or sum(len(f['content']) for f in files) > 1000000:
        raise ValueError('SOURCE_SELECTION_LIMIT')
    manifests = []
    for name in sorted(index):
        if name != 'package.json' and not name.endswith('/package.json'):
            continue
        if len(manifests) >= 100:
            raise ValueError('MANIFEST_LIMIT')
        try:
            doc = json.loads(source(name, 64000))
            if not isinstance(doc, dict):
                raise ValueError('MANIFEST_OBJECT_REQUIRED')
        except (json.JSONDecodeError, UnicodeError):
            manifests.append(dict(filePath=name, resolutionStatus='UNKNOWN', mainStatus='UNKNOWN'))
            continue
        m = dict(filePath=name, resolutionStatus='PARSED', moduleType=doc.get('type', 'commonjs'), mainStatus='ABSENT')
        if 'main' in doc:
            m['mainStatus'] = 'STATIC' if isinstance(doc['main'], str) else 'UNKNOWN'
            if isinstance(doc['main'], str):
                m['main'] = doc['main']
        dependencies = doc.get('dependencies', {})
        if not isinstance(dependencies, dict):
            m['resolutionStatus'] = 'UNKNOWN'
            dependencies = {}
        for dep in ('next', 'express', 'mongodb', 'sequelize', 'mongoose', 'cors', 'validator', 'express-session', 'express-rate-limit'):
            v = dependencies.get(dep)
            if isinstance(v, str) and re.fullmatch(r'[~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', v):
                m[dep] = v
        manifests.append(m)
    configs = [dict(filePath=n, status='SELECTED', content=source(n, 64000)) for n in sorted(index)
               if n == 'tsconfig.json' or n.endswith('/tsconfig.json')]
    if len(configs) > 32:
        raise ValueError('CONFIG_LIMIT')
    # Deliberately do not reconstruct completeness, SQL policies or installed packages.
    payload = dict(files=files, nodeManifests=manifests, typescriptConfigs=configs,
                   nodeSourceInventory=sorted(index)[:1000], nodeSourceInventoryComplete=False,
                   nodeEnumeratedDirectories=[], policyInventoryComplete=False)
    data = json.dumps(payload).encode()
    if len(data) > 1200000:
        raise ValueError('PACKET_BYTE_LIMIT')
    return data, dict(projectId=project_id, sourceSha=prior['commitSha'], planSha256=digest(plan_bytes),
                      inputSha256=digest(data), sourceFileHashes=hashes,
                      scope='RECORDED_PARSED_SOURCES_RECONSTRUCTED_METADATA_NOT_FULL_PRODUCTION_INPUT',
                      inventoryComplete=False, policiesIncluded=False, installedVersionVerified=False,
                      metadataNotReconstructed=['PACKAGE_EXPORTS_IMPORTS_MAPS', 'BOOTSTRAP_SCRIPT_HINTS', 'WORKSPACE_LINKS', 'LIVE_DATABASE'])


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', required=True)
    p.add_argument('--snapshot', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--project-id')
    args = p.parse_args()
    out = Path(args.output).resolve()
    if out.is_relative_to(REPO) or out.exists():
        raise ValueError('NEW_OUTPUT_OUTSIDE_GIT_REQUIRED')
    snapshot = json.loads(Path(args.snapshot).read_text())
    ids = [args.project_id] if args.project_id else [x['projectId'] for x in snapshot['projects']]
    rows = []
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'LANG', 'LC_ALL')}
    for project_id in ids:
        data, provenance = packet(args.root, snapshot, project_id)
        runs, elapsed = [], []
        for _ in range(2):
            start = time.monotonic()
            r = subprocess.run(['node', '--max-old-space-size=192', str(REPO / 'scripts/evaluation/static-route-probe.mjs')],
                               input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=10)
            elapsed.append(round((time.monotonic() - start) * 1000))
            if r.returncode or len(r.stdout) > 1950000:
                raise ValueError('PROTOTYPE_NOT_INSPECTED_PROCESS_OR_OUTPUT_LIMIT')
            runs.append(json.loads(r.stdout))
        rows.append(dict(**provenance, repeatIdentical=runs[0] == runs[1], elapsedMs=elapsed, runs=runs))
    os.umask(0o077)
    with out.open('x') as f:
        json.dump(dict(evaluationVersion='static-route-v1', engineCommit=subprocess.check_output(
            ['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip(), projects=rows), f, indent=2)
    print(json.dumps(dict(projects=len(rows), repeatIdentical=all(x['repeatIdentical'] for x in rows),
                          finalFindingsPromoted=False, targetCodeExecuted=False)))


if __name__ == '__main__':
    main()
