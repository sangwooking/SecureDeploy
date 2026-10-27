"""Same-source injection controls and retained-source differentials; never runs targets."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
from application_track import outside, write
from mongoose18 import run, digest
from benchmark import relative


def safe_file(root, name):
    root = root.resolve()
    target = root / relative(name)
    if target.is_symlink() or not target.resolve().is_relative_to(root):
        raise ValueError('UNSAFE_SOURCE_PATH')
    return target


def classify(case, result):
    rule = 'JS_SEQUELIZE_SQL_INPUT_FLOW' if case['track'] == 'SQL' else 'JS_MONGOOSE_SELECTOR_INPUT_FLOW'
    hits = [f for f in result['findings'] if f['ruleId'] == rule and f['confidence'] == 'HIGH'
            and f['sink']['filePath'] == case['input']['files'][0]['filePath']]
    uses = [u for u in result['nodeUses'] if u['ruleId'] == rule]
    if case['truth'] == 'UNKNOWN':
        if hits:
            return 'UNEXPECTED_CANDIDATE'
        if any(u['kind'] in ['UNKNOWN', 'FLOW_UNRESOLVED', 'CALLBACK_VERSION_UNSUPPORTED'] for u in uses):
            return 'UNKNOWN'
        if any(u['kind'] in ['STATIC_OR_DATA_ONLY', 'STATIC_OR_STRING_FILTER', 'SANITIZE_FILTER_DECLARED'] for u in uses):
            return 'FALSE_SAFE_OBSERVATION'
        return 'NOT_INSPECTED'
    if case['truth'] == 'RISK':
        return 'TP_STATIC_CONTRACT' if hits else 'FN_INCLUDING_DEFERRED'
    if hits:
        return 'FP_STATIC_CONTRACT'
    return 'TN_REVIEWED_STATIC_CONTROL' if uses and any(u['kind'] in ['STATIC_OR_DATA_ONLY', 'STATIC_OR_STRING_FILTER', 'SANITIZE_FILTER_DECLARED'] for u in uses) and not any(u['kind'] in ['UNKNOWN', 'FLOW_UNRESOLVED'] for u in uses) else 'NORMAL_DEFERRED_NOT_TN'


def evaluate(repo, baseline, output):
    node = shutil.which('node')
    fixture = repo / 'analyzers/typescript/test/injection24-cases.mjs'
    cases = run(node, ['--allow-fs-read=' + str(fixture.parent), '--input-type=module', '-e',
                      'import {injection24Cases} from ' + json.dumps(fixture.as_uri()) + ';console.log(JSON.stringify(injection24Cases));'])
    rows = []
    for c in cases:
        row = dict(caseId=c['id'], track=c['track'], truth=c['truth'], split=c['split'],
                   knownGap=c.get('knownGap'), inputSha256=digest(c['input']))
        for label, root in [('before', baseline), ('after', repo)]:
            worker = root / 'analyzers/typescript'
            args = ['--allow-fs-read=' + str(worker), str(worker / 'worker.mjs')]
            first, second = [run(node, args, json.dumps(c['input']).encode()) for _ in range(2)]
            if first != second:
                raise ValueError('NONDETERMINISM')
            row[label] = dict(worker=first['analyzerVersion'], decision=classify(c, first),
                              findings=[f for f in first['findings'] if 'SQL' in f['ruleId'] or 'MONGOOSE' in f['ruleId']],
                              uses=[u for u in first['nodeUses'] if 'SQL' in u['ruleId'] or 'MONGOOSE' in u['ruleId']],
                              budget=first['supabaseAnalysis']['budgetUsage'])
        rows.append(row)
    summary = {track: {label: dict(Counter(r[label]['decision'] for r in rows if r['track'] == track))
                       for label in ['before', 'after']} for track in ['SQL', 'NOSQL']}
    result = dict(schemaVersion=1, grade='B_AUTHORED_NOT_INDEPENDENT', cases=len(rows), rows=rows,
                  summary=summary, repeatIdentical=True, newRealApplicationTP=0,
                  targetExecuted=False, paidAiCalls=0,
                  limitations=['Static query contracts are not actual exploit or successful query proofs.',
                               'Normal controls without a query observation remain deferred, not TN.',
                               'UNKNOWN is not safe; validation sources share the implementation author.'])
    write(outside(output), result)
    print(json.dumps({k: v for k, v in result.items() if k != 'rows'}))
    for c, row in zip(cases, rows):
        expected = 'TP_STATIC_CONTRACT' if c['truth'] == 'RISK' else ('NOT_INSPECTED' if c['id'].endswith(('dynamic-wrapper', 'creation-only')) else 'UNKNOWN') if c['truth'] == 'UNKNOWN' else 'NORMAL_DEFERRED_NOT_TN' if c.get('knownGap') else 'TN_REVIEWED_STATIC_CONTROL'
        if row['after']['decision'] != expected:
            raise ValueError('NEW_CONTROL_CONTRACT_FAILED:' + c['id'])


def prepare_dvna(root, destination):
    root, destination = outside(root), outside(destination)
    if destination.exists() or destination.is_relative_to(root) or root.is_relative_to(destination):
        raise ValueError('FRESH_DISJOINT_ROOT_REQUIRED')
    plan = json.loads((root / 'application-plan.json').read_text())
    original = plan['projects'][0]
    if len(plan['projects']) != 1 or original['commitSha'] != '9ba473add536f66ac9007966acb2a775dd31277a':
        raise ValueError('UNEXPECTED_ORIGINAL_SHA')
    source = safe_file(root / 'sources', original['projectId'])
    blobs = {}
    for f in original['files']:
        path = safe_file(source, f['path'])
        data = path.read_bytes()
        if len(data) != f['bytes'] or hashlib.sha256(data).hexdigest() != f['sha256']:
            raise ValueError('SOURCE_HASH_MISMATCH')
        blobs[f['path']] = data
    name = 'core/appHandler.js'
    old = blobs[name]
    if hashlib.sha256(old).hexdigest() != '0fc237589d5a9e73450d089f97124fb943d68222f70df0e973a8b9acfe2ebb6b':
        raise ValueError('TARGET_HASH_MISMATCH')
    call = b'db.sequelize.query(query, {'
    declaration = b'var query = "SELECT name,id FROM Users WHERE login=\'" + req.body.login + "\'";'
    if old.count(call) != 1 or old.count(declaration) != 1:
        raise ValueError('UNIQUE_ANCHOR_REQUIRED')
    projects = []
    destination.mkdir(mode=0o700, parents=True)
    for ident, fixed in [('query-object', False), ('bound-query-object', True)]:
        content = dict(blobs)
        content[name] = old.replace(call, b'db.sequelize.query({query}, {') if not fixed else old.replace(declaration, b'var query = "SELECT name,id FROM Users WHERE login=$1";').replace(call, b'db.sequelize.query({query,bind:[req.body.login]}, {')
        files = []
        for path, data in content.items():
            target = safe_file(destination / 'sources' / ident, path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o600)
            files.append(dict(path=path, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        projects.append(dict(projectId=ident, commitSha='AUTHORED_NOT_UPSTREAM_' + hashlib.sha256(content[name]).hexdigest(),
                             collectionStatus='COLLECTED_GRADE_B_DIFFERENTIAL', files=files, omitted=original.get('omitted', [])))
    write(destination / 'application-plan.json', dict(schemaVersion=1, projects=projects))
    print(json.dumps(dict(projects=2, originalFilesVerified=len(blobs), originalSha=original['commitSha'], grade='B_NOT_UPSTREAM_FIX')))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='command', required=True)
    e = sub.add_parser('evaluate')
    for name in ['repo', 'baseline', 'output']:
        e.add_argument('--' + name, type=Path, required=True)
    d = sub.add_parser('prepare-dvna')
    d.add_argument('root', type=Path)
    d.add_argument('destination', type=Path)
    a = p.parse_args()
    if a.command == 'evaluate':
        evaluate(a.repo.resolve(), a.baseline.resolve(), a.output)
    else:
        prepare_dvna(a.root, a.destination)
