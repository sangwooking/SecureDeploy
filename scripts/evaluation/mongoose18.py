"""Offline authored selector contracts; metadata only, never a runtime CVE score."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

RULE = 'JS_MONGOOSE_SELECTOR_INPUT_FLOW'


def classify(result):
    findings = [f for f in result['findings'] if f['ruleId'] == RULE]
    states = [u['kind'] for u in result.get('nodeUses', []) if u['ruleId'] == RULE]
    if findings:
        return 'REVIEW_CANDIDATE'
    if 'CALLBACK_VERSION_UNSUPPORTED' in states:
        return 'CALLBACK_VERSION_UNSUPPORTED'
    for state in ('UNKNOWN', 'SANITIZE_FILTER_DECLARED', 'STATIC_OR_STRING_FILTER'):
        if state in states:
            return state
    if any('MONGOOSE' in reason for f in result['files'] for reason in f['limitations']):
        return 'UNKNOWN'
    if 'QUERY_CREATED_EXECUTION_NOT_OBSERVED' in states:
        return 'QUERY_CREATED_EXECUTION_NOT_OBSERVED'
    return 'NOT_SUPPORTED_OR_NOT_APPLICABLE'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def run(node, args, packet=None):
    p = subprocess.run([node, '--permission', '--no-addons', '--max-old-space-size=192', *args],
                       input=packet, capture_output=True, timeout=8,
                       env={k: v for k, v in os.environ.items() if k in ('LANG', 'LC_ALL')}, check=True)
    if len(p.stdout) > 2_000_000:
        raise ValueError('OUTPUT_LIMIT')
    return json.loads(p.stdout)


def evaluate(repo, baseline, output, prepare_root=None, case_set='mongoose18'):
    node = shutil.which('node')
    filename,symbol={'mongoose18':('mongoose-cases.mjs','mongooseCases'),
                     'callback19':('mongoose-callback-cases.mjs','callbackCases'),
                     'field20':('field-cases.mjs','fieldCases')}[case_set]
    casefile = repo/'analyzers/typescript/test'/filename
    allowed=casefile if case_set=='mongoose18' else casefile.parent
    cases = run(node, ['--allow-fs-read='+str(allowed), '--input-type=module', '-e',
                      'import {'+symbol+'} from '+json.dumps(casefile.as_uri())+';console.log(JSON.stringify('+symbol+'));'])
    rows = []
    for c in cases:
        observations = {}
        packet = json.dumps(c['input']).encode()
        for label, source in [('before', baseline), ('after', repo)]:
            worker = source/'analyzers/typescript'
            started = time.monotonic()
            a, b = [run(node, ['--allow-fs-read='+str(worker), str(worker/'worker.mjs')], packet) for _ in range(2)]
            if a != b:
                raise ValueError('NONDETERMINISM')
            observations[label] = dict(worker=a['analyzerVersion'], state=classify(a), repeatIdentical=True,
                averageWallMs=round((time.monotonic()-started)*500, 2),
                findings=[f for f in a['findings'] if f['ruleId'] == RULE],
                uses=[u for u in a['nodeUses'] if u['ruleId'] == RULE],
                budget=a['supabaseAnalysis']['budgetUsage'])
        rows.append(dict(caseId=c['id'], truth=c['truth'], sourceSha256=digest(c['input']), **observations))
    result = dict(grade='B_AUTHORED_DEVELOPMENT_NOT_INDEPENDENT', cases=len(rows), rows=rows,
                  before=dict(Counter(r['before']['state'] for r in rows)),
                  after=dict(Counter(r['after']['state'] for r in rows)),
                  newRealApplicationTP=0, targetExecuted=False, paidAiCalls=0,
                  limitations=['Static candidates are not reproduced vulnerabilities.',
                               'Runtime casts, authentication, middleware and installed versions are not verified.',
                               'UNKNOWN and query construction are not normal TN or detection successes.'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('x') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    if prepare_root:
        for batch in range((len(cases)+7)//8):
            root = prepare_root/('batch-'+str(batch))
            root.mkdir(parents=True)
            projects = []
            for c in cases[batch*8:batch*8+8]:
                folder = root/'sources'/c['id']
                folder.mkdir(parents=True)
                files = []
                deps = c['input']['nodeManifests'][0]
                sources = [dict(filePath='package.json', content=json.dumps({'dependencies': {
                    **{name: deps[name] for name in ('mongoose','express','validator') if name in deps}}})), *c['input']['files']]
                for file in sources:
                    data = file['content'].encode()
                    destination = folder/file['filePath']
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    files.append(dict(path=file['filePath'], bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
                projects.append(dict(projectId=c['id'], commitSha='AUTHORED_'+digest(files), files=files,
                                     collectionStatus='COLLECTED_GRADE_B_CONTROL', omitted=[]))
            (root/'application-plan.json').write_text(json.dumps(dict(schemaVersion=1, projects=projects)))
    print(json.dumps({k: v for k, v in result.items() if k != 'rows'}))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--baseline', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--prepare-root', type=Path)
    p.add_argument('--case-set',choices=['mongoose18','callback19','field20'],default='mongoose18')
    a = p.parse_args()
    # The public tool cannot overwrite tracked files or retained external sources.
    for dest in (a.output, a.prepare_root):
        if dest and (dest.resolve().is_relative_to(a.repo.resolve()) or dest.resolve().is_relative_to(a.baseline.resolve())):
            raise ValueError('OUTPUT_MUST_BE_OUTSIDE_CHECKOUTS')
    evaluate(a.repo.resolve(), a.baseline.resolve(), a.output, a.prepare_root,a.case_set)
