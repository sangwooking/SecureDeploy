"""Grade B copies retain original routing/views; no upstream code is executed."""
import argparse
import ast
from benchmark import read, write, outside, digest, validate, relative

BASELINE = '202ac386bdbf6cd6a331f54c3b534a0d363005fd'
REGRESSION = [
    ('selected', 'DANGEROUS', "'SELECT {}'.format(value)", ''),
    ('unused-position', 'SAFE', "'SELECT {0}'.format('1', value)", ''),
    ('unused-keyword', 'SAFE', "'SELECT {chosen}'.format(chosen='1', unused=value)", ''),
    ('bound', 'SAFE', "'SELECT %s'.format(value)", ', [value]'),
    ('binding-too-late', 'DANGEROUS', "'SELECT {}'.format(value)", ", ['1']"),
    ('opaque', 'UNKNOWN', "'SELECT {}'.format(opaque(value))", ''),
]
VALIDATION = [
    ('escaped', 'SAFE', "\"SELECT '{{1}}'\".format(value)", ''),
    ('repeat-static', 'SAFE', "'SELECT {0}{0}'.format('1', value)", ''),
    ('named-static', 'SAFE', "'SELECT {chosen}'.format(unused=value, chosen='1')", ''),
    ('named-input', 'DANGEROUS', "'SELECT {chosen}'.format(unused='1', chosen=value)", ''),
    ('index-input', 'DANGEROUS', "'SELECT {1}'.format('1', value)", ''),
    ('overwrite', 'SAFE', "'SELECT {1}'.format((value:='1'), value)", ''),
    ('captured', 'DANGEROUS', "'SELECT {0}'.format(value, (value:='1'))", ''),
    ('compound', 'UNKNOWN', "'SELECT {0[x]}'.format({'x':value})", ''),
]


def inject(source, function, expression, params):
    tree = ast.parse(source)
    target = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function)
    first = target.body[0]
    index = first.end_lineno if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str) else first.lineno - 1
    lines = source.splitlines(keepends=True)
    block = ["    value = request.GET.get('q')\n", "    with connection.cursor() as cursor:\n",
             "        cursor.execute("+expression+params+")\n"]
    lines[index:index] = block
    # Preserve module docstrings and future imports.
    imports = 0
    for n in tree.body:
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str) or isinstance(n, ast.ImportFrom) and n.module == '__future__':
            imports = n.end_lineno
        else:
            break
    lines.insert(imports, 'from django.db import connection\n')
    result = ''.join(lines)
    parsed = ast.parse(result)
    sink = next(n for n in ast.walk(parsed) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == 'cursor' and n.func.attr == 'execute')
    return result, sink.lineno


def prepare(applications, independent, output):
    apps, independent, output = outside(applications), outside(independent), outside(output)
    plan = read(apps/'application-plan.json')
    app = next(p for p in plan['projects'] if p['projectId'] == 'wagtail--bakerydemo')
    new = read(independent/'receipt.json')
    groups = [dict(id='bakery', repository=app['repositoryUrl'], sha=app['commitSha'],
        root=apps/'sources'/app['projectId'], receipts=app['files'], view='bakerydemo/search/views.py',
        function='search', paths=['bakerydemo/urls.py','bakerydemo/search/views.py','LICENSE'],
        split='REGRESSION', variants=REGRESSION),
        dict(id='boards', repository=new['repository'], sha=new['sha'], root=independent, receipts=new['files'],
        view='boards/views.py', function='new_topic', paths=['myproject/urls.py','boards/views.py','boards/models.py','LICENSE'],
        split='VALIDATION', variants=VALIDATION)]
    output.mkdir(mode=0o700)
    (output/'cases').mkdir(mode=0o700)
    cases = []
    for group in groups:
        originals = {}
        for name in group['paths']:
            path = group['root']/relative(name)
            data = path.read_bytes()
            receipt = next(f for f in group['receipts'] if f['path'] == name)
            if path.is_symlink() or digest(data) != receipt['sha256']:
                raise ValueError('ORIGINAL_SOURCE_HASH')
            originals[name] = data
        for variant, label, expression, params in group['variants']:
            cid = group['id']+'-'+variant
            directory = output/'cases'/cid
            directory.mkdir(mode=0o700)
            changed, sink = inject(originals[group['view']].decode(), group['function'], expression, params)
            files = []
            for name, original in originals.items():
                data = changed.encode() if name == group['view'] else original
                target = directory/relative(name)
                target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with target.open('xb') as stream:
                    target.chmod(0o600)
                    stream.write(data)
                files.append(dict(path=name,sha256=digest(data),originalSha256=digest(original),
                    controlledVariant=data!=original,url='https://raw.githubusercontent.com/'+group['repository'].removeprefix('https://github.com/')+'/'+group['sha']+'/'+name,
                    urlMeaning='Original unmodified source reference, not a download URL for the controlled variant.'))
            cases.append(dict(caseId=cid,grade='B',repositoryUrl=group['repository'],repositoryCommitSha=group['sha'],
                repositoryGroup=group['repository'],forkGroup=group['repository'],vulnerabilityFamily='controlled-format-'+group['id'],
                language='PYTHON',framework='Django function view; original routing preserved',cwe='CWE-89',area='INPUT_INJECTION',
                license='BSD-3-Clause' if group['id']=='bakery' else 'MIT',sourceDataset='Grade B controlled application copy, NOT an upstream CVE',
                groundTruthLabel=label,reviewed=True,groundTruthConfidence='CONTROLLED_FIELD_SELECTION_STATIC_REVIEW',
                evaluationSplit=group['split'],targetSites=[dict(filePath=group['view'],startLine=sink,endLine=sink)],
                sourceSites=[dict(filePath=group['view'],startLine=sink-2,endLine=sink-2)],
                patternRules=[],flowRules=['PY_SQL_INPUT_FLOW'],files=files,
                labelEvidence=[group['repository']+'/tree/'+group['sha'],'https://docs.python.org/3/library/string.html#formatstrings'],
                labelScope='Injected cursor call only, not the original app or remaining request body.',
                requiredConditions='Named handler invoked; source text is never executed, no database/network target is exercised.',
                sourceToSinkEvidence='Existing route -> original function -> inserted GET q -> format-selected SQL -> cursor.execute.',
                mitigationEvidence='Fixed/unused format slots or separate SQL parameters' if label=='SAFE' else 'Untrusted selected slot' if label=='DANGEROUS' else 'Unsupported transform/compound field',
                sourceOriginalsPreserved=True,sharedWeaknessFamily='python-format-field-selection',independence='Different repository for Validation but shared weakness family; educational application and single-curator controlled injection, not blind or independently adjudicated real CVE truth.',
                contextOmissions=['Remaining app imports/framework runtime are not fully acquired. Original route and remaining view body preserved; target call occurs before the existing body.']))
    manifest = dict(schemaVersion=1,engineBaselineCommit=BASELINE,cases=cases,
        independence='Regression and Validation projects kept separate; both variants deliberately generated to exercise the chosen contract. No Grade A improvement claim.')
    validate(manifest,output)
    write(output/'manifest.json',manifest)
    print(dict(cases=len(cases),regression=len(REGRESSION),validation=len(VALIDATION),grade='B',sourceExecuted=False))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for arg in ['applications','independent','output']:
        parser.add_argument(arg)
    prepare(**vars(parser.parse_args()))
