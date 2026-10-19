"""Acquire a pinned, path-scoped public pilot; never execute upstream code.

Ground truth review is limited to upstream labels and explicit patched paths.
The same developer reviews metadata and runs evaluation: not a blind study.
"""
import ast
import csv
import io
import json
from pathlib import Path
import sys
from benchmark import Fetcher, collect, digest, write, outside

BASELINE = "4ed70124796cdd117a10660f93ed3e093a5903cd"
OWASP = "bc5ffeb09fb18ab039806d84ca1f718c2e332c54"
PATCHES = [
    {"id":"django-28346","repository":"django/django","fixed":"800828887a0509ad1162d6d407e94d8de7eafc60","parent":"78e553b48a728ba68b427a8108e1247e5bb46048",
     "cve":"CVE-2022-28346","cwe":"CWE-89","area":"INPUT_INJECTION","advisory":"https://www.djangoproject.com/weblog/2022/apr/11/security-releases/",
     "paths":{"django/db/models/sql/query.py":["Query.add_annotation","Query.add_extra"]},
     "flow":"Caller-controlled column aliases are retained in Query annotations/extra select and later emitted by SQL compilation.",
     "mitigation":"Query.check_alias rejects SQL delimiters/comments before add_annotation and add_extra retain aliases.",
     "conditions":"Applications expand untrusted dictionaries into annotate/aggregate/extra aliases; database SQL compilation is needed for impact."},
    {"id":"django-28347","repository":"django/django","fixed":"00b0fc50e1738c7174c495464a5ef069408a4402","parent":"800828887a0509ad1162d6d407e94d8de7eafc60",
     "cve":"CVE-2022-28347","cwe":"CWE-89","area":"INPUT_INJECTION","advisory":"https://www.djangoproject.com/weblog/2022/apr/11/security-releases/",
     "paths":{"django/db/models/sql/query.py":["Query.explain"],"django/db/backends/postgresql/operations.py":["DatabaseOperations.explain_query_prefix"],"django/db/backends/postgresql/features.py":[]},
     "flow":"Untrusted explain option names pass from Query.explain to PostgreSQL explain_query_prefix, where names form SQL grammar.",
     "mitigation":"Query validates option names; PostgreSQL consumes supported option names and passes remaining names to base validation.",
     "conditions":"PostgreSQL backend with application-provided untrusted explain option names. Other backends/paths are not labelled."},
    {"id":"django-34265","repository":"django/django","fixed":"0dc9c016fadb71a067e5a42be30164e3f96c0492","parent":"a2b88d7be6fc9b443794518d2f75fd2f3d9e677a",
     "cve":"CVE-2022-34265","cwe":"CWE-89","area":"INPUT_INJECTION","advisory":"https://www.djangoproject.com/weblog/2022/jul/04/security-releases/",
     "paths":{"django/db/models/functions/datetime.py":["Extract.as_sql","TruncBase.as_sql"],"django/db/backends/base/operations.py":[]},
     "flow":"Caller-controlled lookup_name/kind enters date SQL operation selection and generated SQL.",
     "mitigation":"Both affected as_sql methods reject identifiers that fail the shared full-match allowlist.",
     "conditions":"Untrusted kind/lookup_name passed to Trunc/Extract without application allowlisting; database/backend behavior affects impact."},
    {"id":"django-36359","repository":"django/django","fixed":"b7d9529cbe0af4adabb6ea5d01ed8dcce3668fb3","parent":"2eb7dedd8f40f911d581d4e7619c046cefe203ce",
     "cve":"CVE-2022-36359","cwe":"CWE-116","area":"SENSITIVE_EXPOSURE","advisory":"https://www.djangoproject.com/weblog/2022/aug/03/security-releases/",
     "paths":{"django/http/response.py":["FileResponse.set_headers"]},
     "flow":"A caller-supplied filename is formatted into Content-Disposition; quoted filename delimiters were not escaped.",
     "mitigation":"Backslashes and quotes in the ASCII filename branch are escaped before header formatting.",
     "conditions":"Application uses user-derived filenames with FileResponse; reflected-file-download conditions are required."},
    {"id":"django-41323","repository":"django/django","fixed":"23f0093125ac2e553da6c1b2f9988eb6a3dd2ea1","parent":"4a30e0db269a364cb480f48524fa48e6abcf9e94",
     "cve":"CVE-2022-41323","cwe":"CWE-1333","area":"SERVICE_STABILITY","advisory":"https://www.djangoproject.com/weblog/2022/oct/04/security-releases/",
     "paths":{"django/urls/resolvers.py":["LocalePrefixPattern.regex"]},
     "flow":"Locale-derived language_prefix is compiled as a regular expression.",
     "mitigation":"re.escape is applied before compiling the locale prefix.",
     "conditions":"Internationalized URL patterns with attacker-influenced locale; actual timing/DoS not executed."},
    {"id":"hono-url-decoding","repository":"honojs/hono","fixed":"6a0607a929d888893f0c91d92dce2fcfdb3662a3","parent":"076823220335b2ef88360a5619c9e7fee3f568d2",
     "cve":"CVE-2026-29045","ghsa":"GHSA-q5qw-h33p-qvwr","cwe":"CWE-177","area":"AUTHORIZATION",
     "advisory":"https://github.com/honojs/hono/security/advisories/GHSA-q5qw-h33p-qvwr",
     "paths":{"src/middleware/serve-static/index.ts":[],"src/utils/url.ts":[]},
     "anchors":["filename = "],
     "flow":"c.req.path is decoded into the static resource name, while route middleware uses different URL-decoding semantics.",
     "mitigation":"serveStatic switches to tryDecodeURI, matching router decoding instead of decoding encoded slashes with decodeURIComponent.",
     "conditions":"Route middleware protects subpaths served from the same static root. This is authorization bypass, not traversal outside the static root."},
    {"id":"h3-double-decoding","repository":"h3js/h3","fixed":"c56683dcb134969d9c01d403d43eaa6327012007","parent":"e3b9c9e3e78119dc0e047c07396c98d084c28b96",
     "cve":None,"ghsa":"GHSA-72gr-qfp7-vwhw","cwe":"CWE-22","area":"FILE_DESERIALIZATION",
     "advisory":"https://github.com/h3js/h3/security/advisories/GHSA-72gr-qfp7-vwhw",
     "paths":{"src/utils/static.ts":[]},"anchors":["const originalId"],
     "flow":"event.path is decoded into originalId and handed to static-backend callbacks; encoded dot segments may escape a URL-backed root.",
     "mitigation":"The v1 backport removes decodePath and rejects encoded dot-segment forms before static-backend resolution. This differs from the advisory main-branch example.",
     "conditions":"URL-based static backend; decoding and URL normalization must align. No backend access or exploit was performed."},
]


def raw_url(repository, sha, path):
    return f"https://raw.githubusercontent.com/{repository}/{sha}/{path}"


def functions(text):
    result = {}
    class Visitor(ast.NodeVisitor):
        def __init__(self): self.stack=[]
        def visit_ClassDef(self,node):
            self.stack.append(node.name);self.generic_visit(node);self.stack.pop()
        def visit_FunctionDef(self,node):
            result[".".join(self.stack+[node.name])] = (node.lineno,node.end_lineno)
        visit_AsyncFunctionDef = visit_FunctionDef
    Visitor().visit(ast.parse(text))
    return result


def build(fetcher):
    plan={"schemaVersion":1,"engineBaselineCommit":BASELINE,"reviewer":"Single Codex reviewer; not independently blinded",
          "splitPolicy":"Repository, vulnerability family, exact source hashes and paired versions are never split across groups. Observed former holdouts are regression.",
          "cases":[],"assets":[]}
    old=json.loads((Path(__file__).resolve().parents[2]/"src/test/resources/java-sql-public-evaluation.json").read_text())
    labels=list(csv.reader(io.StringIO(fetcher.fetch(raw_url('OWASP-Benchmark/BenchmarkJava',OWASP,'expectedresults-1.2.csv')).decode())))
    truth={r[0]:r[2]for r in labels if len(r)>3 and r[1]=='sqli'}
    for group in ('regression','holdoutFirst'):
        for row in old[group]['rows']:
            name,label=row[:2];path=f'src/main/java/org/owasp/benchmark/testcode/{name}.java'
            data=fetcher.fetch(raw_url('OWASP-Benchmark/BenchmarkJava',OWASP,path));text=data.decode();lines=text.splitlines()
            if digest(data)!=row[6] or (truth[name]=='true')!=(label=='DANGEROUS'):raise ValueError('UPSTREAM_TRUTH_CHANGED')
            # Upstream servlet method boundaries, not every SQL-related warning in the file.
            start=next(i for i,l in enumerate(lines,1)if 'void doPost('in l)
            end=next((i-1 for i,l in enumerate(lines[start:],start+1)if 'private static' in l),len(lines)-1)
            sites=[{"filePath":path,"startLine":start,"endLine":end}]
            plan['cases'].append(dict(caseId='owasp-'+name,sourceDataset='OWASP BenchmarkJava',repositoryUrl='https://github.com/OWASP-Benchmark/BenchmarkJava',
                repositoryCommitSha=OWASP,repositoryGroup='owasp-benchmark-java',forkGroup='owasp-benchmark-java',vulnerabilityFamily='benchmark-java-generated-sqli',
                cve=None,ghsa=None,cwe='CWE-89',area='INPUT_INJECTION',language='JAVA',framework='Servlet',license='GPL-2.0',
                groundTruthLabel=label,groundTruthConfidence='UPSTREAM_LABEL_PATH_REVIEW',reviewed=True,
                affectedFunction='doPost',targetSites=sites,sourceSites=sites,patternRules=['DANGEROUS_SQL'],flowRules=['JAVA_SQL_INPUT_FLOW'],
                labelEvidence=[f'https://github.com/OWASP-Benchmark/BenchmarkJava/blob/{OWASP}/expectedresults-1.2.csv',f'https://github.com/OWASP-Benchmark/BenchmarkJava/blob/{OWASP}/{path}'],
                sourceToSinkEvidence='Upstream SQLi label and selected servlet doPost path; helper/callee dependencies outside this file remain unverified by this pilot.',
                mitigationEvidence='SAFE only for the upstream-labelled SQL condition, never the entire servlet/project.',requiredConditions='Servlet request source and configured SQL test path; no exploit or database execution performed.',
                evaluationSplit='REGRESSION',files=[dict(path=path,url=raw_url('OWASP-Benchmark/BenchmarkJava',OWASP,path),sha256=row[6])],
                unknownFacts=['Older 24 cases have already been observed. No fresh holdout claim.','Missing external helper implementations can limit path verification.']))
    for patch in PATCHES:
        repo=patch['repository'];python=repo=='django/django';split='VALIDATION' if python else 'HOLDOUT'
        for version,label in [('parent','DANGEROUS'),('fixed','SAFE')]:
            sha=patch[version];files=[];targets=[];sources=[]
            for path,names in patch['paths'].items():
                data=fetcher.fetch(raw_url(repo,sha,path));text=data.decode();files.append(dict(path=path,url=raw_url(repo,sha,path),sha256=digest(data)))
                if names:
                    spans=functions(text)
                    for name in names:
                        first,last=spans[name];targets.append(dict(filePath=path,startLine=first,endLine=last));sources.append(dict(filePath=path,startLine=first,endLine=min(last,first+4)))
                elif patch.get('anchors') and path==next(iter(patch['paths'])):
                    for anchor in patch['anchors']:
                        hits=[i for i,l in enumerate(text.splitlines(),1)if anchor in l]
                        if not hits:raise ValueError('PATCH_ANCHOR_NOT_FOUND')
                        for line in hits:targets.append(dict(filePath=path,startLine=max(1,line-2),endLine=line+10));sources.append(dict(filePath=path,startLine=max(1,line-2),endLine=line+10))
            if not targets:raise ValueError('NO_REVIEWED_TARGET')
            plan['cases'].append(dict(caseId=patch['id']+'-'+version,pairId=patch['id'],sourceDataset='Django official security patches'if python else repo+' official advisory/patch',
                repositoryUrl='https://github.com/'+repo,repositoryCommitSha=sha,vulnerableCommitSha=patch['parent'],fixedCommitSha=patch['fixed'],
                repositoryGroup=repo,forkGroup=repo,vulnerabilityFamily=patch['id'],cve=patch['cve'],ghsa=patch.get('ghsa'),
                cwe=patch['cwe'],area=patch['area'],language='PYTHON'if python else'TYPESCRIPT',framework='Django internals'if python else repo.split('/')[0]+' library middleware',
                license='BSD-3-Clause'if python else'MIT',groundTruthLabel=label,groundTruthConfidence='OFFICIAL_ADVISORY_AND_PATCH_REVIEW',reviewed=True,
                affectedFunction=','.join(n for names in patch['paths'].values()for n in names)or'serveStatic',
                targetSites=targets,sourceSites=sources,patternRules=[],flowRules=['PY_SQL_INPUT_FLOW']if patch['cwe']=='CWE-89'else[],
                labelEvidence=[patch['advisory'],f'https://github.com/{repo}/commit/{patch["fixed"]}'],
                sourceToSinkEvidence=patch['flow'],mitigationEvidence=patch['mitigation']if label=='SAFE'else'The named patch mitigation is absent in this parent revision.',
                requiredConditions=patch['conditions'],evaluationSplit=split,files=files,
                unknownFacts=['Only affected implementation files are collected, not a complete application.','SAFE describes the named patched path under stated conditions only.','No runtime/payload/operational reproduction.'],
                improvementProposal='Separate library entry contracts from HTTP handlers, then model supported backend/decoder operations with positive and negative path tests. Do not trust a method name alone.'))
        asset_url=('https://api.github.com/advisories/'+patch['ghsa']) if patch.get('ghsa') else patch['advisory']
        plan['assets'].append(dict(kind='official-advisory',url=asset_url))
    for repo,sha,license_path in [('OWASP-Benchmark/BenchmarkJava',OWASP,'LICENSE'),('django/django',PATCHES[0]['fixed'],'LICENSE'),('honojs/hono',PATCHES[5]['fixed'],'LICENSE'),('h3js/h3',PATCHES[6]['fixed'],'LICENSE')]:
        plan['assets'].append(dict(kind='license',repository=repo,url=raw_url(repo,sha,license_path)))
    return plan


if __name__=='__main__':
    try:
        fetcher=Fetcher(outside(sys.argv[1]).parent/'cache');plan=build(fetcher)
        result=collect(plan,sys.argv[1],fetcher)
        # Metadata-only catalog is safe to inspect; upstream source remains outside Git.
        write(outside(Path(sys.argv[1])/'catalog.json'),plan)
        print(json.dumps(result))
    except Exception as error:
        print('Pilot collection failed; category='+type(error).__name__,file=sys.stderr)
        raise SystemExit(1)
