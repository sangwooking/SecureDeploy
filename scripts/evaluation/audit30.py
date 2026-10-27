"""Source-free audit index. References are evidence pointers, not compliance claims."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASELINE = '45385d3e69d0c6ae321a1d8ec96f2c9248c39d2a'
ROOT = Path(__file__).resolve().parents[2]
T = 'analyzers/typescript/'
J = 'src/main/java/com/securedeploy/'

# Whole vulnerability families stay PARTIAL even when a bounded control passes.
# cause: 1 implementation, 2 flow, 3 unsupported contract, 4 oracle,
# 5 intent, 6 deployment, 7 statically inaccessible runtime facts.
AREAS = [
 ('P0','authentication','PARTIAL','PERMIT_ALL_USAGE', 'auth-result-evidence.mjs',
  'Local getUser/getClaims result and supported absence exit; Django permission declarations',
  'Public APIs are intentional in some services; a call is not successful login',
  ['External auth helpers','getSession verification','Actual JWT and middleware activation'],[3,6]),
 ('P0','administrator','PARTIAL','', 'auth-result-evidence.mjs',
  'Django IsAdminUser/staff declarations; no general JS administrator enforcement detector',
  'Role-like names and service keys do not establish administrator authorization',
  ['General Next/Express administrator guard: NOT_IMPLEMENTED','External role RPC'],[3,5,6]),
 ('P0','idor-bola','PARTIAL','PY_AUTHORIZATION_INVERTED_OWNER_GUARD JS_MONGO_RESOURCE_ACCESS', 'supabase-evidence.mjs',
  'Local identity-to-eq/match filter; Django schema-backed inverted ownership guard',
  'Request ID or absent visible guard alone never creates an IDOR verdict',
  ['Two identity filters after argument escape','Sharing intent','General ORM ownership'],[2,3,5,6]),
 ('P0','protected-fields-bopla','PARTIAL','', 'column-update.mjs',
  'Request write fields and table/PUBLIC/column UPDATE privilege declarations',
  'Field name does not establish protected intent; row ownership differs from column mutation',
  ['SELECT/INSERT column ACL: NOT_IMPLEMENTED','Role inheritance','Protected-field intent'],[3,5,6]),
 ('P0','intent-boundary','REQUIRES_EXTERNAL_CONTEXT','', 'write-origin.mjs',
  'Evaluation-only SOURCE_ONLY versus DECLARED_INTENT; no product Intent Preview',
  'Ownership transfer and editable columns are separate proposed dimensions, not applied',
  ['Owner-approved requirements','PUBLIC availability','CONFLICT plus runtime UNKNOWN'],[4,5,6]),
 ('P0','secret-literals','PARTIAL','HARDCODED_SECRET HARDCODED_PASSWORD HARDCODED_FRONTEND_SECRET WEAK_JWT_SECRET','exposure.mjs',
  'Known credential shapes and supported declaration context; public key controls',
  'Public configuration, dummy values and examples are distinct from usable credentials',
  ['Actual key validity and rotation','Actual client build boundary','Custom envPrefix'],[3,6,7]),
 ('P0','secret-response','PARTIAL','TS_SENSITIVE_DATA_EXPOSURE PY_SENSITIVE_DATA_EXPOSURE TS_ERROR_DETAIL_EXPOSURE PY_ERROR_DETAIL_EXPOSURE','exposure.mjs',
  'Supported Next/Deno/Express/Cloudflare response and log paths, plain objects and helpers',
  'Server-internal consumption is not a client exposure; unknown masking is not safety',
  ['Express request.url environment selector FN1','Unknown wrappers and bundle boundaries'],[3,6]),
 ('P0','rls-grants','PARTIAL','SUPABASE_BROAD_WRITE_DECLARATION','rls.mjs',
  'RLS v4 selected ordered SQL; USING/WITH CHECK, supported roles and explicit grants',
  'Repository declaration is not deployed policy or authenticated database role',
  ['Role inheritance','Dynamic policy functions','Missing SQL','Owner/BYPASSRLS and live JWT'],[3,5,6,7]),
 ('P1','sql','PARTIAL','DANGEROUS_SQL TS_SQL_INPUT_FLOW JS_SEQUELIZE_SQL_INPUT_FLOW PY_SQL_INPUT_FLOW JAVA_SQL_INPUT_FLOW','sequelize.mjs',
  'Bounded Java JDBC/JdbcTemplate/Mapper, Django cursor, Cloudflare prepare and Sequelize contracts',
  'Confirmed parameter binding is data, not SQL construction; unresolved dispatch is not safe',
  ['Prisma/pg: NOT_SUPPORTED','Complex branch/object/helper flow','Java nested loops'],[2,3]),
 ('P1','nosql','PARTIAL','JS_MONGOOSE_SELECTOR_INPUT_FLOW JS_MONGO_WHERE_INPUT_FLOW','mongoose.mjs',
  'Version-aware Mongoose model/selector/execution and field-scoped String/email controls',
  'Conversion of one field never protects other fields; query construction differs from execution',
  ['FlintCMS class and DB event startup','Branch model merging','Unknown schema or version'],[2,3,6]),
 ('P1','xss','PARTIAL','REACT_DANGEROUS_HTML','url-context.mjs',
  'HTML/JSX static passive choices and supported lexical exclusions; Python subset',
  'JSX text and textContent differ from HTML interpretation; no full browser Source-to-DOM claim',
  ['Known DOMPurify pattern FP1','DOM sanitizer configuration and hooks','Stored XSS provenance'],[3,4,6]),
 ('P1','ssrf','PARTIAL','TS_SSRF_INPUT_FLOW','destination.mjs',
  'Supported native HTTP/get/fetch initial destination, exact host/protocol guards and href replacement',
  'Fixed destination and query-only writes are not host control; guarded source reuse remains UNKNOWN',
  ['Remaining FN3: options/callback/prefix','DNS/redirect/port/network policy','Unknown URL setters'],[2,3,6,7]),
 ('P1','command','PARTIAL','JS_SHELL_COMMAND_INPUT_FLOW JS_EVAL_INPUT_FLOW','node-server.mjs',
  'Supported Express request flow to known child_process shell or eval, regex capture forwarding',
  'Fixed command and execFile argv differ; argv does not prove command-specific option safety',
  ['Unsupported overloads','Dynamic dispatch','Actual process execution not performed'],[3,6]),
 ('P1','path','PARTIAL','JS_FILE_PATH_INPUT_FLOW PY_FILE_PATH_INPUT_FLOW','file-access.mjs',
  'Supported request-to-fs/Django paths with bounded lexical relative containment',
  'Prefix/normalize is not filesystem containment; lexical proof is not symlink or TOCTOU proof',
  ['FN6: choices/prefix/post-guard replacement/realpath/originalname/Next File.name','Actual mount permissions'],[2,3,6,7]),
 ('P1','upload','NOT_IMPLEMENTED','','file-access.mjs',
  'Upload-related input is not complete CWE-434/400 validation',
  'SecureDeploy ZIP intake safety does not certify target application upload security',
  ['CWE-434 execution/type protection FN1','CWE-400 resource controls','MIME/signature/storage/download'],[3,4,6]),
 ('P1','cors','PARTIAL','CORS_WILDCARD JS_CORS_CREDENTIAL_REFLECTION','web-security.mjs',
  'Known middleware origin reflection plus credentials plus supported sensitive terminal response',
  'Public wildcard, fixed origin and wildcard credential browser rejection are distinct',
  ['FN5','Dynamic Origin callbacks','Raw headers and Next cookie/CORS contracts'],[3,4,6]),
 ('P1','csrf','PARTIAL','JS_WEB_SECURITY_CONTEXT','web-security.mjs',
  'State-changing operations, exact Origin early rejection and bounded read-only body observations',
  'Missing visible defense never alone produces a new CSRF vulnerability Finding',
  ['FN3','Normal deferred1','Cookie authentication and token/session binding'],[3,4,6]),
 ('P1','cookie-session','PARTIAL','INSECURE_COOKIE LOCAL_STORAGE_TOKEN JS_SESSION_COOKIE_ATTRIBUTE_REVIEW','web-security.mjs',
  'Registered session middleware plus request session use and explicit HttpOnly=false; config patterns',
  'Flag declarations do not prove HTTPS, actual cookie transmission, rotation or server-side revocation',
  ['Normal deferred3','Proxy/TLS','Operational session store and lifecycle'],[3,4,6,7]),
 ('P2','rate-abuse','PARTIAL','JS_RATE_LIMIT_BYPASS_REVIEW JS_RATE_LIMIT_CONTEXT','rate-limit.mjs',
  'Declared express-rate-limit 7.5.0 route scope/order, supported bypass and default stop controls',
  'Rate declaration is not distributed enforcement, identity, billing or complete bot prevention',
  ['FN7','Upstash result/branch: NOT_SUPPORTED','Redis/proxy/WAF and multi-instance state'],[2,3,5,6]),
 ('P2','docker-compose','PARTIAL','DOCKER_ROOT_USER DOCKER_LATEST_TAG DOCKER_SECRET_ENV DOCKER_PRIVILEGED DOCKER_HOST_NETWORK COMPOSE_SOCKET COMPOSE_CAPABILITY COMPOSE_HOST_MOUNT COMPOSE_PORT_BINDING COMPOSE_ROOT_OVERRIDE COMPOSE_SECURITY_DISABLED','',
  'Final-stage USER, bounded logical ENV and supported Compose privilege/mount/port declarations',
  'EXPOSE is not publishing; digest is not patched image; readonly socket is not daemon API isolation',
  ['Docker FN1 ARG','ARG/RUN/COPY/layer flow','Overrides/profiles and actual image/network'],[3,6,7]),
 ('P2','ci','PARTIAL','GITHUB_ACTIONS_UNPINNED GITHUB_ACTIONS_SECRET_ECHO GITHUB_ACTIONS_CURL_PIPE CI_UNTRUSTED_PR_EXECUTION CI_SCRIPT_EXPRESSION','',
  'Workflow/job permissions, supported checkout order, simple project execution and run expressions',
  'Local action is not a remote unpinned action; unpinning is not proven compromise',
  ['CI FN1 env-to-eval','Complex shell and reusable workflows','Organization token/secret/approval'],[3,6,7]),
 ('P2','sca','PARTIAL','VULNERABLE_NPM_DEPENDENCY VULNERABLE_MAVEN_DEPENDENCY VULNERABLE_GRADLE_DEPENDENCY','',
  'npm/PyPI/Maven/Gradle package/exact-version OSV query, dependency provenance and corroborated aliases',
  'Unresolved version/feed failure is not safe; fixed metadata is not compatibility or reachability',
  ['Conflicting fixes retained PARTIAL','Actual installed/dev/production topology','Live KEV access and runtime reachability'],[3,4,6,7]),
 ('P2','deployment','PARTIAL','DEBUG_ENABLED STACKTRACE_EXPOSURE EXPOSED_ACTUATOR DJANGO_DEBUG DJANGO_ALLOWED_HOSTS DJANGO_HTTPS DJANGO_SECRET_LITERAL NGINX_DIRECTORY_LISTING NGINX_SERVER_TOKENS NGINX_HTTP_ONLY K8S_PRIVILEGED_CONTAINER K8S_LATEST_IMAGE K8S_NODEPORT_EXPOSURE K8S_SECRET_PLAIN_TEXT','',
  'Supported properties/YAML/Django/Compose/Wrangler/Nginx/Kubernetes declarations',
  'File parsing and static profile names do not prove effective production settings',
  ['Rendered includes','Activated settings','Proxy/platform environment and actual deployment'],[3,6,7]),
]

MAPPING = {
 'authentication':(['A07'],['API2'],[],[]), 'administrator':(['A01'],['API5'],['862'],[]),
 'idor-bola':(['A01'],['API1'],['639'],[]), 'protected-fields-bopla':(['A01'],['API3'],[],[]),
 'intent-boundary':(['A01'],['API1','API3'],[],[]), 'secret-literals':(['A02','A04'],['API8'],['798'],['13.3.1']),
 'secret-response':(['A02'],['API3'],['200'],[]), 'rls-grants':(['A01'],['API1','API3'],[],[]),
 'sql':(['A05'],[],['89'],['1.2.4']), 'nosql':(['A05'],[],['943'],['1.2.4']),
 'xss':(['A05'],[],['79'],['1.2.1','1.3.1']), 'ssrf':(['A01'],['API7'],['918'],['1.3.6']),
 'command':(['A05'],[],['78'],['1.2.5','1.3.2']), 'path':(['A01'],[],['22'],['5.3.2']),
 'upload':(['A02'],['API4'],['434','400'],[]), 'cors':(['A02'],['API8'],['942'],[]),
 'csrf':(['A01'],[],['352'],[]), 'cookie-session':(['A07'],['API2'],['1004'],[]),
 'rate-abuse':(['A06'],['API4','API6'],['799'],[]), 'docker-compose':(['A02'],['API8'],[],['13.2.2','13.3.1']),
 'ci':(['A03','A08'],[],['78','829'],['15.2.4']), 'sca':(['A03'],[],[],['15.2.1']),
 'deployment':(['A02'],['API8'],[],[])
}

TESTS = {
 'authentication':['modern-supabase.test.mjs'], 'administrator':['modern-supabase.test.mjs'],
 'idor-bola':['access-control.test.mjs'], 'protected-fields-bopla':['column-update.test.mjs','write-origin.test.mjs'],
 'intent-boundary':[], 'secret-literals':['display-context.test.mjs','html-context.test.mjs'],
 'secret-response':['secret-flow.test.mjs','deno-exposure.test.mjs','next.test.mjs'],
 'rls-grants':['rls-column-enforcement23.test.mjs','authorization-update.test.mjs'],
 'sql':['injection24.test.mjs','sequelize.test.mjs'], 'nosql':['mongoose.test.mjs','mongoose-callback.test.mjs','field-validation.test.mjs'],
 'xss':['context25.test.mjs','url-context.test.mjs'], 'ssrf':['audit30.test.mjs','ssrf-quality.test.mjs','context25.test.mjs'],
 'command':['shell-flow.test.mjs','regex-flow.test.mjs'], 'path':['file26.test.mjs'], 'upload':['file26.test.mjs'],
 'cors':['web27.test.mjs'], 'csrf':['web27.test.mjs'], 'cookie-session':['web27.test.mjs'],
 'rate-abuse':['rate28.test.mjs'], 'docker-compose':[], 'ci':[], 'sca':[], 'deployment':[]
}

def sha(data): return hashlib.sha256(data).hexdigest()

def build(root=ROOT):
    roots=[root/'analyzers/typescript',root/'analyzers/python',root/'src/main/java']
    sources=[p for directory in roots for p in directory.rglob('*')
             if p.suffix in ('.java','.mjs','.py') and not any(n in p.parts for n in ('node_modules','test','evaluation','__pycache__')) and not p.name.startswith('test_')]
    text={str(p.relative_to(root)):p.read_text() for p in sorted(sources)}
    matrix=[]
    for priority,area,status,ids,module,contract,normal,gaps,causes in AREAS:
        rules=[]
        for rule in ids.split():
            occurrences=[dict(file=path,line=i+1) for path,body in text.items() for i,line in enumerate(body.splitlines())
                         if re.search(r'[\'\"]'+re.escape(rule)+r'[\'\"]',line)]
            rules.append(dict(ruleId=rule,occurrences=occurrences,implementedLiteralFound=bool(occurrences),
                              validation='BOUNDED_CONTROLS_NOT_FULL_FAMILY',runtime='REQUIRES_EXTERNAL_CONTEXT'))
        top,api,cwe,asvs=MAPPING[area]
        tests=[T+'test/'+p for p in TESTS[area]]
        if area in ('docker-compose','ci'):
            tests+=['src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java','src/test/java/com/securedeploy/analysis/deployment/Supply29BoundaryTest.java']
        if area=='sca':tests+=['src/test/java/com/securedeploy/sca/Alias29ControlsTest.java','src/test/java/com/securedeploy/sca/client/OsvAlias29BoundaryTest.java']
        if area=='deployment':tests+=['src/test/java/com/securedeploy/analysis/deployment/DeploymentAnalyzerTest.java']
        if area=='intent-boundary':tests+=['scripts/evaluation/test_authorization_intent13.py']
        if area in ('authentication','administrator'):
            tests+=['analyzers/python/test_authorization.py','analyzers/python/test_authorization_permissions.py']
        for path in tests:
            if not (root/path).is_file():raise ValueError('MISSING_TEST_REFERENCE:'+path)
        matrix.append(dict(priority=priority,area=area,status=status,boundedContract=contract,normalBoundary=normal,
                           unknownOrUnsupported=gaps,causeClasses=causes,rules=rules,
                           boundedValidation='VERIFIED_WITHIN_SCOPE' if status=='PARTIAL' else status,
                           boundedValidationMeaning='Only the stated declaration/flow or rejection property in authored tests; not the vulnerability family',
                           tests=tests,
                           coreModule=T+module if module else None,
                           standards=dict(owasp2025=top,owaspApi2023=api,cwe=cwe,asvs500=asvs,
                                          meaning='RELATED_SCOPE_ONLY_NOT_ALL_RULES_IMPLEMENT_EVERY_REQUIREMENT'),
                           guidance='EXISTING_GUIDE_ONLY_NO_NEW_AUTOMATIC_FIX',independentRealAccuracy='NOT_VERIFIED'))
    frozen=[]
    evidence=[p for p in (root/'scripts/evaluation').glob('*-results.json') if not p.name.startswith('audit30-')]
    evidence += [root/'scripts/evaluation/authorization_intent13.py',root/'scripts/evaluation/intent13_cases.py']
    evidence += [p for p in (root/'analyzers/typescript/test').glob('*cases.mjs')]
    evidence += [root/'src/test/java/com/securedeploy/analysis/deployment/Supply29ControlsTest.java',root/'src/test/java/com/securedeploy/sca/Alias29ControlsTest.java']
    for p in sorted(evidence):
        path=str(p.relative_to(root))
        original=subprocess.run(['git','show',BASELINE+':'+path],cwd=root,capture_output=True,check=True).stdout
        current=p.read_bytes()
        if original!=current:raise ValueError('FROZEN_EVIDENCE_CHANGED:'+path)
        frozen.append(dict(path=path,sha256=sha(current),unchangedFrom=BASELINE))
    return dict(schemaVersion=1,baselineCommit=BASELINE,matrix=matrix,frozenEvidence=frozen,
                method='Nonblind technical review and source occurrence index; no independent owner or runtime approval',
                inventoryLimit='Literal occurrence is not runtime registration or complete per-rule API/version proof. Unmapped versions and runtime claims remain NOT_VERIFIED.',
                noFamilyFullyVerified=True,originalMetricsNotPooled=True,newIndependentHoldout=0,newRealVulnerabilityTP=0,
                unresolvedIntentBoundary='Separate ownership constraints proposed only; SOURCE_ONLY/DECLARED_INTENT evaluator unchanged',
                implementationReview='SSRF native HTTP branch identity and href replacement only; no new framework, Rule, risk formula or limit increase',
                baselineCoverageMatrix=dict(path='docs/evaluation/security-coverage21.md',sha256=sha((root/'docs/evaluation/security-coverage21.md').read_bytes())))

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path);args=parser.parse_args()
    result=build()
    with args.output.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(areas=len(result['matrix']),frozenEvidence=len(result['frozenEvidence']),familiesFullyVerified=0)))
