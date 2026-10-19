"""Pre-label internal cases before running the engine; never execute target code.

Same developer, later-authored evaluation: not independent or representative.
SAFE/DANGEROUS labels concern the named condition, not whole-application safety.
"""
import hashlib
import json
import pathlib
import sys
import textwrap


def prepare(destination):
    destination.mkdir(parents=True, exist_ok=False)
    cases = []

    def add(name, area, truth, rule, files, support="DATA_FLOW_PARTIAL"):
        directory = destination / name
        directory.mkdir()
        for path, content in files.items():
            target = directory / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        cases.append(dict(id=name, area=area, truth=truth, rule=rule, support=support,
                          files={p: hashlib.sha256(c.encode()).hexdigest() for p, c in files.items()}))

    def py(name, area, truth, rule, body, imports=""):
        add(name, area, truth, rule, {"views.py": imports + "\nfrom rest_framework.decorators import api_view\n"
            "from django.db import connection\nfrom django.http import JsonResponse\n"
            "@api_view(['POST'])\ndef inspect(request):\n" + textwrap.indent(body, "    ")})

    py("sql-forward", "input", "DANGEROUS", "PY_SQL_INPUT_FLOW", "value=request.POST['filter']\nquery=f'SELECT id FROM accounts WHERE name={value}'\nwith connection.cursor() as database:\n    database.execute(query)")
    py("sql-bound", "input", "SAFE", "PY_SQL_INPUT_FLOW", "value=request.POST['filter']\nwith connection.cursor() as database:\n    database.execute('SELECT id FROM accounts WHERE name=%s',[value])")
    py("sql-wrapper", "input", "UNKNOWN", "PY_SQL_INPUT_FLOW", "value=external_filter(request.POST['filter'])\nwith connection.cursor() as database:\n    database.execute('SELECT '+value)")
    py("sql-byte-roundtrip", "input", "DANGEROUS", "PY_SQL_INPUT_FLOW", "value=request.POST['filter']\nquery='SELECT '+value.encode().decode()\nwith connection.cursor() as database:\n    database.execute(query)")
    py("file-relative", "file", "DANGEROUS", "PY_FILE_PATH_INPUT_FLOW", "name=request.POST['filename']\nreturn open(Path('/srv/reports')/name).read()", "from pathlib import Path")
    py("file-fixed", "file", "SAFE", "PY_FILE_PATH_INPUT_FLOW", "open('/srv/reports/fixed','w').write(request.body)")
    py("file-validator", "file", "UNKNOWN", "PY_FILE_PATH_INPUT_FLOW", "name=validate_path(request.POST['filename'])\nreturn open(name).read()")
    py("object-upload", "file", "DANGEROUS", "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW", "data=request.body\nreturn pickle.loads(data)", "import pickle")
    py("object-json", "file", "SAFE", "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW", "return json.loads(request.body)", "import json")
    py("object-loader", "file", "UNKNOWN", "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW", "return yaml.load(request.body,Loader=select_loader())", "import yaml")
    py("token-display", "crypto", "SAFE", "PY_JWT_UNVERIFIED_ACCESS_DECISION", "claims=jwt.decode(request.POST['token'], options={'verify_signature':False})\nreturn JsonResponse({'display':claims})", "import jwt")
    py("token-permission", "crypto", "DANGEROUS", "PY_JWT_UNVERIFIED_ACCESS_DECISION", "claims=jwt.decode(request.POST['token'], options={'verify_signature':False})\nif not claims['admin']:\n    raise PermissionDenied()\nreturn JsonResponse({'allowed':True})", "import jwt\nfrom django.core.exceptions import PermissionDenied")
    py("token-middleware", "crypto", "UNKNOWN", "PY_JWT_UNVERIFIED_ACCESS_DECISION", "claims=verify_elsewhere(request.POST['token'])\nif not claims['admin']:\n    raise PermissionDenied()\nreturn JsonResponse({})", "from django.core.exceptions import PermissionDenied")
    py("exposure-header", "exposure", "DANGEROUS", "PY_SENSITIVE_RESPONSE_EXPOSURE", "auth=request.headers['Authorization']\nreturn JsonResponse({'diagnostic':auth})")
    py("exposure-fixed", "exposure", "SAFE", "PY_SENSITIVE_RESPONSE_EXPOSURE", "return JsonResponse({'diagnostic':'Please sign in'})")
    py("exposure-redactor", "exposure", "UNKNOWN", "PY_SENSITIVE_RESPONSE_EXPOSURE", "auth=request.headers['Authorization']\nreturn JsonResponse({'diagnostic':redact(auth)})")
    py("service-implicit", "stability", "DANGEROUS", "PY_HTTP_TIMEOUT_REVIEW", "requests.get('https://service.invalid/')\nreturn JsonResponse({})", "import requests")
    py("service-explicit", "stability", "SAFE", "PY_HTTP_TIMEOUT_REVIEW", "requests.get('https://service.invalid/',timeout=(2,5))\nreturn JsonResponse({})", "import requests")
    py("service-config", "stability", "UNKNOWN", "PY_HTTP_TIMEOUT_REVIEW", "requests.get('https://service.invalid/',timeout=load_timeout())\nreturn JsonResponse({})", "import requests")
    py("error-stack", "stability", "DANGEROUS", "PY_ERROR_DETAIL_EXPOSURE", "detail=traceback.format_stack()\nreturn JsonResponse({'detail':detail})", "import traceback")
    py("error-log", "stability", "SAFE", "PY_ERROR_DETAIL_EXPOSURE", "logging.error(traceback.format_stack())\nreturn JsonResponse({'detail':'Request failed'})", "import traceback\nimport logging")
    py("error-no-handler", "stability", "UNKNOWN", "PY_ERROR_DETAIL_EXPOSURE", "return JsonResponse({'detail':traceback.format_exc()})", "import traceback")
    for name, truth, body in [
        ("body", "DANGEROUS", "const x=await request.json(); return fetch(x.destination);"),
        ("fixed", "SAFE", "const x=await request.json(); return fetch('https://service.invalid/?q='+encodeURIComponent(x.query));"),
        ("opaque", "UNKNOWN", "const x=new URL(request.url).searchParams.get('target'); return fetch(buildTarget(x));")]:
        add("ssrf-"+name,"input",truth,"TS_SSRF_INPUT_FLOW",{"server.ts":"export default {async fetch(request,env){"+body+"}}"})
    add("ssrf-express","input","DANGEROUS","TS_SSRF_INPUT_FLOW",{"server.ts":"import express from 'express'; const app=express(); app.get('/forward',(req,res)=>{fetch(req.query.target);});"},"NOT_SUPPORTED")
    for name, truth, source in [
        ("root", "DANGEROUS", "FROM alpine:3.20\nUSER root\n"),
        ("nonroot", "SAFE", "FROM alpine:3.20 AS build\nUSER root\nFROM build AS runtime\nUSER 1001\n"),
        ("unknown", "UNKNOWN", "FROM registry.invalid/custom:1\n")]:
        add("docker-"+name,"deployment",truth,"DOCKER_ROOT_USER",{"Dockerfile":source},"STRUCTURAL")
    for name, truth, source in [
        ("public-login", "SAFE", 'http.requestMatchers("/login").permitAll();'),
        ("external", "UNKNOWN", 'http.anyRequest().access(customPolicy);'),
        ("all-public", "DANGEROUS", 'http.anyRequest().permitAll();')]:
        add("java-auth-"+name,"authorization",truth,"PERMIT_ALL_USAGE",{"Routes.java":"class Routes {void configure(){"+source+"}}"},"PATTERN_ONLY")
    for name, truth, source in [
        ("concat", "DANGEROUS", 'String q="SELECT * FROM accounts WHERE id="+input; statement.execute(q);'),
        ("bound", "SAFE", 'PreparedStatement statement=connection.prepareStatement("SELECT * FROM accounts WHERE id=?"); statement.setString(1,input); statement.execute();'),
        ("wrapper", "UNKNOWN", 'String q=buildQuery(input); executor.run(q);')]:
        add("java-sql-"+name,"input",truth,"DANGEROUS_SQL",{"Query.java":"class Query {void run(String input){"+source+"}}"},"PATTERN_ONLY")
    for name, truth, version in [("old","DANGEROUS","4.17.10"),("patched","SAFE","4.17.21"),("range","UNKNOWN","^4.17.10")]:
        add("npm-"+name,"supply-chain",truth,"VULNERABLE_NPM_DEPENDENCY",{"package.json":json.dumps({"dependencies":{"lodash":version}})},"STRUCTURAL")
    manifest=dict(schemaVersion=1,provenance="internal pre-labelled later-authored set; same developer, not independent",
                  truthScope="named static condition only, not exploit success or whole-project safety",cases=cases)
    (destination/"manifest.json").write_text(json.dumps(manifest,indent=2))
    print("prelabelled_internal_cases="+str(len(cases)))


if __name__ == "__main__":
    prepare(pathlib.Path(sys.argv[1]))
