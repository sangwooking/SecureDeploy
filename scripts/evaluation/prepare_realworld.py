"""Curated real-patch intake; only public text, never upstream tooling/PoVs.

Each tuple names reviewed implementation paths, input/operation, patch defense,
conditions and a reusable analysis capability. SAFE is local to that condition.
"""
import argparse
import csv
import difflib
import io
import json
from pathlib import Path
import re
from benchmark import Fetcher, collect, digest, outside, read, write
from cvefixes_metadata import parse_prefix

BASELINE = 'c71863844df520bebe9185bebbc54fef081e4184'
VUL4J_SHA = '376411da11fa705019f731404de1d0679fe73537'
VUL4J_CSV = f'https://raw.githubusercontent.com/tuhh-softsec/vul4j/{VUL4J_SHA}/dataset/vul4j_dataset.csv'

# id, split, CWE (analyst path classification), area, targets, extra context,
# input -> operation, patch defense, required conditions / residual uncertainty, capability
SPECS = [
 ('vul4j-2','REGRESSION','CWE-611','FILE_DESERIALIZATION',
  ['batik-dom/src/main/java/org/apache/batik/dom/util/SAXDocumentFactory.java'],[],
  'Caller-controlled XML InputSource reaches SAX parser.parse; external DTD loading was not explicitly disabled.',
  'Both parser creation paths set load-external-dtd=false.',
  'Attacker-controlled XML and parser implementation that resolves external DTDs; no network or XML payload executed.', 'XML parser feature configuration and caller input contracts'),
 ('vul4j-9','REGRESSION','CWE-502','FILE_DESERIALIZATION',
  ['src/main/java/org/apache/commons/configuration2/YAMLConfiguration.java'],[],
  'Reader/InputStream YAML reaches Yaml.load and can request Java object construction.',
  'All four read paths use a Constructor that rejects class loading.',
  'Untrusted YAML must reach this configuration loader; dependency internals and object gadgets not executed.', 'Library deserialization input contracts and constructor defenses'),
 ('vul4j-10','REGRESSION','CWE-20','FILE_DESERIALIZATION',
  ['src/main/java/org/apache/commons/fileupload/disk/DiskFileItem.java'],[],
  'Deserialized repository state reaches getOutputStream during readObject.',
  'readObject rejects non-directory repositories and null characters.',
  'Label covers the named repository validation defect, not all Java deserialization attacks or gadgets.', 'Deserialized field state and file write effects'),
 ('vul4j-14','VALIDATION','CWE-22','FILE_DESERIALIZATION',
  ['src/main/java/org/apache/commons/io/FilenameUtils.java'],[],
  'Malformed UNC-style filename prefix affects normalization results used by caller filesystem code.',
  'Hostname prefix is checked before returning a valid prefix length.',
  'A caller must rely on normalization for path security; no filesystem operation is in this utility itself. CWE is path-level analyst classification.', 'Normalization contracts, validation and downstream callers'),
 ('vul4j-18','VALIDATION','CWE-22','FILE_DESERIALIZATION',
  ['jspwiki-main/src/main/java/org/apache/wiki/url/DefaultURLConstructor.java'],[],
  'HttpServletRequest.getPathInfo is returned as the forward-page choice.',
  'getForwardPage returns the fixed Wiki.jsp page.',
  'Downstream servlet forwarding and container routing are required; caller wiring is not a complete project here.', 'Servlet path source to forwarding across classes'),
 ('vul4j-22','HOLDOUT','CWE-284','AUTHORIZATION',
  ['web/src/main/java/org/apache/shiro/web/util/WebUtils.java'],[],
  'Servlet context path decoding without consistent normalization can disagree with access-control path matching.',
  'Context path is decoded and normalized before slash special handling.',
  'Servlet container decoding and Shiro filters determine exploitability; no authorization bypass executed.', 'Canonicalization consistency at authorization boundary'),
 ('vul4j-38','REGRESSION','CWE-74','INPUT_INJECTION',
  ['cas-client-core/src/main/java/org/jasig/cas/client/validation/AbstractUrlBasedTicketValidator.java'],
  ['cas-client-core/src/main/java/org/jasig/cas/client/validation/Cas20ServiceTicketValidator.java'],
  'Ticket and other URL parameter values are appended to the CAS validation URL without consistent value encoding.',
  'All parameter values are encoded once when appended; previously pre-encoded values are no longer pre-encoded.',
  'CAS validation endpoint and caller-controlled ticket are needed; patched path is not proof of entire CAS security.', 'URL parameter encoding versus request destination control'),
 ('vul4j-41','VALIDATION','CWE-22','FILE_DESERIALIZATION',
  ['src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java'],[],
  'Archive entryName is resolved under dir and later written as an extracted file.',
  'Patch rejects canonical destination paths that do not start with canonical target directory.',
  'SAFE is restricted to canonical paths outside the prefix. String-prefix sibling-directory cases and symlink races are NOT certified by this historical patch.', 'Archive entry path propagation and boundary-aware containment'),
 ('vul4j-48','HOLDOUT','CWE-347','CRYPTOGRAPHY',
  ['src/main/java/org/primeframework/jwt/JWTDecoder.java'],[],
  'JWT header algorithm=none enters the verifier-required decode path.',
  'Internal decode rejects none when callers have not explicitly allowed it.',
  'Only the verifier-required path is labelled; intentional unsigned parsing elsewhere is not a defect. CWE-347 is analyst classification.', 'JWT API overload and validation option semantics'),
 ('vul4j-51','REGRESSION','CWE-611','FILE_DESERIALIZATION',
  ['src/main/java/hudson/plugins/ccm/parser/CcmParser.java'],[],
  'CCM report InputStream is parsed by a general Digester without external entity hardening.',
  'SecureDigester replaces the general Digester.',
  'Malicious report and dependency SecureDigester behavior required. Vul4J row says CWE-918 but actual patch is XXE; preserve both classifications.', 'XML parser wrapper semantics and dependency defenses'),
 ('cvefixes-cve-2024-34351','HOLDOUT','CWE-918','INPUT_INJECTION',
  ['packages/next/src/server/app-render/action-handler.ts'],['packages/next/src/server/lib/start-server.ts'],
  'Request-derived originalHost is interpolated into the server action redirect fetch URL.',
  'Server startup sets an internal host; request construction prefers it to the incoming host.',
  'Self-hosted Next server, server action redirect and internal-host initialization matter. Fallback still uses originalHost; not universally safe.', 'Next server entry contracts and request-host to fetch destination'),
 ('cvefixes-cve-2024-23334','VALIDATION','CWE-22','FILE_DESERIALIZATION',
  ['aiohttp/web_urldispatcher.py'],[],
  'StaticResource request filename reaches path resolution with follow_symlinks enabled.',
  'Lexically normalized unresolved path must be relative to static root before symlink resolution.',
  'follow_symlinks=True and attacker-influenced static path; the option still permits intentional symlink escape. SAFE excludes other symlink policies.', 'aiohttp route contracts and lexical versus filesystem path validation'),
 ('cvefixes-cve-2023-32681','REGRESSION','CWE-200','SENSITIVE_EXPOSURE',
  ['requests/sessions.py'],[],
  'Proxy credentials are attached as Proxy-Authorization during redirected HTTPS requests and may reach the destination.',
  'Do not append the proxy header for HTTPS tunneling; standard adapter handles proxy auth.',
  'Authenticated proxy, redirect and TLS tunnel conditions; remote requests and credentials are not tested.', 'Sensitive header propagation across redirect and transport boundaries'),
 ('cvefixes-cve-2024-29041','HOLDOUT','CWE-601','INPUT_INJECTION',
  ['lib/response.js'],[],
  'Untrusted redirect URL is encoded before Location header emission, potentially changing its parsed host.',
  'Compare parsed original and encoded hosts and avoid changed-host encoding.',
  'Application redirect allowlist and malformed URL conditions required; patch does not make arbitrary redirects trusted.', 'URL parser and encoder agreement with application allowlists'),
 ('cvefixes-cve-2023-2954','VALIDATION','CWE-79','INPUT_INJECTION',
  ['blog/templatetags/blog_tags.py'],['djangoblog/utils.py','templates/comments/tags/comment_item.html','templates/comments/tags/comment_item_tree.html','comments/models.py'],
  'Stored comment body passes escape then Markdown and mark_safe into comment HTML.',
  'Comment templates select comment_markdown; Markdown output is sanitized with a Bleach tag/attribute allowlist before mark_safe.',
  'Stored attacker comment rendered by changed templates; external Markdown/Bleach semantics not executed or version-audited.', 'Template filters, persistent input and output-context sanitation'),
 ('cvefixes-cve-2023-34110','VALIDATION','CWE-209','SENSITIVE_EXPOSURE',
  ['flask_appbuilder/models/sqla/interface.py'],['flask_appbuilder/models/base.py'],
  'Database exception class and detail enter user-facing model messages and exception logs.',
  'Generic Database Error message replaces exception-derived message and formatted exception detail in selected paths.',
  'Selected add/edit/delete paths only. log.exception still records traceback; do not claim all log disclosures fixed. CWE is analyst classification.', 'Exception-to-message flow and distinction between client and server logs'),
 ('cvefixes-cve-2017-0881','REGRESSION','CWE-862','AUTHORIZATION',
  ['zerver/views/streams.py'],[],
  'Request stream id and autosubscribe can reach bulk_add_subscriptions for an invite-only stream.',
  'Subscription side effect additionally requires not stream.invite_only.',
  'Authenticated user, existing private stream and autosubscribe request needed; surrounding decorators and subscriptions service still matter.', 'Resource policy state and guarded authorization side effects'),
 ('cvefixes-cve-2020-15084','HOLDOUT','CWE-347','CRYPTOGRAPHY',
  ['lib/index.js'],[],
  'JWT middleware accepts verifier configuration without requiring an explicit allowed algorithms list.',
  'Middleware rejects missing or non-array algorithms configuration.',
  'JWT library algorithm/key type behavior and caller options required; algorithm itself is not inherently vulnerable.', 'CommonJS middleware factory and verifier configuration contracts'),
 ('cvefixes-cve-2024-32879','VALIDATION','CWE-287','AUTHORIZATION',
  ['social_django/models.py'],[],
  'Social login provider/uid lookup may use case-insensitive database collation and return another identity.',
  'Candidates returned by DB are compared to uid case-sensitively before returning a user binding.',
  'Case-insensitive DB collation such as MySQL/MariaDB; no real accounts or login attempts used.', 'Identity comparison versus ORM collation semantics'),
 ('cvefixes-cve-2016-9964','REGRESSION','CWE-93','INPUT_INJECTION',
  ['bottle.py'],[],
  'Application-derived redirect/header value reaches HeaderDict without CR/LF validation.',
  'Header keys and values reject CR/LF/NUL; assignment and append use the shared validator.',
  'Attacker-controlled header value supplied by an application; Python 2 compatibility paths may not parse in the current Python worker.', 'HTTP header output context and custom validation helpers'),
]

FAMILIES = {
 'vul4j-2':'xml-external-entity','vul4j-51':'xml-external-entity',
 'vul4j-9':'yaml-object-construction','vul4j-10':'deserialized-repository-state',
 'vul4j-14':'unc-path-normalization','vul4j-18':'servlet-forward-target',
 'vul4j-22':'authorization-path-canonicalization','vul4j-38':'cas-query-value-encoding',
 'vul4j-41':'archive-entry-containment','vul4j-48':'jwt-algorithm-verification',
 'cvefixes-cve-2020-15084':'jwt-algorithm-verification',
 'cvefixes-cve-2024-34351':'server-action-host-ssrf','cvefixes-cve-2024-23334':'static-resource-containment',
 'cvefixes-cve-2023-32681':'redirect-proxy-credential-propagation',
 'cvefixes-cve-2024-29041':'redirect-host-encoding','cvefixes-cve-2023-2954':'stored-markdown-html',
 'cvefixes-cve-2023-34110':'exception-message-disclosure','cvefixes-cve-2017-0881':'private-stream-subscription',
 'cvefixes-cve-2024-32879':'identity-collation-mismatch','cvefixes-cve-2016-9964':'http-header-crlf',
}


def patch_sites(path, before, after):
    """Reviewed patch neighborhoods, not an entire file or arbitrary warning."""
    result = {'parent': [], 'fixed': []}
    for group in difflib.SequenceMatcher(None, before.splitlines(), after.splitlines(), autojunk=False).get_grouped_opcodes(8):
        first, last = group[0], group[-1]
        for version, start, end, length in [('parent',first[1],last[2],len(before.splitlines())),('fixed',first[3],last[4],len(after.splitlines()))]:
            result[version].append(dict(filePath=path,startLine=max(1,min(start+1,length)),endLine=max(1,min(max(start+1,end),length))))
    return result


def build(root, metadata, pins):
    root = outside(root)
    # Parse the actual retained official bytes again, not an unverified row list.
    prefix=outside(Path(metadata)/'prefix.bin')
    if (Path(metadata)/'prefix.bin').is_symlink() or prefix.stat().st_size>2097152:
        raise ValueError('METADATA_PREFIX_PATH_OR_SIZE')
    fixes, receipt = parse_prefix(prefix.read_bytes())
    if read(Path(metadata)/'receipt.json') != receipt:
        raise ValueError('CVEFIXES_RECEIPT_MISMATCH')
    f = Fetcher(root.parent/'cache')
    csv_bytes=f.fetch(VUL4J_CSV)
    vul={r['vul_id'].lower():r for r in csv.DictReader(io.StringIO(csv_bytes.decode()))}
    plan=dict(schemaVersion=1,engineBaselineCommit=BASELINE,
              reviewer='Single curator reviewing patches; not independently blinded',
              splitPolicy='Repository/fork/CVE/family and both revisions stay together; only new projects, no prior BenchmarkJava sources.',
              collectionMetadata=receipt,cases=[],assets=[])
    for spec in SPECS:
        ident,split,cwe,area,targets,extras,flow,defense,conditions,capability=spec
        pin=pins[ident];repo=pin['repository'];fixed=pin['fixed'];parent=pin['parent']
        if ident.startswith('vul4j-'):
            row=vul[ident]
            if row['human_patch'] != f'https://github.com/{repo}/commit/{fixed}':
                raise ValueError('VUL4J_PATCH_IDENTITY')
            dataset='Vul4J official CSV';cve=row['cve_id'];dataset_cwe=row['cwe_id']
            dataset_ref=VUL4J_CSV
        else:
            if not any(r['cve']==pin['cve'] and r['fixed']==fixed and r['repositoryUrl']=='https://github.com/'+repo for r in fixes):
                raise ValueError('CVEFIXES_MEMBERSHIP_REQUIRED')
            dataset='CVEfixes v1.0.8 fixes table';cve=pin['cve'];dataset_cwe=None
            dataset_ref=receipt['sourceUrl']
        commit_url=f'https://api.github.com/repos/{repo}/commits/{fixed}'
        commit=json.loads(f.fetch(commit_url))
        if commit['sha']!=fixed or commit['parents'][0]['sha']!=parent:
            raise ValueError('PARENT_REVISION_MISMATCH')
        changed={x['filename'] for x in commit['files']}
        if not set(targets).issubset(changed):raise ValueError('TARGET_NOT_IN_PATCH')
        versions={v:{} for v in ('parent','fixed')};sites={v:[] for v in versions}
        for path in targets+extras:
            for v,sha in [('parent',parent),('fixed',fixed)]:
                data=f.fetch(f'https://raw.githubusercontent.com/{repo}/{sha}/{path}')
                versions[v][path]=data
            if path in targets:
                spans=patch_sites(path,versions['parent'][path].decode(),versions['fixed'][path].decode())
                for v in versions:sites[v].extend(spans[v])
        if not all(sites.values()):raise ValueError('NO_PATCH_NEIGHBORHOOD')
        license_url=f'https://raw.githubusercontent.com/{repo}/{fixed}/{pin["licensePath"]}'
        license_bytes=f.fetch(license_url)
        if not license_bytes:raise ValueError('LICENSE_REQUIRED')
        plan['assets'] += [dict(kind='upstream-license',url=license_url,repository=repo),dict(kind='patch-metadata',url=commit_url)]
        suffix=targets[0].rsplit('.',1)[-1]
        language={'java':'JAVA','py':'PYTHON','js':'JAVASCRIPT','ts':'TYPESCRIPT'}[suffix]
        rules={'CWE-918':['TS_SSRF_INPUT_FLOW'] if language in {'TYPESCRIPT','JAVASCRIPT'} else [],
               'CWE-22':['PY_FILE_PATH_INPUT_FLOW'] if language=='PYTHON' else [],
               'CWE-209':['PY_ERROR_DETAIL_EXPOSURE'] if language=='PYTHON' else []}.get(cwe,[])
        for v,label in [('parent','DANGEROUS'),('fixed','SAFE')]:
            files=[dict(path=p,url=f'https://raw.githubusercontent.com/{repo}/{pin[v]}/{p}',sha256=digest(data)) for p,data in versions[v].items()]
            plan['cases'].append(dict(caseId=ident+'-'+v,pairId=ident,sourceDataset=dataset,repositoryUrl='https://github.com/'+repo,
                repositoryCommitSha=pin[v],vulnerableCommitSha=parent,fixedCommitSha=fixed,
                repositoryGroup=repo.lower(),forkGroup=repo.lower(),vulnerabilityFamily=FAMILIES[ident],cve=cve,ghsa=None,
                cwe=cwe,datasetCwe=dataset_cwe,cweProvenance='ANALYST_PATH_CLASSIFICATION' if dataset_cwe!=cwe else 'VUL4J_DATASET',
                area=area,language=language,framework=pin['framework'],license=pin['license'],
                groundTruthLabel=label,groundTruthConfidence='DATASET_FIX_AND_ORIGINAL_PATCH_REVIEW',reviewed=True,
                affectedFunction='Reviewed patch neighborhoods; see original commit hunk function context',
                targetSites=sites[v],sourceSites=[dict(filePath=p,startLine=1,endLine=len(data.decode().splitlines())) for p,data in versions[v].items()],
                sourceSiteScope='Whole retained implementation file; library caller input may remain absent. Matching a request-origin trace is still required.',
                patternRules=[],flowRules=rules,labelEvidence=[dataset_ref,f'https://github.com/{repo}/commit/{fixed}'],
                sourceToSinkEvidence=flow,mitigationEvidence=defense if v=='fixed' else 'The named patch defense is absent in this parent revision.',
                requiredConditions=conditions,evaluationSplit=split,files=files,
                improvementProposal=capability,
                unknownFacts=['No upstream code, build, install or PoV executed.','SAFE applies only to the named changed condition under the stated assumptions.',
                              'Selected original application/library files and local context, not a complete deployed application.',
                              'Parent is first parent of the official patch; merge parents are recorded in retained metadata.',
                              'Patch neighborhoods are not a complete source-to-sink ground-truth trace; missing callers remain explicit.']))
    plan['assets'].append(dict(kind='dataset-metadata',url=VUL4J_CSV))
    plan['assets'].append(dict(kind='dataset-license',url=f'https://raw.githubusercontent.com/tuhh-softsec/vul4j/{VUL4J_SHA}/DATA_LICENSE'))
    plan['assets'].append(dict(kind='dataset-license',url='https://raw.githubusercontent.com/secureIT-project/CVEfixes/9283b50b3f04e3c5b0a17fc419ab0feea23fc438/LICENSE.txt'))
    result=collect(plan,root,f)
    write(root/'catalog.json',plan)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('root');parser.add_argument('metadata');parser.add_argument('pins')
    args=parser.parse_args()
    try: print(json.dumps(build(args.root,args.metadata,read(args.pins))))
    except Exception as error:
        print('Real-world collection failed; category='+type(error).__name__)
        raise SystemExit(1)
