"""Offline benchmark accounting. External code is data, never imported or executed."""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import os
import signal
import subprocess
import sys
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[2]
LABELS = {"DANGEROUS", "SAFE", "UNKNOWN", "UNVERIFIED"}
SPLITS = {"REGRESSION", "VALIDATION", "HOLDOUT"}
CAUSES = {"COLLECTION_MISSING", "PARSE_FAILURE", "RESOURCE_LIMIT", "UNSUPPORTED_LANGUAGE_FRAMEWORK",
          "SOURCE_RECOGNITION", "SINK_RECOGNITION", "INTERPROCEDURAL_FLOW", "INTERCLASS_FLOW",
          "OBJECT_FIELD_FLOW", "TYPE_CALL_RESOLUTION", "BRANCH_STATE_MERGE", "DEFENSE_BINDING",
          "PATTERN_FALSE_POSITIVE", "DUPLICATE_FINDING", "COVERAGE_RECORD", "RISK_INTEGRATION", "GROUND_TRUTH_UNCERTAIN", "EVALUATION_CONTEXT_INCOMPLETE"}
HOSTS = {"raw.githubusercontent.com", "api.github.com", "github.com", "www.djangoproject.com"}
ID = re.compile(r"[A-Za-z0-9_-]{1,100}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SECRET = re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{30,}|sk-(?:proj-)?[A-Za-z0-9_-]{35,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_size > 20_000_000:
        raise ValueError("JSON_PATH_OR_SIZE")
    return json.loads(path.read_text())


def write(path, data):
    path = Path(path)
    text=json.dumps(data,indent=2,ensure_ascii=False)+'\n'
    if SECRET.search(text.encode()):raise ValueError('SENSITIVE_METADATA_PATTERN')
    # Exclusive creation preserves first results and consumed-holdout records.
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        stream.write(text)


def outside(path):
    path = Path(path).expanduser().resolve()
    if path == REPO or REPO in path.parents:
        raise ValueError("EXTERNAL_DATA_MUST_STAY_OUTSIDE_GIT")
    return path


def relative(name):
    p = PurePosixPath(name)
    if not name or len(name)>512 or len(p.parts)>20 or urllib.parse.unquote(name)!=name or p.is_absolute() or ".." in p.parts or "\\" in name or ":" in name:
        raise ValueError("SOURCE_PATH")
    return p


def pinned_source(c, f):
    repository=c['repositoryUrl'].rstrip('/').removesuffix('.git')
    if not re.fullmatch(r'https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository):
        raise ValueError('PUBLIC_REPOSITORY_IDENTITY')
    expected='https://raw.githubusercontent.com/'+repository.removeprefix('https://github.com/')+'/'+c['repositoryCommitSha']+'/'+str(relative(f['path']))
    if f.get('url')!=expected or not SHA.fullmatch(c['repositoryCommitSha']):
        raise ValueError('SOURCE_URL_MUST_MATCH_PINNED_REPOSITORY_COMMIT_PATH')


def check_url(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.hostname not in HOSTS or u.username or u.password or u.port not in (None, 443) or u.fragment:
        raise ValueError("PUBLIC_URL_POLICY")
    if re.search(r"token|secret|password|api.?key", u.query, re.I):
        raise ValueError("CREDENTIAL_QUERY")
    return url


class RedirectPolicy(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    def __init__(self, cache_root=None):
        self.cache = {}
        self.total = 0
        self.requests = 0
        self.opener = urllib.request.build_opener(RedirectPolicy())
        self.cache_root = outside(cache_root) if cache_root else None
        if self.cache_root:
            self.cache_root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def fetch(self, url):
        check_url(url)
        key = digest(url.encode())
        if self.cache_root and url not in self.cache:
            metadata = self.cache_root / (key + ".json")
            blob = self.cache_root / (key + ".blob")
            if metadata.exists():
                m = read(metadata)
                if blob.is_symlink() or blob.stat().st_size > 1_000_000:
                    raise ValueError("CACHE_LIMIT")
                value = blob.read_bytes()
                if m["url"] != url or m["sha256"] != digest(value) or SECRET.search(value):
                    raise ValueError("CACHE_INTEGRITY")
                self.total += len(value)
                if self.total > 20_000_000:
                    raise ValueError("CACHE_TOTAL_LIMIT")
                self.cache[url] = value
        if url not in self.cache:
            if self.requests >= 200:
                raise ValueError("REQUEST_LIMIT")
            self.requests += 1
            request = urllib.request.Request(url, headers={"User-Agent": "SecureDeploy-readonly-benchmark", "Accept": "application/vnd.github+json" if "api.github.com" in url else "text/plain"})
            with self.opener.open(request, timeout=25) as response:
                data = response.read(1_000_001)
            self.total += len(data)
            if len(data) > 1_000_000 or self.total > 20_000_000:
                raise ValueError("DOWNLOAD_LIMIT")
            if SECRET.search(data):
                raise ValueError("CREDENTIAL_PATTERN_ACQUISITION_REJECTED")
            self.cache[url] = data
            if self.cache_root:
                with (self.cache_root / (key + ".blob")).open("xb") as stream:
                    (self.cache_root / (key + ".blob")).chmod(0o600)
                    stream.write(data)
                write(self.cache_root / (key + ".json"), {"url": url, "sha256": digest(data)})
        return self.cache[url]


def validate(manifest, root=None):
    if manifest.get("schemaVersion") != 1 or not SHA.fullmatch(manifest.get("engineBaselineCommit", "")):
        raise ValueError("MANIFEST_VERSION")
    cases = manifest.get("cases", [])
    if not cases or len(cases) > 200:
        raise ValueError("CASE_LIMIT")
    ids, groups, content_splits, normalized_splits = set(), {}, {}, {}
    pairs = defaultdict(list)
    for c in cases:
        cid = c["caseId"]
        if not ID.fullmatch(cid) or cid in ids or c["groundTruthLabel"] not in LABELS or c["evaluationSplit"] not in SPLITS:
            raise ValueError("CASE_ID_LABEL_SPLIT")
        ids.add(cid)
        if not SHA.fullmatch(c["repositoryCommitSha"]) or not c.get("license") or not c.get("labelEvidence"):
            raise ValueError("PROVENANCE_REQUIRED")
        if c["groundTruthLabel"] in {"DANGEROUS", "SAFE"} and not c.get("reviewed"):
            raise ValueError("UNREVIEWED_TRUTH")
        identities={k:c.get(k) for k in ("repositoryGroup","vulnerabilityFamily","forkGroup","cloneGroup","cve","ghsa")}
        identities['canonicalRepository']=c['repositoryUrl'].lower().removesuffix('.git').rstrip('/')
        for key, value in identities.items():
            group = (key, value)
            if group[1]:
                if groups.setdefault(group, c["evaluationSplit"]) != c["evaluationSplit"]:
                    raise ValueError("SPLIT_LEAKAGE_" + key)
        if c.get("pairId"):
            pairs[c["pairId"]].append(c)
        if not c.get("targetSites") or not c.get("files") or len(c["files"]) > 40:
            raise ValueError("TARGET_OR_FILES_REQUIRED")
        paths = set()
        total_bytes=0
        for f in c["files"]:
            relative(f["path"])
            pinned_source(c,f)
            if f["path"] in paths or not DIGEST.fullmatch(f["sha256"]):
                raise ValueError("FILE_DIGEST")
            paths.add(f["path"])
            if content_splits.setdefault(f["sha256"], c["evaluationSplit"]) != c["evaluationSplit"]:
                raise ValueError("DUPLICATE_CONTENT_SPLIT_LEAKAGE")
            if root is not None:
                path = Path(root) / "cases" / cid / f["path"]
                total_bytes+=path.stat().st_size
                if path.stat().st_size>1_000_000 or total_bytes>5_000_000:raise ValueError('CASE_SOURCE_LIMIT')
                if path.is_symlink() or not path.resolve().is_relative_to(Path(root).resolve()) or digest(path.read_bytes()) != f["sha256"]:
                    raise ValueError("ACQUIRED_SOURCE_INTEGRITY")
                normalized=digest(re.sub(rb'\s+',b'',path.read_bytes()))
                if normalized_splits.setdefault(normalized,c['evaluationSplit'])!=c['evaluationSplit']:
                    raise ValueError('WHITESPACE_DUPLICATE_SPLIT_LEAKAGE')
        for site in c["targetSites"] + c.get("sourceSites", []):
            if site["filePath"] not in paths or not 1 <= site["startLine"] <= site["endLine"] <= 100_000:
                raise ValueError("TARGET_SITE")
        for cause in c.get("confirmedCauses", []):
            if cause["category"] not in CAUSES or not cause.get("evidence"):
                raise ValueError("CONFIRMED_CAUSE_REQUIRES_EVIDENCE")
    for pair in pairs.values():
        if len(pair) != 2 or {c["groundTruthLabel"] for c in pair} != {"SAFE", "DANGEROUS"} or len({c["evaluationSplit"] for c in pair}) != 1:
            raise ValueError("VULNERABLE_FIXED_PAIR")
        if any(not SHA.fullmatch(c.get(k, "")) for c in pair for k in ("vulnerableCommitSha", "fixedCommitSha")):
            raise ValueError("PAIR_COMMIT_REQUIRED")
        if any(len({c.get(k)for c in pair})!=1 for k in ('repositoryUrl','vulnerableCommitSha','fixedCommitSha','vulnerabilityFamily','cve','ghsa')):
            raise ValueError('PAIR_PROVENANCE_MISMATCH')
        if any(c['repositoryCommitSha']!=c['vulnerableCommitSha'if c['groundTruthLabel']=='DANGEROUS'else'fixedCommitSha']for c in pair):
            raise ValueError('PAIR_REVISION_LABEL_MISMATCH')
    return {"cases": len(cases), "labels": dict(Counter(c["groundTruthLabel"] for c in cases)), "splits": dict(Counter(c["evaluationSplit"] for c in cases)), "pairs": len(pairs)}


def collect(plan, root, fetcher=None):
    root = outside(root)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    (root / "cases").mkdir(mode=0o700)
    fetcher = fetcher or Fetcher()
    stamp = datetime.now(timezone.utc).isoformat()
    for c in plan["cases"]:
        if not ID.fullmatch(c["caseId"]):
            raise ValueError("CASE_ID")
        directory = root / "cases" / c["caseId"]
        directory.mkdir(mode=0o700)
        for f in c["files"]:
            pinned_source(c,f)
            path = directory / relative(f["path"])
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            data = fetcher.fetch(f["url"])
            if f.get("sha256") and digest(data) != f["sha256"]:
                raise ValueError("UPSTREAM_DIGEST_CHANGED")
            f["sha256"] = digest(data)
            with path.open("xb") as stream:
                path.chmod(0o600)
                stream.write(data)
        c["collectionTimestamp"] = stamp
    # Evidence/license text is immutable but never sent to the scanner.
    evidence = root / "provenance"
    evidence.mkdir(mode=0o700)
    for i, asset in enumerate(plan.get("assets", [])):
        data = fetcher.fetch(asset["url"])
        if asset.get("sha256") and digest(data) != asset["sha256"]:
            raise ValueError("EVIDENCE_DIGEST_CHANGED")
        asset["sha256"] = digest(data)
        with (evidence / f"asset-{i}.txt").open("xb") as stream:
            (evidence / f"asset-{i}.txt").chmod(0o600)
            stream.write(data)
    plan["collection"] = {"timestamp": stamp, "requests": fetcher.requests, "bytes": fetcher.total}
    validate(plan, root)
    write(root / "manifest.json", plan)
    return validate(plan)


def at(location, sites):
    return any(location.get("filePath") == s["filePath"] and s["startLine"] <= location.get("line", 0) <= s["endLine"] for s in sites)


def signals(row, layer):
    if layer == "rule":
        return row["raw"]
    if layer == "filteredRule":
        return row["filtered"]
    if layer == "ast":
        out = []
        for use in row["java"]["analysis"]["uses"]:
            if use["kind"] == "INPUT_IN_QUERY":
                out.append({"ruleId": "JAVA_SQL_INPUT_FLOW", "location": use["location"], "trace": use["trace"]})
        for name in ("python", "typescript"):
            for finding in row[name].get("findings", []):
                out.append({"ruleId": finding["ruleId"], "location": finding["sink"], "trace": finding.get("flow", []) + [finding["source"]]})
        return out
    if layer == "reviewCandidate":
        return row["reviewCandidates"]
    if layer == "finalUser":
        return row["filtered"] + row["reviewCandidates"]
    raise ValueError("LAYER")


def matching(c, found, structural=False):
    matches = []
    for f in found:
        rule = f.get("ruleId")
        is_flow = "location" in f
        allowed = c.get("flowRules", []) if is_flow else c.get("patternRules", [])
        if rule not in allowed or not at(f.get("location", f), c["targetSites"]):
            continue
        if is_flow and c.get("sourceSites"):
            origins={'REQUEST_INPUT','REQUEST_COOKIE','COOKIE_VALUE'} if c['language']=='JAVA' else {'QUERY_PARAMETER','REQUEST_BODY','ROUTE_PARAMETER','REQUEST_HEADER','UPLOADED_FILE'}
            if not any(at(l,c['sourceSites']) and l.get('kind')in origins for l in f.get('trace',[])):
                continue
        # A CWE match or another warning elsewhere in the module is never a TP.
        matches.append(f)
    return matches


def inspection(c, row, layer):
    if row.get("analysisError"):
        return "ANALYSIS_FAILED"
    paths = {f["path"] for f in c["files"]}
    selected = {f["filePath"] for f in row["coverage"].get("entries", []) if f["status"] == "SELECTED"}
    if not paths.intersection(selected):
        return "NOT_INSPECTED"
    if layer == "rule" or layer == "filteredRule":
        return "INSPECTED" if c.get("patternRules") else "NOT_SUPPORTED"
    language = c["language"]
    if language == "JAVA":
        if row["java"]["analysis"].get("status") in {"UNAVAILABLE", "TIMEOUT", "FAILED"}:
            return "ANALYSIS_FAILED"
        files = row["java"]["analysis"]["files"]
        uses = row["java"]["analysis"]["uses"]
        if any(f["parseStatus"] == "PARSE_FAILED" for f in files):
            return "PARSE_FAILED"
        if any(f["parseStatus"] in {"LIMIT_EXCEEDED", "NOT_RUN"} for f in files):
            return "RESOURCE_LIMIT"
        relevant = [u for u in uses if at(u["location"], c["targetSites"])]
        if any(u["kind"] == "UNRESOLVED_QUERY" for u in relevant):
            return "UNKNOWN"
        if relevant:
            return "INSPECTED"
        return "NOT_SUPPORTED" if not any(f["entrypoints"] for f in files) else "NOT_INSPECTED"
    name = "python" if language == "PYTHON" else "typescript"
    if row[name].get("status") in {"UNAVAILABLE", "TIMEOUT", "FAILED"}:
        return "ANALYSIS_FAILED"
    files = row[name].get("files", [])
    # Flow budget exhaustion can occur after successful parsing. Preserve old
    # raw results, but do not classify that missing flow as framework support.
    if any(any(reason in {'ANALYSIS_BUDGET_EXCEEDED','ANALYSIS_STEP_BUDGET_EXCEEDED','ANALYSIS_TIME_BUDGET_EXCEEDED'}
               for reason in f.get('limitations',[])) for f in files):
        return "RESOURCE_LIMIT"
    if any(f["parseStatus"] == "PARSE_FAILED" for f in files):
        return "PARSE_FAILED"
    if any(f["parseStatus"] in {"LIMIT_EXCEEDED", "NOT_RUN"} for f in files):
        return "RESOURCE_LIMIT"
    if not any(f["entrypoints"] for f in files):
        return "NOT_SUPPORTED"
    if name == 'python' and 'PY_SQL_INPUT_FLOW' in c.get('flowRules', []):
        uses = [u for u in row[name].get('sqlUses', []) if at(u['location'], c['targetSites'])]
        if any(u['kind'] == 'UNRESOLVED_QUERY' for u in uses):
            return 'UNKNOWN'
        # A negative is inspected only when every named target has its own
        # static/bound query and non-lazy call evidence, not merely a parsed file.
        if c['targetSites'] and all(any(at(u['location'], [site])
                and u['kind'] in {'STATIC_QUERY', 'PARAMETERIZED_QUERY'}
                and u.get('executionObserved') is True and not u.get('limitations')
                for u in uses) for site in c['targetSites']):
            return 'INSPECTED'
    return "UNKNOWN"  # Parsing/entry recognition alone cannot prove the target path inspected.


def outcome(c, row, layer):
    if row.get("analysisError"):
        return {"verdict": "ANALYSIS_FAILED", "matches": 0, "inspection": "ANALYSIS_FAILED"}
    found = matching(c, signals(row, layer))
    truth = c["groundTruthLabel"]
    if truth not in {"SAFE", "DANGEROUS"}:
        return {"verdict": truth, "matches": len(found), "inspection": "GROUND_TRUTH_UNCERTAIN"}
    if found:
        return {"verdict": "TP" if truth == "DANGEROUS" else "FP", "matches": len(found), "inspection": "TARGET_LOCATION_MATCH",
                "evidenceKind": "PATTERN_OR_MIXED" if any("location" not in f for f in found) else "STRUCTURAL_PATH"}
    if layer == "reviewCandidate" and matching(c, signals(row, "ast")) and matching(c, row["filtered"]):
        return {"verdict": "MERGED_WITH_LEGACY", "matches": 0, "inspection": "PATH_EVIDENCE_LINKED_TO_EXISTING_WARNING"}
    state = inspection(c, row, layer)
    # Legacy pattern coverage remains usable while structural support is partial, but a negative
    # pattern result cannot certify a SAFE target whose structural path was never inspected.
    if layer == "finalUser" and state != "INSPECTED" and truth == "DANGEROUS" and c.get("patternRules"):
        state = "INSPECTED_PATTERN_ONLY"
    return {"verdict": ("FN" if truth == "DANGEROUS" else "TN") if state.startswith("INSPECTED") else state,
            "matches": 0, "inspection": state}


def stable(value):
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in {"elapsedMs", "parentHeapUsedBytes", "assessedAt", "generatedAt"}}
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


def metrics(rows):
    counts = Counter(r["verdict"] for r in rows)
    tp, fp, fn, tn = (counts[k] for k in ("TP", "FP", "FN", "TN"))
    def ratio(a, b):
        return a / b if b else None
    # Wilson bounds express small sample uncertainty, not distribution independence.
    def wilson(a, n):
        if not n:
            return None
        p, z = a / n, 1.96
        center = (p + z*z/(2*n)) / (1 + z*z/n)
        delta = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / (1 + z*z/n)
        return [max(0, center-delta), min(1, center+delta)]
    return {"counts": dict(counts), "precision": ratio(tp, tp+fp), "recallWithinScoredScope": ratio(tp, tp+fn),
            "falsePositiveRate": ratio(fp, fp+tn), "precisionWilson95": wilson(tp, tp+fp),
            "scoredCoverage": ratio(tp+fp+fn+tn, len(rows)), "sampleSize": len(rows)}


def score(manifest, raw):
    validate(manifest)
    cases = {c["caseId"]: c for c in manifest["cases"]}
    layers = ("rule", "filteredRule", "ast", "reviewCandidate", "finalUser")
    seen = set()
    results = []
    for r in raw["results"]:
        cid = r["caseId"]
        if cid not in cases or cid in seen or len(r["runs"]) != 2:
            raise ValueError("INVALID_ENGINE_RESULT")
        seen.add(cid)
        c, row = cases[cid], r["runs"][0]
        if c["evaluationSplit"] != raw["split"]:
            raise ValueError("RESULT_SPLIT_MISMATCH")
        target_indices={f'code:index:{i}'for i,f in enumerate(row['filtered'])if matching(c,[f])}
        target_risk=[f for f in row['risk'].get('codeFindings',[])if f['findingId']in target_indices]
        results.append({"caseId": cid, "truth": c["groundTruthLabel"], "language": c["language"], "framework": c["framework"],
                        "cwe": c["cwe"], "area": c["area"], "sourceDataset": c["sourceDataset"],
                        "repeatConsistent": stable(row) == stable(r["runs"][1]),
                        "layers": {layer: outcome(c, row, layer) for layer in layers},
                        "elapsedMs": [run["elapsedMs"] for run in r["runs"]],
                        "parentHeapUsedBytes": [run["parentHeapUsedBytes"] for run in r["runs"]],
                        "blocking": row["risk"]["prioritySummary"].get("BLOCKING", 0),
                        "targetRiskPriorities": dict(Counter(f['priority']for f in target_risk)),
                        "targetRiskReasons": sorted({f['reasonCode']for f in target_risk}),
                        "deploymentAssessment": row["risk"]["prioritizedDeploymentAssessment"],
                        "referenceSecurityScore": row.get('securityScore'), "riskPolicyVersion": row['risk'].get('policyVersion'),
                        "exactDuplicateSignals": exact_duplicates(matching(c, signals(row, "finalUser")))})
    selection=raw.get('selectionCaseId','ALL')
    expected = {c["caseId"] for c in cases.values() if c["evaluationSplit"] == raw["split"] and (selection=='ALL' or c['caseId']==selection)}
    if seen != expected:
        raise ValueError("INCOMPLETE_SPLIT_RESULTS")
    view = overview(results)
    return {"schemaVersion": 1, "engineCommit": raw["engineCommit"], "manifestSha256": raw["manifestSha256"],
            "runnerVersion": raw.get("runnerVersion", "LEGACY_UNRECORDED"), "accountingVersion": digest(Path(__file__).read_bytes()),
            "externalLookups": raw.get('externalLookups','UNRECORDED'),
            "split": raw["split"], **view, "results": results,
            "warnings": ["Scores are target-path alert accounting, not exploitation or whole-project safety.",
                         "NOT_SUPPORTED/UNKNOWN/NOT_INSPECTED are not TN; unsupported cases remain in effective coverage.",
                         "Related public source families and single-reviewer labels are not a blind independent benchmark.",
                         "Wilson intervals are descriptive; paired/correlated cases are not IID."]}


def overview(results):
    layers=("rule","filteredRule","ast","reviewCandidate","finalUser")
    summary = {layer: metrics([r["layers"][layer] for r in results]) for layer in layers}
    dangerous = sum(r["truth"] == "DANGEROUS" for r in results)
    for layer in layers:
        summary[layer]["effectiveDangerousDetectionCoverage"] = (sum(r["layers"][layer]["verdict"] in {"TP", "MERGED_WITH_LEGACY"} and r["truth"] == "DANGEROUS" for r in results) / dangerous) if dangerous else None
    groups = {}
    for field in ("language", "framework", "cwe", "area", "sourceDataset"):
        groups[field] = {value: {layer: metrics([r["layers"][layer] for r in results if r[field] == value]) for layer in layers}
                         for value in sorted({r[field] for r in results})}
    return {"summary": summary, "groups": groups,
            "effectiveDangerousDetectionCoverage": sum(r["layers"]["finalUser"]["verdict"] == "TP" for r in results) / max(1, sum(r["truth"] == "DANGEROUS" for r in results)),
            "exactDuplicateRate": sum(r['exactDuplicateSignals']for r in results)/max(1,sum(r['layers']['finalUser']['matches']for r in results)),
            "targetRiskCaseCounts": {p:sum(r.get('targetRiskPriorities',{}).get(p,0)>0 for r in results)for p in ('BLOCKING','REVIEW_REQUIRED','SHOULD_FIX','INFORMATIONAL')},
            "allRepeatsConsistent": all(r['repeatConsistent']for r in results)}


def combine(manifest, scored):
    if len(scored)!=3 or {s['split']for s in scored}!=SPLITS:
        raise ValueError('ALL_THREE_SPLITS_REQUIRED')
    if any(len({s[k]for s in scored})!=1 for k in ('manifestSha256','engineCommit','runnerVersion','accountingVersion','externalLookups')):
        raise ValueError('COMBINE_VERSION_MISMATCH')
    rows=[r for s in scored for r in s['results']]
    if len({r['caseId']for r in rows})!=len(rows) or {r['caseId']for r in rows}!={c['caseId']for c in manifest['cases']}:
        raise ValueError('COMBINE_CASE_MISMATCH')
    return {**{k:scored[0][k]for k in ('schemaVersion','engineCommit','manifestSha256','runnerVersion','accountingVersion','externalLookups','warnings')},
            'split':'ALL','results':rows,**overview(rows)}


def merge_raw(raws):
    if len(raws)!=3 or {r['split']for r in raws}!=SPLITS:
        raise ValueError('ALL_THREE_SPLITS_REQUIRED')
    if any(len({r.get(k)for r in raws})!=1 for k in ('manifestSha256','engineCommit','runnerVersion','isolation','externalLookups')):
        raise ValueError('RAW_COMBINATION_VERSION_MISMATCH')
    results=[item for raw in raws for item in raw['results']]
    if len({r['caseId']for r in results})!=len(results):raise ValueError('DUPLICATE_RAW_CASE')
    return {**raws[0],'split':'ALL','results':results}


def inferred_cause(c, row, result):
    v = result["layers"]["finalUser"]["verdict"]
    state = inspection(c, row, "ast")
    if c["groundTruthLabel"] not in {"SAFE", "DANGEROUS"}:
        return "GROUND_TRUTH_UNCERTAIN"
    if state == "PARSE_FAILED":
        return "PARSE_FAILURE"
    if state == "RESOURCE_LIMIT":
        return "RESOURCE_LIMIT"
    if state == "ANALYSIS_FAILED":
        return "COVERAGE_RECORD"
    if state == "NOT_SUPPORTED":
        return "UNSUPPORTED_LANGUAGE_FRAMEWORK"
    if state == "NOT_INSPECTED":
        return "COLLECTION_MISSING" if not row["coverage"].get("selectedFiles") else "SINK_RECOGNITION"
    return "PATTERN_FALSE_POSITIVE" if v == "FP" else "TYPE_CALL_RESOLUTION"


def packs(manifest, raw, scored, output, review=None):
    if any(raw.get(k)!=scored.get(k) for k in ('manifestSha256','engineCommit','split','runnerVersion')):
        raise ValueError('PACK_RESULT_VERSION_MISMATCH')
    if {r['caseId']for r in raw['results']}!={r['caseId']for r in scored['results']}:
        raise ValueError('PACK_CASE_MISMATCH')
    output = outside(output)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    byid = {r["caseId"]: r for r in raw["results"]}
    cases = {c["caseId"]: c for c in manifest["cases"]}
    index, groups = [], defaultdict(list)
    for result in scored["results"]:
        c = cases[result["caseId"]]
        final = result["layers"]["finalUser"]["verdict"]
        ast = result["layers"]["ast"]["verdict"]
        incomplete = {"UNKNOWN", "NOT_SUPPORTED", "NOT_INSPECTED", "PARSE_FAILED", "UNVERIFIED", "RESOURCE_LIMIT", "ANALYSIS_FAILED"}
        if final not in incomplete | {"FP", "FN"} and ast not in incomplete | {"FN"}:
            continue
        row = byid[c["caseId"]]["runs"][0]
        inferred = inferred_cause(c, row, result)
        confirmed = c.get("confirmedCauses", [])
        if review:
            if review["manifestSha256"] != raw["manifestSha256"] or review["engineCommit"] != raw["engineCommit"] or review.get('runnerVersion')!=raw.get('runnerVersion'):
                raise ValueError("MANUAL_REVIEW_VERSION_MISMATCH")
            confirmed = review.get("cases", {}).get(c["caseId"], [])
            if any(p["category"] not in CAUSES or not p.get("evidence") for p in confirmed):
                raise ValueError("MANUAL_CAUSE_EVIDENCE_REQUIRED")
        group = confirmed[0]["category"] if confirmed else inferred
        counterpart = [p["caseId"] for p in cases.values() if p["caseId"] != c["caseId"] and c.get("pairId") and p.get("pairId") == c["pairId"]]
        pack = {"schemaVersion": 1, "caseId": c["caseId"], "engineCommit": raw["engineCommit"],
                "publicReferences": {k: c.get(k) for k in ("sourceDataset", "repositoryUrl", "repositoryCommitSha", "vulnerableCommitSha", "fixedCommitSha", "cve", "ghsa", "cwe", "license", "labelEvidence")},
                "truth": {"label": c["groundTruthLabel"], "confidence": c["groundTruthConfidence"], "requiredConditions": c["requiredConditions"]},
                "targetSites": c["targetSites"], "sourceSites": c.get("sourceSites", []),
                "affectedFunction": c.get("affectedFunction"),
                "sourceToSinkEvidence": c["sourceToSinkEvidence"], "mitigationEvidence": c["mitigationEvidence"],
                "engineEvidence": {"rawTargetSignals": [signal_metadata(f)for f in matching(c,row['raw'])], "userTargetSignals": [signal_metadata(f)for f in matching(c,row['filtered'])],
                    "javaUses": [u for u in row['java']['analysis']['uses']if at(u['location'],c['targetSites'])],
                    "javaFiles": row['java']['analysis']['files'], "pythonFiles": row['python'].get('files',[]),
                    "typeScriptFiles": row['typescript'].get('files',[]), "filterAudit": row.get('filterAudit',[]),
                    "risk": {k:row['risk'][k]for k in ('prioritySummary','prioritizedDeploymentAssessment')}},
                "failureKind": "FINAL_FALSE_POSITIVE" if final=='FP' else "FINAL_FALSE_NEGATIVE" if final=='FN' else "STRUCTURAL_SCOPE_OR_UNCERTAINTY",
                "observed": result, "automaticCauseHypothesis": {"category": inferred, "confidence": "LOW", "status": "REQUIRES_MANUAL_REVIEW"},
                "manuallyConfirmedCauses": confirmed, "counterpartCaseIds": counterpart,
                "sourceReferences": [{"url": f["url"], "sha256": f["sha256"]} for f in c["files"]],
                "reproduce": f"gradle benchmarkEngine -PbenchmarkRoot=DATA_ROOT -PbenchmarkOutput=NEW_OUTSIDE_GIT_JSON -PbenchmarkSplit={c['evaluationSplit']} -PbenchmarkCase={c['caseId']}",
                "generalizedImprovement": next((p['improvementProposal']for p in confirmed if p.get('improvementProposal')),
                    c.get("improvementProposal", "Review target API/entry/type boundaries; do not hardcode this repository or names.")),
                "unknownFacts": c.get("unknownFacts", []) + ["No target execution, runtime reachability or exploit success validated."],
                "regressionUsePolicy": "Once used to improve the engine, move the entire repository/family to regression in a NEW manifest; never rewrite this baseline."}
        write(output / (c["caseId"] + ".json"), pack)
        index.append({"caseId": c["caseId"], "group": group, "confirmed": bool(confirmed), "verdict": final, "structuralVerdict": ast})
        groups[group].append(c["caseId"])
    stats=[]
    for group,ids in groups.items():
        entries=[r for r in index if r['caseId']in ids]
        stats.append({'category':group,'caseCount':len(ids),'repositoryCount':len({cases[cid]['repositoryGroup']for cid in ids}),
                      'manuallyConfirmed':sum(e['confirmed']for e in entries),'finalFalsePositives':sum(e['verdict']=='FP'for e in entries),
                      'finalFalseNegatives':sum(e['verdict']=='FN'for e in entries),'scopeGapCount':sum(e['verdict']not in {'FP','FN'}for e in entries)})
    write(output / "index.json", {"packs": index, "groups": dict(groups), 'groupStatistics':stats,
          "priorityPolicy": "Evidence and cross-repository recurrence before raw frequency; scope gaps are not confirmed vulnerabilities; automatic groups are hypotheses, not confirmed causes."})
    return {"packCount": len(index), "groups": {k: len(v) for k, v in groups.items()}}


def compare(a, b):
    if a["manifestSha256"] != b["manifestSha256"] or a["split"] != b["split"]:
        raise ValueError("COMPARISON_REQUIRES_IDENTICAL_DATASET_AND_SPLIT")
    if any(a.get(k) != b.get(k) for k in ('runnerVersion','accountingVersion')):
        raise ValueError("EVALUATOR_VERSION_CHANGED_NOT_ENGINE_EFFECT")
    if a.get('externalLookups')!=b.get('externalLookups'):
        raise ValueError('EXTERNAL_DATA_MODE_CHANGED')
    old, new = ({r["caseId"]: r for r in x["results"]} for x in (a, b))
    if old.keys() != new.keys():
        raise ValueError("COMPARISON_CASE_MISMATCH")
    changes, signal_changes, priority_changes, performance = [], [], [], []
    for cid in old:
        for layer in old[cid]["layers"]:
            before, after = (x[cid]["layers"][layer]["verdict"] for x in (old, new))
            if before != after:
                changes.append({"caseId": cid, "layer": layer, "before": before, "after": after})
            counts=[x[cid]['layers'][layer]['matches']for x in (old,new)]
            if counts[0]!=counts[1]:signal_changes.append(dict(caseId=cid,layer=layer,before=counts[0],after=counts[1]))
        if old[cid].get('targetRiskPriorities')!=new[cid].get('targetRiskPriorities'):
            priority_changes.append(dict(caseId=cid,before=old[cid].get('targetRiskPriorities'),after=new[cid].get('targetRiskPriorities')))
        def mean(values):return sum(values)/len(values) if values else None
        times=[mean(x[cid].get('elapsedMs',[]))for x in (old,new)]
        heaps=[max(x[cid].get('parentHeapUsedBytes',[0]))for x in (old,new)]
        performance.append(dict(caseId=cid,beforeMeanMs=times[0],afterMeanMs=times[1],deltaMs=times[1]-times[0]if None not in times else None,
                                beforeMaxSampledParentHeapBytes=heaps[0],afterMaxSampledParentHeapBytes=heaps[1]))
    regressions = [c for c in changes if c["before"] in {"TP", "TN"} and c["after"] != c["before"]]
    return {"beforeEngine": a["engineCommit"], "afterEngine": b["engineCommit"], "changes": changes,
            'signalChanges':signal_changes,'priorityChanges':priority_changes,'performance':performance,
            'riskPolicyChanged':any(old[cid].get('riskPolicyVersion')!=new[cid].get('riskPolicyVersion')for cid in old),
            'measurementLimits':'Timing includes worker startup; heap samples are not peak RSS/worker memory; repeated runs are not causal proof of performance change.',
            "regressions": regressions, "automaticSuccess": False, "status": "REGRESSION_REVIEW_REQUIRED" if regressions else "HUMAN_REVIEW_REQUIRED"}


def exact_duplicates(found):
    identities = [(f["ruleId"], f.get("location", f).get("filePath"), f.get("location", f).get("line"), f.get("location", f).get("column")) for f in found]
    return len(identities) - len(set(identities))


def signal_metadata(f):
    return {k:v for k,v in f.items()if k in {'ruleId','filePath','line','severity','confidence','falsePositiveRisk','location','trace','priority'}}


def execute(root, output, split, release=False, case_id=None):
    root, output = outside(root), outside(output)
    validate(read(root/'manifest.json'),root)
    if output.exists() or split not in SPLITS or case_id is not None and not ID.fullmatch(case_id):
        raise ValueError("RUN_OUTPUT_OR_SELECTION")
    if split=='HOLDOUT' and not release:
        raise ValueError("EXPLICIT_HOLDOUT_RELEASE_REQUIRED")
    # Benchmark changes are allowed; production analyzer/policy changes need a committed baseline.
    changed=subprocess.check_output(['git','diff','HEAD','--name-only','--','src/main','analyzers'],cwd=REPO)
    untracked=subprocess.check_output(['git','ls-files','--others','--exclude-standard','--','src/main','analyzers'],cwd=REPO)
    if changed.strip() or untracked.strip():
        raise ValueError("COMMIT_ENGINE_CHANGES_BEFORE_VERSIONED_EVALUATION")
    if split=='HOLDOUT':
        events=root/'holdout-events'
        events.mkdir(mode=0o700,exist_ok=True)
        write(events/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')+'.json'),
              {'event':'RESULTS_WILL_BE_OBSERVED','split':split,'caseId':case_id,'reusePolicy':'No longer unobserved after this execution; any subsequent tuning consumes this family.'})
    env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','LANG','LC_ALL','TMPDIR','JAVA_HOME'}}
    if release:env['BENCHMARK_RELEASE_HOLDOUT']='YES'
    args=['gradle','--no-daemon','benchmarkEngine',f'-PbenchmarkRoot={root}',f'-PbenchmarkOutput={output}',f'-PbenchmarkSplit={split}']
    if case_id:args.append('-PbenchmarkCase='+case_id)
    child=subprocess.Popen(args,cwd=REPO,env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
    try:
        code=child.wait(timeout=900)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid,signal.SIGTERM)
        try:child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL);child.wait()
        raise ValueError('EVALUATION_TIMEOUT')
    if code!=0 or not output.exists():raise ValueError('ENGINE_EXECUTION_FAILED')
    return {'status':'COMPLETE','split':split,'output':str(output),'externalLookups':'NOT_RUN'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["collect", "validate", "run", "score", "combine", "merge-raw", "packs", "compare", "show"])
    parser.add_argument('--release-holdout',action='store_true')
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    p = args.paths
    if args.command == "collect":
        result = collect(read(p[0]), p[1])
    elif args.command == "validate":
        result = validate(read(Path(p[0]) / "manifest.json"), p[0])
    elif args.command == "run":
        result = execute(p[0],p[1],p[2],args.release_holdout,p[3]if len(p)>3 else None)
    elif args.command == "score":
        manifest = read(Path(p[0]) / "manifest.json")
        raw = read(p[1])
        if digest((Path(p[0]) / "manifest.json").read_bytes()) != raw["manifestSha256"]:
            raise ValueError("MANIFEST_CHANGED_AFTER_RUN")
        result = score(manifest, raw)
        write(outside(p[2]), result)
        result = {"summary": result["summary"], "repeatConsistent": all(r["repeatConsistent"] for r in result["results"])}
    elif args.command == "packs":
        manifest = read(Path(p[0]) / "manifest.json")
        result = packs(manifest, read(p[1]), read(p[2]), p[3], read(p[4]) if len(p) > 4 else None)
    elif args.command == "combine":
        result=combine(read(Path(p[0])/'manifest.json'),[read(path)for path in p[2:]])
        write(outside(p[1]),result)
        result={'summary':result['summary'],'allRepeatsConsistent':result['allRepeatsConsistent']}
    elif args.command == 'merge-raw':
        result=merge_raw([read(path)for path in p[1:]])
        write(outside(p[0]),result)
        result={'caseCount':len(result['results']),'split':result['split']}
    elif args.command == "compare":
        result = compare(read(p[0]), read(p[1]))
        write(outside(p[2]), result)
    else:
        if not ID.fullmatch(p[1]):
            raise ValueError("CASE_ID")
        result = read(Path(p[0]) / (p[1] + ".json"))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Exception messages from HTTP/parser clients can contain source/credentials; do not echo.
        print("Benchmark failed; category=" + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
