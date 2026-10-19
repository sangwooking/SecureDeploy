"""Bounded, anonymous read-only acquisition of pinned public evaluation text.

No clone, install, import, build, service probe or target execution. Do not use
these sources as new blind holdouts after reviewing the baseline results.
"""
import csv
import hashlib
import io
import json
import pathlib
import re
import sys
import urllib.request

BENCHMARK = "OWASP-Benchmark/BenchmarkJava"
BENCHMARK_SHA = "bc5ffeb09fb18ab039806d84ca1f718c2e332c54"
PYGOAT = "adeyosemanputra/pygoat"
PYGOAT_SHA = "19d17cc8874861142b330636d068bbde54e86b85"


def fetch(repository, sha, path):
    url = f"https://raw.githubusercontent.com/{repository}/{sha}/{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "SecureDeploy-readonly-evaluation"})
    with urllib.request.urlopen(request, timeout=25) as response:
        data = response.read(1_000_001)
    if len(data) > 1_000_000:
        raise ValueError("Public evaluation source exceeds download limit")
    return data


def acquire(output):
    output.mkdir(parents=True, exist_ok=False)
    truth = fetch(BENCHMARK, BENCHMARK_SHA, "expectedresults-1.2.csv").decode()
    rows = list(csv.reader(io.StringIO(truth)))
    selected = []
    for label in ("true", "false"):
        matching = [r for r in rows if len(r) > 3 and r[1] == "sqli" and r[2] == label]
        for row in matching[:6]:
            if not re.fullmatch(r"BenchmarkTest[0-9]{5}", row[0]):
                raise ValueError("Invalid upstream evaluation identifier")
            selected.append(dict(id=row[0], area="input", truth="DANGEROUS" if label == "true" else "SAFE",
                                 cwe=row[3], sourcePath=f"src/main/java/org/owasp/benchmark/testcode/{row[0]}.java"))
    if len(selected) != 12:
        raise ValueError("Pinned upstream truth table does not match selection policy")
    manifest = dict(repository=BENCHMARK, sha=BENCHMARK_SHA, cases=selected,
                    selection="first six SQLi true and first six SQLi false in upstream CSV")
    # Freeze labels before acquiring sources or invoking any engine.
    (output / "benchmark-truth.json").write_text(json.dumps(manifest, indent=2))
    for case in selected:
        data = fetch(BENCHMARK, BENCHMARK_SHA, case["sourcePath"])
        (output / (case["id"] + ".java")).write_bytes(data)
        case["sha256"] = hashlib.sha256(data).hexdigest()
    (output / "benchmark-truth.json").write_text(json.dumps(manifest, indent=2))
    for name in ("views.py", "urls.py"):
        (output / ("pygoat-" + name)).write_bytes(fetch(PYGOAT, PYGOAT_SHA, "introduction/" + name))
    (output / "pygoat-provenance.json").write_text(json.dumps(dict(repository=PYGOAT, sha=PYGOAT_SHA,
        files=["introduction/views.py", "introduction/urls.py"], labelStatus="MANUAL_SCOPE_REVIEW_REQUIRED"), indent=2))
    print("public_text_acquisition_complete; target_execution=NONE")


if __name__ == "__main__":
    acquire(pathlib.Path(sys.argv[1]))
