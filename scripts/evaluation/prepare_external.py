"""Prepare locally acquired, pinned public sources without executing them.

Sources stay outside Git. Labels for Java come from the upstream CSV.
PyGoat SQL is manually reviewed static evidence, not a complete truth corpus.
"""
import hashlib
import json
import pathlib
import re
import shutil
import sys


def prepare(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    upstream=json.loads((source/"benchmark-truth.json").read_text())
    cases=[]
    for original in upstream["cases"]:
        case=dict(original,rule="DANGEROUS_SQL",support="PATTERN_ONLY")
        if not re.fullmatch(r"BenchmarkTest[0-9]{5}", case["id"]):
            raise ValueError("Invalid upstream evaluation identifier")
        data=(source/(case["id"]+".java")).read_bytes()
        if hashlib.sha256(data).hexdigest()!=case["sha256"]:
            raise ValueError("Public evaluation source fingerprint mismatch")
        directory=destination/case["id"]
        directory.mkdir()
        shutil.copyfile(source/(case["id"]+".java"),directory/(case["id"]+".java"))
        cases.append(case)
    pygoat=json.loads((source/"pygoat-provenance.json").read_text())
    directory=destination/"pygoat-sql"/"introduction"
    directory.mkdir(parents=True)
    for name in ("views.py","urls.py"):
        shutil.copyfile(source/("pygoat-"+name),directory/name)
    cases.append(dict(id="pygoat-sql",area="input",truth="DANGEROUS",rule="PY_SQL_INPUT_FLOW",
        support="DATA_FLOW_PARTIAL",labelBasis="SQL string concatenation with POST input, objects.raw and result indexing in sql_lab/injection_sql_lab; broader try/model execution is not supported",
        targetFunctions=["sql_lab","injection_sql_lab"],sha=pygoat["sha"]))
    manifest=dict(schemaVersion=1,provenance="external unmodified public sources, not whole-benchmark scoring",
        repositories=[dict(repository=upstream["repository"],sha=upstream["sha"]),pygoat],cases=cases)
    text=json.dumps(manifest,indent=2)
    (destination/"manifest.json").write_text(text)
    print("external_cases="+str(len(cases))+" manifest_sha256="+hashlib.sha256(text.encode()).hexdigest())


if __name__=="__main__":
    prepare(pathlib.Path(sys.argv[1]),pathlib.Path(sys.argv[2]))
