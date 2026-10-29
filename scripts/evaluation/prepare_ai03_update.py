"""Opt-in evaluation helper: npm bytes after validated AI version selection, never a product patch validator."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(sys.argv[1]).resolve(strict=True)
name = sys.argv[2]
if name not in {"runwhen", "urisai"}:
    raise ValueError("PINNED_EVALUATION_PROJECT_REQUIRED")
project = root / name
advice = json.loads((project / "live-advice.json").read_text())
if advice["state"] != "GENERATED" or advice["provider"]["origin"] != "OPENAI":
    raise ValueError("VALIDATED_LIVE_DIRECTION_REQUIRED")
o = advice["output"]
if o["packageName"] != "undici" or o["candidateVersion"] not in {"7.30.1", "8.12.2"}:
    raise ValueError("PUBLIC_CANDIDATE_SCOPE_REQUIRED")
source = project / "before"
manifest = json.loads((source / "package.json").read_text())
original = json.loads((source / "package-lock.json").read_text())
if manifest.get("workspaces") or manifest.get("overrides") or original.get("lockfileVersion") != 3 or (source / ".npmrc").exists():
    raise ValueError("UNSUPPORTED_NPM_CONTRACT")
for section in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]:
    for spec in manifest.get(section, {}).values():
        if not isinstance(spec, str) or any(x in spec for x in ["file:", "git", "http:", "https:", "workspace:", "npm:"]):
            raise ValueError("PUBLIC_REGISTRY_SPEC_REQUIRED")
for item in original["packages"].values():
    if item.get("resolved") and not item["resolved"].startswith("https://registry.npmjs.org/"):
        raise ValueError("REGISTRY_SCOPE_REQUIRED")
if not any(p.endswith("node_modules/undici") and v.get("version") == o["lockedVersion"] for p, v in original["packages"].items()):
    raise ValueError("LOCKED_VERSION_MISMATCH")
target = project / "after"
if target.exists():
    raise ValueError("DO_NOT_OVERWRITE_EXISTING_OUTPUT")
shutil.copytree(source, target)
manifest["overrides"] = {"undici@" + o["lockedVersion"]: o["candidateVersion"]}
(target / "package.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
for f in ["empty-user.npmrc", "empty-global.npmrc"]:
    (root / f).touch(exist_ok=True)
cmd = ["/opt/homebrew/bin/npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
       "--registry=https://registry.npmjs.org/", "--userconfig=" + str(root / "empty-user.npmrc"),
       "--globalconfig=" + str(root / "empty-global.npmrc"), "--cache=" + str(root / "npm-cache")]
with (project / "npm-after-model.log").open("w") as log:
    subprocess.run(cmd, cwd=target, env={"PATH": "/opt/homebrew/bin:/usr/bin:/bin", "LANG": "en_US.UTF-8"},
                   stdout=log, stderr=subprocess.STDOUT, timeout=150, check=True)
updated = json.loads((target / "package-lock.json").read_text())
metadata = json.loads((root / "public-version-evidence.json").read_text())[o["candidateVersion"]]
changed_entries = []
for p in set(original["packages"]) | set(updated["packages"]):
    a, b = original["packages"].get(p), updated["packages"].get(p)
    if a == b:
        continue
    if not p.endswith("node_modules/undici") or (a is not None and a.get("version") != o["lockedVersion"]) or (b is not None and b.get("version") != o["candidateVersion"]):
        raise ValueError("UNEXPECTED_LOCK_GRAPH_CHANGE")
    changed_entries.append(p)
    if b and (b.get("integrity") != metadata["dist"]["integrity"] or b.get("resolved") != metadata["dist"]["tarball"]):
        raise ValueError("REGISTRY_INTEGRITY_MISMATCH")
if not changed_entries or (target / "node_modules").exists():
    raise ValueError("UNEXPECTED_PACKAGE_MANAGER_RESULT")
changed_files = []
for p in source.rglob("*"):
    if p.is_file() and p.read_bytes() != (target / p.relative_to(source)).read_bytes():
        changed_files.append(str(p.relative_to(source)))
if set(changed_files) != {"package.json", "package-lock.json"}:
    raise ValueError("UNEXPECTED_SOURCE_CHANGE")
if {str(p.relative_to(source)) for p in source.rglob("*") if p.is_file()} != {str(p.relative_to(target)) for p in target.rglob("*") if p.is_file()}:
    raise ValueError("UNEXPECTED_FILE_ADDITION_OR_DELETION")
receipt = dict(origin="NPM_AFTER_VALIDATED_MODEL_VERSION_SELECTION", modelProposal=advice["id"],
               changedFiles=changed_files, changedLockEntries=changed_entries, compatibility="NOT_VERIFIED", scriptsExecuted=False)
(project / "package-manager-receipt.json").write_text(json.dumps(receipt, indent=2))
print(json.dumps(receipt))
