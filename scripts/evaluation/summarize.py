"""Report fixed evaluation results without treating missing/unknown as safety."""
import collections
import json
import pathlib
import sys

# A harness identifier typo, not a truth-label or engine change. Keep original rows.
RULE_CORRECTIONS = {"PY_SENSITIVE_RESPONSE_EXPOSURE": "PY_SENSITIVE_DATA_EXPOSURE"}


def verdict(case):
    run = case["runs"][0]
    rule = RULE_CORRECTIONS.get(case["targetRule"], case["targetRule"])
    detected = rule in run["ruleIds"]
    if case["support"] == "NOT_SUPPORTED":
        return "NOT_SUPPORTED"
    if any(run.get(language, {}).get("status") in {"TIMEOUT", "UNAVAILABLE", "DISABLED"}
           for language in ("python", "typescript")):
        return "NOT_INSPECTED"
    if case["truth"] == "UNKNOWN":
        return "UNKNOWN_WITH_SIGNAL" if detected else "UNKNOWN"
    if case["truth"] == "DANGEROUS":
        return "TP_SIGNAL" if detected else "FN_SIGNAL"
    return "FP_SIGNAL" if detected else "TN_SIGNAL"


def summarize(data):
    counts = collections.Counter()
    by_area = collections.defaultdict(collections.Counter)
    rows = []
    for case in data["results"]:
        result = verdict(case)
        counts[result] += 1
        by_area[case["area"]][result] += 1
        repetitions = [{k: v for k, v in r.items() if k != "elapsedMs"} for r in case["runs"]]
        rows.append(dict(id=case["id"], truth=case["truth"], result=result,
                         repeatEqual=all(r == repetitions[0] for r in repetitions),
                         elapsedMs=[r["elapsedMs"] for r in case["runs"]]))
    return dict(unit="named warning/candidate signal, not exploit or deployment-verdict accuracy",
                labelCorrections=RULE_CORRECTIONS, counts=dict(counts),
                byArea={k: dict(v) for k, v in by_area.items()}, cases=rows)


if __name__ == "__main__":
    data = json.loads(pathlib.Path(sys.argv[1]).read_text())
    result = summarize(data)
    pathlib.Path(sys.argv[2]).write_text(json.dumps(result, indent=2))
    print(json.dumps({k: v for k, v in result.items() if k != "cases"}, indent=2))
    print("repeat_equal_cases=" + str(sum(c["repeatEqual"] for c in result["cases"])))
