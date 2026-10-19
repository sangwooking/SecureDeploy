import copy
import contextlib
import io
import json
import pathlib
import tempfile
import unittest
from summarize import summarize, verdict
from prepare_cases import prepare as prepare_internal
from prepare_external import prepare as prepare_external


def case(truth="UNKNOWN", detected=False, support="DATA_FLOW_PARTIAL"):
    row = dict(ruleIds=["target"] if detected else [], elapsedMs=1,
               python=dict(status="PARTIAL"), typescript=dict(status="NOT_APPLICABLE"))
    return dict(id="fixture", area="input", truth=truth, support=support,
                targetRule="target", runs=[row, copy.deepcopy(row)])


class EvaluationAccountingTest(unittest.TestCase):
    def test_unknown_is_never_true_negative(self):
        self.assertEqual(verdict(case()), "UNKNOWN")
        self.assertEqual(verdict(case(detected=True)), "UNKNOWN_WITH_SIGNAL")

    def test_unsupported_danger_is_visible_not_hidden_as_safe(self):
        self.assertEqual(verdict(case("DANGEROUS", support="NOT_SUPPORTED")), "NOT_SUPPORTED")

    def test_known_danger_without_signal_remains_missed_signal(self):
        self.assertEqual(verdict(case("DANGEROUS")), "FN_SIGNAL")

    def test_failure_is_not_safe_or_ordinary_negative(self):
        row = case("SAFE")
        row["runs"][0]["python"]["status"] = "TIMEOUT"
        self.assertEqual(verdict(row), "NOT_INSPECTED")

    def test_repeat_comparison_ignores_time_only(self):
        row = case("SAFE")
        row["runs"][1]["elapsedMs"] = 300
        self.assertTrue(summarize(dict(results=[row]))["cases"][0]["repeatEqual"])
        row["runs"][1]["python"]["status"] = "TIMEOUT"
        self.assertFalse(summarize(dict(results=[row]))["cases"][0]["repeatEqual"])

    def test_identifier_correction_does_not_relabel_truth(self):
        row = case("DANGEROUS")
        row["targetRule"] = "PY_SENSITIVE_RESPONSE_EXPOSURE"
        row["runs"][0]["ruleIds"] = ["PY_SENSITIVE_DATA_EXPOSURE"]
        self.assertEqual(verdict(row), "TP_SIGNAL")
        self.assertEqual(row["truth"], "DANGEROUS")

    def test_internal_manifest_is_prelabelled_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "cases"
            with contextlib.redirect_stdout(io.StringIO()):
                prepare_internal(root)
            manifest = json.loads((root / "manifest.json").read_text())
            self.assertEqual(len(manifest["cases"]), 38)
            self.assertEqual({c["truth"] for c in manifest["cases"]}, {"DANGEROUS", "SAFE", "UNKNOWN"})
            self.assertEqual(len({c["area"] for c in manifest["cases"]}), 8)
            with self.assertRaises(FileExistsError):
                prepare_internal(root)

    def test_public_preparation_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "benchmark-truth.json").write_text(json.dumps({"cases": [{"id": "../../outside"}]}))
            with self.assertRaises(ValueError):
                prepare_external(source, root / "cases")

    def test_public_source_fingerprint_is_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "BenchmarkTest00001.java").write_text("class Fixture {}")
            (source / "benchmark-truth.json").write_text(json.dumps({"cases": [{"id": "BenchmarkTest00001", "sha256": "incorrect"}]}))
            with self.assertRaises(ValueError):
                prepare_external(source, root / "cases")


if __name__ == "__main__":
    unittest.main()
