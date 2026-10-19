"""Later-authored synthetic variants, not independent real-world accuracy measurements."""
import unittest
from worker import Analyzer


class SettingVariations(unittest.TestCase):
    def test_later_variants(self):
        cases = [
            ("flag=True\nDEBUG=flag", "RISK"),
            ("ALLOWED_HOSTS=('*', 'example.invalid')", "RISK"),
            ("SESSION_COOKIE_SECURE=not True", "RISK"),
            ("if False:\n DEBUG=True\nelse:\n DEBUG=False", "NORMAL"),
            ("allowed=['example.invalid']\nALLOWED_HOSTS=allowed", "NORMAL"),
            ("CSRF_COOKIE_SECURE=True", "NORMAL"),
            ("from .shared import DEBUG", "UNKNOWN"),
            ("DEBUG=bool(environment_flag)", "UNKNOWN"),
            ("if environment_flag:\n DEBUG=True", "UNKNOWN"),
        ]
        counts = dict(RISK=0, NORMAL=0, UNKNOWN=0)
        for index, (source, expected) in enumerate(cases):
            files = [dict(filePath=f"configuration_{index}.py", content=source),
                     dict(filePath="entry.py", content=f"import os\nos.environ['DJANGO_SETTINGS_MODULE']='configuration_{index}'")]
            result = Analyzer(files).run()["deploymentAnalysis"]
            entries = [o for f in result["files"] for o in f["observations"]]
            actual = "RISK" if any(o["ruleId"] for o in entries) else "UNKNOWN" if any(o["valueStatus"] == "UNKNOWN" for o in entries) else "NORMAL"
            self.assertTrue(entries)
            self.assertEqual(actual, expected, f"variant {index}")
            counts[actual] += 1
        print("Django synthetic variants (not production safety):", counts, "FP=0 FN=0 within labeled supported cases")


if __name__ == "__main__":
    unittest.main()
