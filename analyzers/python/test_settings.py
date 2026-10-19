"""Synthetic configuration declarations; no Django import or target execution."""
import unittest
from worker import Analyzer

HEADER = "ROOT_URLCONF='app.urls'\nINSTALLED_APPS=[]\n"


def inspect(code, name="settings.py", others=()):
    return Analyzer([dict(filePath=name, content=HEADER + code), *others]).run()["deploymentAnalysis"]


class SettingsTest(unittest.TestCase):
    def observations(self, result):
        return {o["setting"]: o for f in result["files"] for o in f["observations"]}

    def test_risky_and_safe_literals_and_no_secret_content(self):
        risky = self.observations(inspect("DEBUG=True\nSECRET_KEY='synthetic-never-valid'\nALLOWED_HOSTS=['*']\nSESSION_COOKIE_SECURE=False\nCSRF_COOKIE_SECURE=False\nSECURE_SSL_REDIRECT=False\nSECURE_HSTS_SECONDS=0"))
        self.assertEqual(sum(bool(o["ruleId"]) for o in risky.values()), 7)
        self.assertNotIn("synthetic-never-valid", str(risky))
        safe = self.observations(inspect("DEBUG=False\nALLOWED_HOSTS=['example.invalid']\nSESSION_COOKIE_SECURE=True\nCSRF_COOKIE_SECURE=True\nSECURE_SSL_REDIRECT=True\nSECURE_HSTS_SECONDS=86400"))
        self.assertFalse(any(o["ruleId"] for o in safe.values()))

    def test_environment_import_and_overwrite_do_not_invent_values(self):
        values = self.observations(inspect("import os\nDEBUG=os.getenv('DEBUG','False')=='True'\nSECRET_KEY=os.environ['SECRET_KEY']\n"))
        self.assertTrue(all(o["valueStatus"] == "UNKNOWN" for o in values.values()))
        values = self.observations(inspect("DEBUG=True\nfrom .base import *\nSESSION_COOKIE_SECURE=True"))
        self.assertEqual(values["DEBUG"]["valueStatus"], "UNKNOWN")
        self.assertEqual(values["SESSION_COOKIE_SECURE"]["valueSummary"], "true")
        self.assertEqual(self.observations(inspect("DEBUG=True\nDEBUG=False"))["DEBUG"]["ruleId"], "")

    def test_branch_unknown_and_same_value_merge(self):
        values = self.observations(inspect("if environment:\n DEBUG=True\nelse:\n DEBUG=False\n"))
        self.assertEqual(values["DEBUG"]["valueStatus"], "UNKNOWN")
        values = self.observations(inspect("if environment:\n DEBUG=False\nelse:\n DEBUG=False\n"))
        self.assertEqual(values["DEBUG"]["valueSummary"], "false")

    def test_development_name_is_hint_not_production_or_safety_proof(self):
        result = inspect("DEBUG=True", "conf/settings/development.py")
        self.assertEqual(result["files"][0]["observations"][0]["scope"], "DEVELOPMENT_NAME_HINT_NOT_RUNTIME_PROOF")
        self.assertEqual(result["files"][0]["observations"][0]["ruleId"], "DJANGO_DEBUG")

    def test_entry_module_reference_is_not_runtime_activation(self):
        result = Analyzer([dict(filePath="config.py", content="DEBUG=True"), dict(filePath="wsgi.py", content="import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE','config')")]).run()["deploymentAnalysis"]
        self.assertEqual(result["files"][0]["observations"][0]["scope"], "MODULE_REFERENCE_ACTIVATION_UNKNOWN")

    def test_normal_python_variable_names_are_not_django_settings(self):
        result = Analyzer([dict(filePath="tool.py", content="DEBUG=True\nSECRET_KEY='not-a-django-project'")]).run()["deploymentAnalysis"]
        self.assertEqual(result["files"], [])

    def test_mutation_unknown_calls_and_exceptions_do_not_certify_settings(self):
        for suffix in ("configure()", "globals().update(overrides)", "ALLOWED_HOSTS.append('*')", "try:\n DEBUG=True\nexcept Exception:\n pass"):
            values = self.observations(inspect("DEBUG=False\nALLOWED_HOSTS=[]\n" + suffix))
            self.assertEqual(values["DEBUG"]["valueStatus"], "UNKNOWN")

    def test_alias_subscript_and_assignment_calls_cannot_preserve_stale_values(self):
        values = self.observations(inspect("hosts=['example.invalid']\nALLOWED_HOSTS=hosts\nhosts[0]='*'"))
        self.assertEqual(values["ALLOWED_HOSTS"]["valueStatus"], "UNKNOWN")
        values = self.observations(inspect("DEBUG=False\nunused=configure()"))
        self.assertEqual(values["DEBUG"]["valueStatus"], "UNKNOWN")

    def test_unsupported_module_side_effects_are_explicitly_unknown(self):
        for code in ("other=(DEBUG:=False)", "if mutate():\n pass", "class Local:\n globals().update(external)", "@configure\ndef task():\n pass", "def task(x=mutate()):\n pass"):
            values = self.observations(inspect("DEBUG=True\n" + code))
            self.assertEqual(values["DEBUG"]["valueStatus"], "UNKNOWN", code.splitlines()[0])


if __name__ == "__main__":
    unittest.main()
