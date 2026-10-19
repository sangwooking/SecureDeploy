"""Synthetic request-flow pairs. The parser never opens these paths or imports these modules."""
import unittest
from worker import Analyzer


def analyze(body, imports="", helpers="", extra=()):
    source = imports + "\nfrom rest_framework.decorators import api_view\n" + helpers + "\n@api_view(['POST'])\ndef endpoint(request):\n" + "\n".join("    " + line for line in body.splitlines())
    return Analyzer([dict(filePath="views.py", content=source), *extra]).run()


def outcomes(result, rule):
    return [c for c in result["findings"] if c["ruleId"] == rule]


class ResourceFlows(unittest.TestCase):
    def test_request_path_and_fixed_content_are_distinct(self):
        for body, expected in [("open(request.GET['path']).read()", 1), ("open('/fixed/report', 'w').write(request.body)", 0), ("open('/fixed/report').read()", 0)]:
            result = analyze(body)
            self.assertEqual(len(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")), expected)
            if expected:
                self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["confidence"], "HIGH")

    def test_pathlib_join_and_normalization_preserve_input(self):
        for body in ["Path(request.GET['file']).read_text()", "(Path('/srv') / request.GET['file']).read_bytes()", "Path('/srv').joinpath(request.GET['file']).resolve().open()"]:
            result = analyze(body, "from pathlib import Path")
            self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["confidence"], "HIGH")
        result = analyze("p=os.path.normpath(os.path.join('/srv', request.GET['path']))\nopen(p)", "import os")
        self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["confidence"], "HIGH")

    def test_literal_base_safe_join_is_only_lexical_defense(self):
        result = analyze("open(safe_join('/srv', request.GET['path']))", "from django.utils._os import safe_join")
        self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW"), [])
        self.assertEqual(result["resourceUses"][0]["kind"], "LEXICALLY_CONFINED_PATH")
        self.assertIn("SYMLINKS_PERMISSIONS_AND_RUNTIME_NOT_VERIFIED", result["resourceUses"][0]["limitations"])
        result = analyze("open(safe_join(configured_root, request.GET['path']))", "from django.utils._os import safe_join")
        self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["confidence"], "MEDIUM")
        for root in ('/', '/srv/..'):
            result=analyze(f"open(safe_join('{root}', request.GET['path']))", "from django.utils._os import safe_join")
            self.assertNotEqual(result['resourceUses'][0]['kind'],'LEXICALLY_CONFINED_PATH')

    def test_prefix_and_unknown_validator_never_certify_confinement(self):
        for body in ["p=request.GET['path']\nif p.startswith('/srv'):\n open(p)", "p=validate(request.GET['path'])\nopen(p)"]:
            result = analyze(body)
            self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["confidence"], "MEDIUM")

    def test_helper_and_relative_import_forward_paths(self):
        result = analyze("fetch_file(request.GET['path'])", helpers="def fetch_file(name):\n return open(name).read()\n")
        self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["confidence"], "HIGH")
        result = analyze("fetch_file(request.GET['path'])", "from service import fetch_file", extra=[dict(filePath="service.py", content="def fetch_file(name):\n return open(name).read()")])
        self.assertEqual(outcomes(result, "PY_FILE_PATH_INPUT_FLOW")[0]["sink"]["filePath"], "service.py")

    def test_reassignment_branches_and_evaluation_order(self):
        for body, count in [("p=request.GET['path']\np='/fixed'\nopen(p)", 0),
                            ("p=request.GET['path']\nopen(p + (p:='fixed'))", 1),
                            ("p=request.GET['path']\nopen((p:='fixed') + p)", 0),
                            ("p=request.GET['path']\nif request.GET['flag']:\n p='/fixed'\nopen(p)", 1)]:
            self.assertEqual(len(outcomes(analyze(body), "PY_FILE_PATH_INPUT_FLOW")), count)

    def test_pickle_body_upload_and_bytesio_are_untrusted(self):
        for body in ["pickle.loads(request.body)", "pickle.load(request.FILES['payload'])", "pickle.load(io.BytesIO(request.body))"]:
            result = analyze(body, "import pickle\nimport io")
            self.assertEqual(outcomes(result, "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW")[0]["confidence"], "HIGH")
        result = analyze("pickle.load(open('/fixed/data', 'rb'))", "import pickle")
        self.assertEqual(outcomes(result, "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW"), [])
        self.assertEqual(result["resourceUses"][-1]["kind"], "UNRESOLVED_RESOURCE")

    def test_fixed_pickle_data_and_json_are_not_external_object_findings(self):
        for body, imports in [("pickle.loads(b'synthetic-not-executed')", "import pickle"), ("json.loads(request.body)", "import json")]:
            self.assertEqual(outcomes(analyze(body, imports), "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW"), [])
        result=analyze("pickle.loads(request.GET['data'])", "import pickle")
        self.assertEqual(outcomes(result,"PY_UNSAFE_DESERIALIZATION_INPUT_FLOW"),[])
        self.assertEqual(result['resourceUses'][0]['kind'],'UNSUPPORTED_ARGUMENT_TYPE')

    def test_yaml_loader_identity_and_unknown_versions(self):
        for expression, confidence in [("yaml.unsafe_load(request.body)", "HIGH"), ("yaml.load(request.body, Loader=yaml.UnsafeLoader)", "HIGH"),
                                       ("yaml.load(request.body, Loader=yaml.Loader)", "HIGH"), ("yaml.load(request.body)", "MEDIUM"),
                                       ("yaml.load(request.body, Loader=yaml.FullLoader)", "MEDIUM"), ("yaml.safe_load(request.body)", None),
                                       ("yaml.load(request.body, Loader=yaml.SafeLoader)", None)]:
            result = outcomes(analyze(expression, "import yaml"), "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW")
            self.assertEqual(result[0]["confidence"] if result else None, confidence, expression)

    def test_shadowing_and_dynamic_calls_are_not_known_sinks_or_defenses(self):
        for body in ["open=lambda value: value\nopen(request.GET['path'])", "reader=getattr(service, request.GET['name'])\nreader(request.body)"]:
            self.assertEqual(analyze(body)["resourceUses"], [])
        result = analyze("yaml.safe_load(request.body)", "import yaml\nyaml.safe_load=external")
        self.assertEqual(result["resourceUses"], [])
        self.assertIn("MODULE_OBJECT_WRITE_UNRESOLVED", result["files"][0]["limitations"])

    def test_unresolved_source_and_control_never_promote(self):
        result = analyze("pickle.loads(unknown_source())", "import pickle")
        self.assertEqual(outcomes(result, "PY_UNSAFE_DESERIALIZATION_INPUT_FLOW"), [])
        result = analyze("p=transform(request.GET['path'])\nopen(p)")
        self.assertIn("RESOURCE_FLOW_UNRESOLVED", result["resourceUses"][0]["limitations"])

    def test_source_literals_are_not_serialized_and_record_limits_remain(self):
        result = analyze("open('/private-synthetic/fixed')\npickle.loads(request.body)", "import pickle")
        self.assertNotIn("/private-synthetic/fixed", str(result))
        result = analyze("\n".join("open(request.GET['file'])" for _ in range(210)))
        self.assertLessEqual(len(result["resourceUses"]), 200)
        self.assertIn("RESULT_LIMIT_EXCEEDED", result["files"][0]["limitations"])


if __name__ == "__main__":
    unittest.main()
