"""Later-authored synthetic evaluation; these cases are not an external blind benchmark."""
import unittest
from test_resources import analyze


class ResourceVariations(unittest.TestCase):
    def test_risk_normal_and_uncertain_matrix(self):
        cases = [
            ("data=request.POST['name']\np=data\nopen(p,'rb')", "", "RISK"),
            ("Path(request.headers['X-File']).write_text('fixed')", "from pathlib import Path", "RISK"),
            ("p='/srv/'+request.GET['key']\nopen(p)", "", "RISK"),
            ("restore(request.body)", "from pickle import loads as restore", "RISK"),
            ("p=request.FILES.get('data')\npickle.load(p)", "import pickle", "RISK"),
            ("yaml.load(request.body,yaml.CUnsafeLoader)", "import yaml", "RISK"),
            ("p=request.GET['key']\np='/fixed'\nPath(p).read_bytes()", "from pathlib import Path", "NORMAL"),
            ("open(safe_join('/srv',request.GET['key']))", "from django.utils._os import safe_join", "NORMAL"),
            ("Path('/fixed').write_bytes(request.body)", "from pathlib import Path", "NORMAL"),
            ("pickle.loads(b'fixed-inert-test-not-executed')", "import pickle", "NORMAL"),
            ("yaml.load(request.body,Loader=yaml.CSafeLoader)", "import yaml", "NORMAL"),
            ("json.loads(request.body)", "import json", "NORMAL"),
            ("Path(check(request.GET['path'])).read_bytes()", "from pathlib import Path", "UNKNOWN"),
            ("open(safe_join(root,request.GET['path']))", "from django.utils._os import safe_join", "UNKNOWN"),
            ("p=request.GET['p']\nif p.startswith('/srv'):\n open(p)", "", "UNKNOWN"),
            ("pickle.loads(convert(request.body))", "import pickle", "UNKNOWN"),
            ("yaml.load(request.body,Loader=custom)", "import yaml", "UNKNOWN"),
            ("yaml.unsafe_load_all(request.body)", "import yaml", "UNKNOWN"),
        ]
        counts = dict(RISK=0, NORMAL=0, UNKNOWN=0)
        for index, (body, imports, expected) in enumerate(cases):
            result = analyze(body, imports)
            findings = [f for f in result['findings'] if f['ruleId'] in {'PY_FILE_PATH_INPUT_FLOW','PY_UNSAFE_DESERIALIZATION_INPUT_FLOW'}]
            actual = 'RISK' if any(f['confidence']=='HIGH' for f in findings) else 'UNKNOWN' if findings or any(u['kind']=='UNRESOLVED_RESOURCE' for u in result['resourceUses']) else 'NORMAL'
            self.assertEqual(actual, expected, f'variant {index}')
            counts[actual] += 1
        print('File/deserialization synthetic variants:', counts, 'FP=0 FN=0 in labeled supported cases; not whole-project accuracy')

    def test_unsupported_control_and_depth_are_not_safe_or_confirmed(self):
        result = analyze("for value in values:\n open(request.GET['file'])")
        self.assertFalse(result['resourceUses'])
        self.assertIn('RESOURCE_CALLS_OUTSIDE_TRACED_FLOW',result['files'][0]['limitations'])
        helpers='\n'.join(f'def f{i}(p):\n return f{i+1}(p)' for i in range(7))+'\ndef f7(p):\n return open(p)\n'
        result=analyze("f0(request.GET['path'])",helpers=helpers)
        self.assertFalse(any(f['confidence']=='HIGH' for f in result['findings']))
        self.assertTrue(any('CALL_DEPTH_EXCEEDED' in f['limitations'] for f in result['files']))


if __name__ == '__main__':
    unittest.main()
