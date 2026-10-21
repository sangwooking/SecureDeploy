import ast
import unittest
from format_cases import inject, REGRESSION, VALIDATION


class FormatCasesTest(unittest.TestCase):
    def test_original_route_and_body_are_not_replaced_by_minimal_stubs(self):
        original = 'from django.shortcuts import render\ndef home(request):\n    return render(request, "home.html")\n'
        changed, sink = inject(original, 'home', "'SELECT {0}'.format('1', value)", '')
        self.assertIn('def home(request):', changed)
        self.assertIn('    return render(request, "home.html")', changed)
        tree = ast.parse(changed)
        self.assertEqual('cursor.execute', ast.unparse(next(n.func for n in ast.walk(tree) if isinstance(n, ast.Call) and n.lineno == sink)))

    def test_docstrings_and_future_imports_preserve_their_roles(self):
        original = '"module doc"\nfrom __future__ import annotations\ndef home(request):\n    "function doc"\n    return None\n'
        changed, _ = inject(original, 'home', "'SELECT {}'.format(value)", '')
        tree = ast.parse(changed)
        self.assertEqual('module doc', ast.get_docstring(tree))
        self.assertEqual('__future__', tree.body[1].module)
        self.assertEqual('function doc', ast.get_docstring(next(n for n in tree.body if isinstance(n, ast.FunctionDef))))

    def test_controlled_truth_contains_risk_normal_and_unknown_in_both_sets(self):
        for cases in [REGRESSION, VALIDATION]:
            self.assertEqual({'DANGEROUS','SAFE','UNKNOWN'}, {c[1] for c in cases})
            self.assertEqual(len(cases), len({c[0] for c in cases}))
