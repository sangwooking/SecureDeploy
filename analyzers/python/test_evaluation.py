"""First-run evaluation variants authored after the initial implementation/regression suite.

These are synthetic, not external ground truth. Once used to fix the analyzer they
must be described as regressions, not a fresh blind evaluation.
"""
import unittest
from worker import Analyzer


CASES = [
    ("renamed_direct", "x=web.query_params['search']\nc.execute('select '+x)", "CONFIRMED"),
    ("header_source", "c.execute(f\"select {web.headers['x-id']}\")", "CONFIRMED"),
    ("named_sql", "c.execute(sql='select '+web.POST['x'])", "CONFIRMED"),
    ("argument_side_effect", "x=web.GET['x']\nc.execute('select '+x, [(x:='fixed')])", "CONFIRMED"),
    ("dead_branch", "if False:\n    c.execute('select '+web.GET['x'])", "NO_FINDING"),
    ("both_branches_replace", "x=web.GET['x']\nif web.GET['flag']:\n    x='a'\nelse:\n    x='b'\nc.execute('select '+x)", "NO_FINDING"),
    ("binding_named", "c.execute('select * from t where a=%s', params=[web.data['x']])", "NO_FINDING"),
    ("numeric_conversion", "x=int(web.GET['x'])\nc.execute('select %s' % x)", "NO_FINDING"),
    ("one_branch_input", "x='literal'\nif web.GET['flag']:\n    x=web.GET['x']\nc.execute('select '+x)", "CONFIRMED"),
    ("unknown_cleaner", "x=clean(web.GET['x'])\nc.execute('select '+x)", "DEFERRED"),
    ("unknown_query", "c.execute(make_query(web))", "DEFERRED"),
    ("unsupported_loop", "x=web.GET['x']\nwhile x:\n    x=clean(x)\nc.execute('select '+x)", "DEFERRED"),
    ("safe_format_values", "c.execute('select * from t where a=%s', ['{}'.format(web.GET['x'])])", "NO_FINDING"),
    ("format_query", "c.execute('select {}'.format(web.data['x']))", "CONFIRMED"),
    ("unknown_branch", "x=web.GET['x']\nif web.GET['flag']:\n    x=clean(x)\nc.execute('select '+x)", "DEFERRED"),
]


class EvaluationTest(unittest.TestCase):
    def test_first_run_matrix(self):
        import textwrap
        outcomes = {"CONFIRMED": 0, "NO_FINDING": 0, "DEFERRED": 0}
        for name, body, expected in CASES:
            with self.subTest(case=name):
                source = "from rest_framework.decorators import api_view as route\nfrom django.db import connection as database\n@route(['POST'])\ndef process(web):\n    with database.cursor() as c:\n" + textwrap.indent(body, "        ")
                result = Analyzer([{"filePath": "different/layout/handlers.py", "content": source}]).run()
                incomplete = any(q["kind"] == "UNRESOLVED_QUERY" for q in result["sqlUses"]) or any(
                    reason.startswith("UNSUPPORTED_STATEMENT_") for file in result["files"] for reason in file["limitations"])
                actual = "CONFIRMED" if any(f["confidence"] == "HIGH" for f in result["findings"]) else "DEFERRED" if incomplete else "NO_FINDING"
                outcomes[actual] += 1
                self.assertEqual(expected, actual)
        print("Synthetic evaluation outcomes (not whole-project accuracy):", outcomes)


if __name__ == "__main__":
    unittest.main()
