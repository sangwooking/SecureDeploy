"""Development regressions for Python evaluation, not target project source."""
import unittest
from unittest.mock import patch
from worker import Analyzer
from test_worker import analyze, confirmed


class AccuracyTest(unittest.TestCase):
    def test_oversized_ast_does_not_spend_budget_of_later_small_file(self):
        files=[dict(filePath='large.py',content='data=['+','.join('1' for _ in range(50))+']'),
               dict(filePath='small.py',content='value=1')]
        with patch('worker.MAX_NODES',30):
            result=Analyzer(files).run()
        self.assertEqual('LIMIT_EXCEEDED',result['files'][0]['parseStatus'])
        self.assertIn('AST_NODE_LIMIT',result['files'][0]['limitations'])
        self.assertEqual('PARSED',result['files'][1]['parseStatus'])

    def test_guard_uncertainty_survives_helper_return(self):
        result = analyze("pass", {"app/views.py": """from django.db import connection
def transform(value):
    if not validates(value):
        return '0'
    return value
def endpoint(request, key):
    with connection.cursor() as c:
        c.execute('select '+transform(request.GET['q']))
"""})
        self.assertEqual([], confirmed(result))
        self.assertTrue(result['findings'])

    def test_guard_uncertainty_survives_cursor_context_exit(self):
        result = analyze("v=request.GET['q']\nwith connection.cursor() as c:\n    if not validates(v):\n        return None\nwith connection.cursor() as d:\n    d.execute('select '+v)")
        self.assertEqual([], confirmed(result))
        self.assertTrue(result['findings'])

    def test_expression_guards_are_not_proven_execution(self):
        for expression in ["validates(v) and c.execute('select '+v)",
                           "c.execute('select '+v) if validates(v) else None"]:
            with self.subTest(expression=expression):
                result=analyze("v=request.GET['q']\nwith connection.cursor() as c:\n    "+expression)
                self.assertEqual([], confirmed(result))
                self.assertTrue(result['findings'])

    def test_terminated_branch_does_not_contaminate_sibling(self):
        result=analyze("v=request.GET['q']\nif request.user:\n    with opaque_context():\n        return None\nelse:\n    with connection.cursor() as c:\n        c.execute('select '+v)")
        self.assertEqual(1,len(confirmed(result)))

    def test_nested_scope_does_not_shadow_outer_import(self):
        result=analyze("with connection.cursor() as c:\n    c.execute('select '+request.GET['q'])\ndef nested():\n    connection=other")
        self.assertEqual(1,len(confirmed(result)))

    def test_comprehension_iteration_scope_and_walrus_outer_scope_differ(self):
        prefix="with connection.cursor() as c:\n    c.execute('select '+request.GET['q'])\n"
        self.assertEqual(1,len(confirmed(analyze(prefix+"[connection for connection in values]"))))
        self.assertEqual([],confirmed(analyze(prefix+"[(connection:=x) for x in values]")))
        self.assertEqual([],confirmed(analyze(prefix+"try:\n    unknown()\nexcept Exception as connection:\n    pass")))

    def test_unknown_mutation_invalidates_collection_elements(self):
        result=analyze("values=['0']\nmodify(values,request.GET['q'])\n(a,)=values\nwith connection.cursor() as c:\n    c.execute('select '+a)")
        self.assertEqual([],confirmed(result))
        self.assertTrue(any(s['kind']=='UNRESOLVED_QUERY' for s in result['sqlUses']))

    def test_keyword_only_parameter_is_not_reset_by_assignment(self):
        result=analyze("pass", {"app/views.py": """from django.db import connection
def write(*, value):
    with connection.cursor() as c:
        c.execute('select '+value)
    value='0'
def endpoint(request, key):
    write(value=request.GET['q'])
"""})
        self.assertEqual(1,len(confirmed(result)))

    def test_invalid_function_binding_never_confirms_sink(self):
        result=analyze("pass", {"app/views.py": """from django.db import connection
def write(value):
    with connection.cursor() as c:
        c.execute('select '+value)
def endpoint(request, key):
    write(request.GET['q'], value='0')
"""})
        self.assertEqual([],confirmed(result))
        self.assertTrue(any('CALL_ARGUMENT_BINDING_UNRESOLVED' in f['limitations'] for f in result['files']))
        result=analyze("pass", {"app/views.py": """from django.db import connection
def called(value):
    return value
def endpoint(request, key):
    called('0', value='1')
    with connection.cursor() as c:
        c.execute('select '+request.GET['q'])
"""})
        self.assertEqual([],confirmed(result))
        self.assertTrue(any(s['kind']=='UNRESOLVED_QUERY' for s in result['sqlUses']))

    def test_unpacking_does_not_contaminate_static_sibling(self):
        result=analyze("a,b=(request.GET['q'],'0')\nwith connection.cursor() as c:\n    c.execute('select '+b)")
        self.assertEqual([],result['findings'])
        result=analyze("a,b=(request.GET['q'],'0')\nwith connection.cursor() as c:\n    c.execute('select '+a)")
        self.assertEqual(1,len(confirmed(result)))

    def test_order_branch_and_format_pairs(self):
        for expression, count in [("v+(v:='0')",1),("(v:='0')+v",0),
                                   ("f'{v}{(v:=\"0\")}'",1),("f'{(v:=\"0\")}{v}'",0),
                                   ("'{}{}'.format(v,(v:='0'))",1),("'{}{}'.format((v:='0'),v)",0)]:
            with self.subTest(expression=expression):
                self.assertEqual(count,len(confirmed(analyze("v=request.GET['q']\nwith connection.cursor() as c:\n    c.execute("+expression+")"))))


if __name__ == '__main__': unittest.main()
