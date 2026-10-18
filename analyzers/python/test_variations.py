"""Post-implementation synthetic checks, not external or independently authored ground truth.

First results must be retained if a case drives a fix; it then becomes a regression.
No private repository source is used.
"""
import collections
import textwrap
import unittest
from worker import Analyzer

CASES = [
    ('chain_assignment', "left=right=incoming.GET['x']\nc.execute('select '+left)", 'CONFIRMED'),
    ('representation', "v=incoming.GET['x']\nc.execute(f'select {v!r}')", 'CONFIRMED'),
    ('captured_first_argument', "v=incoming.GET['x']\nc.execute('select '+v, [(v:='static')])", 'CONFIRMED'),
    ('literal_exit', "v=incoming.GET['x']\nif False:\n    return None\nc.execute('select '+v)", 'CONFIRMED'),
    ('tuple_safe', "ignored,value=(incoming.GET['x'],'constant')\nc.execute('select '+value)", 'NO_FINDING'),
    ('tuple_risky', "value,ignored=(incoming.GET['x'],'constant')\nc.execute('select '+value)", 'CONFIRMED'),
    ('overwrite_before_format', "v=incoming.GET['x']\nc.execute('{}{}'.format((v:='constant'),v))", 'NO_FINDING'),
    ('all_paths_fixed', "v=incoming.GET['x']\nif incoming.user:\n    v='a'\nelse:\n    v='b'\nc.execute('select '+v)", 'NO_FINDING'),
    ('named_binding', "c.execute(sql='select * from record where name=%s',params=[incoming.GET['x']])", 'NO_FINDING'),
    ('predicate_expression', "v=incoming.GET['x']\nallow(value=v) and c.execute('select '+v)", 'DEFERRED'),
    ('unknown_sql_origin', "c.execute(sql_factory())", 'DEFERRED'),
    ('unknown_mutation', "v=incoming.GET['x']\nv=normalizer(v)\nc.execute('select '+v)", 'DEFERRED'),
    ('loop_not_executed_by_analyzer', "for v in incoming.GET.getlist('x'):\n    c.execute('select '+v)", 'DEFERRED'),
    ('query_construction_not_execution', "sql='select '+incoming.GET['x']\nreturn sql", 'NO_FINDING'),
]


def outcome(result):
    if any(f['confidence']=='HIGH' for f in result['findings']): return 'CONFIRMED'
    if any(s['kind']=='UNRESOLVED_QUERY' for s in result['sqlUses']) or any(
            l.startswith('UNSUPPORTED_STATEMENT_') for f in result['files'] for l in f['limitations']): return 'DEFERRED'
    return 'NO_FINDING'


class VariationTest(unittest.TestCase):
    def test_same_semantics_across_names_and_file_boundaries(self):
        counts=collections.Counter()
        for case,body,expected in CASES:
            for layout in ('single','split'):
                with self.subTest(case=case,layout=layout):
                    if layout=='single':
                        files={'renamed/feature.py': 'from rest_framework.decorators import api_view as route\nfrom django.db import connection as db\n@route(["POST"])\ndef receive(incoming):\n    with db.cursor() as c:\n'+textwrap.indent(body,'        ')}
                    else:
                        files={'other/router.py': "from django.urls import path as link\nfrom .entry import handle\nurlpatterns=[link('',handle)]",
                            'other/entry.py': 'from .operation import process\ndef handle(web):\n    return process(web)',
                            'other/operation.py': 'from django.db import connection as db\ndef process(incoming):\n    with db.cursor() as c:\n'+textwrap.indent(body,'        ')}
                    result=Analyzer([dict(filePath=p,content=s) for p,s in files.items()]).run()
                    actual=outcome(result); counts[actual]+=1
                    self.assertEqual(expected,actual)
        print('Synthetic variation classifications (no general accuracy claim):',dict(counts))


if __name__=='__main__': unittest.main()
