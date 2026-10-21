import unittest
from benchmark import inspection


class PythonInspectionTest(unittest.TestCase):
    def inputs(self):
        case=dict(language='PYTHON', files=[dict(path='views.py')], flowRules=['PY_SQL_INPUT_FLOW'],
            targetSites=[dict(filePath='views.py',startLine=5,endLine=5)])
        use=dict(kind='STATIC_QUERY',location=dict(filePath='views.py',line=5),executionObserved=True,limitations=[])
        row=dict(coverage=dict(entries=[dict(filePath='views.py',status='SELECTED')]),
            python=dict(status='PARTIAL',files=[dict(parseStatus='PARSED',entrypoints=1,limitations=[])],sqlUses=[use]))
        return case,row,use

    def test_target_static_and_bound_queries_are_inspected(self):
        case,row,use=self.inputs()
        self.assertEqual('INSPECTED',inspection(case,row,'ast'))
        use['kind']='PARAMETERIZED_QUERY'
        self.assertEqual('INSPECTED',inspection(case,row,'finalUser'))

    def test_unrelated_lazy_or_incomplete_use_is_not_a_negative_proof(self):
        for change in [dict(location=dict(filePath='views.py',line=6)),dict(executionObserved=False),dict(limitations=['LAZY_RAW_EXECUTION_NOT_VERIFIED']),dict(kind='UNRESOLVED_QUERY')]:
            case,row,use=self.inputs();use.update(change)
            self.assertEqual('UNKNOWN',inspection(case,row,'ast'))

    def test_all_targets_and_supported_entry_are_required(self):
        case,row,use=self.inputs()
        case['targetSites'].append(dict(filePath='views.py',startLine=8,endLine=8))
        self.assertEqual('UNKNOWN',inspection(case,row,'ast'))
        row['python']['files'][0]['entrypoints']=0
        self.assertEqual('NOT_SUPPORTED',inspection(case,row,'ast'))
