import unittest
from pathlib import Path
import tempfile
from injection_precision24 import classify, safe_file


class InjectionPrecision24Test(unittest.TestCase):
    def case(self, truth='RISK'):
        return dict(track='SQL', truth=truth, input=dict(files=[dict(filePath='server.cjs')]))

    def test_risk_deferred_is_still_a_miss(self):
        self.assertEqual(classify(self.case(), dict(findings=[], nodeUses=[])), 'FN_INCLUDING_DEFERRED')

    def test_normal_without_query_observation_is_not_tn(self):
        self.assertEqual(classify(self.case('NORMAL'), dict(findings=[], nodeUses=[])), 'NORMAL_DEFERRED_NOT_TN')
        r = dict(findings=[], nodeUses=[dict(ruleId='JS_SEQUELIZE_SQL_INPUT_FLOW', kind='STATIC_OR_DATA_ONLY')])
        r['files'] = [dict(filePath='server.cjs', parseStatus='PARSED', entrypoints=1)]
        self.assertEqual(classify(self.case('NORMAL'), r), 'TN_REVIEWED_STATIC_CONTROL')
        r['files'][0]['parseStatus'] = 'PARSE_FAILED'
        self.assertEqual(classify(self.case('NORMAL'), r), 'NORMAL_DEFERRED_NOT_TN')

    def test_unrelated_rule_or_file_is_not_target_success(self):
        for rule, file in [('JS_SHELL_COMMAND_INPUT_FLOW', 'server.cjs'), ('JS_SEQUELIZE_SQL_INPUT_FLOW', 'unrelated.cjs')]:
            r = dict(findings=[dict(ruleId=rule, confidence='HIGH', sink=dict(filePath=file))], nodeUses=[])
            self.assertEqual(classify(self.case(), r), 'FN_INCLUDING_DEFERRED')
        self.assertEqual(classify(self.case('UNKNOWN'), dict(findings=[], nodeUses=[])), 'NOT_INSPECTED')

    def test_unknown_with_a_safe_observation_is_not_hidden(self):
        r = dict(findings=[], nodeUses=[dict(ruleId='JS_SEQUELIZE_SQL_INPUT_FLOW', kind='STATIC_OR_DATA_ONLY')])
        self.assertEqual(classify(self.case('UNKNOWN'), r), 'FALSE_SAFE_OBSERVATION')
        r['nodeUses'].append(dict(ruleId='JS_SEQUELIZE_SQL_INPUT_FLOW', kind='UNKNOWN'))
        self.assertEqual(classify(self.case('UNKNOWN'), r), 'FALSE_SAFE_OBSERVATION')

    def test_differential_paths_cannot_overwrite_originals(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            original = root / 'original'
            original.write_text('unchanged')
            destination = root / 'destination'
            destination.mkdir()
            (destination / 'link').symlink_to(original)
            (destination / 'sources').symlink_to(root, target_is_directory=True)
            for name in [str(original), '../original', 'x/%2e%2e/original', 'link']:
                with self.assertRaises(ValueError):
                    safe_file(destination, name)
            self.assertEqual(original.read_text(), 'unchanged')
            with self.assertRaises(ValueError):
                safe_file(destination, 'sources/original')
            self.assertEqual(safe_file(destination, 'nested/file.js'), destination.resolve() / 'nested/file.js')


if __name__ == '__main__':
    unittest.main()
