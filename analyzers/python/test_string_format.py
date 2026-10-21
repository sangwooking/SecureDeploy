"""Paired string-format regressions; target code is parsed, never executed."""
import unittest
from test_worker import analyze, confirmed


def query(expression, suffix=''):
    return analyze("value=request.GET['q']\nwith connection.cursor() as c:\n    c.execute("+expression+suffix+")")


class StringFormatTest(unittest.TestCase):
    def test_unused_positional_and_keyword_input_is_not_sql(self):
        for expr in ["'select {0}'.format('1', value)", "'select {chosen}'.format(chosen='1', unused=value)", "'select 1'.format(value)", "\"select '{{0}}'\".format(value)"]:
            with self.subTest(expression=expr):
                result = query(expr)
                self.assertEqual([], result['findings'])
                self.assertEqual('STATIC_QUERY', result['sqlUses'][0]['kind'])

    def test_selected_input_and_repetition_retain_source(self):
        for expr in ["'select {}'.format(value)", "'select {1}'.format('1', value)", "'select {q}{q}'.format(q=value, unused='1')"]:
            with self.subTest(expression=expr):
                self.assertEqual(1, len(confirmed(query(expr))))

    def test_all_argument_effects_still_happen_left_to_right(self):
        self.assertEqual(1, len(confirmed(query("'select {0}'.format(value, (value:='1'))"))))
        self.assertEqual([], query("'select {1}'.format((value:='1'), value)")['findings'])
        result = analyze("value=request.GET['q']\n'select {0}'.format('1', (value:='2'))\nwith connection.cursor() as c:\n    c.execute('select '+value)")
        self.assertEqual([], result['findings'])

    def test_bound_values_remain_distinct_from_query_text(self):
        self.assertEqual([], query("'select %s'.format(value)", ', [value]')['findings'])
        self.assertEqual(1, len(confirmed(query("'select {}'.format(value)", ", ['1']"))))

    def test_dynamic_or_compound_fields_are_not_certified(self):
        for expr in ["'select {0[x]}'.format({'x':value})", "'select {0.real}'.format(value)", "'select {missing}'.format(value)", "'select {} {0}'.format(value)", "'select {'.format(value)"]:
            with self.subTest(expression=expr):
                result = query(expr)
                self.assertEqual([], confirmed(result))
                self.assertEqual('UNRESOLVED_QUERY', result['sqlUses'][0]['kind'])

    def test_unknown_template_and_unknown_argument_keep_uncertainty(self):
        self.assertEqual([], confirmed(query("value.format('1')")))
        self.assertEqual([], confirmed(query("'select {}'.format(opaque(value))")))

    def test_large_format_is_bounded_and_explicit(self):
        result = query(repr('select '+'{0}'*100)+'.format(value)')
        self.assertEqual([], confirmed(result))
        self.assertTrue(any('STRING_FORMAT_UNRESOLVED' in f['limitations'] for f in result['files']))


if __name__ == '__main__':
    unittest.main()
