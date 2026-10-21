import unittest
from collection_cases import inject, REGRESSION, VALIDATION


class CollectionCasesTest(unittest.TestCase):
    def test_route_and_original_body_preserved(self):
        source='@GetMapping("/items") public String view() { return "original"; }'
        result,sink,origin=inject(source,'public String view() {','String[] x={input};','x[0]',False)
        self.assertIn('@GetMapping("/items")',result)
        self.assertIn('return "original";',result)
        self.assertIn('HttpServletRequest benchmarkRequest',result)
        self.assertIn('.execute()',result.splitlines()[sink-1])
        self.assertIn('getParameter(',result.splitlines()[origin-1])

    def test_binding_targets_execution_not_preparation(self):
        result,sink,_=inject('void view() {}','void view() {','','input',True)
        self.assertIn('benchmarkStatement.execute()',result.splitlines()[sink-1])
        self.assertIn('setString(1,input)',result)

    def test_ambiguous_or_absent_handler_rejected(self):
        for source in ['class Empty {}','void view() {} void view() {}']:
            with self.assertRaisesRegex(ValueError,'EXACT_HANDLER_REQUIRED'):
                inject(source,'void view() {','','input',False)

    def test_each_split_has_danger_safe_and_uncertain_labels(self):
        for cases in [REGRESSION,VALIDATION]:
            self.assertEqual({row[1] for row in cases},{'DANGEROUS','SAFE','UNKNOWN'})
        self.assertFalse({row[0] for row in REGRESSION}&{row[0] for row in VALIDATION})


if __name__=='__main__':
    unittest.main()
