import unittest
from cast_cases import REGRESSION, VALIDATION, BASELINE
from collection_cases import inject, source_sites


class CastCasesTest(unittest.TestCase):
    def test_controlled_splits_keep_all_three_truth_states(self):
        for cases in [REGRESSION,VALIDATION]:
            self.assertEqual({c[1]for c in cases},{'DANGEROUS','SAFE','UNKNOWN'})
        self.assertFalse({c[0]for c in REGRESSION}&{c[0]for c in VALIDATION})
        self.assertEqual(len(BASELINE),40)

    def test_every_probe_preserves_original_route_and_targets_its_execution(self):
        original='@GetMapping("/original") public String inspect() {return "original";}'
        for _,_,state,selected,bound in REGRESSION+VALIDATION:
            source,sink,_=inject(original,'public String inspect() {',state,selected,bound)
            self.assertIn('@GetMapping("/original")',source)
            self.assertIn('return "original";',source)
            self.assertIn('.execute()',source.splitlines()[sink-1])
            self.assertTrue(source_sites('Endpoint.java',source))


if __name__=='__main__':
    unittest.main()
