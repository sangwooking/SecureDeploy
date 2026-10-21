import copy
import unittest
import json
import tempfile
from pathlib import Path
from eligibility import assess, CONDITIONS, conjunction, inventory
from benchmark import read


class EligibilityTest(unittest.TestCase):
    def review(self, *values):
        return {k:dict(value=v, reason='Named evaluation path reviewed', references=['receipt.json#path']) for k,v in zip(CONDITIONS,values)}

    def test_truth_and_support_are_independent(self):
        result = assess(self.review(True, True, False))
        self.assertTrue(result['EXTENSION_CANDIDATE'])
        self.assertFalse(result['NOT_EVALUABLE'])
        self.assertFalse(result['endToEndEligible'])

    def test_missing_context_is_not_an_extension_ready_case(self):
        result = assess(self.review(True, False, False))
        self.assertFalse(result['EXTENSION_CANDIDATE'])
        self.assertTrue(result['NOT_EVALUABLE'])

    def test_unknown_is_not_zero_or_ready(self):
        result = assess(self.review(True, None, None))
        self.assertIsNone(result['endToEndEligible'])
        self.assertIsNone(result['NOT_EVALUABLE'])

    def test_only_three_true_conditions_make_a_case_eligible(self):
        self.assertTrue(assess(self.review(True, True, True))['endToEndEligible'])
        self.assertFalse(assess(self.review(False, True, True))['endToEndEligible'])

    def test_no_warning_counts_or_rule_verdicts_are_accepted_as_conditions(self):
        with self.assertRaises(ValueError):
            assess(dict(findings=0))

    def test_decisions_require_explicit_cited_evidence(self):
        review = self.review(True, True, True)
        review[CONDITIONS[0]]['references'] = []
        with self.assertRaises(ValueError):
            assess(review)

    def test_integer_boolean_and_unexplained_unknown_are_rejected(self):
        review = self.review(True, True, 1)
        with self.assertRaises(ValueError):
            assess(review)
        review = self.review(None, None, None)
        review[CONDITIONS[0]]['reason'] = ''
        with self.assertRaises(ValueError):
            assess(review)

    def test_assessment_does_not_mutate_review(self):
        review = self.review(True, True, False)
        before = copy.deepcopy(review)
        assess(review)
        self.assertEqual(review, before)
        self.assertFalse(conjunction(None, False, True))

    def test_inventory_preserves_unknown_without_source_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps(dict(cases=[dict(caseId='unreviewed', groundTruthLabel='UNKNOWN')])) )
            config = root/'config.json'
            config.write_text(json.dumps(dict(schemaVersion=1, scope='Test metadata only', engineCommit='a'*40,
                datasets=[dict(id='test', kind='CANDIDATE', manifest=str(manifest),
                    independence='Not blind', reviews={'unreviewed': self.review(None, None, None)})])))
            output = root/'result.json'
            inventory(config, output)
            result = read(output)
            self.assertEqual(result['assetCount'], 1)
            self.assertEqual(result['counts']['endToEndEligible'], {'UNKNOWN': 1})
            self.assertIsNone(result['assets'][0]['NOT_EVALUABLE'])

    def test_inventory_cannot_silently_omit_unreviewed_cases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root/'manifest.json'
            manifest.write_text(json.dumps(dict(cases=[dict(caseId='missing-review')])))
            config = root/'config.json'
            config.write_text(json.dumps(dict(schemaVersion=1, scope='Test metadata only', engineCommit='a'*40,
                datasets=[dict(id='test', kind='CANDIDATE', manifest=str(manifest), independence='Not blind', reviews={})])))
            with self.assertRaisesRegex(ValueError, 'EXACT_REVIEW_COVERAGE_REQUIRED'):
                inventory(config, root/'result.json')


if __name__ == '__main__':
    unittest.main()
