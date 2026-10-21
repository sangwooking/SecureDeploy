import copy
from pathlib import Path
import tempfile
import unittest

import vibe_track as vibe
from benchmark import read


class VibeTrackTests(unittest.TestCase):
    def setUp(self):
        self.catalog = read(Path(__file__).with_name('vibe-catalog.json'))

    def test_pins_license_and_observed_provenance_are_explicit(self):
        cases = vibe.validate_catalog(self.catalog)
        self.assertEqual(len(cases), 4)
        self.assertTrue(all(c['grade'] == 'C' for c in cases))
        self.assertTrue(all(c['provenanceKind'] != 'ORIGINAL_GENERATED' for c in cases))
        self.assertIn('NONE', self.catalog['holdout'])

    def test_same_prompt_or_project_family_cannot_leak_between_splits(self):
        for key in ('promptFamily', 'repositoryFamily'):
            catalog = copy.deepcopy(self.catalog)
            catalog['candidates'][1][key] = catalog['candidates'][0][key]
            with self.assertRaisesRegex(ValueError, 'FAMILY_SPLIT'):
                vibe.validate_catalog(catalog)

    def test_duplicate_repository_and_unpinned_url_are_rejected(self):
        for key, value in [('commitSha', 'main'), ('repositoryUrl', 'https://example.com/source'), ('license', ''), ('provenancePaths', []), ('licensePath', '../LICENSE')]:
            catalog = copy.deepcopy(self.catalog); catalog['candidates'][0][key] = value
            with self.assertRaises(ValueError):
                vibe.validate_catalog(catalog)
        self.catalog['candidates'][1] = self.catalog['candidates'][0]
        with self.assertRaisesRegex(ValueError, 'REPOSITORY_IDENTITY'):
            vibe.validate_catalog(self.catalog)

    def case(self, truth='UNKNOWN', outcome='UNKNOWN'):
        return dict(truth=truth, outcome=outcome, sites=[dict(filePath='api.ts', line=10)],
                    condition='Named condition only', evidence='Static path review',
                    limitations='Runtime unknown', fixDirection='Check boundary', verification='Recheck after modification')

    def test_unknown_and_unsupported_are_not_safe_or_vulnerable_metrics(self):
        for outcome in ('TP', 'FP', 'FN', 'TN'):
            with self.assertRaisesRegex(ValueError, 'UNKNOWN_NOT'):
                vibe.validate_case(self.case(outcome=outcome))
        for truth in ('SAFE', 'DANGEROUS', 'UNKNOWN'):
            for outcome in ('NOT_SUPPORTED', 'NOT_INSPECTED', 'RESOURCE_LIMIT', 'ANALYSIS_FAILED', 'UNKNOWN'):
                vibe.validate_case(self.case(truth, outcome))

    def test_negative_requires_inspection_not_no_warning(self):
        case = dict(self.case('SAFE', 'TN'), targetRules=['RULE'])
        with self.assertRaisesRegex(ValueError, 'INSPECTION'):
            vibe.validate_case(case)
        case['inspectionEvidence'] = 'Supported target observed and safe binding confirmed'
        vibe.validate_case(case)

    def test_target_rule_file_and_line_must_match(self):
        case = dict(self.case('SAFE', 'FP'), targetRules=['RULE'])
        run = {'filtered': [dict(ruleId='OTHER', filePath='api.ts', line=10),
                            dict(ruleId='RULE', filePath='other.ts', line=10),
                            dict(ruleId='RULE', filePath='api.ts', line=11),
                            dict(ruleId='RULE', filePath='api.ts', line=10)]}
        self.assertEqual(len(vibe.matching_signals(case, run)), 1)

    def test_safe_and_dangerous_labels_cannot_be_swapped(self):
        for truth, outcome in [('SAFE', 'TP'), ('SAFE', 'FN'), ('DANGEROUS', 'FP'), ('DANGEROUS', 'TN')]:
            with self.assertRaisesRegex(ValueError, 'MISMATCH'):
                vibe.validate_case(dict(self.case(truth, outcome), targetRules=['RULE']))

    def test_unsupported_cases_still_need_locations_and_review_evidence(self):
        for key in ('sites', 'condition', 'evidence', 'limitations', 'fixDirection', 'verification'):
            case = self.case('DANGEROUS', 'NOT_SUPPORTED'); case[key] = [] if key == 'sites' else ''
            with self.assertRaises(ValueError):
                vibe.validate_case(case)

    def test_source_hash_and_provenance_are_checked_before_reporting(self):
        catalog = copy.deepcopy(self.catalog); catalog['candidates'] = [catalog['candidates'][0]]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); source = root / 'sources' / 'app'; source.mkdir(parents=True)
            files = []
            for name, value in [('LICENSE', b'MIT License'), ('README.md', b'Author attributes app generation to AI tooling')]:
                (source / name).write_bytes(value)
                files.append(dict(path=name, sha256=vibe.digest(value), bytes=len(value)))
            plan = {'projects': [dict(catalog['candidates'][0], projectId='app', files=files, collectionStatus='COLLECTED')]}
            result = vibe.validate_sources(root, catalog, plan)
            self.assertEqual(result['projects'][0]['status'], 'HASH_AND_PROVENANCE_VERIFIED')
            (source / 'README.md').write_text('unreviewed change')
            with self.assertRaisesRegex(ValueError, 'SOURCE_HASH'):
                vibe.validate_sources(root, catalog, plan)

    def test_missing_provenance_and_separate_enterprise_license_fail_closed(self):
        catalog = copy.deepcopy(self.catalog); catalog['candidates'] = [catalog['candidates'][0]]
        for files in ([], [dict(path='enterprise/secret.ts', bytes=0, sha256=vibe.digest(b''))]):
            plan = {'projects': [dict(catalog['candidates'][0], projectId='app', files=files, collectionStatus='COLLECTED')]}
            with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(ValueError, 'PROVENANCE_NOT_RETAINED|SEPARATE_LICENSE'):
                vibe.validate_sources(Path(folder), catalog, plan)

    def test_checked_review_counts_only_seven_named_warnings_not_project_safety(self):
        review = read(Path(__file__).with_name('vibe-review.json'))
        for case in review['cases']:
            vibe.validate_case(case)
        self.assertEqual(len(review['cases']), 16)
        self.assertEqual(sum(c['outcome'] == 'FP' for c in review['cases']), 3)
        self.assertFalse(any(c['outcome'] in {'TN', 'TP', 'FN'} for c in review['cases']))


if __name__ == '__main__':
    unittest.main()
