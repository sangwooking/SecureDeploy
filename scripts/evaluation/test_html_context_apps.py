import copy
import unittest
from html_context_apps import project


class HtmlApplicationProjectionTest(unittest.TestCase):
    def baseline(self):
        row = dict(raw=[], filtered=[], reviewCandidates=[], typescript={}, securityScore=100,
            risk=dict(prioritySummary={}, prioritizedDeploymentAssessment='REVIEW_REQUIRED'),
            elapsedMs=1, parentHeapUsedBytes=100)
        return dict(planSha256='a'*64, engineCommit='b'*40,
            projects=[dict(projectId='synthetic', commitSha='c'*40, runs=[copy.deepcopy(row), copy.deepcopy(row)])])

    def test_projection_contains_only_locations_counts_and_limits(self):
        baseline = self.baseline()
        result = project(baseline, copy.deepcopy(baseline))
        self.assertTrue(result['projects'][0]['semanticRepeatable'])
        self.assertEqual(result['projects'][0]['currentHtml'], [])
        self.assertIn('Parent heap samples are not worker peak RSS', result['limitations'])

    def test_different_source_or_missing_repeat_cannot_pass(self):
        for kind in ('SHA', 'PLAN', 'REPEAT'):
            before = self.baseline()
            after = copy.deepcopy(before)
            if kind == 'SHA':
                after['projects'][0]['commitSha'] = 'd'*40
            elif kind == 'PLAN':
                after['planSha256'] = 'e'*64
            else:
                after['projects'][0]['runs'].pop()
            with self.assertRaises(AssertionError):
                project(before, after)

    def test_structural_or_non_html_regression_is_not_hidden(self):
        for key in ('typescript', 'reviewCandidates', 'filtered', 'securityScore'):
            before = self.baseline()
            after = copy.deepcopy(before)
            for row in after['projects'][0]['runs']:
                row[key] = {'changed': True} if key == 'typescript' else ([{'ruleId': 'OTHER'}] if key != 'securityScore' else 99)
            with self.assertRaises(AssertionError):
                project(before, after)
