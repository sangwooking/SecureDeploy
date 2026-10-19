"""Committed metadata records observed failures without pretending projects are safe."""
import unittest
from pathlib import Path
from benchmark import read

ROOT=Path(__file__).parent
class ApplicationMetadataTests(unittest.TestCase):
    def test_nineteen_candidates_eight_selected_seven_collected(self):
        selection=read(ROOT/'application-selection.json');baseline=read(ROOT/'application-baseline.json')
        self.assertEqual(len(selection['candidates']),19)
        self.assertEqual(sum(c['selected']for c in selection['candidates']),8)
        self.assertEqual(len(baseline['projects']),8)
        self.assertEqual(sum(p['evaluationStatus'].startswith('ANALYZED_')for p in baseline['projects']),7)
        self.assertTrue(all(p['wholeProjectTruth']=='UNVERIFIED'for p in baseline['projects']))
        self.assertEqual(baseline['crossProjectExactCodeHashGroups'],0)
        self.assertEqual(baseline['crossProjectWhitespaceCloneGroups'],0)

    def test_real_coverage_failures_and_unknown_sca_are_not_safe_zeroes(self):
        baseline=read(ROOT/'application-baseline.json');projects={p['projectId']:p for p in baseline['projects']}
        for ident in ['spring-projects--spring-petclinic','macrozheng--mall-tiny']:
            self.assertEqual(projects[ident]['analyzers']['java']['status'],'UNAVAILABLE')
            self.assertIn('JAVA_WORKER_FAILED',projects[ident]['analyzers']['java']['limitations'])
        for p in baseline['projects']:
            if not p['evaluationStatus'].startswith('ANALYZED_'):continue
            self.assertTrue(p['repeatConsistent'])
            self.assertEqual(p['sca']['status'],'EXTERNAL_LOOKUP_NOT_RUN')
            self.assertEqual(p['assessmentCoverage']['sca'],'UNKNOWN')
            self.assertNotEqual(p['deploymentAssessment'],'READY')
        self.assertEqual(projects['sahat--hackathon-starter']['evaluationStatus'],'COLLECTION_FAILED_NOT_ANALYZED')

    def test_scoped_truth_and_failure_packs_have_versioned_public_locations(self):
        baseline=read(ROOT/'application-baseline.json');review=read(ROOT/'application-review.json');index=read(ROOT/'application-failure-index.json')
        self.assertEqual(baseline['planSha256'],review['planSha256'])
        self.assertEqual(baseline['engineCommit'],review['engineCommit'])
        self.assertEqual(len(index['packs']),19)
        self.assertEqual(sum(p['groundTruthLabel']=='DANGEROUS'for p in index['packs']),3)
        self.assertEqual(sum(p['groundTruthLabel']=='SAFE'for p in index['packs']),5)
        self.assertFalse(any(p['observed']in {'TP','TN','FN'}for p in index['packs']))
        item=next(x for x in review['pathReviews']if x['caseId']=='northwind-generated-type-comment')
        self.assertEqual(item['fileLicense'],'Apache-2.0')
        for item in review['pathReviews']:
            self.assertFalse(item['attackExecuted'])
            self.assertTrue(item['requiredConditions'])

    def test_url_change_preserves_cve_scope_and_separates_real_app_baseline(self):
        delta=read(ROOT/'url-hardening-delta.json')
        self.assertEqual(delta['removedFalseAlertObservations'],12)
        self.assertEqual(delta['newAlertObservations'],0)
        self.assertEqual(delta['retainedUncertainObservations'],2)
        self.assertFalse(delta['riskPolicyChanged'])
        self.assertFalse(delta['userReviewsRecomputed'])
        self.assertTrue(delta['allComparisonFingerprintsChanged'])
        self.assertEqual(delta['primaryCveMetrics']['finalUser']['counts'],{'NOT_SUPPORTED':38,'RESOURCE_LIMIT':2})
        self.assertTrue(delta['applicationBeforeA'].startswith('NOT_RUN'))
        self.assertTrue(all(x['beforeAssessment']==x['afterAssessment']=='REVIEW_REQUIRED'for x in delta['changes']))

    def test_privacy_revision_preserves_explicit_omission_not_full_settings_review(self):
        baseline=read(ROOT/'application-baseline.json');receipt=read(ROOT/'application-privacy-receipt.json')
        self.assertEqual(receipt['planSha256'],baseline['planSha256'])
        self.assertFalse(receipt['valuesPrinted']);self.assertFalse(receipt['validityChecked'])
        self.assertTrue(receipt['oldSourceCopiesRemoved'])
        bakery=next(p for p in baseline['projects']if p['projectId']=='wagtail--bakerydemo')
        self.assertEqual(bakery['omissionCounts']['CREDENTIAL_SHAPED_CONTENT_NOT_PERSISTED'],1)
        self.assertEqual(sum(p.get('coverage',{}).get('selectedFiles',0)for p in baseline['projects']),1761)
        review=read(ROOT/'application-review.json')
        scope=next(p for p in review['pathReviews']if p['caseId']=='wagtail--bakerydemo-scope')
        self.assertIn('effective settings are not fully reviewed',scope['evidence'])

if __name__=='__main__':unittest.main()
