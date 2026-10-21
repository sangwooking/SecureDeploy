import copy
import unittest
from supabase_rls import summary


class RlsReceiptTests(unittest.TestCase):
    def data(self):
        run=dict(filtered=[],reviewCandidates=[],typescript=dict(supabaseAnalysis=dict(status='PARTIAL',findings=[])),
                 risk=dict(prioritySummary={}),securityScore=100,elapsedMs=1,parentHeapUsedBytes=2)
        return dict(projects=[dict(projectId='controlled',commitSha='a'*40,runs=[run,copy.deepcopy(run)])])

    def test_partial_empty_results_do_not_become_safe_or_automatic_truth(self):
        result=summary(self.data())[0]
        self.assertEqual(result['rls']['status'],'PARTIAL')
        self.assertNotIn('TN',result)

    def test_repeat_mismatch_is_not_hidden(self):
        data=self.data();data['projects'][0]['runs'][1]['typescript']['supabaseAnalysis']['status']='NOT_APPLICABLE'
        with self.assertRaisesRegex(ValueError,'REPEAT_MISMATCH'):summary(data)

    def test_old_snapshot_absence_is_not_a_fabricated_zero_rls_count(self):
        data=self.data()
        for run in data['projects'][0]['runs']:run['typescript']={}
        self.assertIsNone(summary(data)[0]['rls'])
