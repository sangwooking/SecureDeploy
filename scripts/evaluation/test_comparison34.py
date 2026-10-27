import copy
import unittest
from comparison34 import ENGINES,validate_results

class Comparison34Tests(unittest.TestCase):
    def fixtures(self):
        plan={'projects':[{'projectId':'public-app','commitSha':'a'*40}]}
        versions={}
        for v,(commit,worker) in ENGINES.items():
            run={'ruleInputs':[{'filePath':'app/route.ts'}],'typescript':{'analyzerVersion':worker,'files':[{'filePath':'app/route.ts','parseStatus':'PARSED'}]},'elapsedMs':1,'parentHeapUsedBytes':100}
            versions[v]={'engineCommit':commit,'planSha256':'f'*64,'externalLookups':'NOT_RUN','userDatabase':'NOT_USED',
                         'projects':[{'projectId':'public-app','commitSha':'a'*40,'status':'ANALYZED_WITH_SCOPE_LIMITS_NOT_SAFETY_CERTIFICATION','runs':[run,copy.deepcopy(run)]}]}
        return plan,versions
    def test_three_versions_require_the_same_pinned_source_and_repeats(self):
        plan,data=self.fixtures();validate_results(plan,data,'f'*64)
    def test_result_editing_or_scope_drift_is_not_accepted(self):
        for kind in ['sha','input','parse','repeat','worker','engine','external','database','project']:
            plan,data=self.fixtures();r=data['v42'];p=r['projects'][0]
            if kind=='sha':p['commitSha']='b'*40
            elif kind=='input':
                for row in p['runs']:row['ruleInputs']=[]
            elif kind=='parse':
                for row in p['runs']:row['typescript']['files']=[]
            elif kind=='repeat':p['runs'][1]['unexpectedFinding']=True
            elif kind=='worker':
                for row in p['runs']:row['typescript']['analyzerVersion']='other'
            elif kind=='engine':r['engineCommit']='b'*40
            elif kind=='external':r['externalLookups']='RUN'
            elif kind=='database':r['userDatabase']='USED'
            else:p['projectId']='another-app'
            with self.subTest(kind=kind),self.assertRaises(ValueError):validate_results(plan,data,'f'*64)
    def test_missing_repeat_or_duplicate_project_is_not_complete(self):
        for kind in ['repeat','duplicate']:
            plan,data=self.fixtures();p=data['v42']['projects'][0]
            if kind=='repeat':p['runs'].pop()
            else:data['v42']['projects'].append(copy.deepcopy(p))
            with self.assertRaises(ValueError):validate_results(plan,data,'f'*64)

if __name__=='__main__':unittest.main()
