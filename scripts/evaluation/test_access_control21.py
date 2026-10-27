import unittest
from access_control21 import facts


class AccessFactsTest(unittest.TestCase):
    def test_missing_auth_evidence_is_not_synthesized(self):
        r={'analyzerVersion':'fixture','findings':[],'supabaseAnalysis':{'accesses':[{}],'findings':[],'budgetUsage':{}}}
        f=facts(r)
        self.assertEqual(f['identityFilters'],0)
        self.assertEqual(f['requestAssociations'],0)
        self.assertEqual(f['roles'],[None])

    def test_guard_and_filters_do_not_change_unknown_role(self):
        r={'analyzerVersion':'fixture','findings':[],'supabaseAnalysis':{'accesses':[{'authorizationEvidence':{
            'state':'UNKNOWN','effectiveRole':'UNKNOWN','requestEntry':{'kind':'NEXT_ROUTE_HANDLER'},
            'authChecks':[{'resultEvidence':{'userIdFilters':[{'line':1}]}}]}}],'findings':[],'budgetUsage':{}}}
        f=facts(r)
        self.assertEqual(f['identityFilters'],1)
        self.assertEqual(f['states'],['UNKNOWN'])
        self.assertEqual(f['roles'],['UNKNOWN'])
