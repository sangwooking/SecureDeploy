import unittest
from modern_supabase_summary import compare, evidence


class ModernSupabaseSummaryTest(unittest.TestCase):
    def test_absent_legacy_evidence_does_not_invent_authentication(self):
        self.assertEqual(evidence({'typescript': {'supabaseAnalysis': {'accesses': [
            {'clientStatus': 'CLIENT_ORIGIN_UNKNOWN'}]}}}),
            dict(linkedAccesses=0, resultGuards=0, identityIdFilters=0,
                 directNextDeclarations=0, policyStates={'UNKNOWN': 1}))

    def test_repeated_references_are_not_independent_guards(self):
        check = dict(resultEvidence=dict(guardLocation={'line': 2}, userIdFilters=[{'line': 3}]))
        access = dict(clientStatus='CLIENT_DECLARATION_LINKED', authorizationEvidence=dict(
            state='UNKNOWN', authChecks=[check, check], requestEntry={'line': 1}))
        result = evidence({'typescript': {'supabaseAnalysis': {'accesses': [access, access]}}})
        self.assertEqual(result['resultGuards'], 1)
        self.assertEqual(result['identityIdFilters'], 1)
        self.assertEqual(result['directNextDeclarations'], 2)

    def test_different_source_plans_or_projects_cannot_be_compared(self):
        with self.assertRaisesRegex(ValueError, 'SOURCE_PLAN_CHANGED'):
            compare({'planSha256': 'a'}, {'planSha256': 'b'})
        with self.assertRaisesRegex(ValueError, 'PROJECT_SET_CHANGED'):
            compare({'planSha256': 'a', 'projects': []},
                    {'planSha256': 'a', 'projects': [{'projectId': 'different'}]})
