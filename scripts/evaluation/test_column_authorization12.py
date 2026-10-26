import unittest
from column_authorization12 import freeze,configuration,sql_for,database
from column_report12 import adjudicate,declaration

class ColumnTruthTest(unittest.TestCase):
    def test_frozen_cases_have_distinct_identifiers_and_explicit_requirements(self):
        p=freeze();self.assertEqual(36,len(p['cases']));self.assertEqual(36,len({c['caseId'] for c in p['cases']}))
        self.assertTrue(all(c['requirement'] and len(c['sourceSha256'])==64 for c in p['cases']))
        self.assertEqual({'RISK','NORMAL','UNKNOWN'},{c['truth'] for c in p['cases']})
        self.assertEqual(0,p['gradeA']);self.assertFalse(p['independentReview'])

    def test_oracle_refuses_modified_sources_before_opening_a_database(self):
        p=freeze();p['cases'][0]['truth']='NORMAL'
        with self.assertRaises(ValueError):database(p)

    def test_table_revoke_clears_columns_but_column_revoke_does_not_clear_table(self):
        self.assertIn('role',configuration('column-revoke-table-stays')[2])
        self.assertEqual(set(),configuration('table-revoke-clears-columns')[2])
        self.assertIn('GRANT writers TO authenticated',sql_for('inherited'))

    def test_validation_changes_identifiers_without_claiming_an_independent_project(self):
        p=freeze();self.assertEqual(18,sum(c['split'].startswith('VALIDATION') for c in p['cases']))
        self.assertIn('classification',p['cases'][18]['packet']['files'][0]['content'])
        self.assertIn('public.records',p['cases'][18]['packet']['policyFiles'][0]['content'])

    def test_no_record_is_unknown_not_denial_or_a_true_positive(self):
        self.assertEqual('UNKNOWN',declaration({},'role'))
        p=freeze();rows=[dict(caseId=c['caseId'],sourceSha256=c['sourceSha256'],supabase={'accesses':[],'findings':[]}) for c in p['cases']]
        r=adjudicate(p,{'rows':rows});self.assertEqual({'TP':0,'FP':0,'FN':14,'TN':16,'UNKNOWN':6},r['counts']);self.assertEqual(0,r['declarationKnown'])

    def test_incomplete_or_duplicate_case_set_cannot_produce_metrics(self):
        p=freeze()
        with self.assertRaises(ValueError):adjudicate(p,{'rows':[]})
        with self.assertRaises(ValueError):adjudicate(p,{'rows':[{'caseId':p['cases'][0]['caseId']}]*36})
