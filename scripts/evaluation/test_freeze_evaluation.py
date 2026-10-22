from collections import Counter
import unittest
from unittest.mock import patch
from pathlib import Path
from freeze_evaluation import controls,report,ENGINE


class FreezeControlsTest(unittest.TestCase):
    def test_comparison_rejects_a_different_raw_engine_before_scoring(self):
        with patch('freeze_evaluation.outside',return_value=Path('/private/tmp/frozen')),\
             patch('freeze_evaluation.read',side_effect=[{}, {'engineCommit':ENGINE},{'engineCommit':ENGINE}]):
            with self.assertRaisesRegex(ValueError,'ENGINE_CHANGED'):
                report(Path('/private/tmp/frozen'),Path('/private/tmp/raw'),Path('/private/tmp/new'),'0'*40)

    def test_truth_and_support_are_declared_before_execution(self):
        rows=[]
        for kind in ('EDGE','NEXT'):
            cases,files=controls(kind)
            self.assertEqual(Counter(c['truth']for c in cases),{'RISK':12,'NORMAL':12,'UNKNOWN':6})
            self.assertEqual({c['area']for c in cases},{'EXPOSURE','SSRF','HTML','RLS','DEPLOYMENT','SCA'})
            for c in cases:
                self.assertIn(c['targetFile'],files)
                self.assertLessEqual(c['targetLine'],len(files[c['targetFile']].splitlines()))
                self.assertTrue(c['rationale'])
                self.assertEqual(c['grade'],'B')
            rows.extend(cases)
        self.assertEqual(len({c['caseId']for c in rows}),60)
        self.assertEqual(sum(c['support']=='NOT_SUPPORTED'for c in rows),2)
        self.assertEqual(sum(c['support']=='LOOKUP_REQUIRED'for c in rows),6)

    def test_known_normal_link_is_not_relabelled_as_uncertain(self):
        for kind in ('EDGE','NEXT'):
            cases,_=controls(kind)
            c=next(c for c in cases if c['caseId'].endswith('react-link'))
            self.assertEqual(c['truth'],'NORMAL')

    def test_server_source_pairs_are_not_just_identifier_renames(self):
        edge,ef=controls('EDGE');nxt,nf=controls('NEXT')
        self.assertTrue(any('Deno.serve' in text for text in ef.values()))
        self.assertTrue(any('export async function POST' in text for text in nf.values()))
        self.assertTrue(any('headers.get' in text for text in ef.values()))
        self.assertTrue(any('searchParams.set' in text for text in nf.values()))
        self.assertTrue(any('CREATE POLICY' in text for text in nf.values()))
