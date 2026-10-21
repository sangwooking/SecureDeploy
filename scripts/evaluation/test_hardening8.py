import unittest
from hardening8 import verify_lineage, run_summary
from benchmark import digest


class EntryContextReportTest(unittest.TestCase):
    def manifests(self):
        item = dict(caseId='example-parent', repositoryCommitSha='a'*40,
            files=[dict(path='app.js', sha256='b'*64)])
        original = dict(_bytes=b'original manifest', cases=[item])
        enriched = dict(parentManifestSha256=digest(original['_bytes']),
            cases=[dict(item, files=item['files']+[dict(path='router.js', sha256='c'*64)])])
        return original, enriched

    def test_enrichment_preserves_original_source(self):
        verify_lineage(*self.manifests())

    def test_source_changes_rejected(self):
        old, new = self.manifests()
        new['cases'][0]['files'][0] = dict(path='app.js', sha256='d'*64)
        with self.assertRaisesRegex(ValueError, 'ORIGINAL_SOURCE_CHANGED'):
            verify_lineage(old, new)

    def test_revision_changes_rejected(self):
        old, new = self.manifests()
        new['cases'][0]['repositoryCommitSha'] = 'e'*40
        with self.assertRaisesRegex(ValueError, 'SOURCE_COMMIT_CHANGED'):
            verify_lineage(old, new)

    def test_callback_is_not_an_entry_or_finding(self):
        run = dict(typescript=dict(analyzerVersion='ts-server-v11', status='PARTIAL',
            files=[dict(parseStatus='PARSED', entrypoints=0, functionsAnalyzed=1,
                limitations=['EXTERNAL_IMPLEMENTATION_UNKNOWN'])],
            nodeUses=[dict(kind='CALLBACK_BOUND')], findings=[]),
            elapsedMs=10, parentHeapUsedBytes=100)
        result = run_summary([run, run])
        self.assertEqual(result['entries'], 0)
        self.assertEqual(result['structuralFindingCount'], 0)
        self.assertEqual(result['nodeUseKinds'], {'CALLBACK_BOUND': 1})


if __name__ == '__main__':
    unittest.main()
