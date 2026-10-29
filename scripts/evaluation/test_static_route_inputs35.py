import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from static_route_inputs35 import packet


class StaticRouteInputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.base = self.root / 'sources' / 'owned-example'
        self.base.mkdir(parents=True)
        self.files = {'routes.cjs': "const r=require('express').Router();\r\nr.post('/',(req,res)=>eval(req.body.code));\r\n",
                      'omitted.cjs': "throw 'not-selected';", 'package.json': '{"dependencies":{"express":"4.18.2"}}',
                      'policy.sql': 'SELECT 1;'}
        for name, text in self.files.items():
            (self.base / name).write_bytes(text.encode())
        self.plan = {'projects': [{'projectId': 'owned-example', 'files': [dict(path=n, sha256=hashlib.sha256(t.encode()).hexdigest()) for n, t in self.files.items()]}]}
        self.snapshot = {'projects': [{'projectId': 'owned-example', 'commitSha': '1' * 40, 'runs': [{'typescript': {'files': [
            dict(filePath='routes.cjs', parseStatus='PARSED'), dict(filePath='omitted.cjs', parseStatus='NOT_RUN')]}}]}]}
        self.save_plan()

    def save_plan(self):
        data = json.dumps(self.plan).encode()
        (self.root / 'application-plan.json').write_bytes(data)
        self.snapshot['planSha256'] = hashlib.sha256(data).hexdigest()

    def run_packet(self):
        return packet(self.root, self.snapshot, 'owned-example')

    def test_selection_hash_and_line_normalization(self):
        data, meta = self.run_packet()
        p = json.loads(data)
        self.assertEqual([x['filePath'] for x in p['files']], ['routes.cjs'])
        self.assertNotIn('\r', p['files'][0]['content'])
        self.assertEqual(meta['sourceFileHashes']['routes.cjs'], hashlib.sha256(self.files['routes.cjs'].encode()).hexdigest())
        self.assertEqual(data, self.run_packet()[0])

    def test_no_policy_or_completeness_claim(self):
        data, meta = self.run_packet()
        self.assertNotIn('policyFiles', json.loads(data))
        self.assertFalse(json.loads(data)['nodeSourceInventoryComplete'])
        self.assertFalse(meta['policiesIncluded'])
        self.assertNotIn('policy.sql', meta['sourceFileHashes'])

    def test_changed_source_rejected(self):
        (self.base / 'routes.cjs').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'HASH'):
            self.run_packet()

    def test_changed_plan_rejected(self):
        (self.root / 'application-plan.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'PLAN_HASH'):
            self.run_packet()

    def test_path_escape_rejected(self):
        self.plan['projects'][0]['files'][0]['path'] = '../escape.cjs'
        self.save_plan()
        with self.assertRaisesRegex(ValueError, 'PATH'):
            self.run_packet()

    def test_symlink_rejected(self):
        (self.base / 'routes.cjs').unlink()
        (self.base / 'routes.cjs').symlink_to(self.base / 'omitted.cjs')
        with self.assertRaisesRegex(ValueError, 'SYMLINK'):
            self.run_packet()

    def test_duplicate_paths_rejected(self):
        self.plan['projects'][0]['files'].append(self.plan['projects'][0]['files'][0])
        self.save_plan()
        with self.assertRaisesRegex(ValueError, 'DUPLICATE'):
            self.run_packet()

    def test_unparsed_source_not_opened(self):
        (self.base / 'omitted.cjs').unlink()
        self.assertEqual(len(json.loads(self.run_packet()[0])['files']), 1)

    def test_malformed_dependency_shape_is_unknown(self):
        self.files['package.json'] = '{"dependencies":[]}'
        (self.base / 'package.json').write_text(self.files['package.json'])
        next(x for x in self.plan['projects'][0]['files'] if x['path'] == 'package.json')['sha256'] = hashlib.sha256(self.files['package.json'].encode()).hexdigest()
        self.save_plan()
        self.assertEqual(json.loads(self.run_packet()[0])['nodeManifests'][0]['resolutionStatus'], 'UNKNOWN')

    def test_selection_limit_rejected(self):
        self.snapshot['projects'][0]['runs'][0]['typescript']['files'] *= 101
        with self.assertRaisesRegex(ValueError, 'SELECTION_LIMIT'):
            self.run_packet()


if __name__ == '__main__':
    unittest.main()
