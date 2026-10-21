import json
from pathlib import Path
import tempfile
import unittest
from supabase_authorization import prepare,CASES
from application_track import digest

class SupabaseAuthorizationTest(unittest.TestCase):
    def roots(self,root):
        roots=[]
        for name,ident,file in [('edge','nglguarino--echoverse-11labs','supabase/functions/base/index.ts'),('next','next-boundary-original','app/api/seed/route.ts')]:
            folder=root/name;source=folder/'sources'/ident;path=source/file;path.parent.mkdir(parents=True);path.write_text('export const synthetic=1;\n')
            project=dict(projectId=ident,commitSha='a'*40,license='MIT',files=[dict(path=file,sha256=digest(path.read_bytes()),bytes=path.stat().st_size)])
            (folder/'application-plan.json').write_text(json.dumps(dict(schemaVersion=1,projects=[project])))
            roots.append(folder)
        return roots

    def test_two_structures_have_hashed_controls_without_whole_app_truth(self):
        with tempfile.TemporaryDirectory()as directory:
            root=Path(directory);edge,next_root=self.roots(root);out=root/'controls';prepare(edge,next_root,out)
            plan=json.loads((out/'application-plan.json').read_text());self.assertEqual(len(plan['projects']),8)
            self.assertIn('not independent',plan['splits'])
            self.assertEqual(set(p['targetState']for p in plan['projects']),{x[1]for x in CASES.values()})
            for p in plan['projects']:
                self.assertEqual(p['grade'],'B')
                for f in p['files']:self.assertEqual(digest((out/'sources'/p['projectId']/f['path']).read_bytes()),f['sha256'])

    def test_missing_license_and_source_integrity_fail_closed(self):
        for invalid in ('LICENSE','HASH'):
            with tempfile.TemporaryDirectory()as directory:
                root=Path(directory);edge,next_root=self.roots(root)
                plan=json.loads((next_root/'application-plan.json').read_text())
                if invalid=='LICENSE':plan['projects'][0]['license']='UNVERIFIED'
                else:plan['projects'][0]['files'][0]['sha256']='0'*64
                (next_root/'application-plan.json').write_text(json.dumps(plan))
                with self.assertRaisesRegex(ValueError,'LICENSE|SOURCE_HASH'):prepare(edge,next_root,root/'out')
