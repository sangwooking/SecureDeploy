import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import application_track as app

SHA='a'*40
ROOT='demo-'+SHA
def archive(rows):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w:gz')as tar:
        for name,content,link in rows:
            info=tarfile.TarInfo(ROOT+'/'+name)
            if link:info.type=tarfile.SYMTYPE;info.linkname=link;tar.addfile(info)
            else:info.size=len(content);tar.addfile(info,io.BytesIO(content))
    return stream.getvalue()

class ApplicationIntakeTests(unittest.TestCase):
    def test_explicit_license_scope_exclusion_is_component_bounded_and_recorded(self):
        with tempfile.TemporaryDirectory()as folder:
            p=Path(folder)/'source'
            data=archive([('LICENSE',b'AGPL',None),('ee/route.ts',b'private()',None),('app/(ee)/page.ts',b'private()',None),('eel/route.ts',b'public()',None)])
            result=app.unpack(data,p,'example/demo',SHA,['ee','app/(ee)'])
            self.assertEqual({f['path']for f in result['files']},{'LICENSE','eel/route.ts'})
            self.assertEqual(result['omissionCounts'],{'LICENSE_SCOPE_EXCLUDED':2})
    def test_license_scope_exclusion_rejects_root_traversal_and_unbounded_lists(self):
        for prefixes in [['.'],['../outside'],['/outside'],['a']*17,'ee']:
            with tempfile.TemporaryDirectory()as folder,self.assertRaises(ValueError):
                app.unpack(archive([('LICENSE',b'MIT',None)]),Path(folder)/'source','example/demo',SHA,prefixes)
    def unpack(self,rows):
        with tempfile.TemporaryDirectory()as folder:
            p=Path(folder)/'source'
            result=app.unpack(archive(rows),p,'example/demo',SHA)
            return result,{str(f.relative_to(p)):f.read_bytes()for f in p.rglob('*')if f.is_file()}
    def test_whole_context_is_text_data_with_exact_hashes(self):
        result,files=self.unpack([('LICENSE',b'MIT License',None),('src/routes.ts',b'throw Error("must not run");',None),('src/service.ts',b'export const query = "SELECT 1";',None)])
        self.assertEqual(result['retainedFiles'],3)
        self.assertEqual(len(result['licenseFiles']),1)
        self.assertEqual(set(files),{'LICENSE','src/routes.ts','src/service.ts'})
        self.assertTrue(all(app.digest(files[f['path']])==f['sha256']for f in result['files']))
    def test_links_generated_binary_and_credential_shaped_files_are_explicit_omissions(self):
        result,files=self.unpack([('LICENSE',b'MIT License',None),('alias',b'','../../outside'),('node_modules/install.js',b'bad()',None),('image.png',b'image',None),('config.ts',('const k="ghp_'+'a'*40+'"').encode(),None)])
        self.assertEqual(set(files),{'LICENSE'})
        self.assertEqual(result['discoveredArchiveFiles'],5)
        self.assertEqual(len(result['omitted']),4)
        self.assertIn('CREDENTIAL_SHAPED_CONTENT_NOT_PERSISTED',result['omissionCounts'])
    def test_cloud_key_shapes_are_omitted_without_printing_or_validating_values(self):
        values=['AI'+'za'+'a'*35,'AK'+'IA'+'A'*16,'xo'+'xb-'+'a'*24,'-----BEGIN '+'ENCRYPTED PRIVATE KEY-----']
        for value in values:
            result,files=self.unpack([('LICENSE',b'MIT',None),('settings.py',value.encode(),None)])
            self.assertEqual(set(files),{'LICENSE'})
            self.assertEqual(result['omissionCounts'],{'CREDENTIAL_SHAPED_CONTENT_NOT_PERSISTED':1})
            with tempfile.TemporaryDirectory()as folder,self.assertRaisesRegex(ValueError,'SENSITIVE_METADATA'):
                app.write(Path(folder)/'output.json',{'value':value})
    def test_traversal_duplicate_wrong_root_and_encoded_path_fail_closed(self):
        for rows in [[('LICENSE',b'MIT',None),('../outside',b'x',None)],
                     [('LICENSE',b'MIT',None),('LICENSE',b'other',None)],
                     [('LICENSE',b'MIT',None),('encoded%20path.ts',b'x',None)]]:
            with self.assertRaises(ValueError):self.unpack(rows)
        with tempfile.TemporaryDirectory()as folder,self.assertRaisesRegex(ValueError,'ROOT_IDENTITY'):
            app.unpack(archive([('LICENSE',b'MIT',None)]),Path(folder)/'source','example/other',SHA)
    def test_expansion_and_per_file_limits_are_not_clean_results(self):
        with patch.object(app,'MAX_EXPANDED',100),self.assertRaisesRegex(ValueError,'EXPANSION'):
            self.unpack([('LICENSE',b'MIT',None)])
        with patch.object(app,'MAX_FILE',20):
            result,files=self.unpack([('LICENSE',b'MIT',None),('big.py',b'x'*21,None)])
        self.assertEqual(result['omitted'][0]['status'],'LIMIT_EXCEEDED')
    def test_license_required_and_no_archive_persistence(self):
        with self.assertRaisesRegex(ValueError,'ROOT_LICENSE'):
            self.unpack([('source.py',b'import os',None)])

class ApplicationSummaryTests(unittest.TestCase):
    def setup_data(self,root):
        source=root/'sources/demo';source.mkdir(parents=True)
        (source/'entry.ts').write_text('export const value = 1;')
        plan={'projects':[{'projectId':'demo','files':[{'path':'entry.ts','sha256':app.digest((source/'entry.ts').read_bytes()),'bytes':23}]}]}
        app.write(root/'application-plan.json',plan)
        raw={'planSha256':app.digest((root/'application-plan.json').read_bytes()),'engineCommit':'a'*40,'projects':[{'projectId':'demo'}]}
        app.write(root/'raw.json',raw)
        return raw,{'planSha256':raw['planSha256'],'engineCommit':raw['engineCommit'],'pathReviews':[]}
    def test_changed_source_and_review_version_are_rejected(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);raw,review=self.setup_data(root)
            with self.assertRaisesRegex(ValueError,'REVIEW_VERSION'):
                app.summarize(root,root/'raw.json',root/'packs',dict(review,engineCommit='b'*40))
            (root/'sources/demo/entry.ts').write_text('changed')
            with self.assertRaisesRegex(ValueError,'SOURCE_CHANGED'):
                app.summarize(root,root/'raw.json',root/'packs',review)
    def test_missing_project_or_repeat_is_not_a_complete_evaluation(self):
        for projects in [[],[{'projectId':'demo','runs':[{}]}]]:
            with tempfile.TemporaryDirectory()as folder:
                root=Path(folder);raw,review=self.setup_data(root)
                app.write(root/'bad.json',dict(raw,projects=projects))
                with self.assertRaisesRegex(ValueError,'RESULT_'):
                    app.summarize(root,root/'bad.json',root/'packs',review)

if __name__=='__main__':unittest.main()
