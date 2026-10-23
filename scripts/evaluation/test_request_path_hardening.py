import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import request_path_hardening as audit

class RequestPathAuditTests(unittest.TestCase):
    def test_missing_repeat_and_real_result_changes_fail_closed(self):
        for runs in [[{}],[{'risk':'first'},{'risk':'changed'}]]:
            with patch.object(audit,'read',return_value={'projects':[{'runs':runs}]}),self.assertRaisesRegex(ValueError,'REPEAT_MISMATCH'):
                audit.load(Path('/unused'),'sample','after')
    def test_timing_changes_are_not_security_result_changes(self):
        project={'runs':[{'elapsedMs':1,'risk':{'assessedAt':'a'}},{'elapsedMs':2,'risk':{'assessedAt':'b'}}]}
        with patch.object(audit,'read',return_value={'projects':[project]}) as reader:
            _,result=audit.load(Path('/unused'),'sample','after')
            self.assertEqual(result,project)
            self.assertTrue(str(reader.call_args.args[0]).endswith('sample-hardening2-release.json'))
    @unittest.skipUnless((Path(__file__).resolve().parents[2]/'analyzers/typescript/node_modules/typescript/lib/typescript.js').is_file(),'Trusted parser not installed')
    def test_parser_distinguishes_fragments_without_importing_or_executing_source(self):
        with tempfile.TemporaryDirectory() as folder:
            marker=Path(folder)/'must-not-exist'
            sources=[{'filePath':'ordinary.ts','content':"import fs from 'node:fs';fs.writeFileSync("+json.dumps(str(marker))+",'unexpected');export const value=1;"},
                     {'filePath':'member.ts','content':"field:()=>1\n}"},
                     {'filePath':'method.ts','content':"render(){ return 1; }"}]
            p=subprocess.run(['node',str(Path(__file__).with_name('request_path_syntax_probe.mjs'))],input=json.dumps({'files':sources}).encode(),
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=True)
            result=json.loads(p.stdout)
            self.assertFalse(marker.exists());self.assertFalse(result['targetExecuted'])
            self.assertEqual([f['category'] for f in result['files']],['PARSED_STANDALONE','MEMBER_FRAGMENT','METHOD_FRAGMENT'])

if __name__=='__main__':unittest.main()
