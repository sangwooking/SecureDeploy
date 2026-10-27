import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

TOOL=Path(__file__).with_name('module_inventory34.mjs')
class ModuleInventory34Tests(unittest.TestCase):
    def run_inventory(self,content,path='entry.ts',bad_plan=False):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);source=root/'sources/public-app';source.mkdir(parents=True)
            (source/'entry.ts').write_text(content)
            plan={'projects':[{'projectId':'public-app','full_name':'fixture/public-app','files':[{'path':'entry.ts','sha256':hashlib.sha256(content.encode()).hexdigest()}]}]}
            data=json.dumps(plan).encode();(root/'application-plan.json').write_bytes(data)
            raw={'planSha256':'bad' if bad_plan else hashlib.sha256(data).hexdigest(),
                 'projects':[{'projectId':'public-app','runs':[{'typescript':{'files':[{'filePath':path,'parseStatus':'PARSED'}]}}]}]}
            (root/'raw.json').write_text(json.dumps(raw))
            result=subprocess.run(['node',str(TOOL),str(root),str(root/'raw.json'),str(root/'inventory.json')],capture_output=True,text=True,timeout=10)
            output=json.loads((root/'inventory.json').read_text())if(root/'inventory.json').exists()else None
            return result.returncode,output
    def test_inventory_parses_strings_without_executing_target(self):
        code,output=self.run_inventory("throw new Error('must not execute');import {run} from './helper';export const GET=wrap(handler);")
        self.assertEqual(code,0)
        p=output['projects'][0];self.assertEqual(len(p['references']),1)
        self.assertEqual(p['handlerFactoryShapes'][0]['kind'],'NAMED_HTTP_CALL_INITIALIZER_SYNTAX_ONLY')
    def test_path_plan_and_budget_failures_do_not_emit_partial_success(self):
        for args in [('export {};','../outside.ts',False),('export {};','entry.ts',True),('x'*100001,'entry.ts',False)]:
            with self.subTest(args=(args[1],args[2],len(args[0]))):
                code,output=self.run_inventory(*args);self.assertNotEqual(code,0);self.assertIsNone(output)

if __name__=='__main__':unittest.main()
