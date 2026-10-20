import tempfile
from pathlib import Path
import unittest
from java_worker_probe import packet
from benchmark import digest

class WorkerProbeSafetyTest(unittest.TestCase):
    def test_hash_checked_text_is_packet_data_not_executed(self):
        with tempfile.TemporaryDirectory()as folder:
            root=Path(folder);source=root/'sources/demo';source.mkdir(parents=True)
            text=b'throw new Error("must never execute");'
            (source/'Input.java').write_bytes(text)
            plan={'projects':[{'projectId':'demo','files':[{'path':'Input.java','sha256':digest(text)}]}]}
            project={'projectId':'demo','runs':[{'java':{'analysis':{'files':[{'filePath':'Input.java','parseStatus':'NOT_RUN'}]}}}]}
            data,content=packet(root,project,plan)
            self.assertEqual(data[:4],b'\0\0\0\1');self.assertIn('Input.java',content)
            (source/'Input.java').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'SOURCE_HASH'):packet(root,project,plan)

if __name__=='__main__':unittest.main()
