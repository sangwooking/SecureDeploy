// Our trusted analyzer only. The parent supplies frozen target strings on stdin.
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';
try {
  const {analyze}=await import(pathToFileURL(process.argv[2]).href);
  const input=fs.readFileSync(0,'utf8');if(input.length>1200000)throw Error('INPUT_LIMIT');
  process.stdout.write(JSON.stringify(analyze(JSON.parse(input))));
}catch {process.stderr.write('TRUSTED_ANALYZER_PROBE_FAILED\n');process.exitCode=1;}
