import { analyze } from './analyzer.mjs';
let size = 0;
const chunks = [];
try {
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 8000000) throw new Error('INPUT_LIMIT');
    chunks.push(chunk);
  }
  process.stdout.write(JSON.stringify(analyze(JSON.parse(Buffer.concat(chunks).toString('utf8')))));
} catch {
  // Parser diagnostics can contain source text. Do not log them.
  process.exitCode = 2;
}
