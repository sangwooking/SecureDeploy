import { analyze } from './analyzer.mjs';
let size = 0;
const chunks = [];
try {
  for await (const chunk of process.stdin) {
    size += chunk.length;
    if (size > 8000000) throw new Error('INPUT_LIMIT');
    chunks.push(chunk);
  }
  const result=analyze(JSON.parse(Buffer.concat(chunks).toString('utf8')));
  if(result.supabaseAnalysis&&Buffer.byteLength(JSON.stringify(result))>1950000)
    result.supabaseAnalysis={schemaVersion:1,analyzerVersion:'supabase-rls-v1',status:'PARTIAL',files:[],tables:[],clients:[],accesses:[],findings:[],limitations:['SUPABASE_OUTPUT_LIMIT','DECLARATIONS_NOT_LIVE_DATABASE']};
  process.stdout.write(JSON.stringify(result));
} catch {
  // Parser diagnostics can contain source text. Do not log them.
  process.exitCode = 2;
}
