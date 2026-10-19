import { classify } from './url-context.mjs';
let input = '';
for await (const chunk of process.stdin) {
  input += chunk;
  if (input.length > 3000000) process.exit(2);
}
try {
  const data = JSON.parse(input);
  if (!Array.isArray(data.files) || data.files.length > 100) process.exit(2);
  process.stdout.write(JSON.stringify(classify(data.files)));
} catch { process.exit(2); }
