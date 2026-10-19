import test from 'node:test';
import assert from 'node:assert/strict';
import { classify } from '../url-context.mjs';
const row = (content, filePath = 'server.ts') => classify([{ filePath, content }]).files[0];
test('documentation comments differ from strings, regexes and template execution', () => {
  assert.deepEqual(row('/** http://api.example.org */\nfetch("http://remote.example/path");').excludedLines, [1]);
  assert.deepEqual(row('const x = "/* http://remote.example */";').excludedLines, []);
  assert.deepEqual(row('fetch(`http://remote.example/${x}`);').excludedLines, []);
  assert.deepEqual(row('/* http://docs.example */ fetch("http://remote.example");').excludedLines, []);
  assert.deepEqual(row('// http://docs.example\nconst x = /[/][*]/;\nfetch("http://remote.example");').requestLines,[3]);
});
test('inert URL base versus real network URL propagation', () => {
  for (const source of [
    'const parsed = new URL(input,"http://base.example"); consume(parsed.pathname);',
    'const p = new URL(input,"http://base.example"); const b = expected === p.host; consume(p.pathname);',
    'consume(new URL(input,"http://base.example").pathname);',
  ]) assert.deepEqual(row(source).excludedLines,[1]);
  for (const source of [
    'fetch(new URL(input,"http://remote.example"));',
    'const p = new URL(input,"http://remote.example"); fetch(p);',
    'const p = new URL(input,"http://remote.example"); fetch(p.href);',
    'const p = new URL(input,"http://remote.example"); use(p.origin);',
    'const p = new URL(input,"http://remote.example"); p.pathname = input;',
    'const p = new URL(input,"http://remote.example"); const alias = p; fetch(alias);',
    'function f(URL) { const p = new URL(input,"http://remote.example"); use(p.pathname); }',
    'const p = new URL(input,"http://remote.example"); function f(p) {use(p.pathname);}',
    'const networkUrl = hostname ? `http://${host}:${port}` : null;',
    'let p = new URL(input,"http://remote.example"); use(p.pathname);',
  ]) assert.deepEqual(row(source).excludedLines,[],source);
});
test('parse errors, JSX, size and caller uncertainty never suppress', () => {
  assert.equal(row('const = "http://remote.example"').status,'UNKNOWN');
  assert.equal(row('x'.repeat(100001)).status,'UNKNOWN');
  assert.deepEqual(row('const x = <div>http://remote.example</div>;', 'App.tsx').excludedLines,[]);
  assert.deepEqual(row('const address = "http://remote.example"; wrapper(address);').excludedLines,[]);
});
