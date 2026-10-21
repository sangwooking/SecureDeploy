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
  assert.equal(row('x'.repeat(250001)).status,'UNKNOWN');
  assert.deepEqual(row('const x = <div>http://remote.example</div>;', 'App.tsx').excludedLines,[]);
  assert.deepEqual(row('const address = "http://remote.example"; wrapper(address);').excludedLines,[]);
});
test('intrinsic SVG namespace is an identifier, but custom props and network uses remain unknown', () => {
  assert.deepEqual(row('const icon = <svg xmlns="http://www.w3.org/2000/svg"/>;', 'Icon.tsx').excludedLines,[1]);
  assert.deepEqual(row('const icon = <svg xmlns:xlink="http://www.w3.org/1999/xlink"/>;', 'Icon.tsx').excludedLines,[1]);
  for (const code of ['const icon = <Widget xmlns="http://www.w3.org/2000/svg"/>;',
    'const icon = <svg data-url="http://remote.example"/>;',
    'const icon = <svg xmlns="http://www.w3.org/2000/svg"/>; fetch("http://remote.example");'])
    assert.deepEqual(row(code,'Icon.tsx').excludedLines,[]);
  assert.deepEqual(row('fetch("http://www.w3.org/2000/svg");').excludedLines,[]);
});
test('bounded leading comments in oversized source do not classify code or incomplete comments as safe', () => {
  const file=(content)=>classify([{filePath:'generated.d.ts',content,prefixOnly:true}]).files[0];
  assert.deepEqual(file('/** License http://license.example */\ndeclare const x: string;').excludedLines,[1]);
  assert.deepEqual(file('/** License http://license.example */ fetch("http://remote.example");').excludedLines,[]);
  assert.deepEqual(file('/* http://license.example').excludedLines,[]);
  assert.deepEqual(file('declare const text: "http://remote.example";').excludedLines,[]);
  assert.deepEqual(file('interface Env { binding: string; }\n/** License http://license.example */\ndeclare const x: string;').excludedLines,[2]);
  assert.deepEqual(file('declare const pattern: "/* http://not-comment.example */";\n').excludedLines,[]);
  assert.deepEqual(file('const invalid=;\n/* http://after-error.example */\n').excludedLines,[]);
});
test('secret-like text inside display strings or comments is not a declaration', () => {
  assert.deepEqual(row("button.innerText = hidden ? 'Show Secret' : 'Hide Secret';").excludedSecretLines,[1]);
  assert.deepEqual(row('// secret = "something-long"').excludedSecretLines,[1]);
  for (const code of ['const secret="something-long";', 'const config={"secret":"something-long"};',
    "const title='Show Secret'; const secret='something-long';",'unknown.secret="something-long";',
    'config["secret"]="something-long";', 'class Config { "secret"="something-long"; }',
    'const config={["secret"]:"something-long"};'])
    assert.deepEqual(row(code).excludedSecretLines,[]);
  const fake='sk-'+'Q9zT4pL7mN2vX6aB8cD3eF5gH1jK0rS9';
  assert.deepEqual(row('// secret = "'+fake+'"').excludedSecretLines,[]);
  assert.deepEqual(row('const payload = `secret="embedded-short-secret"`;').excludedSecretLines,[]);
});
