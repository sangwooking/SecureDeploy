import test from 'node:test';
import assert from 'node:assert/strict';
import { classify } from '../url-context.mjs';

// Separate synthetic variations, not externally sourced or independently curated truth.
test('renamed and relocated string contexts retain narrow semantic decisions', () => {
  const cases = [
    ['NORMAL','url','export const image=<svg xmlns="http://www.w3.org/2000/svg"/>;'],
    ['NORMAL','secret',"control.textContent = visible ? 'Reveal Token' : 'Conceal Token';"],
    ['NORMAL','secret','// const apiKey="synthetic-credential-example";'],
    ['NORMAL','url','/* Guide http://manual.example */'],
    ['NORMAL','url','const parsed=new URL(raw,"http://parser.example"); consume(parsed.pathname);'],
    ['WARNING','url','fetch("http://service.example");'],
    ['WARNING','url','axios.post("http://service.example");'],
    ['WARNING','secret','const apiKey="synthetic-credential-example";'],
    ['WARNING','secret','const opts={"token":"synthetic-credential-example"};'],
    ['WARNING','secret','store["secret"]="synthetic-credential-example";'],
    ['UNKNOWN','url','wrapper("http://service.example");'],
    ['UNKNOWN','url','const x=<Svg xmlns="http://www.w3.org/2000/svg"/>;'],
    ['UNKNOWN','url','const x=<svg data-endpoint="http://service.example"/>;'],
    ['UNKNOWN','url','const broken = ; fetch("http://service.example");'],
  ];
  const counts={NORMAL:0,WARNING:0,UNKNOWN:0};
  for (const [label,kind,content] of cases) {
    for (const filePath of ['features/a/Controls.tsx','unrelated/renamed.tsx']) {
      const row=classify([{filePath,content}]).files[0];
      const excluded=kind==='url'?row.excludedLines:row.excludedSecretLines;
      assert.deepEqual(excluded,label==='NORMAL'?[1]:[],label+':'+content);
      if (label==='WARNING'&&kind==='url') assert.deepEqual(row.requestLines,[1]);
    }
    counts[label]++;
  }
  assert.deepEqual(counts,{NORMAL:5,WARNING:5,UNKNOWN:4});
});
